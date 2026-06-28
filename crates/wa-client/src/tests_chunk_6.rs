// Auto-partitioned test chunk 6 of 8 (feature `wat6`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat6 to stay within the VM RAM budget.
// Included into `mod chunk_6` in lib.rs; allow-attrs live on that module decl.
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
async fn incoming_processor_with_placeholder_retry_and_media_retry_downloads_pending_media() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut events = client.subscribe();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-combined-media",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [8u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"combined retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/combined/old"),
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
        direct_path: Some("/combined/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[7u8; 12],
    )
    .unwrap();
    let incoming = BinaryNode::new("receipt")
        .with_attr("id", &key.id)
        .with_attr("from", "999@s.whatsapp.net")
        .with_attr("type", "server-error")
        .with_content(vec![
            BinaryNode::new("rmr")
                .with_attr("jid", &key.remote_jid)
                .with_attr("from_me", "false")
                .with_attr("participant", key.participant.as_deref().unwrap()),
            BinaryNode::new("encrypt").with_content(vec![
                BinaryNode::new("enc_p").with_content(payload.ciphertext),
                BinaryNode::new("enc_iv").with_content(payload.iv),
            ]),
        ]);
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/combined/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_retry_and_media_retry(
            connection.clone(),
            IncomingDecryptor,
            RelayEncryptor::default(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-combined-media");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    let processed = recv_media_retry_processed_event(&mut events).await;
    assert_eq!(processed.downloads.len(), 1);
    assert_eq!(processed.downloads[0].plaintext, b"combined retried media");
    assert!(processed.errors.is_empty());
    assert_eq!(processed.ignored_without_pending, 0);
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_media_and_signal_provider_emits_offline_group_notification_append_stub()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_retry_and_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-combined-offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000190")
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
    assert_eq!(
        ack.attrs["id"],
        "spawn-combined-offline-group-ephemeral-stub"
    );
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
        "spawn-combined-offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000190");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "spawn-combined-offline-group-ephemeral-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_190));
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
    tokio::task::yield_now().await;
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::MediaRetryProcessed(_)),
            "notification-only combined processor must not emit media retry side effects"
        );
    }
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_media_and_signal_provider_emits_offline_group_participant_add_append_stub()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_retry_and_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-combined-offline-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000290")
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
    assert_eq!(
        ack.attrs["id"],
        "spawn-combined-offline-group-participant-add-stub"
    );
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
        "spawn-combined-offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000290");
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
    assert_eq!(
        stub.key.id,
        "spawn-combined-offline-group-participant-add-stub"
    );
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_290));
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
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::MediaRetryProcessed(_)),
            "notification-only combined processor must not emit media retry side effects"
        );
    }
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_media_and_signal_provider_normalizes_legacy_retry_receipt()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 91;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-spawn-media-signal-legacy",
            wa_proto::proto::Message {
                conversation: Some("spawn media signal legacy retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_retry_and_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-spawn-media-signal-legacy")
        .with_attr("from", "123:1@c.us")
        .with_attr("recipient", "123@c.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0310, 4).unwrap()),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-spawn-media-signal-legacy");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

    let encrypt_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(encrypt_query.attrs["xmlns"], "encrypt");
    assert_eq!(
        encrypt_key_query_user_attrs(&encrypt_query),
        vec![(
            "123:1@s.whatsapp.net".to_owned(),
            Some("identity".to_owned())
        )]
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&valid_session_response_for_query(
                &encrypt_query,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-spawn-media-signal-legacy");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "spawn media signal legacy retry",
    );
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
    );
    let plan = client
        .plan_retry_resend(
            &wa_core::parse_retry_receipt(&receipt).unwrap().unwrap(),
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared_after_success = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_success.jobs.is_empty());
    assert_eq!(
        prepared_after_success.missing_message_ids,
        vec!["retry-spawn-media-signal-legacy"]
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_media_and_signal_provider_deduplicates_own_pn_lid_all_devices()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 130;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-spawn-combined-own-alias-all-devices",
            wa_proto::proto::Message {
                conversation: Some("spawn combined own alias retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_retry_and_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-spawn-combined-own-alias-all-devices")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![BinaryNode::new("retry").with_attr("count", "1")]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "retry-spawn-combined-own-alias-all-devices"
    );
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

    let refresh_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(refresh_query.attrs["xmlns"], "encrypt");
    assert_eq!(
        encrypt_key_query_user_attrs(&refresh_query),
        vec![("123@s.whatsapp.net".to_owned(), Some("identity".to_owned()))]
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&valid_session_response_for_query(
                &refresh_query,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();

    let usync_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(usync_query.attrs["xmlns"], "usync");
    assert_usync_query_protocol(&usync_query, "devices");
    assert_eq!(
        usync_query_user_jids(&usync_query),
        vec![
            "123@s.whatsapp.net".to_owned(),
            "999:7@s.whatsapp.net".to_owned(),
            "ownlid@lid".to_owned(),
        ]
    );
    let usync_response = BinaryNode::new("iq")
        .with_attr("id", usync_query.attrs["id"].clone())
        .with_attr("type", "result")
        .with_content(vec![BinaryNode::new("usync").with_content(vec![
            BinaryNode::new("list").with_content(vec![
                BinaryNode::new("user")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_content(vec![BinaryNode::new("devices").with_content(vec![
                        BinaryNode::new("device-list")
                            .with_content(vec![BinaryNode::new("device").with_attr("id", "0")]),
                    ])]),
                BinaryNode::new("user")
                    .with_attr("jid", "999@s.whatsapp.net")
                    .with_content(vec![BinaryNode::new("devices").with_content(vec![
                        BinaryNode::new("device-list").with_content(vec![
                            BinaryNode::new("device")
                                .with_attr("id", "7")
                                .with_attr("key-index", "7"),
                            BinaryNode::new("device")
                                .with_attr("id", "8")
                                .with_attr("key-index", "8"),
                        ]),
                    ])]),
                BinaryNode::new("user")
                    .with_attr("jid", "ownlid@lid")
                    .with_content(vec![BinaryNode::new("devices").with_content(vec![
                        BinaryNode::new("device-list").with_content(vec![
                            BinaryNode::new("device")
                                .with_attr("id", "7")
                                .with_attr("key-index", "17"),
                            BinaryNode::new("device")
                                .with_attr("id", "8")
                                .with_attr("key-index", "18"),
                        ]),
                    ])]),
            ]),
        ])]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&usync_response).unwrap(),
        ))
        .await
        .unwrap();

    let linked_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(linked_query.attrs["xmlns"], "encrypt");
    assert_eq!(
        encrypt_key_query_user_attrs(&linked_query),
        vec![("999:8@s.whatsapp.net".to_owned(), None)]
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&valid_session_response_for_query(
                &linked_query,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(
        resent.attrs["id"],
        "retry-spawn-combined-own-alias-all-devices"
    );
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(resent.attrs["type"], "text");
    let participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    for (jid, expected_device_sent) in [
        ("123@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        assert_eq!(enc.attrs["type"], "pkmsg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
        assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));
        let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
            &remote_material,
            Some(&remote_pre_key),
            &ciphertext,
        )
        .unwrap();
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            assert_eq!(
                device_sent.message.unwrap().conversation.as_deref(),
                Some("spawn combined own alias retry")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.conversation.as_deref(),
                Some("spawn combined own alias retry")
            );
        }
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("ownlid:8@lid")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
    );
    let plan = client
        .plan_retry_resend(
            &wa_core::parse_retry_receipt(&receipt).unwrap().unwrap(),
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared_after_success = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_success.jobs.is_empty());
    assert_eq!(
        prepared_after_success.missing_message_ids,
        vec!["retry-spawn-combined-own-alias-all-devices"]
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::MediaRetry(_) | Event::MediaRetryProcessed(_)),
            "spawned combined own-alias retry must not emit media retry side effects"
        );
    }

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_media_and_signal_provider_preserves_legacy_missing_key()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 96;
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_retry_and_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let placeholder = BinaryNode::new("message")
        .with_attr("id", "missing-spawn-media-signal-legacy")
        .with_attr("from", "123@c.us")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key =
        wa_core::build_message_key("123@c.us", false, "missing-spawn-media-signal-legacy", None)
            .unwrap();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&placeholder).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-spawn-media-signal-legacy");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@c.us");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "missing-spawn-media-signal-legacy"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["kind"],
        "placeholder_unavailable"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["unavailable_type"],
        "temporary_unavailable"
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .expect("spawned media-capable placeholder event should be persisted");
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);

    let usync_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(usync_query.attrs["xmlns"], "usync");
    assert_usync_query_protocol(&usync_query, "devices");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", usync_query.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "999@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "0"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "7")
                                            .with_attr("key-index", "11"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "8")
                                            .with_attr("key-index", "12"),
                                    ])],
                                )]),
                        ]),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let encrypt_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(encrypt_query.attrs["xmlns"], "encrypt");
    assert_eq!(
        encrypt_key_query_user_attrs(&encrypt_query)
            .into_iter()
            .map(|(jid, _)| jid)
            .collect::<Vec<_>>(),
        vec![
            "999@s.whatsapp.net".to_owned(),
            "999:8@s.whatsapp.net".to_owned(),
        ]
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&valid_session_response_for_query(
                &encrypt_query,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["to"], "999@s.whatsapp.net");
    assert_eq!(sent.attrs["category"], "peer");
    assert_eq!(sent.attrs["push_priority"], "high_force");
    assert_signal_placeholder_resend_request(
        &sent,
        "999@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "999@s.whatsapp.net",
        &expected_key,
    );
    assert!(
        client
            .placeholder_resend_tracker()
            .contains(
                "missing-spawn-media-signal-legacy",
                current_unix_timestamp_ms()
            )
            .unwrap()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_media_and_signal_provider_accepts_same_base_pre_key_wrapper()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "media-same-base")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let sender_base_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public));
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let first_text = wa_proto::proto::Message {
        conversation: Some("spawn media same-base first".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let first_plaintext = pad_random_max16_for_test(Bytes::from(first_text.encode_to_vec()), 4);
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &first_plaintext,
    )
    .unwrap();
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);
    let first_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-media-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_retry_and_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_incoming).unwrap(),
        ))
        .await
        .unwrap();

    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-media-same-base-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-media-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn media same-base first")
    );
    let stored_first_key = wa_core::message_event_store_key(&first_batch.messages_upsert[0].key);
    let stored_first = store
        .get(KeyNamespace::MessageEvent, &stored_first_key)
        .await
        .unwrap()
        .unwrap();
    let stored_first = wa_core::decode_stored_message_event(&stored_first).unwrap();
    assert_eq!(stored_first, first_batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    let record_after_first = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let identity_after_first = client
        .signal_provider_state_store()
        .load_identity_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        identity_after_first,
        sender_material.identity.public_key.clone()
    );

    let second_text = wa_proto::proto::Message {
        conversation: Some("spawn media same-base wrapped second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 5);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    let changed_sender_credentials = wa_core::create_initial_credentials().unwrap();
    let changed_sender_material = test_signal_local_key_material(&changed_sender_credentials);
    assert_ne!(
        changed_sender_material.identity.public_key,
        sender_material.identity.public_key
    );
    let changed_identity_wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: changed_sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
        base_key: sender_base_public_key.clone(),
        identity_key: changed_sender_material.identity.public_key,
        message: second.message.clone(),
    };
    let changed_identity_wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &changed_identity_wrapped_second,
        &[0u8; 32],
        &changed_identity_wrapped_second.identity_key,
        &receiver_identity,
    )
    .unwrap();
    let changed_identity_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-media-same-base-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&changed_identity_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let changed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(changed_identity_nack.tag, "ack");
    assert_eq!(
        changed_identity_nack.attrs["id"],
        "signal-spawn-media-same-base-2-identity-change"
    );
    assert_eq!(changed_identity_nack.attrs["class"], "message");
    assert_eq!(changed_identity_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(changed_identity_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        changed_identity_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "combined same-base identity-change wrapper must not emit a typed batch"
        );
        assert!(
            !matches!(event, Event::MediaRetry(_)),
            "combined same-base identity-change wrapper must not emit media-retry events"
        );
    }
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        identity_after_first
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );

    let mismatched_signed_pre_key_wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        base_key: sender_base_public_key.clone(),
        identity_key: sender_material.identity.public_key.clone(),
        message: second.message.clone(),
    };
    let mismatched_signed_pre_key_wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &mismatched_signed_pre_key_wrapped_second,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    let signed_pre_key_mismatch_incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-media-same-base-2-signed-pre-key-mismatch",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&signed_pre_key_mismatch_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let signed_pre_key_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_mismatch_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["id"],
        "signal-spawn-media-same-base-2-signed-pre-key-mismatch"
    );
    assert_eq!(signed_pre_key_mismatch_nack.attrs["class"], "message");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["to"],
        "123@s.whatsapp.net"
    );
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["from"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "combined same-base signed-pre-key-id mismatch wrapper must not emit a typed batch"
        );
        assert!(
            !matches!(event, Event::MediaRetry(_)),
            "combined same-base signed-pre-key-id mismatch wrapper must not emit media-retry events"
        );
    }
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        identity_after_first
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );

    let wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
        base_key: sender_base_public_key.clone(),
        identity_key: sender_material.identity.public_key.clone(),
        message: second.message.clone(),
    };
    let wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &wrapped_second,
        wa_core::ratchet_signal_message_chain(
            &wa_core::decode_signal_provider_session_record(&first.record)
                .unwrap()
                .sending_chain,
        )
        .unwrap()
        .message_keys
        .mac_key
        .expose(),
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    let second_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-media-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&second_incoming).unwrap(),
        ))
        .await
        .unwrap();

    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-spawn-media-same-base-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-media-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn media same-base wrapped second")
    );
    let stored_second_key = wa_core::message_event_store_key(&second_batch.messages_upsert[0].key);
    let stored_second = store
        .get(KeyNamespace::MessageEvent, &stored_second_key)
        .await
        .unwrap()
        .unwrap();
    let stored_second = wa_core::decode_stored_message_event(&stored_second).unwrap();
    assert_eq!(stored_second, second_batch.messages_upsert[0]);
    let record_after_wrapped = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let decoded_after_wrapped =
        wa_core::decode_signal_provider_session_record(&record_after_wrapped).unwrap();
    assert_eq!(
        decoded_after_wrapped.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        decoded_after_wrapped
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    assert!(decoded_after_wrapped.message_keys.is_empty());
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let wrapped_replay = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-media-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&wrapped_replay).unwrap(),
        ))
        .await
        .unwrap();
    let replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_ack.tag, "ack");
    assert_eq!(
        replay_ack.attrs["id"],
        "signal-spawn-media-same-base-2-replay"
    );
    assert_eq!(replay_ack.attrs["class"], "message");
    assert_eq!(replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "media-capable same-base replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_wrapped
    );

    let third_text = wa_proto::proto::Message {
        conversation: Some("spawn media same-base third".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let third_plaintext = pad_random_max16_for_test(Bytes::from(third_text.encode_to_vec()), 6);
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &third_plaintext,
        &sender_identity,
    )
    .unwrap();
    let third_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-media-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&third_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-spawn-media-same-base-3");
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-spawn-media-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn media same-base third")
    );
    let stored_third_key = wa_core::message_event_store_key(&third_batch.messages_upsert[0].key);
    let stored_third = store
        .get(KeyNamespace::MessageEvent, &stored_third_key)
        .await
        .unwrap()
        .unwrap();
    let stored_third = wa_core::decode_stored_message_event(&stored_third).unwrap();
    assert_eq!(stored_third, third_batch.messages_upsert[0]);
    let record_after_third = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_third =
        wa_core::decode_signal_provider_session_record(&record_after_third).unwrap();
    assert_eq!(
        record_after_third.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_third.receiving_chain.as_ref().unwrap().counter,
        3
    );
    assert!(record_after_third.message_keys.is_empty());

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_handles_raw_message_nodes() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
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
    let text = wa_proto::proto::Message {
        conversation: Some("automatic".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "auto-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(text.encode_to_vec())),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "auto-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "auto-1");
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(decoded.conversation.as_deref(), Some("automatic"));
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_raw_pre_key_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "pre-key")
        .await
        .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text = wa_proto::proto::Message {
        conversation: Some("spawn encrypted hello".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let plaintext = pad_random_max16_for_test(Bytes::from(text.encode_to_vec()), 4);
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);
    let sender_base_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public));
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-in-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-in-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "signal-spawn-in-1");
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn encrypted hello")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    let record_after_first = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let identity_after_first = client
        .signal_provider_state_store()
        .load_identity_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        identity_after_first,
        sender_material.identity.public_key.clone()
    );
    let second_text = wa_proto::proto::Message {
        conversation: Some("spawn encrypted second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 5);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();

    let replay = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-in-1-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&replay).unwrap()))
        .await
        .unwrap();
    let replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_ack.tag, "ack");
    assert_eq!(replay_ack.attrs["id"], "signal-spawn-in-1-replay");
    assert_eq!(replay_ack.attrs["class"], "message");
    assert_eq!(replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "pre-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );
    let changed_sender_credentials = wa_core::create_initial_credentials().unwrap();
    let changed_sender_material = test_signal_local_key_material(&changed_sender_credentials);
    assert_ne!(
        changed_sender_material.identity.public_key,
        sender_material.identity.public_key
    );
    let changed_identity_wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: changed_sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
        base_key: sender_base_public_key.clone(),
        identity_key: changed_sender_material.identity.public_key,
        message: second.message.clone(),
    };
    let changed_identity_wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &changed_identity_wrapped_second,
        &[0u8; 32],
        &changed_identity_wrapped_second.identity_key,
        &receiver_identity,
    )
    .unwrap();
    let changed_identity_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-in-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&changed_identity_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let changed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(changed_identity_nack.tag, "ack");
    assert_eq!(
        changed_identity_nack.attrs["id"],
        "signal-spawn-in-2-identity-change"
    );
    assert_eq!(changed_identity_nack.attrs["class"], "message");
    assert_eq!(changed_identity_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(changed_identity_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        changed_identity_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "same-base identity-change wrapper must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        identity_after_first
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let mismatched_signed_pre_key_wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        base_key: sender_base_public_key.clone(),
        identity_key: sender_material.identity.public_key.clone(),
        message: second.message.clone(),
    };
    let mismatched_signed_pre_key_wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &mismatched_signed_pre_key_wrapped_second,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    let signed_pre_key_mismatch_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-in-2-signed-pre-key-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&signed_pre_key_mismatch_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let signed_pre_key_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_mismatch_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["id"],
        "signal-spawn-in-2-signed-pre-key-mismatch"
    );
    assert_eq!(signed_pre_key_mismatch_nack.attrs["class"], "message");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["to"],
        "123@s.whatsapp.net"
    );
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["from"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "same-base signed-pre-key-id mismatch wrapper must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        identity_after_first
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
        base_key: sender_base_public_key.clone(),
        identity_key: sender_material.identity.public_key.clone(),
        message: second.message.clone(),
    };
    let wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &wrapped_second,
        wa_core::ratchet_signal_message_chain(
            &wa_core::decode_signal_provider_session_record(&first.record)
                .unwrap()
                .sending_chain,
        )
        .unwrap()
        .message_keys
        .mac_key
        .expose(),
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-in-2-wrapper")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_second).unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-spawn-in-2-wrapper");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-in-2-wrapper"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn encrypted second")
    );
    let stored_second_key = wa_core::message_event_store_key(&second_batch.messages_upsert[0].key);
    let stored_second = store
        .get(KeyNamespace::MessageEvent, &stored_second_key)
        .await
        .unwrap()
        .unwrap();
    let stored_second = wa_core::decode_stored_message_event(&stored_second).unwrap();
    assert_eq!(stored_second, second_batch.messages_upsert[0]);
    let record_after_second = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second).unwrap();
    assert_eq!(
        record_after_second.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    assert!(record_after_second.message_keys.is_empty());

    let record_after_wrapped = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );
    let wrapped_replay = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-in-2-wrapper-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&wrapped_replay).unwrap(),
        ))
        .await
        .unwrap();
    let wrapped_replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(wrapped_replay_ack.tag, "ack");
    assert_eq!(
        wrapped_replay_ack.attrs["id"],
        "signal-spawn-in-2-wrapper-replay"
    );
    assert_eq!(wrapped_replay_ack.attrs["class"], "message");
    assert_eq!(wrapped_replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(wrapped_replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        wrapped_replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "same-base wrapped pre-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_wrapped
    );

    let third_text = wa_proto::proto::Message {
        conversation: Some("spawn encrypted third".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let third_plaintext = pad_random_max16_for_test(Bytes::from(third_text.encode_to_vec()), 6);
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &third_plaintext,
        &sender_identity,
    )
    .unwrap();
    let incoming_third = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-in-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_third).unwrap(),
        ))
        .await
        .unwrap();
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-spawn-in-3");
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(third_batch.messages_upsert[0].key.id, "signal-spawn-in-3");
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn encrypted third")
    );
    let stored_third_key = wa_core::message_event_store_key(&third_batch.messages_upsert[0].key);
    let stored_third = store
        .get(KeyNamespace::MessageEvent, &stored_third_key)
        .await
        .unwrap()
        .unwrap();
    let stored_third = wa_core::decode_stored_message_event(&stored_third).unwrap();
    assert_eq!(stored_third, third_batch.messages_upsert[0]);
    let record_after_third = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_third =
        wa_core::decode_signal_provider_session_record(&record_after_third).unwrap();
    assert_eq!(
        record_after_third.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_third.receiving_chain.as_ref().unwrap().counter,
        3
    );
    assert!(record_after_third.message_keys.is_empty());
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_canonicalizes_legacy_direct_signal_sender() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "pre-key")
        .await
        .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let legacy_sender_jid = "123:7@c.us";
    let canonical_sender_jid = "123:7@s.whatsapp.net";
    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text = wa_proto::proto::Message {
        conversation: Some("spawn legacy encrypted hello".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let plaintext = pad_random_max16_for_test(Bytes::from(text.encode_to_vec()), 4);
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-legacy-direct-in-1")
        .with_attr("from", legacy_sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-legacy-direct-in-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], canonical_sender_jid);
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        canonical_sender_jid
    );
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-legacy-direct-in-1"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn legacy encrypted hello")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record(canonical_sender_jid)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record(canonical_sender_jid)
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_canonicalizes_offline_legacy_direct_signal_sender()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "offline-legacy")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let legacy_sender_jid = "123:7@c.us";
    let canonical_sender_jid = "123:7@s.whatsapp.net";
    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text = wa_proto::proto::Message {
        conversation: Some("spawn offline legacy encrypted hello".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let plaintext = pad_random_max16_for_test(Bytes::from(text.encode_to_vec()), 4);
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-legacy-direct-1")
        .with_attr("from", legacy_sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![incoming]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&offline).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-offline-legacy-direct-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], canonical_sender_jid);
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        canonical_sender_jid
    );
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-legacy-direct-1"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline legacy encrypted hello")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record(canonical_sender_jid)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record(canonical_sender_jid)
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_offline_raw_pre_key_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "offline-pre-key")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text = wa_proto::proto::Message {
        conversation: Some("spawn offline encrypted hello".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let plaintext = pad_random_max16_for_test(Bytes::from(text.encode_to_vec()), 4);
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);
    let sender_base_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public));
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-in-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![incoming]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&offline).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-offline-in-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(batch.messages_upsert[0].key.id, "signal-spawn-offline-in-1");
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline encrypted hello")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    let record_after_first = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let identity_after_first = client
        .signal_provider_state_store()
        .load_identity_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        identity_after_first,
        sender_material.identity.public_key.clone()
    );
    let second_text = wa_proto::proto::Message {
        conversation: Some("spawn offline encrypted second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 5);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();

    let replay = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-in-1-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&BinaryNode::new("offline").with_content(vec![replay])).unwrap(),
        ))
        .await
        .unwrap();
    let replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_ack.tag, "ack");
    assert_eq!(replay_ack.attrs["id"], "signal-spawn-offline-in-1-replay");
    assert_eq!(replay_ack.attrs["class"], "message");
    assert_eq!(replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline pre-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );
    let changed_sender_credentials = wa_core::create_initial_credentials().unwrap();
    let changed_sender_material = test_signal_local_key_material(&changed_sender_credentials);
    assert_ne!(
        changed_sender_material.identity.public_key,
        sender_material.identity.public_key
    );
    let changed_identity_wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: changed_sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
        base_key: sender_base_public_key.clone(),
        identity_key: changed_sender_material.identity.public_key,
        message: second.message.clone(),
    };
    let changed_identity_wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &changed_identity_wrapped_second,
        &[0u8; 32],
        &changed_identity_wrapped_second.identity_key,
        &receiver_identity,
    )
    .unwrap();
    let changed_identity_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-in-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("offline").with_content(vec![changed_identity_incoming]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();
    let changed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(changed_identity_nack.tag, "ack");
    assert_eq!(
        changed_identity_nack.attrs["id"],
        "signal-spawn-offline-in-2-identity-change"
    );
    assert_eq!(changed_identity_nack.attrs["class"], "message");
    assert_eq!(changed_identity_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(changed_identity_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        changed_identity_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline same-base identity-change wrapper must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        identity_after_first
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let mismatched_signed_pre_key_wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        base_key: sender_base_public_key.clone(),
        identity_key: sender_material.identity.public_key.clone(),
        message: second.message.clone(),
    };
    let mismatched_signed_pre_key_wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &mismatched_signed_pre_key_wrapped_second,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    let signed_pre_key_mismatch_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-in-2-signed-pre-key-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("offline").with_content(vec![signed_pre_key_mismatch_incoming]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();
    let signed_pre_key_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_mismatch_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["id"],
        "signal-spawn-offline-in-2-signed-pre-key-mismatch"
    );
    assert_eq!(signed_pre_key_mismatch_nack.attrs["class"], "message");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["to"],
        "123@s.whatsapp.net"
    );
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["from"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline same-base signed-pre-key-id mismatch wrapper must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        identity_after_first
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let wrapped_second = wa_core::SignalPreKeyWhisperMessage {
        registration_id: sender_material.registration_id,
        pre_key_id: Some(receiver_pre_key_id),
        signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
        base_key: sender_base_public_key.clone(),
        identity_key: sender_material.identity.public_key.clone(),
        message: second.message.clone(),
    };
    let wrapped_second = wa_core::encode_signal_pre_key_whisper_message(
        &wrapped_second,
        wa_core::ratchet_signal_message_chain(
            &wa_core::decode_signal_provider_session_record(&first.record)
                .unwrap()
                .sending_chain,
        )
        .unwrap()
        .message_keys
        .mac_key
        .expose(),
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-in-2-wrapper")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&BinaryNode::new("offline").with_content(vec![incoming_second]))
                .unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-spawn-offline-in-2-wrapper");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-in-2-wrapper"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline encrypted second")
    );
    let stored_second_key = wa_core::message_event_store_key(&second_batch.messages_upsert[0].key);
    let stored_second = store
        .get(KeyNamespace::MessageEvent, &stored_second_key)
        .await
        .unwrap()
        .unwrap();
    let stored_second = wa_core::decode_stored_message_event(&stored_second).unwrap();
    assert_eq!(stored_second, second_batch.messages_upsert[0]);
    let record_after_second = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second).unwrap();
    assert_eq!(
        record_after_second.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    assert!(record_after_second.message_keys.is_empty());

    let record_after_wrapped = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );
    let wrapped_replay = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-in-2-wrapper-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&BinaryNode::new("offline").with_content(vec![wrapped_replay]))
                .unwrap(),
        ))
        .await
        .unwrap();
    let wrapped_replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(wrapped_replay_ack.tag, "ack");
    assert_eq!(
        wrapped_replay_ack.attrs["id"],
        "signal-spawn-offline-in-2-wrapper-replay"
    );
    assert_eq!(wrapped_replay_ack.attrs["class"], "message");
    assert_eq!(wrapped_replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(wrapped_replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        wrapped_replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline same-base wrapped pre-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_wrapped
    );

    let third_text = wa_proto::proto::Message {
        conversation: Some("spawn offline encrypted third".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let third_plaintext = pad_random_max16_for_test(Bytes::from(third_text.encode_to_vec()), 6);
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &third_plaintext,
        &sender_identity,
    )
    .unwrap();
    let incoming_third = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-in-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&BinaryNode::new("offline").with_content(vec![incoming_third]))
                .unwrap(),
        ))
        .await
        .unwrap();
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-spawn-offline-in-3");
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-in-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn offline encrypted third")
    );
    let stored_third_key = wa_core::message_event_store_key(&third_batch.messages_upsert[0].key);
    let stored_third = store
        .get(KeyNamespace::MessageEvent, &stored_third_key)
        .await
        .unwrap()
        .unwrap();
    let stored_third = wa_core::decode_stored_message_event(&stored_third).unwrap();
    assert_eq!(stored_third, third_batch.messages_upsert[0]);
    let record_after_third = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_third =
        wa_core::decode_signal_provider_session_record(&record_after_third).unwrap();
    assert_eq!(
        record_after_third.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_third.receiving_chain.as_ref().unwrap().counter,
        3
    );
    assert!(record_after_third.message_keys.is_empty());
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_rejects_missing_one_time_pre_key() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "spawn-pre-key")
        .await
        .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let encrypted_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn missing pre-key".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        8,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &encrypted_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    assert!(
        client
            .signal_provider_state_store()
            .consume_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_some()
    );

    let failed = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-missing-pre-key")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-missing-pre-key");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let plaintext = wa_proto::proto::Message {
        conversation: Some("processor survived missing pre-key".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let follow_up = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-after-missing-pre-key")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(plaintext.encode_to_vec())),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&follow_up).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-after-missing-pre-key");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-after-missing-pre-key"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("processor survived missing pre-key")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_rejects_pre_key_identity_change() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "spawn-identity-change")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let existing_identity =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&generate_key_pair().public));
    let existing_session = Bytes::from_static(b"opaque-provider-session");
    client
        .signal_provider_state_store()
        .store_session_record("123@s.whatsapp.net", &existing_session)
        .await
        .unwrap();
    client
        .signal_provider_state_store()
        .store_identity_record("123@s.whatsapp.net", &existing_identity)
        .await
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    assert_ne!(sender_material.identity.public_key, existing_identity);
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let encrypted_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn identity change".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        8,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &encrypted_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let failed = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-identity-change");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(existing_session.clone())
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(existing_identity.clone())
    );

    let plaintext = wa_proto::proto::Message {
        conversation: Some("processor survived identity change".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let follow_up = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-after-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(plaintext.encode_to_vec())),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&follow_up).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-after-identity-change");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-after-identity-change"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("processor survived identity change")
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(existing_session)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(existing_identity)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_tampered_pre_key_decrypt() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "spawn-tampered-pre-key")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn pre-key after tamper".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        14,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut tampered =
        wa_core::decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
    let mut tampered_ciphertext = tampered.message.ciphertext.to_vec();
    *tampered_ciphertext.last_mut().unwrap() ^= 1;
    tampered.message.ciphertext = Bytes::from(tampered_ciphertext);
    let tampered = wa_core::encode_signal_pre_key_whisper_message(
        &tampered,
        &[0u8; 32],
        &tampered.identity_key,
        &receiver_identity,
    )
    .unwrap();

    let failed = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-tampered")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(tampered),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-pre-key-tampered");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "tampered pre-key message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let valid = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-after-tamper")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-pre-key-after-tamper");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-pre-key-after-tamper"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn pre-key after tamper")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_tampered_pre_key_decrypt()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-tampered-pre-key",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline pre-key after tamper".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        15,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut tampered =
        wa_core::decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
    let mut tampered_ciphertext = tampered.message.ciphertext.to_vec();
    *tampered_ciphertext.last_mut().unwrap() ^= 1;
    tampered.message.ciphertext = Bytes::from(tampered_ciphertext);
    let tampered = wa_core::encode_signal_pre_key_whisper_message(
        &tampered,
        &[0u8; 32],
        &tampered.identity_key,
        &receiver_identity,
    )
    .unwrap();

    let failed_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-pre-key-tampered")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(tampered),
        ]);
    let failed = BinaryNode::new("offline").with_content(vec![failed_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-offline-pre-key-tampered");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "tampered offline pre-key message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let valid_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-pre-key-after-tamper")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid = BinaryNode::new("offline").with_content(vec![valid_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-offline-pre-key-after-tamper");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-pre-key-after-tamper"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline pre-key after tamper")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_wrong_pre_key_material() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 2, "spawn-wrong-pre-key")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let wrong_receiver_pre_key_id = upload.pre_key_ids[1];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();
    let wrong_receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(wrong_receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn pre-key after wrong material".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        12,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut wrong_pre_key_message =
        wa_core::decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
    wrong_pre_key_message.pre_key_id = Some(wrong_receiver_pre_key_id);
    let wrong_pre_key_message = wa_core::encode_signal_pre_key_whisper_message(
        &wrong_pre_key_message,
        &[0u8; 32],
        &wrong_pre_key_message.identity_key,
        &receiver_identity,
    )
    .unwrap();

    let failed = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-wrong-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrong_pre_key_message),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-pre-key-wrong-material");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "wrong-material pre-key message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(wrong_receiver_pre_key_id)
            .await
            .unwrap(),
        Some(wrong_receiver_pre_key.clone())
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let valid = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-after-wrong-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-pre-key-after-wrong-material");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-pre-key-after-wrong-material"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn pre-key after wrong material")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(wrong_receiver_pre_key_id)
            .await
            .unwrap(),
        Some(wrong_receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_wrong_pre_key_material()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        2,
        "spawn-offline-wrong-pre-key",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let wrong_receiver_pre_key_id = upload.pre_key_ids[1];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();
    let wrong_receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(wrong_receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline pre-key after wrong material".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        13,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut wrong_pre_key_message =
        wa_core::decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
    wrong_pre_key_message.pre_key_id = Some(wrong_receiver_pre_key_id);
    let wrong_pre_key_message = wa_core::encode_signal_pre_key_whisper_message(
        &wrong_pre_key_message,
        &[0u8; 32],
        &wrong_pre_key_message.identity_key,
        &receiver_identity,
    )
    .unwrap();

    let failed_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-pre-key-wrong-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrong_pre_key_message),
        ]);
    let failed = BinaryNode::new("offline").with_content(vec![failed_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(
        nack.attrs["id"],
        "signal-spawn-offline-pre-key-wrong-material"
    );
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "wrong-material offline pre-key message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(wrong_receiver_pre_key_id)
            .await
            .unwrap(),
        Some(wrong_receiver_pre_key.clone())
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let valid_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-pre-key-after-wrong-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid = BinaryNode::new("offline").with_content(vec![valid_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-pre-key-after-wrong-material"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-pre-key-after-wrong-material"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline pre-key after wrong material")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(wrong_receiver_pre_key_id)
            .await
            .unwrap(),
        Some(wrong_receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_signed_pre_key_id_mismatch()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-signed-pre-key-mismatch",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn pre-key after signed id mismatch".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        10,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut mismatched_signed_pre_key =
        wa_core::decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
    mismatched_signed_pre_key.signed_pre_key_id =
        receiver_credentials.signed_pre_key.key_id.wrapping_add(1);
    let mismatched_signed_pre_key = wa_core::encode_signal_pre_key_whisper_message(
        &mismatched_signed_pre_key,
        &[0u8; 32],
        &mismatched_signed_pre_key.identity_key,
        &receiver_identity,
    )
    .unwrap();

    let failed = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-signed-id-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-pre-key-signed-id-mismatch");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "signed-pre-key-id mismatch must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let valid = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-after-signed-id-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-pre-key-after-signed-id-mismatch"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-pre-key-after-signed-id-mismatch"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn pre-key after signed id mismatch")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_signed_pre_key_id_mismatch()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-signed-pre-key-mismatch",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline pre-key after signed id mismatch".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        11,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut mismatched_signed_pre_key =
        wa_core::decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
    mismatched_signed_pre_key.signed_pre_key_id =
        receiver_credentials.signed_pre_key.key_id.wrapping_add(1);
    let mismatched_signed_pre_key = wa_core::encode_signal_pre_key_whisper_message(
        &mismatched_signed_pre_key,
        &[0u8; 32],
        &mismatched_signed_pre_key.identity_key,
        &receiver_identity,
    )
    .unwrap();

    let failed_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-pre-key-signed-id-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key),
        ]);
    let failed = BinaryNode::new("offline").with_content(vec![failed_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(
        nack.attrs["id"],
        "signal-spawn-offline-pre-key-signed-id-mismatch"
    );
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline signed-pre-key-id mismatch must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let valid_child = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-pre-key-after-signed-id-mismatch",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid = BinaryNode::new("offline").with_content(vec![valid_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-pre-key-after-signed-id-mismatch"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-pre-key-after-signed-id-mismatch"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline pre-key after signed id mismatch")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_when_local_key_material_missing() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-missing-local-material",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn pre-key after missing material".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        9,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    store
        .delete_signal_key(KeyNamespace::Credentials, "schema-version")
        .await
        .unwrap();
    let failed = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-missing-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-pre-key-missing-material");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "missing local Signal material must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();

    let valid = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-pre-key-after-missing-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-pre-key-after-missing-material"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-pre-key-after-missing-material"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn pre-key after missing material")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_local_key_material_missing()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-missing-local-material",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline pre-key after missing material".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        10,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    store
        .delete_signal_key(KeyNamespace::Credentials, "schema-version")
        .await
        .unwrap();
    let failed_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-pre-key-missing-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let failed = BinaryNode::new("offline").with_content(vec![failed_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&failed).unwrap()))
        .await
        .unwrap();

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(
        nack.attrs["id"],
        "signal-spawn-offline-pre-key-missing-material"
    );
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline missing local Signal material must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key)
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();

    let valid_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-pre-key-after-missing-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid = BinaryNode::new("offline").with_content(vec![valid_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&valid).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-pre-key-after-missing-material"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-pre-key-after-missing-material"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline pre-key after missing material")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_session_after_missing_provider_identity()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-missing-provider-identity",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn provider identity seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        8,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn session after missing identity".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        9,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_message = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-provider-identity-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-provider-identity-seed");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-provider-identity-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn provider identity seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .delete_signal_key(KeyNamespace::SignalProviderIdentity, "123.0")
        .await
        .unwrap();
    let missing_identity = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-missing-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&missing_identity).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-session-missing-identity");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "missing provider identity must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(accepted_session.clone())
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            "123.0",
            &sender_material.identity.public_key,
        )
        .await
        .unwrap();
    let recovered = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-after-missing-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-session-after-missing-identity"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-session-after-missing-identity"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn session after missing identity")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_session_after_offline_missing_provider_identity()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-missing-provider-identity",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline provider identity seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        10,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline session after missing identity".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        11,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-provider-identity-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let first_message = BinaryNode::new("offline").with_content(vec![first_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-offline-provider-identity-seed"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-provider-identity-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline provider identity seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .delete_signal_key(KeyNamespace::SignalProviderIdentity, "123.0")
        .await
        .unwrap();
    let missing_identity_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-missing-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let missing_identity = BinaryNode::new("offline").with_content(vec![missing_identity_child]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&missing_identity).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(
        nack.attrs["id"],
        "signal-spawn-offline-session-missing-identity"
    );
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline missing provider identity must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(accepted_session.clone())
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    client
        .signal_provider_state_store()
        .store_identity_record("123@s.whatsapp.net", &sender_material.identity.public_key)
        .await
        .unwrap();
    let recovered_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-after-missing-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    let recovered = BinaryNode::new("offline").with_content(vec![recovered_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-session-after-missing-identity"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-session-after-missing-identity"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline session after missing identity")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_session_after_malformed_provider_session()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-malformed-provider-session",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn malformed session seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        12,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn session after malformed session".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        13,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_message = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-malformed-session-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-malformed-session-seed");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-malformed-session-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn malformed session seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let malformed_session = Bytes::from_static(b"not-a-provider-session");
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &malformed_session,
        )
        .await
        .unwrap();
    let malformed_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-malformed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&malformed_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-session-malformed");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "malformed provider session must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(malformed_session)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &accepted_session,
        )
        .await
        .unwrap();
    let recovered = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-after-malformed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-session-after-malformed");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-session-after-malformed"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn session after malformed session")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_session_after_offline_malformed_provider_session()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-malformed-provider-session",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline malformed session seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        14,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline session after malformed session".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        15,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-malformed-session-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let first_message = BinaryNode::new("offline").with_content(vec![first_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-offline-malformed-session-seed"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-malformed-session-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline malformed session seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let malformed_session = Bytes::from_static(b"offline-not-a-provider-session");
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &malformed_session,
        )
        .await
        .unwrap();
    let malformed_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-malformed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let malformed_incoming = BinaryNode::new("offline").with_content(vec![malformed_child]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&malformed_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-offline-session-malformed");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline malformed provider session must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(malformed_session)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &accepted_session,
        )
        .await
        .unwrap();
    let recovered_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-after-malformed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    let recovered = BinaryNode::new("offline").with_content(vec![recovered_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-session-after-malformed"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-session-after-malformed"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline session after malformed session")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_identity_after_missing_provider_session()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-missing-provider-session",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn missing session seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        16,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn session after missing session".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        15,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_message = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-missing-session-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-missing-session-seed");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-missing-session-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn missing session seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .delete_signal_key(KeyNamespace::SignalProviderSession, "123.0")
        .await
        .unwrap();
    let missing_session = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-missing")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&missing_session).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-session-missing");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "missing provider session must not emit a typed batch"
        );
    }
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &accepted_session,
        )
        .await
        .unwrap();
    let recovered = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-after-missing")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-spawn-session-after-missing");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-session-after-missing"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn session after missing session")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_identity_after_offline_missing_provider_session()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-missing-provider-session",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline missing session seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        12,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline session after missing session".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        13,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-missing-session-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let first_message = BinaryNode::new("offline").with_content(vec![first_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-offline-missing-session-seed"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-missing-session-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline missing session seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .delete_signal_key(KeyNamespace::SignalProviderSession, "123.0")
        .await
        .unwrap();
    let missing_session_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-missing")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let missing_session = BinaryNode::new("offline").with_content(vec![missing_session_child]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&missing_session).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-offline-session-missing");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline missing provider session must not emit a typed batch"
        );
    }
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &accepted_session,
        )
        .await
        .unwrap();
    let recovered_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-after-missing")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    let recovered = BinaryNode::new("offline").with_content(vec![recovered_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-session-after-missing"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-session-after-missing"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline session after missing session")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_session_after_malformed_provider_identity()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-malformed-provider-identity",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn malformed identity seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        14,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn session after malformed identity".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        15,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_message = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-malformed-identity-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-malformed-identity-seed"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-malformed-identity-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn malformed identity seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let malformed_identity = Bytes::from_static(b"short");
    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            "123.0",
            &malformed_identity,
        )
        .await
        .unwrap();
    let malformed_identity_message = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-malformed-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&malformed_identity_message).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-session-malformed-identity");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "malformed provider identity must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(accepted_session.clone())
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(malformed_identity)
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            "123.0",
            &sender_material.identity.public_key,
        )
        .await
        .unwrap();
    let recovered = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-after-malformed-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-session-after-malformed-identity"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-session-after-malformed-identity"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn session after malformed identity")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_session_after_offline_malformed_provider_identity()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-malformed-provider-identity",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline malformed identity seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        12,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline session after malformed identity".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        13,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-malformed-identity-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let first_message = BinaryNode::new("offline").with_content(vec![first_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-offline-malformed-identity-seed"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-malformed-identity-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline malformed identity seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let malformed_identity = Bytes::from_static(b"short");
    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            "123.0",
            &malformed_identity,
        )
        .await
        .unwrap();
    let malformed_identity_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-malformed-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let malformed_identity_message =
        BinaryNode::new("offline").with_content(vec![malformed_identity_child]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&malformed_identity_message).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(
        nack.attrs["id"],
        "signal-spawn-offline-session-malformed-identity"
    );
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline malformed provider identity must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(accepted_session.clone())
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(malformed_identity)
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            "123.0",
            &sender_material.identity.public_key,
        )
        .await
        .unwrap();
    let recovered_child = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-session-after-malformed-identity",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    let recovered = BinaryNode::new("offline").with_content(vec![recovered_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-session-after-malformed-identity"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-session-after-malformed-identity"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline session after malformed identity")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_invalid_provider_session_invariant()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-invalid-provider-session-invariant",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn invalid session invariant seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        10,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn session after invalid session invariant".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        11,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_message = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-invalid-session-invariant-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-invalid-session-invariant-seed"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-invalid-session-invariant-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn invalid session invariant seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&accepted_session).unwrap();
    let local_public =
        prefixed_signal_public_key(&valid_session_record.local_ratchet_key_pair.public);
    let local_public_offset = accepted_session
        .windows(local_public.len())
        .position(|window| window == local_public)
        .expect("encoded session contains local ratchet public key");
    let mut invalid_session = accepted_session.to_vec();
    invalid_session[local_public_offset + local_public.len() - 1] ^= 1;
    let invalid_session = Bytes::from(invalid_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &invalid_session,
        )
        .await
        .unwrap();
    let invalid_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-invalid-invariant")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&invalid_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-session-invalid-invariant");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "invalid provider session invariant must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(invalid_session)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &accepted_session,
        )
        .await
        .unwrap();
    let recovered = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-session-after-invalid-invariant")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-session-after-invalid-invariant"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-session-after-invalid-invariant"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn session after invalid session invariant")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_invalid_provider_session_invariant()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-invalid-provider-session-invariant",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let seed_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline invalid session invariant seed".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        12,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &seed_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let session_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some(
                    "spawn offline session after invalid session invariant".to_owned(),
                ),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        13,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &session_plaintext,
        &sender_identity,
    )
    .unwrap();

    let first_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-invalid-session-invariant-seed")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let first_message = BinaryNode::new("offline").with_content(vec![first_child]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&first_message).unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-offline-invalid-session-invariant-seed"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-invalid-session-invariant-seed"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline invalid session invariant seed")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let accepted_session = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&accepted_session).unwrap();
    let local_public =
        prefixed_signal_public_key(&valid_session_record.local_ratchet_key_pair.public);
    let local_public_offset = accepted_session
        .windows(local_public.len())
        .position(|window| window == local_public)
        .expect("encoded session contains local ratchet public key");
    let mut invalid_session = accepted_session.to_vec();
    invalid_session[local_public_offset + local_public.len() - 1] ^= 1;
    let invalid_session = Bytes::from(invalid_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &invalid_session,
        )
        .await
        .unwrap();
    let invalid_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-invalid-invariant")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let invalid_incoming = BinaryNode::new("offline").with_content(vec![invalid_child]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&invalid_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(
        nack.attrs["id"],
        "signal-spawn-offline-session-invalid-invariant"
    );
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline invalid provider session invariant must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(invalid_session)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &accepted_session,
        )
        .await
        .unwrap();
    let recovered_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-session-after-invalid-invariant")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    let recovered = BinaryNode::new("offline").with_content(vec![recovered_child]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&recovered).unwrap()))
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-session-after-invalid-invariant"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-session-after-invalid-invariant"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline session after invalid session invariant")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_ne!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        accepted_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_invalid_skipped_key_counter()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-invalid-skipped-counter",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text_plaintext = |text: &str, pad_len: u8| {
        pad_random_max16_for_test(
            Bytes::from(
                wa_proto::proto::Message {
                    conversation: Some(text.to_owned()),
                    ..wa_proto::proto::Message::default()
                }
                .encode_to_vec(),
            ),
            pad_len,
        )
    };
    let incoming_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", enc_type)
                    .with_content(ciphertext),
            ])
    };

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("spawn skipped counter first", 6),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn skipped counter second", 7),
        &sender_identity,
    )
    .unwrap();
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn skipped counter third", 8),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-counter-1",
                "pkmsg",
                first.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-skipped-counter-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn skipped counter first")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let record_after_first_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();

    let mut tampered_third = third.message.clone();
    let mut tampered_third_ciphertext = tampered_third.ciphertext.to_vec();
    *tampered_third_ciphertext.last_mut().unwrap() ^= 1;
    tampered_third.ciphertext = Bytes::from(tampered_third_ciphertext);
    let tampered_third = wa_core::encode_signal_whisper_message(
        &tampered_third,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-counter-3-tampered",
                "msg",
                tampered_third,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_third_ack.tag, "ack");
    assert_eq!(
        tampered_third_ack.attrs["id"],
        "signal-spawn-skipped-counter-3-tampered"
    );
    assert_eq!(tampered_third_ack.attrs["class"], "message");
    assert_eq!(tampered_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_third_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "tampered future active-chain message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-counter-3",
                "msg",
                third.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-spawn-skipped-counter-3");
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn skipped counter third")
    );
    let record_after_third_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_third =
        wa_core::decode_signal_provider_session_record(&record_after_third_bytes).unwrap();
    assert_eq!(
        record_after_third.receiving_chain.as_ref().unwrap().counter,
        3
    );
    assert_eq!(record_after_third.message_keys.len(), 1);
    assert_eq!(record_after_third.message_keys[0].counter, 1);
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet = record_after_third.message_keys[0].ratchet_key.clone();
    let skipped_counter_offset = record_after_third_bytes
        .windows(skipped_ratchet.len())
        .rposition(|window| window == skipped_ratchet)
        .expect("encoded session contains skipped ratchet key")
        + skipped_ratchet.len();
    let mut invalid_skipped_session = record_after_third_bytes.to_vec();
    invalid_skipped_session[skipped_counter_offset..skipped_counter_offset + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    let invalid_skipped_session = Bytes::from(invalid_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &invalid_skipped_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-counter-invalid",
                "msg",
                second.message_bytes.clone(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let invalid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_ack.tag, "ack");
    assert_eq!(
        invalid_ack.attrs["id"],
        "signal-spawn-skipped-counter-invalid"
    );
    assert_eq!(invalid_ack.attrs["class"], "message");
    assert_eq!(invalid_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(invalid_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        invalid_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "invalid skipped-key counter must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        invalid_skipped_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &record_after_third_bytes,
        )
        .await
        .unwrap();

    let mut tampered_second = second.message.clone();
    let mut tampered_second_ciphertext = tampered_second.ciphertext.to_vec();
    *tampered_second_ciphertext.last_mut().unwrap() ^= 1;
    tampered_second.ciphertext = Bytes::from(tampered_second_ciphertext);
    let tampered_second = wa_core::encode_signal_whisper_message(
        &tampered_second,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-counter-2-tampered",
                "msg",
                tampered_second,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_second_ack.tag, "ack");
    assert_eq!(
        tampered_second_ack.attrs["id"],
        "signal-spawn-skipped-counter-2-tampered"
    );
    assert_eq!(tampered_second_ack.attrs["class"], "message");
    assert_eq!(tampered_second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_second_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_second_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "tampered retained skipped-key message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_third_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-counter-2",
                "msg",
                second.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-spawn-skipped-counter-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn skipped counter second")
    );
    let stored_key = wa_core::message_event_store_key(&second_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, second_batch.messages_upsert[0]);
    let record_after_second_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second_bytes).unwrap();
    assert_eq!(
        record_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        3
    );
    assert!(record_after_second.message_keys.is_empty());
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_invalid_skipped_key_counter()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-invalid-skipped-counter",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text_plaintext = |text: &str, pad_len: u8| {
        pad_random_max16_for_test(
            Bytes::from(
                wa_proto::proto::Message {
                    conversation: Some(text.to_owned()),
                    ..wa_proto::proto::Message::default()
                }
                .encode_to_vec(),
            ),
            pad_len,
        )
    };
    let incoming_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", enc_type)
                    .with_content(ciphertext),
            ])
    };
    let offline_node = |child: BinaryNode| BinaryNode::new("offline").with_content(vec![child]);

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("spawn offline skipped counter first", 9),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline skipped counter second", 10),
        &sender_identity,
    )
    .unwrap();
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn offline skipped counter third", 11),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-counter-1",
                "pkmsg",
                first.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-offline-skipped-counter-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-skipped-counter-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline skipped counter first")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );
    let record_after_first_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();

    let mut tampered_third = third.message.clone();
    let mut tampered_third_ciphertext = tampered_third.ciphertext.to_vec();
    *tampered_third_ciphertext.last_mut().unwrap() ^= 1;
    tampered_third.ciphertext = Bytes::from(tampered_third_ciphertext);
    let tampered_third = wa_core::encode_signal_whisper_message(
        &tampered_third,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-counter-3-tampered",
                "msg",
                tampered_third,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_third_ack.tag, "ack");
    assert_eq!(
        tampered_third_ack.attrs["id"],
        "signal-spawn-offline-skipped-counter-3-tampered"
    );
    assert_eq!(tampered_third_ack.attrs["class"], "message");
    assert_eq!(tampered_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_third_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline tampered future active-chain message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-counter-3",
                "msg",
                third.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(
        third_ack.attrs["id"],
        "signal-spawn-offline-skipped-counter-3"
    );
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-skipped-counter-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn offline skipped counter third")
    );
    let record_after_third_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_third =
        wa_core::decode_signal_provider_session_record(&record_after_third_bytes).unwrap();
    assert_eq!(
        record_after_third.receiving_chain.as_ref().unwrap().counter,
        3
    );
    assert_eq!(record_after_third.message_keys.len(), 1);
    assert_eq!(record_after_third.message_keys[0].counter, 1);
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet = record_after_third.message_keys[0].ratchet_key.clone();
    let skipped_counter_offset = record_after_third_bytes
        .windows(skipped_ratchet.len())
        .rposition(|window| window == skipped_ratchet)
        .expect("encoded session contains skipped ratchet key")
        + skipped_ratchet.len();
    let mut invalid_skipped_session = record_after_third_bytes.to_vec();
    invalid_skipped_session[skipped_counter_offset..skipped_counter_offset + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    let invalid_skipped_session = Bytes::from(invalid_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &invalid_skipped_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-counter-invalid",
                "msg",
                second.message_bytes.clone(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let invalid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_ack.tag, "ack");
    assert_eq!(
        invalid_ack.attrs["id"],
        "signal-spawn-offline-skipped-counter-invalid"
    );
    assert_eq!(invalid_ack.attrs["class"], "message");
    assert_eq!(invalid_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(invalid_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        invalid_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline invalid skipped-key counter must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        invalid_skipped_session
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &record_after_third_bytes,
        )
        .await
        .unwrap();

    let mut tampered_second = second.message.clone();
    let mut tampered_second_ciphertext = tampered_second.ciphertext.to_vec();
    *tampered_second_ciphertext.last_mut().unwrap() ^= 1;
    tampered_second.ciphertext = Bytes::from(tampered_second_ciphertext);
    let tampered_second = wa_core::encode_signal_whisper_message(
        &tampered_second,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-counter-2-tampered",
                "msg",
                tampered_second,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_second_ack.tag, "ack");
    assert_eq!(
        tampered_second_ack.attrs["id"],
        "signal-spawn-offline-skipped-counter-2-tampered"
    );
    assert_eq!(tampered_second_ack.attrs["class"], "message");
    assert_eq!(tampered_second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_second_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_second_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline tampered retained skipped-key message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_third_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-counter-2",
                "msg",
                second.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(
        second_ack.attrs["id"],
        "signal-spawn-offline-skipped-counter-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-skipped-counter-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline skipped counter second")
    );
    let stored_key = wa_core::message_event_store_key(&second_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, second_batch.messages_upsert[0]);
    let record_after_second_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second_bytes).unwrap();
    assert_eq!(
        record_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        3
    );
    assert!(record_after_second.message_keys.is_empty());
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_prunes_old_skipped_message_keys() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "spawn-skipped-prune")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text_plaintext = |text: &str, pad_len: u8| {
        pad_random_max16_for_test(
            Bytes::from(
                wa_proto::proto::Message {
                    conversation: Some(text.to_owned()),
                    ..wa_proto::proto::Message::default()
                }
                .encode_to_vec(),
            ),
            pad_len,
        )
    };
    let incoming_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", enc_type)
                    .with_content(ciphertext),
            ])
    };

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("spawn prune first", 6),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let skipped_key_cap = 2_000usize;
    let pruned_counter = 1u32; // 0-based: `first` is counter 0
    let retained_counter = 2u32;
    let target_counter = u32::try_from(skipped_key_cap).unwrap() + 2;
    let mut sender_record = first.record.clone();
    let mut pruned_message_bytes = None;
    let mut retained_message_bytes = None;
    let mut target_message_bytes = None;
    for counter in 1..=target_counter {
        let plaintext = match counter {
            value if value == pruned_counter => text_plaintext("spawn prune second", 7),
            value if value == retained_counter => text_plaintext("spawn prune third", 8),
            value if value == target_counter => text_plaintext("spawn prune target", 9),
            _ => Bytes::from_static(b"unused skipped plaintext"),
        };
        let encrypted = wa_core::encrypt_signal_provider_session_record_message(
            &sender_record,
            &plaintext,
            &sender_identity,
        )
        .unwrap();
        assert_eq!(encrypted.message.counter, counter);
        sender_record = encrypted.record.clone();
        match counter {
            value if value == pruned_counter => {
                pruned_message_bytes = Some(encrypted.message_bytes)
            }
            value if value == retained_counter => {
                retained_message_bytes = Some(encrypted.message_bytes)
            }
            value if value == target_counter => {
                target_message_bytes = Some(encrypted.message_bytes)
            }
            _ => {}
        }
    }
    let pruned_message_bytes = pruned_message_bytes.unwrap();
    let retained_message_bytes = retained_message_bytes.unwrap();
    let target_message_bytes = target_message_bytes.unwrap();

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-prune-1",
                "pkmsg",
                first.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-prune-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn prune first")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-prune-target",
                "msg",
                target_message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let target_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(target_ack.tag, "ack");
    assert_eq!(target_ack.attrs["id"], "signal-spawn-prune-target");
    assert_eq!(target_ack.attrs["class"], "message");
    assert_eq!(target_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(target_ack.attrs["from"], "999:7@s.whatsapp.net");
    let target_batch = recv_batch_event(&mut events).await;
    assert_eq!(target_batch.messages_upsert.len(), 1);
    let target_payload = target_batch.messages_upsert[0].payload.clone().unwrap();
    let target_decoded = wa_proto::proto::Message::decode(target_payload).unwrap();
    assert_eq!(
        target_decoded.conversation.as_deref(),
        Some("spawn prune target")
    );
    let stored_key = wa_core::message_event_store_key(&target_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, target_batch.messages_upsert[0]);
    let record_after_target_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_target =
        wa_core::decode_signal_provider_session_record(&record_after_target_bytes).unwrap();
    assert_eq!(record_after_target.message_keys.len(), skipped_key_cap);
    assert_eq!(
        record_after_target.message_keys.first().unwrap().counter,
        retained_counter
    );
    assert_eq!(
        record_after_target.message_keys.last().unwrap().counter,
        target_counter - 1
    );
    assert_eq!(
        record_after_target
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        target_counter + 1
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-prune-2",
                "msg",
                pruned_message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let pruned_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(pruned_ack.tag, "ack");
    assert_eq!(pruned_ack.attrs["id"], "signal-spawn-prune-2");
    assert_eq!(pruned_ack.attrs["class"], "message");
    assert_eq!(pruned_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(pruned_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        pruned_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "pruned skipped-key counter must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_target_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-prune-3",
                "msg",
                retained_message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let retained_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(retained_ack.tag, "ack");
    assert_eq!(retained_ack.attrs["id"], "signal-spawn-prune-3");
    assert_eq!(retained_ack.attrs["class"], "message");
    assert_eq!(retained_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(retained_ack.attrs["from"], "999:7@s.whatsapp.net");
    let retained_batch = recv_batch_event(&mut events).await;
    assert_eq!(retained_batch.messages_upsert.len(), 1);
    let retained_payload = retained_batch.messages_upsert[0].payload.clone().unwrap();
    let retained_decoded = wa_proto::proto::Message::decode(retained_payload).unwrap();
    assert_eq!(
        retained_decoded.conversation.as_deref(),
        Some("spawn prune third")
    );
    let stored_key = wa_core::message_event_store_key(&retained_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, retained_batch.messages_upsert[0]);
    let record_after_retained_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_retained =
        wa_core::decode_signal_provider_session_record(&record_after_retained_bytes).unwrap();
    assert_eq!(
        record_after_retained.message_keys.len(),
        skipped_key_cap - 1
    );
    assert_eq!(
        record_after_retained.message_keys.first().unwrap().counter,
        retained_counter + 1
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_prunes_old_offline_skipped_message_keys() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-skipped-prune",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text_plaintext = |text: &str, pad_len: u8| {
        pad_random_max16_for_test(
            Bytes::from(
                wa_proto::proto::Message {
                    conversation: Some(text.to_owned()),
                    ..wa_proto::proto::Message::default()
                }
                .encode_to_vec(),
            ),
            pad_len,
        )
    };
    let incoming_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", enc_type)
                    .with_content(ciphertext),
            ])
    };
    let offline_node = |child: BinaryNode| BinaryNode::new("offline").with_content(vec![child]);

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("spawn offline prune first", 10),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let skipped_key_cap = 2_000usize;
    let pruned_counter = 1u32; // 0-based: `first` is counter 0
    let retained_counter = 2u32;
    let target_counter = u32::try_from(skipped_key_cap).unwrap() + 2;
    let mut sender_record = first.record.clone();
    let mut pruned_message_bytes = None;
    let mut retained_message_bytes = None;
    let mut target_message_bytes = None;
    for counter in 1..=target_counter {
        let plaintext = match counter {
            value if value == pruned_counter => text_plaintext("spawn offline prune second", 11),
            value if value == retained_counter => text_plaintext("spawn offline prune third", 12),
            value if value == target_counter => text_plaintext("spawn offline prune target", 13),
            _ => Bytes::from_static(b"unused skipped plaintext"),
        };
        let encrypted = wa_core::encrypt_signal_provider_session_record_message(
            &sender_record,
            &plaintext,
            &sender_identity,
        )
        .unwrap();
        assert_eq!(encrypted.message.counter, counter);
        sender_record = encrypted.record.clone();
        match counter {
            value if value == pruned_counter => {
                pruned_message_bytes = Some(encrypted.message_bytes)
            }
            value if value == retained_counter => {
                retained_message_bytes = Some(encrypted.message_bytes)
            }
            value if value == target_counter => {
                target_message_bytes = Some(encrypted.message_bytes)
            }
            _ => {}
        }
    }
    let pruned_message_bytes = pruned_message_bytes.unwrap();
    let retained_message_bytes = retained_message_bytes.unwrap();
    let target_message_bytes = target_message_bytes.unwrap();

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-prune-1",
                "pkmsg",
                first.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-offline-prune-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-prune-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline prune first")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-prune-target",
                "msg",
                target_message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let target_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(target_ack.tag, "ack");
    assert_eq!(target_ack.attrs["id"], "signal-spawn-offline-prune-target");
    assert_eq!(target_ack.attrs["class"], "message");
    assert_eq!(target_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(target_ack.attrs["from"], "999:7@s.whatsapp.net");
    let target_batch = recv_batch_event(&mut events).await;
    assert_eq!(target_batch.messages_upsert.len(), 1);
    assert_eq!(
        target_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-prune-target"
    );
    let target_payload = target_batch.messages_upsert[0].payload.clone().unwrap();
    let target_decoded = wa_proto::proto::Message::decode(target_payload).unwrap();
    assert_eq!(
        target_decoded.conversation.as_deref(),
        Some("spawn offline prune target")
    );
    let stored_key = wa_core::message_event_store_key(&target_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, target_batch.messages_upsert[0]);
    let record_after_target_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_target =
        wa_core::decode_signal_provider_session_record(&record_after_target_bytes).unwrap();
    assert_eq!(record_after_target.message_keys.len(), skipped_key_cap);
    assert_eq!(
        record_after_target.message_keys.first().unwrap().counter,
        retained_counter
    );
    assert_eq!(
        record_after_target.message_keys.last().unwrap().counter,
        target_counter - 1
    );
    assert_eq!(
        record_after_target
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        target_counter + 1
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-prune-2",
                "msg",
                pruned_message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let pruned_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(pruned_ack.tag, "ack");
    assert_eq!(pruned_ack.attrs["id"], "signal-spawn-offline-prune-2");
    assert_eq!(pruned_ack.attrs["class"], "message");
    assert_eq!(pruned_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(pruned_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        pruned_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline pruned skipped-key counter must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_target_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-prune-3",
                "msg",
                retained_message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let retained_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(retained_ack.tag, "ack");
    assert_eq!(retained_ack.attrs["id"], "signal-spawn-offline-prune-3");
    assert_eq!(retained_ack.attrs["class"], "message");
    assert_eq!(retained_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(retained_ack.attrs["from"], "999:7@s.whatsapp.net");
    let retained_batch = recv_batch_event(&mut events).await;
    assert_eq!(retained_batch.messages_upsert.len(), 1);
    assert_eq!(
        retained_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-prune-3"
    );
    let retained_payload = retained_batch.messages_upsert[0].payload.clone().unwrap();
    let retained_decoded = wa_proto::proto::Message::decode(retained_payload).unwrap();
    assert_eq!(
        retained_decoded.conversation.as_deref(),
        Some("spawn offline prune third")
    );
    let stored_key = wa_core::message_event_store_key(&retained_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, retained_batch.messages_upsert[0]);
    let record_after_retained_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_retained =
        wa_core::decode_signal_provider_session_record(&record_after_retained_bytes).unwrap();
    assert_eq!(
        record_after_retained.message_keys.len(),
        skipped_key_cap - 1
    );
    assert_eq!(
        record_after_retained.message_keys.first().unwrap().counter,
        retained_counter + 1
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_accepts_new_remote_ratchet() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "spawn-new-ratchet")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text_plaintext = |text: &str, pad_len: u8| {
        pad_random_max16_for_test(
            Bytes::from(
                wa_proto::proto::Message {
                    conversation: Some(text.to_owned()),
                    ..wa_proto::proto::Message::default()
                }
                .encode_to_vec(),
            ),
            pad_len,
        )
    };
    let incoming_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", enc_type)
                    .with_content(ciphertext),
            ])
    };

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("spawn ratchet first", 14),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn ratchet second", 15),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn ratchet old third", 16),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-1",
                "pkmsg",
                first.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver ratchet reply"),
        )
        .await
        .unwrap()
        .unwrap();
    let record_after_reply_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_reply =
        wa_core::decode_signal_provider_session_record(&record_after_reply_bytes).unwrap();
    assert_eq!(record_after_reply.sending_chain.counter, 1);
    assert_eq!(
        record_after_reply.receiving_chain.as_ref().unwrap().counter,
        1
    );

    let sender_after_reply = wa_core::decrypt_signal_provider_session_record_message(
        &old_third.record,
        &reply.message_bytes,
        &sender_identity,
    )
    .unwrap();
    let fourth = wa_core::encrypt_signal_provider_session_record_message(
        &sender_after_reply.record,
        &text_plaintext("spawn ratchet fourth", 4),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(fourth.message.counter, 0);
    assert_eq!(fourth.message.previous_counter, 2);
    assert_ne!(
        fourth.message.ephemeral_key,
        Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public))
    );
    let fifth = wa_core::encrypt_signal_provider_session_record_message(
        &fourth.record,
        &text_plaintext("spawn ratchet fifth", 5),
        &sender_identity,
    )
    .unwrap();
    let sixth = wa_core::encrypt_signal_provider_session_record_message(
        &fifth.record,
        &text_plaintext("spawn ratchet sixth", 6),
        &sender_identity,
    )
    .unwrap();
    let seventh = wa_core::encrypt_signal_provider_session_record_message(
        &sixth.record,
        &text_plaintext("spawn ratchet seventh", 7),
        &sender_identity,
    )
    .unwrap();

    let mut tampered_fourth = fourth.message.clone();
    let mut tampered_fourth_ciphertext = tampered_fourth.ciphertext.to_vec();
    *tampered_fourth_ciphertext.last_mut().unwrap() ^= 1;
    tampered_fourth.ciphertext = Bytes::from(tampered_fourth_ciphertext);
    let tampered_fourth = wa_core::encode_signal_whisper_message(
        &tampered_fourth,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-4-tampered",
                "msg",
                tampered_fourth,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_fourth_ack.tag, "ack");
    assert_eq!(
        tampered_fourth_ack.attrs["id"],
        "signal-spawn-ratchet-4-tampered"
    );
    assert_eq!(tampered_fourth_ack.attrs["class"], "message");
    assert_eq!(tampered_fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_fourth_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "tampered new-ratchet message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_reply_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-4",
                "msg",
                fourth.message_bytes.clone(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-spawn-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn ratchet fourth")
    );
    let stored_key = wa_core::message_event_store_key(&fourth_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, fourth_batch.messages_upsert[0]);
    let record_after_fourth_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fourth =
        wa_core::decode_signal_provider_session_record(&record_after_fourth_bytes).unwrap();
    assert_eq!(
        record_after_fourth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_fourth
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        1
    );
    assert_eq!(
        record_after_fourth
            .message_keys
            .iter()
            .map(|message_key| message_key.counter)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-4-replay",
                "msg",
                fourth.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_ack.tag, "ack");
    assert_eq!(replay_ack.attrs["id"], "signal-spawn-ratchet-4-replay");
    assert_eq!(replay_ack.attrs["class"], "message");
    assert_eq!(replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "new-ratchet replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_fourth_bytes
    );

    let mut tampered_old_third = old_third.message.clone();
    let mut tampered_old_third_ciphertext = tampered_old_third.ciphertext.to_vec();
    *tampered_old_third_ciphertext.last_mut().unwrap() ^= 1;
    tampered_old_third.ciphertext = Bytes::from(tampered_old_third_ciphertext);
    let tampered_old_third = wa_core::encode_signal_whisper_message(
        &tampered_old_third,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-old-3-tampered",
                "msg",
                tampered_old_third,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_old_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_old_ack.tag, "ack");
    assert_eq!(
        tampered_old_ack.attrs["id"],
        "signal-spawn-ratchet-old-3-tampered"
    );
    assert_eq!(tampered_old_ack.attrs["class"], "message");
    assert_eq!(tampered_old_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_old_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_old_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "tampered previous-chain message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_fourth_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-old-3",
                "msg",
                old_third.message_bytes.clone(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(old_third_ack.attrs["id"], "signal-spawn-ratchet-old-3");
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("spawn ratchet old third")
    );
    let record_after_old_third_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_old_third =
        wa_core::decode_signal_provider_session_record(&record_after_old_third_bytes).unwrap();
    assert_eq!(
        record_after_old_third.remote_ratchet_key,
        Some(fourth.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_old_third
            .message_keys
            .iter()
            .map(|message_key| message_key.counter)
            .collect::<Vec<_>>(),
        vec![1]
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-old-3-replay",
                "msg",
                old_third.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let old_third_replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_replay_ack.tag, "ack");
    assert_eq!(
        old_third_replay_ack.attrs["id"],
        "signal-spawn-ratchet-old-3-replay"
    );
    assert_eq!(old_third_replay_ack.attrs["class"], "message");
    assert_eq!(old_third_replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        old_third_replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "consumed previous-chain replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_old_third_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-2",
                "msg",
                second.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-spawn-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn ratchet second")
    );
    let record_after_second_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second_bytes).unwrap();
    assert_eq!(
        record_after_second.remote_ratchet_key,
        Some(fourth.message.ephemeral_key.clone())
    );
    assert!(record_after_second.message_keys.is_empty());

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-5",
                "msg",
                fifth.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-spawn-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("spawn ratchet fifth")
    );
    let stored_key = wa_core::message_event_store_key(&fifth_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, fifth_batch.messages_upsert[0]);
    let record_after_fifth_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth_bytes).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fifth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());

    let stale_ratchet_key_pair = generate_key_pair();
    let stale_previous = wa_core::SignalWhisperMessage {
        ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
            &stale_ratchet_key_pair.public,
        )),
        counter: 1,
        previous_counter: 1,
        ciphertext: Bytes::from_static(b"spawn-stale-previous-counter"),
    };
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-stale-previous",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &stale_previous,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let stale_previous_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(stale_previous_ack.tag, "ack");
    assert_eq!(
        stale_previous_ack.attrs["id"],
        "signal-spawn-ratchet-stale-previous"
    );
    assert_eq!(stale_previous_ack.attrs["class"], "message");
    assert_eq!(stale_previous_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(stale_previous_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        stale_previous_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "stale previous-counter message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_fifth_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-6",
                "msg",
                sixth.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let sixth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sixth_ack.tag, "ack");
    assert_eq!(sixth_ack.attrs["id"], "signal-spawn-ratchet-6");
    assert_eq!(sixth_ack.attrs["class"], "message");
    assert_eq!(sixth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sixth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let sixth_batch = recv_batch_event(&mut events).await;
    assert_eq!(sixth_batch.messages_upsert.len(), 1);
    let sixth_payload = sixth_batch.messages_upsert[0].payload.clone().unwrap();
    let sixth_decoded = wa_proto::proto::Message::decode(sixth_payload).unwrap();
    assert_eq!(
        sixth_decoded.conversation.as_deref(),
        Some("spawn ratchet sixth")
    );
    let stored_key = wa_core::message_event_store_key(&sixth_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, sixth_batch.messages_upsert[0]);
    let record_after_sixth_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_sixth =
        wa_core::decode_signal_provider_session_record(&record_after_sixth_bytes).unwrap();
    assert_eq!(
        record_after_sixth.remote_ratchet_key,
        Some(sixth.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_sixth.receiving_chain.as_ref().unwrap().counter,
        3
    );
    assert!(record_after_sixth.message_keys.is_empty());

    let far_future_counter = 25_004;
    let far_future_previous_ratchet_key_pair = generate_key_pair();
    let far_future_previous = wa_core::SignalWhisperMessage {
        ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
            &far_future_previous_ratchet_key_pair.public,
        )),
        counter: 1,
        previous_counter: far_future_counter,
        ciphertext: Bytes::from_static(b"spawn-far-future-previous-counter"),
    };
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-far-future-previous",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &far_future_previous,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let far_future_previous_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(far_future_previous_ack.tag, "ack");
    assert_eq!(
        far_future_previous_ack.attrs["id"],
        "signal-spawn-ratchet-far-future-previous"
    );
    assert_eq!(far_future_previous_ack.attrs["class"], "message");
    assert_eq!(far_future_previous_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(
        far_future_previous_ack.attrs["from"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(
        far_future_previous_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "far-future previous-counter message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_sixth_bytes
    );

    let far_future_current = wa_core::SignalWhisperMessage {
        ephemeral_key: sixth.message.ephemeral_key.clone(),
        counter: far_future_counter,
        previous_counter: 3,
        ciphertext: Bytes::from_static(b"spawn-far-future-current-counter"),
    };
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-far-future-current",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &far_future_current,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let far_future_current_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(far_future_current_ack.tag, "ack");
    assert_eq!(
        far_future_current_ack.attrs["id"],
        "signal-spawn-ratchet-far-future-current"
    );
    assert_eq!(far_future_current_ack.attrs["class"], "message");
    assert_eq!(far_future_current_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(far_future_current_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        far_future_current_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "far-future current-counter message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_sixth_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-ratchet-7",
                "msg",
                seventh.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let seventh_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(seventh_ack.tag, "ack");
    assert_eq!(seventh_ack.attrs["id"], "signal-spawn-ratchet-7");
    assert_eq!(seventh_ack.attrs["class"], "message");
    assert_eq!(seventh_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(seventh_ack.attrs["from"], "999:7@s.whatsapp.net");
    let seventh_batch = recv_batch_event(&mut events).await;
    assert_eq!(seventh_batch.messages_upsert.len(), 1);
    let seventh_payload = seventh_batch.messages_upsert[0].payload.clone().unwrap();
    let seventh_decoded = wa_proto::proto::Message::decode(seventh_payload).unwrap();
    assert_eq!(
        seventh_decoded.conversation.as_deref(),
        Some("spawn ratchet seventh")
    );
    let stored_key = wa_core::message_event_store_key(&seventh_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, seventh_batch.messages_upsert[0]);
    let record_after_seventh = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_seventh =
        wa_core::decode_signal_provider_session_record(&record_after_seventh).unwrap();
    assert_eq!(
        record_after_seventh.remote_ratchet_key,
        Some(seventh.message.ephemeral_key)
    );
    assert_eq!(
        record_after_seventh
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        4
    );
    assert!(record_after_seventh.message_keys.is_empty());
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_accepts_offline_new_remote_ratchet() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(
        &store,
        &receiver_credentials,
        1,
        "spawn-offline-new-ratchet",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();

    let sender_credentials = wa_core::create_initial_credentials().unwrap();
    let sender_material = test_signal_local_key_material(&sender_credentials);
    #[allow(unused_variables)]
    let sender_identity = sender_material.identity.public_key.clone();
    #[allow(unused_variables)]
    let receiver_identity = Bytes::copy_from_slice(&prefixed_signal_public_key(
        &receiver_credentials.signed_identity_key.public,
    ));
    let sender_base_key = generate_key_pair();
    let receiver_session = wa_core::SignalSession {
        registration_id: receiver_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: receiver_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(
                &receiver_credentials.signed_pre_key.key_pair.public,
            ),
            signature: receiver_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: receiver_pre_key_id,
            public_key: receiver_pre_key.public_key.clone(),
        }),
    };
    let text_plaintext = |text: &str, pad_len: u8| {
        pad_random_max16_for_test(
            Bytes::from(
                wa_proto::proto::Message {
                    conversation: Some(text.to_owned()),
                    ..wa_proto::proto::Message::default()
                }
                .encode_to_vec(),
            ),
            pad_len,
        )
    };
    let incoming_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", enc_type)
                    .with_content(ciphertext),
            ])
    };
    let offline_node = |child: BinaryNode| BinaryNode::new("offline").with_content(vec![child]);

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("spawn offline ratchet first", 8),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline ratchet second", 9),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn offline ratchet old third", 10),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-1",
                "pkmsg",
                first.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-spawn-offline-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver offline ratchet reply"),
        )
        .await
        .unwrap()
        .unwrap();
    let record_after_reply_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_reply =
        wa_core::decode_signal_provider_session_record(&record_after_reply_bytes).unwrap();
    assert_eq!(record_after_reply.sending_chain.counter, 1);
    assert_eq!(
        record_after_reply.receiving_chain.as_ref().unwrap().counter,
        1
    );

    let sender_after_reply = wa_core::decrypt_signal_provider_session_record_message(
        &old_third.record,
        &reply.message_bytes,
        &sender_identity,
    )
    .unwrap();
    let fourth = wa_core::encrypt_signal_provider_session_record_message(
        &sender_after_reply.record,
        &text_plaintext("spawn offline ratchet fourth", 11),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(fourth.message.counter, 0);
    assert_eq!(fourth.message.previous_counter, 2);
    assert_ne!(
        fourth.message.ephemeral_key,
        Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public))
    );
    let fifth = wa_core::encrypt_signal_provider_session_record_message(
        &fourth.record,
        &text_plaintext("spawn offline ratchet fifth", 12),
        &sender_identity,
    )
    .unwrap();
    let sixth = wa_core::encrypt_signal_provider_session_record_message(
        &fifth.record,
        &text_plaintext("spawn offline ratchet sixth", 13),
        &sender_identity,
    )
    .unwrap();
    let seventh = wa_core::encrypt_signal_provider_session_record_message(
        &sixth.record,
        &text_plaintext("spawn offline ratchet seventh", 14),
        &sender_identity,
    )
    .unwrap();

    let mut tampered_fourth = fourth.message.clone();
    let mut tampered_fourth_ciphertext = tampered_fourth.ciphertext.to_vec();
    *tampered_fourth_ciphertext.last_mut().unwrap() ^= 1;
    tampered_fourth.ciphertext = Bytes::from(tampered_fourth_ciphertext);
    let tampered_fourth = wa_core::encode_signal_whisper_message(
        &tampered_fourth,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-4-tampered",
                "msg",
                tampered_fourth,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_fourth_ack.tag, "ack");
    assert_eq!(
        tampered_fourth_ack.attrs["id"],
        "signal-spawn-offline-ratchet-4-tampered"
    );
    assert_eq!(tampered_fourth_ack.attrs["class"], "message");
    assert_eq!(tampered_fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_fourth_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline tampered new-ratchet message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_reply_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-4",
                "msg",
                fourth.message_bytes.clone(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-spawn-offline-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn offline ratchet fourth")
    );
    let stored_key = wa_core::message_event_store_key(&fourth_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, fourth_batch.messages_upsert[0]);
    let record_after_fourth_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fourth =
        wa_core::decode_signal_provider_session_record(&record_after_fourth_bytes).unwrap();
    assert_eq!(
        record_after_fourth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_fourth
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        1
    );
    assert_eq!(
        record_after_fourth
            .message_keys
            .iter()
            .map(|message_key| message_key.counter)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-4-replay",
                "msg",
                fourth.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_ack.tag, "ack");
    assert_eq!(
        replay_ack.attrs["id"],
        "signal-spawn-offline-ratchet-4-replay"
    );
    assert_eq!(replay_ack.attrs["class"], "message");
    assert_eq!(replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline new-ratchet replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_fourth_bytes
    );

    let mut tampered_old_third = old_third.message.clone();
    let mut tampered_old_third_ciphertext = tampered_old_third.ciphertext.to_vec();
    *tampered_old_third_ciphertext.last_mut().unwrap() ^= 1;
    tampered_old_third.ciphertext = Bytes::from(tampered_old_third_ciphertext);
    let tampered_old_third = wa_core::encode_signal_whisper_message(
        &tampered_old_third,
        &[0u8; 32],
        &sender_identity,
        &receiver_identity,
    )
    .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-old-3-tampered",
                "msg",
                tampered_old_third,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let tampered_old_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_old_ack.tag, "ack");
    assert_eq!(
        tampered_old_ack.attrs["id"],
        "signal-spawn-offline-ratchet-old-3-tampered"
    );
    assert_eq!(tampered_old_ack.attrs["class"], "message");
    assert_eq!(tampered_old_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_old_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_old_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline tampered previous-chain message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_fourth_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-old-3",
                "msg",
                old_third.message_bytes.clone(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(
        old_third_ack.attrs["id"],
        "signal-spawn-offline-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("spawn offline ratchet old third")
    );
    let record_after_old_third_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_old_third =
        wa_core::decode_signal_provider_session_record(&record_after_old_third_bytes).unwrap();
    assert_eq!(
        record_after_old_third.remote_ratchet_key,
        Some(fourth.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_old_third
            .message_keys
            .iter()
            .map(|message_key| message_key.counter)
            .collect::<Vec<_>>(),
        vec![1]
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-old-3-replay",
                "msg",
                old_third.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let old_third_replay_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_replay_ack.tag, "ack");
    assert_eq!(
        old_third_replay_ack.attrs["id"],
        "signal-spawn-offline-ratchet-old-3-replay"
    );
    assert_eq!(old_third_replay_ack.attrs["class"], "message");
    assert_eq!(old_third_replay_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_replay_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        old_third_replay_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline consumed previous-chain replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_old_third_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-2",
                "msg",
                second.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-spawn-offline-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline ratchet second")
    );
    let record_after_second_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second_bytes).unwrap();
    assert_eq!(
        record_after_second.remote_ratchet_key,
        Some(fourth.message.ephemeral_key.clone())
    );
    assert!(record_after_second.message_keys.is_empty());

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-5",
                "msg",
                fifth.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-spawn-offline-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("spawn offline ratchet fifth")
    );
    let stored_key = wa_core::message_event_store_key(&fifth_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, fifth_batch.messages_upsert[0]);
    let record_after_fifth_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth_bytes).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fifth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());

    let stale_ratchet_key_pair = generate_key_pair();
    let stale_previous = wa_core::SignalWhisperMessage {
        ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
            &stale_ratchet_key_pair.public,
        )),
        counter: 1,
        previous_counter: 1,
        ciphertext: Bytes::from_static(b"spawn-offline-stale-previous-counter"),
    };
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-stale-previous",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &stale_previous,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let stale_previous_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(stale_previous_ack.tag, "ack");
    assert_eq!(
        stale_previous_ack.attrs["id"],
        "signal-spawn-offline-ratchet-stale-previous"
    );
    assert_eq!(stale_previous_ack.attrs["class"], "message");
    assert_eq!(stale_previous_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(stale_previous_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        stale_previous_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline stale previous-counter message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_fifth_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-6",
                "msg",
                sixth.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let sixth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sixth_ack.tag, "ack");
    assert_eq!(sixth_ack.attrs["id"], "signal-spawn-offline-ratchet-6");
    assert_eq!(sixth_ack.attrs["class"], "message");
    assert_eq!(sixth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sixth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let sixth_batch = recv_batch_event(&mut events).await;
    assert_eq!(sixth_batch.messages_upsert.len(), 1);
    assert_eq!(
        sixth_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-ratchet-6"
    );
    let sixth_payload = sixth_batch.messages_upsert[0].payload.clone().unwrap();
    let sixth_decoded = wa_proto::proto::Message::decode(sixth_payload).unwrap();
    assert_eq!(
        sixth_decoded.conversation.as_deref(),
        Some("spawn offline ratchet sixth")
    );
    let stored_key = wa_core::message_event_store_key(&sixth_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, sixth_batch.messages_upsert[0]);
    let record_after_sixth_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_sixth =
        wa_core::decode_signal_provider_session_record(&record_after_sixth_bytes).unwrap();
    assert_eq!(
        record_after_sixth.remote_ratchet_key,
        Some(sixth.message.ephemeral_key.clone())
    );
    assert_eq!(
        record_after_sixth.receiving_chain.as_ref().unwrap().counter,
        3
    );
    assert!(record_after_sixth.message_keys.is_empty());

    let far_future_counter = 25_004;
    let far_future_previous_ratchet_key_pair = generate_key_pair();
    let far_future_previous = wa_core::SignalWhisperMessage {
        ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
            &far_future_previous_ratchet_key_pair.public,
        )),
        counter: 1,
        previous_counter: far_future_counter,
        ciphertext: Bytes::from_static(b"spawn-offline-far-future-previous-counter"),
    };
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-far-future-previous",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &far_future_previous,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let far_future_previous_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(far_future_previous_ack.tag, "ack");
    assert_eq!(
        far_future_previous_ack.attrs["id"],
        "signal-spawn-offline-ratchet-far-future-previous"
    );
    assert_eq!(far_future_previous_ack.attrs["class"], "message");
    assert_eq!(far_future_previous_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(
        far_future_previous_ack.attrs["from"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(
        far_future_previous_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline far-future previous-counter message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_sixth_bytes
    );

    let far_future_current = wa_core::SignalWhisperMessage {
        ephemeral_key: sixth.message.ephemeral_key.clone(),
        counter: far_future_counter,
        previous_counter: 3,
        ciphertext: Bytes::from_static(b"spawn-offline-far-future-current-counter"),
    };
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-far-future-current",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &far_future_current,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let far_future_current_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(far_future_current_ack.tag, "ack");
    assert_eq!(
        far_future_current_ack.attrs["id"],
        "signal-spawn-offline-ratchet-far-future-current"
    );
    assert_eq!(far_future_current_ack.attrs["class"], "message");
    assert_eq!(far_future_current_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(far_future_current_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        far_future_current_ack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline far-future current-counter message must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_sixth_bytes
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-ratchet-7",
                "msg",
                seventh.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let seventh_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(seventh_ack.tag, "ack");
    assert_eq!(seventh_ack.attrs["id"], "signal-spawn-offline-ratchet-7");
    assert_eq!(seventh_ack.attrs["class"], "message");
    assert_eq!(seventh_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(seventh_ack.attrs["from"], "999:7@s.whatsapp.net");
    let seventh_batch = recv_batch_event(&mut events).await;
    assert_eq!(seventh_batch.messages_upsert.len(), 1);
    assert_eq!(
        seventh_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-ratchet-7"
    );
    let seventh_payload = seventh_batch.messages_upsert[0].payload.clone().unwrap();
    let seventh_decoded = wa_proto::proto::Message::decode(seventh_payload).unwrap();
    assert_eq!(
        seventh_decoded.conversation.as_deref(),
        Some("spawn offline ratchet seventh")
    );
    let stored_key = wa_core::message_event_store_key(&seventh_batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, seventh_batch.messages_upsert[0]);
    let record_after_seventh = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_seventh =
        wa_core::decode_signal_provider_session_record(&record_after_seventh).unwrap();
    assert_eq!(
        record_after_seventh.remote_ratchet_key,
        Some(seventh.message.ephemeral_key)
    );
    assert_eq!(
        record_after_seventh
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        4
    );
    assert!(record_after_seventh.message_keys.is_empty());
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );
    processor.abort();
    connection.close().await.unwrap();
}
