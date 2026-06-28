// Auto-partitioned test chunk 5 of 8 (feature `wat5`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat5 to stay within the VM RAM budget.
// Included into `mod chunk_5` in lib.rs; allow-attrs live on that module decl.
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
async fn process_incoming_node_with_placeholder_resend_with_signal_provider_preserves_legacy_missing_key()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 95;
    let incoming = BinaryNode::new("message")
        .with_attr("id", "missing-live-signal-legacy")
        .with_attr("from", "123@c.us")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key =
        wa_core::build_message_key("123@c.us", false, "missing-live-signal-legacy", None).unwrap();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_placeholder_resend_with_signal_provider(
        &connection,
        &incoming,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => panic!("processing completed before ACK: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-live-signal-legacy");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@c.us");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
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
                ])])
        },
        &mut process_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node)
                    .into_iter()
                    .map(|(jid, _)| jid)
                    .collect::<Vec<_>>(),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:8@s.whatsapp.net".to_owned(),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;

    let outcome = process_fut.await.unwrap();
    assert_eq!(outcome.inbound.action, wa_core::InboundNodeAction::Message);
    assert_eq!(outcome.inbound.event_count, 1);
    assert!(outcome.inbound.error.is_none());
    let relay = outcome.placeholder_resend.unwrap();
    assert_eq!(relay.recipient_count, 2);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
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
            .contains("missing-live-signal-legacy", current_unix_timestamp_ms())
            .unwrap()
    );

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "missing-live-signal-legacy"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["kind"],
        "placeholder_unavailable"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["unavailable_type"],
        "temporary_unavailable"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_persists_linked_profile_mappings() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let incoming = BinaryNode::new("notification")
        .with_attr("id", "n-linked")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "mex")
        .with_content(vec![BinaryNode::new("update")
            .with_attr("op_name", "NotificationLinkedProfilesUpdates")
            .with_content(
                br#"{"data":{"xwa2_notify_linked_profiles":{"jid":"abc@lid","added_profiles":[{"pn":"123@s.whatsapp.net"}]}}}"#.to_vec(),
            )]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "n-linked");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

    let Event::Node(node) = events.recv().await.unwrap() else {
        panic!("expected raw notification event");
    };
    assert_eq!(node, incoming);
    let Event::LidMappingUpdate(mappings) = events.recv().await.unwrap() else {
        panic!("expected LID mapping event");
    };
    assert_eq!(
        mappings,
        vec![wa_core::LidMappingEvent::new(
            "abc@lid",
            "123@s.whatsapp.net"
        )]
    );

    let mapping_store = wa_core::LidPnMappingStore::new(store);
    assert_eq!(
        mapping_store
            .lid_for_pn("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some("abc".to_owned())
    );
    assert_eq!(
        mapping_store.pn_for_lid("abc@lid").await.unwrap(),
        Some("123".to_owned())
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_emits_business_notification_alias_metadata() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "biz-alias-live")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "business")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000420")
        .with_content(vec![
            BinaryNode::new("cover_photo")
                .with_attr("media-id", "cover-1")
                .with_content(vec![
                    BinaryNode::new("image").with_content(vec![0xab, 0xcd]),
                ]),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &notification, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "biz-alias-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.business_notifications.len(), 1);
    assert!(batch.messages_upsert.is_empty());
    let event = &batch.business_notifications[0];
    assert_eq!(event.from, "server@s.whatsapp.net");
    assert_eq!(event.notification_id, "biz-alias-live");
    assert_eq!(event.event_type, "cover_photo");
    assert_eq!(event.fields["notification_type"], "business");
    assert_eq!(event.fields["timestamp"], "1700000420");
    assert_eq!(event.fields["actor"], "111@lid");
    assert_eq!(event.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(event.fields["actor_username"], "actor-one");
    assert_eq!(event.fields["attr_media_id"], "cover-1");
    assert_eq!(event.fields["child_image"], "true");
    assert_eq!(event.fields["child_image_bytes_hex"], "abcd");

    let stored = store
        .get(
            KeyNamespace::BusinessNotificationEvent,
            &wa_core::business_notification_event_store_key(event),
        )
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_business_notification_event(&stored).unwrap();
    assert_eq!(stored, *event);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_emits_newsletter_notification_events() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let plaintext = wa_proto::proto::Message {
        conversation: Some("newsletter text".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let notification = BinaryNode::new("notification")
        .with_attr("id", "newsletter-live")
        .with_attr("from", "abc@newsletter")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("type", "newsletter")
        .with_content(vec![
            BinaryNode::new("reaction")
                .with_attr("message_id", "server-1")
                .with_content(vec![BinaryNode::new("reaction").with_content("+")]),
            BinaryNode::new("view")
                .with_attr("message_id", "server-2")
                .with_content("42"),
            BinaryNode::new("participant")
                .with_attr("jid", "222@s.whatsapp.net")
                .with_attr("action", "promote")
                .with_attr("role", "ADMIN"),
            BinaryNode::new("update").with_content(vec![BinaryNode::new("settings").with_content(
                vec![
                    BinaryNode::new("name").with_content("Updates"),
                    BinaryNode::new("description").with_content("Daily notes"),
                ],
            )]),
            BinaryNode::new("message")
                .with_attr("message_id", "server-3")
                .with_attr("t", "1700000440")
                .with_content(vec![
                    BinaryNode::new("plaintext")
                        .with_content(Bytes::from(plaintext.encode_to_vec())),
                ]),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &notification, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    assert_eq!(result.event_count, 6);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "newsletter-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "abc@newsletter");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let Event::NewsletterReactionUpdate(reactions) = events.recv().await.unwrap() else {
        panic!("expected newsletter reaction update");
    };
    assert_eq!(reactions.len(), 1);
    let reaction = &reactions[0];
    assert_eq!(reaction.id, "abc@newsletter");
    assert_eq!(reaction.server_id, "server-1");
    assert_eq!(reaction.code.as_deref(), Some("+"));
    assert_eq!(reaction.count, Some(1));

    let Event::NewsletterViewUpdate(views) = events.recv().await.unwrap() else {
        panic!("expected newsletter view update");
    };
    assert_eq!(views.len(), 1);
    let view = &views[0];
    assert_eq!(view.id, "abc@newsletter");
    assert_eq!(view.server_id, "server-2");
    assert_eq!(view.count, 42);

    let Event::NewsletterParticipantsUpdate(participants) = events.recv().await.unwrap() else {
        panic!("expected newsletter participant update");
    };
    assert_eq!(participants.len(), 1);
    let participant = &participants[0];
    assert_eq!(participant.id, "abc@newsletter");
    assert_eq!(participant.author, "111@s.whatsapp.net");
    assert_eq!(participant.user, "222@s.whatsapp.net");
    assert_eq!(participant.action, "promote");
    assert_eq!(participant.new_role, "ADMIN");

    let Event::NewsletterSettingsUpdate(settings) = events.recv().await.unwrap() else {
        panic!("expected newsletter settings update");
    };
    assert_eq!(settings.len(), 1);
    let setting = &settings[0];
    assert_eq!(setting.id, "abc@newsletter");
    assert_eq!(setting.fields["name"], "Updates");
    assert_eq!(setting.fields["description"], "Daily notes");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert!(batch.messages_update.is_empty());
    let message = &batch.messages_upsert[0];
    assert_eq!(message.key.remote_jid, "abc@newsletter");
    assert_eq!(message.key.id, "server-3");
    assert!(message.key.participant.is_none());
    assert_eq!(message.timestamp, Some(1_700_000_440));
    assert_eq!(message.fields["kind"], "newsletter");
    assert_eq!(message.fields["payload_kind"], "plaintext");
    assert_eq!(message.fields["source"], "newsletter_notification");
    assert_eq!(message.fields["from_me"], "false");
    let decoded = wa_proto::proto::Message::decode(message.payload.clone().unwrap()).unwrap();
    assert_eq!(decoded.conversation.as_deref(), Some("newsletter text"));

    let stored_reaction = store
        .get(
            KeyNamespace::NewsletterReactionEvent,
            &wa_core::newsletter_reaction_event_store_key(reaction),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_reaction =
        wa_core::decode_stored_newsletter_reaction_event(&stored_reaction).unwrap();
    assert_eq!(stored_reaction, *reaction);
    let stored_view = store
        .get(
            KeyNamespace::NewsletterViewEvent,
            &wa_core::newsletter_view_event_store_key(view),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_view = wa_core::decode_stored_newsletter_view_event(&stored_view).unwrap();
    assert_eq!(stored_view, *view);
    let stored_participant = store
        .get(
            KeyNamespace::NewsletterParticipantEvent,
            &wa_core::newsletter_participant_update_event_store_key(participant),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_participant =
        wa_core::decode_stored_newsletter_participant_update_event(&stored_participant).unwrap();
    assert_eq!(stored_participant, *participant);
    let stored_settings = store
        .get(
            KeyNamespace::NewsletterSettingsEvent,
            &wa_core::newsletter_settings_update_event_store_key(setting),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_settings =
        wa_core::decode_stored_newsletter_settings_update_event(&stored_settings).unwrap();
    assert_eq!(stored_settings, *setting);
    let stored_message = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&message.key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message, *message);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_emits_newsletter_mex_admin_promotion_update() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "newsletter-mex-admin")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "mex")
        .with_content(vec![BinaryNode::new("update")
            .with_attr("op_name", "NotificationNewsletterAdminPromote")
            .with_content(
                br#"{"data":{"NotificationNewsletterAdminPromote":{"updates":[{"newsletterId":"abc@newsletter","participant_jid":"333@s.whatsapp.net"}]}}}"#.to_vec(),
            )]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &notification, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "newsletter-mex-admin");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let Event::NewsletterParticipantsUpdate(updates) = events.recv().await.unwrap() else {
        panic!("expected newsletter participant update");
    };
    assert_eq!(
        updates,
        vec![wa_core::NewsletterParticipantUpdateEvent::new(
            "abc@newsletter",
            "server@s.whatsapp.net",
            "333@s.whatsapp.net",
            "promote",
            "ADMIN"
        )]
    );
    let participant = &updates[0];
    let stored = store
        .get(
            KeyNamespace::NewsletterParticipantEvent,
            &wa_core::newsletter_participant_update_event_store_key(participant),
        )
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_newsletter_participant_update_event(&stored).unwrap();
    assert_eq!(stored, *participant);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_media_retry_downloads_pending_media() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-1",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [8u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"live retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/live/old"),
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
        direct_path: Some("/live/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[6u8; 12],
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
        "https://media.test/live/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_media_retry(
            &connection,
            &incoming,
            &IncomingDecryptor,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Receipt);
    assert_eq!(result.inbound.event_count, 2);
    assert_eq!(result.media_retry.downloads.len(), 1);
    assert_eq!(
        result.media_retry.downloads[0].plaintext,
        b"live retried media"
    );
    assert!(result.media_retry.errors.is_empty());
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-1");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    let retry_store_key = wa_core::media_retry_event_store_key(&batch.media_retry[0]);
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_media_retry_loads_persisted_pending_media() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let registering_client = Client::builder(store.clone()).connect().await.unwrap();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-persisted-live",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [10u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"persisted live retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/persisted-live/old"),
    )
    .unwrap();
    registering_client
        .register_pending_media_retry_persisted(
            key.clone(),
            wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    let store_key = wa_core::pending_media_retry_store_key(&key);
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(key.id.clone()),
        direct_path: Some("/persisted-live/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[8u8; 12],
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
        "https://media.test/persisted-live/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_media_retry(
            &connection,
            &incoming,
            &IncomingDecryptor,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.media_retry.downloads.len(), 1);
    assert_eq!(
        result.media_retry.downloads[0].plaintext,
        b"persisted live retried media"
    );
    assert!(result.media_retry.errors.is_empty());
    assert_eq!(result.media_retry.ignored_without_pending, 0);
    assert!(
        client
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
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "msg-persisted-live");
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_media_retry_with_signal_provider_downloads_pending_media() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-signal-media",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [9u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"provider retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/provider/old"),
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
        direct_path: Some("/provider/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[9u8; 12],
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
        "https://media.test/provider/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Receipt);
    assert_eq!(result.inbound.event_count, 2);
    assert_eq!(result.media_retry.downloads.len(), 1);
    assert_eq!(
        result.media_retry.downloads[0].plaintext,
        b"provider retried media"
    );
    assert!(result.media_retry.errors.is_empty());
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-signal-media");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_media_retry_with_signal_provider_preserves_legacy_retry_key() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = wa_core::MessageEventKey::new(
        "123@c.us",
        "msg-signal-media-legacy",
        Some("456@c.us".to_owned()),
    );
    let media_key = [7u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"provider legacy media retry",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/provider-legacy/old"),
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
        direct_path: Some("/provider-legacy/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[5u8; 12],
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
        "https://media.test/provider-legacy/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Receipt);
    assert_eq!(result.inbound.event_count, 2);
    assert_eq!(result.media_retry.downloads.len(), 1);
    assert_eq!(
        result.media_retry.downloads[0].plaintext,
        b"provider legacy media retry"
    );
    assert!(result.media_retry.errors.is_empty());
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-signal-media-legacy");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    assert_eq!(batch.media_retry[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.media_retry[0].key.participant.as_deref(),
        Some("456@c.us")
    );
    let retry_store_key = wa_core::media_retry_event_store_key(&batch.media_retry[0]);
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_media_retry_signal_provider_accepts_same_base_pre_key_wrapper()
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
        "media-retry-direct-same-base",
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
    let first_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("media retry direct same-base first".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        4,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &first_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let first_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-media-retry-direct-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &first_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        first_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(first_result.inbound.event_count, 1);
    assert!(first_result.inbound.error.is_none());
    assert!(first_result.media_retry.is_empty());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-media-retry-direct-same-base-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-media-retry-direct-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("media retry direct same-base first")
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

    let second_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("media retry direct same-base wrapped second".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        5,
    );
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
        .with_attr(
            "id",
            "signal-media-retry-direct-same-base-2-identity-change",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    let changed_identity_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &changed_identity_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        changed_identity_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(changed_identity_result.inbound.event_count, 0);
    assert!(changed_identity_result.media_retry.is_empty());
    assert!(
        changed_identity_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal provider identity changed for 123.0"))
    );
    let changed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(changed_identity_nack.tag, "ack");
    assert_eq!(
        changed_identity_nack.attrs["id"],
        "signal-media-retry-direct-same-base-2-identity-change"
    );
    assert_eq!(changed_identity_nack.attrs["class"], "message");
    assert_eq!(
        changed_identity_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
    let expected_signed_pre_key_error = format!(
        "Signal signed pre-key id mismatch: message {}, local {}",
        receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        receiver_credentials.signed_pre_key.key_id
    );
    let signed_pre_key_mismatch_incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-media-retry-direct-same-base-2-signed-pre-key-mismatch",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    let signed_pre_key_mismatch_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &signed_pre_key_mismatch_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        signed_pre_key_mismatch_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(signed_pre_key_mismatch_result.inbound.event_count, 0);
    assert!(signed_pre_key_mismatch_result.media_retry.is_empty());
    assert!(
        signed_pre_key_mismatch_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains(&expected_signed_pre_key_error))
    );
    let signed_pre_key_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_mismatch_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["id"],
        "signal-media-retry-direct-same-base-2-signed-pre-key-mismatch"
    );
    assert_eq!(signed_pre_key_mismatch_nack.attrs["class"], "message");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
        .with_attr("id", "signal-media-retry-direct-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    let second_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &second_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        second_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(second_result.inbound.event_count, 1);
    assert!(second_result.inbound.error.is_none());
    assert!(second_result.media_retry.is_empty());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(
        second_ack.attrs["id"],
        "signal-media-retry-direct-same-base-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-media-retry-direct-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("media retry direct same-base wrapped second")
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
    let decoded_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second).unwrap();
    assert_eq!(
        decoded_after_second.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        decoded_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    assert!(decoded_after_second.message_keys.is_empty());

    let replay_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-media-retry-direct-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    let replay_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &replay_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        replay_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(replay_result.inbound.event_count, 0);
    assert!(replay_result.media_retry.is_empty());
    assert!(
        replay_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 1"))
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(
        replay_nack.attrs["id"],
        "signal-media-retry-direct-same-base-2-replay"
    );
    assert_eq!(replay_nack.attrs["class"], "message");
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let third_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("media retry direct same-base third".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        6,
    );
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &third_plaintext,
        &sender_identity,
    )
    .unwrap();
    let third_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-media-retry-direct-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    let third_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &third_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        third_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(third_result.inbound.event_count, 1);
    assert!(third_result.inbound.error.is_none());
    assert!(third_result.media_retry.is_empty());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(
        third_ack.attrs["id"],
        "signal-media-retry-direct-same-base-3"
    );
    assert_eq!(third_ack.attrs["class"], "message");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-media-retry-direct-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("media retry direct same-base third")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_media_retry_signal_provider_accepts_new_remote_ratchet() {
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
        "media-retry-direct-new-ratchet",
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
        &text_plaintext("media retry ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("media retry ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("media retry ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let first_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-media-retry-ratchet-1",
                "pkmsg",
                first.message_bytes.clone(),
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        first_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(first_result.inbound.event_count, 1);
    assert!(first_result.inbound.error.is_none());
    assert!(first_result.media_retry.is_empty());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-media-retry-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-media-retry-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("media retry ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver media retry ratchet reply"),
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
        &text_plaintext("media retry ratchet fourth", 7),
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
        &text_plaintext("media retry ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    let fourth_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-media-retry-ratchet-4",
                "msg",
                fourth.message_bytes.clone(),
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        fourth_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(fourth_result.inbound.event_count, 1);
    assert!(fourth_result.inbound.error.is_none());
    assert!(fourth_result.media_retry.is_empty());
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-media-retry-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-media-retry-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("media retry ratchet fourth")
    );
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

    let old_third_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-media-retry-ratchet-old-3",
                "msg",
                old_third.message_bytes.clone(),
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        old_third_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(old_third_result.inbound.event_count, 1);
    assert!(old_third_result.inbound.error.is_none());
    assert!(old_third_result.media_retry.is_empty());
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(
        old_third_ack.attrs["id"],
        "signal-media-retry-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-media-retry-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("media retry ratchet old third")
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

    let old_third_replay_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-media-retry-ratchet-old-3-replay",
                "msg",
                old_third.message_bytes,
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        old_third_replay_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(old_third_replay_result.inbound.event_count, 0);
    assert!(old_third_replay_result.media_retry.is_empty());
    assert!(
        old_third_replay_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains("decryption failed"))
    );
    let old_third_replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_replay_nack.tag, "ack");
    assert_eq!(
        old_third_replay_nack.attrs["id"],
        "signal-media-retry-ratchet-old-3-replay"
    );
    assert_eq!(old_third_replay_nack.attrs["class"], "message");
    assert_eq!(old_third_replay_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        old_third_replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_old_third_bytes
    );

    let second_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming_node("signal-media-retry-ratchet-2", "msg", second.message_bytes),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        second_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(second_result.inbound.event_count, 1);
    assert!(second_result.inbound.error.is_none());
    assert!(second_result.media_retry.is_empty());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-media-retry-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-media-retry-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("media retry ratchet second")
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

    let fifth_result = client
        .process_incoming_node_with_media_retry_with_signal_provider(
            &connection,
            &incoming_node("signal-media-retry-ratchet-5", "msg", fifth.message_bytes),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        fifth_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(fifth_result.inbound.event_count, 1);
    assert!(fifth_result.inbound.error.is_none());
    assert!(fifth_result.media_retry.is_empty());
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-media-retry-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-media-retry-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("media retry ratchet fifth")
    );
    let record_after_fifth = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_placeholder_retry_media_and_signal_provider_downloads_pending_media()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-combined-direct",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [8u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"direct combined retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/combined-direct/old"),
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
        direct_path: Some("/combined-direct/new".to_owned()),
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
        "https://media.test/combined-direct/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Receipt);
    assert_eq!(result.inbound.event_count, 2);
    assert!(result.placeholder_resend.is_none());
    assert!(result.retry_resend.is_none());
    assert_eq!(result.media_retry.downloads.len(), 1);
    assert_eq!(
        result.media_retry.downloads[0].plaintext,
        b"direct combined retried media"
    );
    assert!(result.media_retry.errors.is_empty());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-combined-direct");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_placeholder_retry_media_and_signal_provider_normalizes_legacy_retry_receipt()
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
    let remote_one_time_pre_key_id = 94;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-direct-combined-signal-legacy",
            wa_proto::proto::Message {
                conversation: Some("direct combined legacy retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-direct-combined-signal-legacy")
        .with_attr("from", "123:1@c.us")
        .with_attr("recipient", "123@c.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0307, 4).unwrap()),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &receipt,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("direct combined retry processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-direct-combined-signal-legacy");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![(
                    "123:1@s.whatsapp.net".to_owned(),
                    Some("identity".to_owned())
                )]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;

    let result = process_fut.await.unwrap();
    assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Receipt);
    assert_eq!(result.inbound.event_count, 1);
    assert!(result.placeholder_resend.is_none());
    assert!(result.media_retry.is_empty());
    let retry = result
        .retry_resend
        .as_ref()
        .expect("legacy retry receipt should replay cached message");
    assert_eq!(retry.plan.remote_jid, "123@s.whatsapp.net");
    assert_eq!(retry.plan.participant_jid, "123:1@s.whatsapp.net");
    assert_eq!(retry.relays.len(), 1);

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-direct-combined-signal-legacy");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "direct combined legacy retry",
    );
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_placeholder_retry_media_and_signal_provider_deduplicates_own_pn_lid_all_devices()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 128;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-combined-signal-own-alias-all-devices",
            wa_proto::proto::Message {
                conversation: Some("combined signal own alias retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-combined-signal-own-alias-all-devices")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![BinaryNode::new("retry").with_attr("count", "1")]);
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &receipt,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("direct combined own-alias retry completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "retry-combined-signal-own-alias-all-devices"
    );
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), Some("identity".to_owned()))]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "123@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                    "ownlid@lid".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "999@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "7"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "ownlid@lid")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "17"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "18"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut process_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("999:8@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;

    let result = process_fut.await.unwrap();
    assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Receipt);
    assert_eq!(result.inbound.event_count, 1);
    assert!(result.placeholder_resend.is_none());
    assert!(result.media_retry.is_empty());
    let retry = result
        .retry_resend
        .as_ref()
        .expect("all-device retry receipt should replay cached message");
    assert_eq!(retry.plan.remote_jid, "123@s.whatsapp.net");
    assert_eq!(retry.plan.participant_jid, "123@s.whatsapp.net");
    assert_eq!(
        retry.plan.resend_target,
        wa_core::RetryResendTarget::AllDevices
    );
    assert!(retry.session_action.refreshed_sessions);
    assert_eq!(retry.relays.len(), 1);
    assert_eq!(
        retry.relays[0].message_id,
        "retry-combined-signal-own-alias-all-devices"
    );
    assert_eq!(retry.relays[0].recipient_count, 2);

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(
        resent.attrs["id"],
        "retry-combined-signal-own-alias-all-devices"
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
                Some("combined signal own alias retry")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.conversation.as_deref(),
                Some("combined signal own alias retry")
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
    let prepared_after_success = client
        .prepare_retry_resends(&retry.plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_success.jobs.is_empty());
    assert_eq!(
        prepared_after_success.missing_message_ids,
        vec!["retry-combined-signal-own-alias-all-devices"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_placeholder_retry_media_and_signal_provider_preserves_legacy_missing_key()
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
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let mut events = client.subscribe();
    let placeholder = BinaryNode::new("message")
        .with_attr("id", "missing-direct-combined-signal-legacy")
        .with_attr("from", "123@c.us")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key = wa_core::build_message_key(
        "123@c.us",
        false,
        "missing-direct-combined-signal-legacy",
        None,
    )
    .unwrap();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &placeholder,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("direct combined placeholder processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-direct-combined-signal-legacy");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@c.us");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "missing-direct-combined-signal-legacy"
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
        .expect("direct combined placeholder event should be persisted");
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);

    let usync_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("direct combined placeholder processing completed before USync query: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let usync_query = decode_inbound_binary_node(&usync_frame).unwrap().node;
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

    let encrypt_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("direct combined placeholder processing completed before encrypt query: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let encrypt_query = decode_inbound_binary_node(&encrypt_frame).unwrap().node;
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

    let result = tokio::time::timeout(Duration::from_secs(1), &mut process_fut)
        .await
        .expect("direct combined placeholder processing should complete after session response")
        .unwrap();
    assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.inbound.event_count, 1);
    assert!(result.placeholder_resend.is_some());
    assert!(result.retry_resend.is_none());
    assert!(result.media_retry.is_empty());

    let sent = decode_inbound_binary_node(
        &tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
            .await
            .expect("direct combined placeholder relay should be sent")
            .unwrap(),
    )
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
                "missing-direct-combined-signal-legacy",
                current_unix_timestamp_ms()
            )
            .unwrap()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_placeholder_retry_media_and_signal_provider_accepts_same_base_pre_key_wrapper()
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
        "combined-direct-same-base",
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
    let first_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("combined direct same-base first".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        4,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &first_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let first_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-combined-direct-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &first_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        first_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(first_result.inbound.event_count, 1);
    assert!(first_result.inbound.error.is_none());
    assert!(first_result.placeholder_resend.is_none());
    assert!(first_result.retry_resend.is_none());
    assert!(first_result.media_retry.is_empty());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-combined-direct-same-base-1");
    assert_eq!(first_ack.attrs["class"], "message");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-combined-direct-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("combined direct same-base first")
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

    let second_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("combined direct same-base wrapped second".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        5,
    );
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
        .with_attr("id", "signal-combined-direct-same-base-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    let changed_identity_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &changed_identity_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        changed_identity_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(changed_identity_result.inbound.event_count, 0);
    assert!(changed_identity_result.placeholder_resend.is_none());
    assert!(changed_identity_result.retry_resend.is_none());
    assert!(changed_identity_result.media_retry.is_empty());
    assert!(
        changed_identity_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal provider identity changed for 123.0"))
    );
    let changed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(changed_identity_nack.tag, "ack");
    assert_eq!(
        changed_identity_nack.attrs["id"],
        "signal-combined-direct-same-base-2-identity-change"
    );
    assert_eq!(changed_identity_nack.attrs["class"], "message");
    assert_eq!(
        changed_identity_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
    let expected_signed_pre_key_error = format!(
        "Signal signed pre-key id mismatch: message {}, local {}",
        receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        receiver_credentials.signed_pre_key.key_id
    );
    let signed_pre_key_mismatch_incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-combined-direct-same-base-2-signed-pre-key-mismatch",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    let signed_pre_key_mismatch_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &signed_pre_key_mismatch_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        signed_pre_key_mismatch_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(signed_pre_key_mismatch_result.inbound.event_count, 0);
    assert!(signed_pre_key_mismatch_result.placeholder_resend.is_none());
    assert!(signed_pre_key_mismatch_result.retry_resend.is_none());
    assert!(signed_pre_key_mismatch_result.media_retry.is_empty());
    assert!(
        signed_pre_key_mismatch_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains(&expected_signed_pre_key_error))
    );
    let signed_pre_key_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_mismatch_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["id"],
        "signal-combined-direct-same-base-2-signed-pre-key-mismatch"
    );
    assert_eq!(signed_pre_key_mismatch_nack.attrs["class"], "message");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
        .with_attr("id", "signal-combined-direct-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    let second_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &second_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        second_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(second_result.inbound.event_count, 1);
    assert!(second_result.inbound.error.is_none());
    assert!(second_result.placeholder_resend.is_none());
    assert!(second_result.retry_resend.is_none());
    assert!(second_result.media_retry.is_empty());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-combined-direct-same-base-2");
    assert_eq!(second_ack.attrs["class"], "message");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-combined-direct-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("combined direct same-base wrapped second")
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
    let decoded_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second).unwrap();
    assert_eq!(
        decoded_after_second.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        decoded_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    assert!(decoded_after_second.message_keys.is_empty());

    let replay_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-combined-direct-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    let replay_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &replay_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        replay_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(replay_result.inbound.event_count, 0);
    assert!(replay_result.placeholder_resend.is_none());
    assert!(replay_result.retry_resend.is_none());
    assert!(replay_result.media_retry.is_empty());
    assert!(
        replay_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 1"))
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(
        replay_nack.attrs["id"],
        "signal-combined-direct-same-base-2-replay"
    );
    assert_eq!(replay_nack.attrs["class"], "message");
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let third_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("combined direct same-base third".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        6,
    );
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &third_plaintext,
        &sender_identity,
    )
    .unwrap();
    let third_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-combined-direct-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    let third_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &third_incoming,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        third_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(third_result.inbound.event_count, 1);
    assert!(third_result.inbound.error.is_none());
    assert!(third_result.placeholder_resend.is_none());
    assert!(third_result.retry_resend.is_none());
    assert!(third_result.media_retry.is_empty());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-combined-direct-same-base-3");
    assert_eq!(third_ack.attrs["class"], "message");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-combined-direct-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("combined direct same-base third")
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
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        0
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_placeholder_retry_media_signal_provider_accepts_new_remote_ratchet()
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
        "combined-direct-new-ratchet",
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
        &text_plaintext("combined ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("combined ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("combined ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let first_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-combined-ratchet-1",
                "pkmsg",
                first.message_bytes.clone(),
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        first_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(first_result.inbound.event_count, 1);
    assert!(first_result.inbound.error.is_none());
    assert!(first_result.placeholder_resend.is_none());
    assert!(first_result.retry_resend.is_none());
    assert!(first_result.media_retry.is_empty());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-combined-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-combined-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("combined ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver combined ratchet reply"),
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
        &text_plaintext("combined ratchet fourth", 7),
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
        &text_plaintext("combined ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    let fourth_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-combined-ratchet-4",
                "msg",
                fourth.message_bytes.clone(),
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        fourth_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(fourth_result.inbound.event_count, 1);
    assert!(fourth_result.inbound.error.is_none());
    assert!(fourth_result.placeholder_resend.is_none());
    assert!(fourth_result.retry_resend.is_none());
    assert!(fourth_result.media_retry.is_empty());
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-combined-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-combined-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("combined ratchet fourth")
    );
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

    let old_third_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-combined-ratchet-old-3",
                "msg",
                old_third.message_bytes.clone(),
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        old_third_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(old_third_result.inbound.event_count, 1);
    assert!(old_third_result.inbound.error.is_none());
    assert!(old_third_result.placeholder_resend.is_none());
    assert!(old_third_result.retry_resend.is_none());
    assert!(old_third_result.media_retry.is_empty());
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(old_third_ack.attrs["id"], "signal-combined-ratchet-old-3");
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-combined-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("combined ratchet old third")
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

    let old_third_replay_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-combined-ratchet-old-3-replay",
                "msg",
                old_third.message_bytes,
            ),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        old_third_replay_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(old_third_replay_result.inbound.event_count, 0);
    assert!(old_third_replay_result.placeholder_resend.is_none());
    assert!(old_third_replay_result.retry_resend.is_none());
    assert!(old_third_replay_result.media_retry.is_empty());
    assert!(
        old_third_replay_result
            .inbound
            .error
            .as_deref()
            .is_some_and(|error| error.contains("decryption failed"))
    );
    let old_third_replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_replay_nack.tag, "ack");
    assert_eq!(
        old_third_replay_nack.attrs["id"],
        "signal-combined-ratchet-old-3-replay"
    );
    assert_eq!(old_third_replay_nack.attrs["class"], "message");
    assert_eq!(old_third_replay_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        old_third_replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_old_third_bytes
    );

    let second_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &incoming_node("signal-combined-ratchet-2", "msg", second.message_bytes),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        second_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(second_result.inbound.event_count, 1);
    assert!(second_result.inbound.error.is_none());
    assert!(second_result.placeholder_resend.is_none());
    assert!(second_result.retry_resend.is_none());
    assert!(second_result.media_retry.is_empty());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-combined-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-combined-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("combined ratchet second")
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

    let fifth_result = client
        .process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &incoming_node("signal-combined-ratchet-5", "msg", fifth.message_bytes),
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(
        fifth_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(fifth_result.inbound.event_count, 1);
    assert!(fifth_result.inbound.error.is_none());
    assert!(fifth_result.placeholder_resend.is_none());
    assert!(fifth_result.retry_resend.is_none());
    assert!(fifth_result.media_retry.is_empty());
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-combined-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-combined-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("combined ratchet fifth")
    );
    let record_after_fifth = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_downloads_pending_media()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-offline-combined",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [10u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"offline combined retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/offline-combined/old"),
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
        direct_path: Some("/offline-combined/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[8u8; 12],
    )
    .unwrap();
    let receipt = BinaryNode::new("receipt")
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
    let offline = BinaryNode::new("offline").with_content(vec![receipt]);
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/offline-combined/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 2);
    assert!(result.placeholder_resends.is_empty());
    assert!(result.retry_resends.is_empty());
    assert_eq!(result.media_retry.downloads.len(), 1);
    assert_eq!(
        result.media_retry.downloads[0].plaintext,
        b"offline combined retried media"
    );
    assert!(result.media_retry.errors.is_empty());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-offline-combined");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_emits_group_notification_append_stub()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "combined-offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000180")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 2);
    assert_eq!(
        result.offline.results[0].action,
        wa_core::InboundNodeAction::Notification
    );
    assert!(result.offline.results[0].error.is_none());
    assert!(result.placeholder_resends.is_empty());
    assert!(result.retry_resends.is_empty());
    assert!(result.media_retry.is_empty());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "combined-offline-group-ephemeral-stub");
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
        "combined-offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000180");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "combined-offline-group-ephemeral-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_180));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_emits_group_participant_add_append_stub()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "combined-offline-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000280")
        .with_attr("offline", "1")
        .with_content(vec![BinaryNode::new("add").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
        ])]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 2);
    assert_eq!(
        result.offline.results[0].action,
        wa_core::InboundNodeAction::Notification
    );
    assert!(result.offline.results[0].error.is_none());
    assert!(result.placeholder_resends.is_empty());
    assert!(result.retry_resends.is_empty());
    assert!(result.media_retry.is_empty());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "combined-offline-group-participant-add-stub"
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
        "combined-offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000280");
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
    assert_eq!(stub.key.id, "combined-offline-group-participant-add-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_280));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_preserves_legacy_retry_key()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = wa_core::MessageEventKey::new(
        "123@c.us",
        "msg-offline-combined-legacy",
        Some("456@c.us".to_owned()),
    );
    let media_key = [11u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"offline legacy retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/offline-legacy/old"),
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
        direct_path: Some("/offline-legacy/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[3u8; 12],
    )
    .unwrap();
    let receipt = BinaryNode::new("receipt")
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
    let offline = BinaryNode::new("offline").with_content(vec![receipt]);
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/offline-legacy/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();

    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 2);
    assert!(result.placeholder_resends.is_empty());
    assert!(result.retry_resends.is_empty());
    assert_eq!(result.media_retry.downloads.len(), 1);
    assert_eq!(
        result.media_retry.downloads[0].plaintext,
        b"offline legacy retried media"
    );
    assert!(result.media_retry.errors.is_empty());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-offline-combined-legacy");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    assert_eq!(batch.media_retry[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.media_retry[0].key.participant.as_deref(),
        Some("456@c.us")
    );
    let retry_store_key = wa_core::media_retry_event_store_key(&batch.media_retry[0]);
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_replays_retry() {
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
    let remote_one_time_pre_key_id = 97;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-offline-combined",
            wa_proto::proto::Message {
                conversation: Some("offline combined retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-offline-combined")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![receipt]);
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline retry processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-offline-combined");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![(
                    "123:1@s.whatsapp.net".to_owned(),
                    Some("identity".to_owned())
                )]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;

    let result = process_fut.await.unwrap();
    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 1);
    assert!(result.placeholder_resends.is_empty());
    assert_eq!(result.retry_resends.len(), 1);
    assert_eq!(result.retry_resends[0].relays.len(), 1);
    assert!(result.media_retry.is_empty());

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-offline-combined");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "offline combined retry",
    );
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_deduplicates_own_pn_lid_all_devices()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 129;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-offline-combined-own-alias-all-devices",
            wa_proto::proto::Message {
                conversation: Some("offline combined own alias retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-offline-combined-own-alias-all-devices")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![BinaryNode::new("retry").with_attr("count", "1")]);
    let offline = BinaryNode::new("offline").with_content(vec![receipt]);
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline own-alias retry processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs["id"],
        "retry-offline-combined-own-alias-all-devices"
    );
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), Some("identity".to_owned()))]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "123@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                    "ownlid@lid".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "999@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "7"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "ownlid@lid")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "17"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "18"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut process_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("999:8@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;

    let result = process_fut.await.unwrap();
    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 1);
    assert!(result.placeholder_resends.is_empty());
    assert_eq!(result.retry_resends.len(), 1);
    assert!(result.media_retry.is_empty());
    let retry = &result.retry_resends[0];
    assert_eq!(retry.plan.remote_jid, "123@s.whatsapp.net");
    assert_eq!(retry.plan.participant_jid, "123@s.whatsapp.net");
    assert_eq!(
        retry.plan.resend_target,
        wa_core::RetryResendTarget::AllDevices
    );
    assert!(retry.session_action.refreshed_sessions);
    assert_eq!(retry.relays.len(), 1);
    assert_eq!(
        retry.relays[0].message_id,
        "retry-offline-combined-own-alias-all-devices"
    );
    assert_eq!(retry.relays[0].recipient_count, 2);

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(
        resent.attrs["id"],
        "retry-offline-combined-own-alias-all-devices"
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
                Some("offline combined own alias retry")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.conversation.as_deref(),
                Some("offline combined own alias retry")
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
    let prepared_after_success = client
        .prepare_retry_resends(&retry.plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_success.jobs.is_empty());
    assert_eq!(
        prepared_after_success.missing_message_ids,
        vec!["retry-offline-combined-own-alias-all-devices"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_normalizes_legacy_retry_receipt()
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
    let remote_one_time_pre_key_id = 93;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-offline-combined-legacy",
            wa_proto::proto::Message {
                conversation: Some("offline combined legacy retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-offline-combined-legacy")
        .with_attr("from", "123:1@c.us")
        .with_attr("recipient", "123@c.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0308, 4).unwrap()),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![receipt]);
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline legacy retry processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-offline-combined-legacy");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![(
                    "123:1@s.whatsapp.net".to_owned(),
                    Some("identity".to_owned())
                )]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut process_fut,
    )
    .await;

    let result = process_fut.await.unwrap();
    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 1);
    assert!(result.placeholder_resends.is_empty());
    assert_eq!(result.retry_resends.len(), 1);
    assert_eq!(
        result.retry_resends[0].plan.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(
        result.retry_resends[0].plan.participant_jid,
        "123:1@s.whatsapp.net"
    );
    assert_eq!(result.retry_resends[0].relays.len(), 1);
    assert!(result.media_retry.is_empty());

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-offline-combined-legacy");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "offline combined legacy retry",
    );
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_requests_stub() {
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
    let remote_one_time_pre_key_id = 96;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let mut events = client.subscribe();
    let placeholder = BinaryNode::new("message")
        .with_attr("id", "missing-offline-signal")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![placeholder]);
    let expected_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "missing-offline-signal", None)
            .unwrap();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline placeholder processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-offline-signal");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "missing-offline-signal");
    assert_eq!(
        batch.messages_upsert[0].fields["kind"],
        "placeholder_unavailable"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["unavailable_type"],
        "temporary_unavailable"
    );

    let usync_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline placeholder processing completed before USync query: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let usync_query = decode_inbound_binary_node(&usync_frame).unwrap().node;
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

    let encrypt_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline placeholder processing completed before encrypt query: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let encrypt_query = decode_inbound_binary_node(&encrypt_frame).unwrap().node;
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

    let result = tokio::time::timeout(Duration::from_secs(1), &mut process_fut)
        .await
        .expect("offline placeholder processing should complete after session response")
        .unwrap();
    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 1);
    assert_eq!(result.placeholder_resends.len(), 1);
    assert!(result.retry_resends.is_empty());
    assert!(result.media_retry.is_empty());

    let sent = decode_inbound_binary_node(
        &tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
            .await
            .expect("offline placeholder relay should be sent")
            .unwrap(),
    )
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
            .contains("missing-offline-signal", current_unix_timestamp_ms())
            .unwrap()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_preserves_legacy_missing_key()
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
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let mut events = client.subscribe();
    let placeholder = BinaryNode::new("message")
        .with_attr("id", "missing-offline-signal-legacy")
        .with_attr("from", "123@c.us")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![placeholder]);
    let expected_key =
        wa_core::build_message_key("123@c.us", false, "missing-offline-signal-legacy", None)
            .unwrap();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &offline,
            &mut buffer,
            &transfer,
        );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline placeholder processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-offline-signal-legacy");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@c.us");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "missing-offline-signal-legacy"
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
        .expect("offline placeholder event should be persisted");
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);

    let usync_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline placeholder processing completed before USync query: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let usync_query = decode_inbound_binary_node(&usync_frame).unwrap().node;
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

    let encrypt_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("offline placeholder processing completed before encrypt query: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let encrypt_query = decode_inbound_binary_node(&encrypt_frame).unwrap().node;
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

    let result = tokio::time::timeout(Duration::from_secs(1), &mut process_fut)
        .await
        .expect("offline placeholder processing should complete after session response")
        .unwrap();
    assert_eq!(result.offline.child_count, 1);
    assert_eq!(result.offline.response_count(), 1);
    assert_eq!(result.offline.event_count(), 1);
    assert_eq!(result.placeholder_resends.len(), 1);
    assert!(result.retry_resends.is_empty());
    assert!(result.media_retry.is_empty());

    let sent = decode_inbound_binary_node(
        &tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
            .await
            .expect("offline placeholder relay should be sent")
            .unwrap(),
    )
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
            .contains("missing-offline-signal-legacy", current_unix_timestamp_ms())
            .unwrap()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_accepts_same_base_pre_key_wrapper()
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
        "offline-combined-same-base",
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
    let first_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline combined same-base first".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        7,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &first_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let first_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-combined-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_offline = BinaryNode::new("offline").with_content(vec![first_child]);
    let first_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &first_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(first_result.offline.child_count, 1);
    assert_eq!(first_result.offline.response_count(), 1);
    assert_eq!(first_result.offline.event_count(), 1);
    assert!(first_result.offline.results[0].error.is_none());
    assert!(first_result.placeholder_resends.is_empty());
    assert!(first_result.retry_resends.is_empty());
    assert!(first_result.media_retry.is_empty());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-offline-combined-same-base-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-offline-combined-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("offline combined same-base first")
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

    let second_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline combined same-base wrapped second".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        8,
    );
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
    let changed_identity_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-combined-same-base-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    let changed_identity_offline =
        BinaryNode::new("offline").with_content(vec![changed_identity_child]);
    let changed_identity_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &changed_identity_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(changed_identity_result.offline.child_count, 1);
    assert_eq!(changed_identity_result.offline.response_count(), 1);
    assert_eq!(changed_identity_result.offline.event_count(), 0);
    assert!(changed_identity_result.placeholder_resends.is_empty());
    assert!(changed_identity_result.retry_resends.is_empty());
    assert!(changed_identity_result.media_retry.is_empty());
    assert!(
        changed_identity_result.offline.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal provider identity changed for 123.0"))
    );
    let changed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(changed_identity_nack.tag, "ack");
    assert_eq!(
        changed_identity_nack.attrs["id"],
        "signal-offline-combined-same-base-2-identity-change"
    );
    assert_eq!(changed_identity_nack.attrs["class"], "message");
    assert_eq!(changed_identity_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(changed_identity_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        changed_identity_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
    let expected_signed_pre_key_error = format!(
        "Signal signed pre-key id mismatch: message {}, local {}",
        receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        receiver_credentials.signed_pre_key.key_id
    );
    let signed_pre_key_mismatch_child = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-offline-combined-same-base-2-signed-pre-key-mismatch",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    let signed_pre_key_mismatch_offline =
        BinaryNode::new("offline").with_content(vec![signed_pre_key_mismatch_child]);
    let signed_pre_key_mismatch_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &signed_pre_key_mismatch_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(signed_pre_key_mismatch_result.offline.child_count, 1);
    assert_eq!(signed_pre_key_mismatch_result.offline.response_count(), 1);
    assert_eq!(signed_pre_key_mismatch_result.offline.event_count(), 0);
    assert!(
        signed_pre_key_mismatch_result
            .placeholder_resends
            .is_empty()
    );
    assert!(signed_pre_key_mismatch_result.retry_resends.is_empty());
    assert!(signed_pre_key_mismatch_result.media_retry.is_empty());
    assert!(
        signed_pre_key_mismatch_result.offline.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains(&expected_signed_pre_key_error))
    );
    let signed_pre_key_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_mismatch_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["id"],
        "signal-offline-combined-same-base-2-signed-pre-key-mismatch"
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
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        0
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
    let second_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-combined-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    let second_offline = BinaryNode::new("offline").with_content(vec![second_child]);
    let second_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &second_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(second_result.offline.child_count, 1);
    assert_eq!(second_result.offline.response_count(), 1);
    assert_eq!(second_result.offline.event_count(), 1);
    assert!(second_result.offline.results[0].error.is_none());
    assert!(second_result.placeholder_resends.is_empty());
    assert!(second_result.retry_resends.is_empty());
    assert!(second_result.media_retry.is_empty());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(
        second_ack.attrs["id"],
        "signal-offline-combined-same-base-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-offline-combined-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("offline combined same-base wrapped second")
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
    let decoded_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second).unwrap();
    assert_eq!(
        decoded_after_second.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        decoded_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    assert!(decoded_after_second.message_keys.is_empty());

    let replay_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-combined-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    let replay_offline = BinaryNode::new("offline").with_content(vec![replay_child]);
    let replay_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &replay_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(replay_result.offline.child_count, 1);
    assert_eq!(replay_result.offline.response_count(), 1);
    assert_eq!(replay_result.offline.event_count(), 0);
    assert!(replay_result.placeholder_resends.is_empty());
    assert!(replay_result.retry_resends.is_empty());
    assert!(replay_result.media_retry.is_empty());
    assert!(
        replay_result.offline.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 1"))
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(
        replay_nack.attrs["id"],
        "signal-offline-combined-same-base-2-replay"
    );
    assert_eq!(replay_nack.attrs["class"], "message");
    assert_eq!(replay_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let third_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline combined same-base third".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        9,
    );
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &third_plaintext,
        &sender_identity,
    )
    .unwrap();
    let third_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-combined-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    let third_offline = BinaryNode::new("offline").with_content(vec![third_child]);
    let third_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &third_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(third_result.offline.child_count, 1);
    assert_eq!(third_result.offline.response_count(), 1);
    assert_eq!(third_result.offline.event_count(), 1);
    assert!(third_result.offline.results[0].error.is_none());
    assert!(third_result.placeholder_resends.is_empty());
    assert!(third_result.retry_resends.is_empty());
    assert!(third_result.media_retry.is_empty());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-offline-combined-same-base-3");
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-offline-combined-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("offline combined same-base third")
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
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        0
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_rejects_missing_one_time_pre_key() {
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
        "offline-missing-pre-key",
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
                conversation: Some("offline missing pre-key".to_owned()),
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
    assert!(
        client
            .signal_provider_state_store()
            .consume_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_some()
    );

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-offline-missing-pre-key")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![incoming]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_signal_provider(&connection, &offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.event_count(), 0);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains(&format!(
                "missing local Signal one-time pre-key {receiver_pre_key_id}"
            )))
    );
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-offline-missing-pre-key");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_signal_provider_accepts_same_base_pre_key_wrapper() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "offline-same-base")
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
    let first_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline same-base first".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        7,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &first_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let first_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_offline = BinaryNode::new("offline").with_content(vec![first_child]);
    let first_result = client
        .process_offline_node_with_signal_provider(&connection, &first_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(first_result.child_count, 1);
    assert_eq!(first_result.response_count(), 1);
    assert_eq!(first_result.event_count(), 1);
    assert_eq!(first_result.yielded_count, 0);
    assert!(first_result.results[0].error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-offline-same-base-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-offline-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("offline same-base first")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .is_none()
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

    let second_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline same-base wrapped second".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        8,
    );
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
    let changed_identity_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-same-base-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    let changed_identity_offline =
        BinaryNode::new("offline").with_content(vec![changed_identity_child]);
    let changed_identity_result = client
        .process_offline_node_with_signal_provider(
            &connection,
            &changed_identity_offline,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(changed_identity_result.child_count, 1);
    assert_eq!(changed_identity_result.response_count(), 1);
    assert_eq!(changed_identity_result.event_count(), 0);
    assert!(
        changed_identity_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal provider identity changed for 123.0"))
    );
    let changed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(changed_identity_nack.tag, "ack");
    assert_eq!(
        changed_identity_nack.attrs["id"],
        "signal-offline-same-base-2-identity-change"
    );
    assert_eq!(changed_identity_nack.attrs["class"], "message");
    assert_eq!(
        changed_identity_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
    let expected_signed_pre_key_error = format!(
        "Signal signed pre-key id mismatch: message {}, local {}",
        receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        receiver_credentials.signed_pre_key.key_id
    );
    let signed_pre_key_mismatch_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-same-base-2-signed-pre-key-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    let signed_pre_key_mismatch_offline =
        BinaryNode::new("offline").with_content(vec![signed_pre_key_mismatch_child]);
    let signed_pre_key_mismatch_result = client
        .process_offline_node_with_signal_provider(
            &connection,
            &signed_pre_key_mismatch_offline,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(signed_pre_key_mismatch_result.child_count, 1);
    assert_eq!(signed_pre_key_mismatch_result.response_count(), 1);
    assert_eq!(signed_pre_key_mismatch_result.event_count(), 0);
    assert!(
        signed_pre_key_mismatch_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains(&expected_signed_pre_key_error))
    );
    let signed_pre_key_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_mismatch_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["id"],
        "signal-offline-same-base-2-signed-pre-key-mismatch"
    );
    assert_eq!(signed_pre_key_mismatch_nack.attrs["class"], "message");
    assert_eq!(
        signed_pre_key_mismatch_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
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
    let second_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    let second_offline = BinaryNode::new("offline").with_content(vec![second_child]);
    let second_result = client
        .process_offline_node_with_signal_provider(&connection, &second_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(second_result.child_count, 1);
    assert_eq!(second_result.response_count(), 1);
    assert_eq!(second_result.event_count(), 1);
    assert_eq!(second_result.yielded_count, 0);
    assert!(second_result.results[0].error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-offline-same-base-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-offline-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("offline same-base wrapped second")
    );
    let record_after_second = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(record_after_second, record_after_first);
    let decoded_after_second =
        wa_core::decode_signal_provider_session_record(&record_after_second).unwrap();
    assert_eq!(
        decoded_after_second.remote_ratchet_key,
        Some(second.message.ephemeral_key.clone())
    );
    assert_eq!(
        decoded_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
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

    let replay_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    let replay_offline = BinaryNode::new("offline").with_content(vec![replay_child]);
    let replay_result = client
        .process_offline_node_with_signal_provider(&connection, &replay_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(replay_result.child_count, 1);
    assert_eq!(replay_result.response_count(), 1);
    assert_eq!(replay_result.event_count(), 0);
    assert!(
        replay_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 1"))
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(replay_nack.attrs["id"], "signal-offline-same-base-2-replay");
    assert_eq!(replay_nack.attrs["class"], "message");
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let third_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline same-base third".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        9,
    );
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &third_plaintext,
        &sender_identity,
    )
    .unwrap();
    let third_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    let third_offline = BinaryNode::new("offline").with_content(vec![third_child]);
    let third_result = client
        .process_offline_node_with_signal_provider(&connection, &third_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(third_result.child_count, 1);
    assert_eq!(third_result.response_count(), 1);
    assert_eq!(third_result.event_count(), 1);
    assert_eq!(third_result.yielded_count, 0);
    assert!(third_result.results[0].error.is_none());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-offline-same-base-3");
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-offline-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("offline same-base third")
    );
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_placeholder_retry_media_and_signal_provider_accepts_new_remote_ratchet()
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
        "offline-combined-new-ratchet",
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
    let offline_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("offline").with_content(vec![
            BinaryNode::new("message")
                .with_attr("id", id)
                .with_attr("from", "123@s.whatsapp.net")
                .with_attr("type", "text")
                .with_content(vec![
                    BinaryNode::new("enc")
                        .with_attr("type", enc_type)
                        .with_content(ciphertext),
                ]),
        ])
    };

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("offline combined ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("offline combined ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("offline combined ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let first_offline = offline_node(
        "signal-offline-combined-ratchet-1",
        "pkmsg",
        first.message_bytes.clone(),
    );
    let first_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &first_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(first_result.offline.child_count, 1);
    assert_eq!(first_result.offline.response_count(), 1);
    assert_eq!(first_result.offline.event_count(), 1);
    assert_eq!(first_result.offline.yielded_count, 0);
    assert_eq!(
        first_result.offline.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(first_result.offline.results[0].error.is_none());
    assert!(first_result.placeholder_resends.is_empty());
    assert!(first_result.retry_resends.is_empty());
    assert!(first_result.media_retry.is_empty());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-offline-combined-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-offline-combined-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("offline combined ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver offline combined ratchet reply"),
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
        &text_plaintext("offline combined ratchet fourth", 7),
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
        &text_plaintext("offline combined ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    let fourth_offline = offline_node(
        "signal-offline-combined-ratchet-4",
        "msg",
        fourth.message_bytes.clone(),
    );
    let fourth_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &fourth_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(fourth_result.offline.child_count, 1);
    assert_eq!(fourth_result.offline.response_count(), 1);
    assert_eq!(fourth_result.offline.event_count(), 1);
    assert_eq!(fourth_result.offline.yielded_count, 0);
    assert_eq!(
        fourth_result.offline.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(fourth_result.offline.results[0].error.is_none());
    assert!(fourth_result.placeholder_resends.is_empty());
    assert!(fourth_result.retry_resends.is_empty());
    assert!(fourth_result.media_retry.is_empty());
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-offline-combined-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-offline-combined-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("offline combined ratchet fourth")
    );
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

    let old_third_offline = offline_node(
        "signal-offline-combined-ratchet-old-3",
        "msg",
        old_third.message_bytes.clone(),
    );
    let old_third_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &old_third_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(old_third_result.offline.child_count, 1);
    assert_eq!(old_third_result.offline.response_count(), 1);
    assert_eq!(old_third_result.offline.event_count(), 1);
    assert_eq!(old_third_result.offline.yielded_count, 0);
    assert_eq!(
        old_third_result.offline.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(old_third_result.offline.results[0].error.is_none());
    assert!(old_third_result.placeholder_resends.is_empty());
    assert!(old_third_result.retry_resends.is_empty());
    assert!(old_third_result.media_retry.is_empty());
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(
        old_third_ack.attrs["id"],
        "signal-offline-combined-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-offline-combined-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("offline combined ratchet old third")
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

    let old_third_replay_offline = offline_node(
        "signal-offline-combined-ratchet-old-3-replay",
        "msg",
        old_third.message_bytes,
    );
    let old_third_replay_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &old_third_replay_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(old_third_replay_result.offline.child_count, 1);
    assert_eq!(old_third_replay_result.offline.response_count(), 1);
    assert_eq!(old_third_replay_result.offline.event_count(), 0);
    assert_eq!(old_third_replay_result.offline.yielded_count, 0);
    assert_eq!(
        old_third_replay_result.offline.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        old_third_replay_result.offline.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("decryption failed"))
    );
    assert!(old_third_replay_result.placeholder_resends.is_empty());
    assert!(old_third_replay_result.retry_resends.is_empty());
    assert!(old_third_replay_result.media_retry.is_empty());
    let old_third_replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_replay_nack.tag, "ack");
    assert_eq!(
        old_third_replay_nack.attrs["id"],
        "signal-offline-combined-ratchet-old-3-replay"
    );
    assert_eq!(old_third_replay_nack.attrs["class"], "message");
    assert_eq!(old_third_replay_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        old_third_replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_old_third_bytes
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    let second_offline = offline_node(
        "signal-offline-combined-ratchet-2",
        "msg",
        second.message_bytes,
    );
    let second_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &second_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(second_result.offline.child_count, 1);
    assert_eq!(second_result.offline.response_count(), 1);
    assert_eq!(second_result.offline.event_count(), 1);
    assert_eq!(second_result.offline.yielded_count, 0);
    assert_eq!(
        second_result.offline.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(second_result.offline.results[0].error.is_none());
    assert!(second_result.placeholder_resends.is_empty());
    assert!(second_result.retry_resends.is_empty());
    assert!(second_result.media_retry.is_empty());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-offline-combined-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-offline-combined-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("offline combined ratchet second")
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

    let fifth_offline = offline_node(
        "signal-offline-combined-ratchet-5",
        "msg",
        fifth.message_bytes,
    );
    let fifth_result = client
        .process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider(
            &connection,
            &fifth_offline,
            &mut buffer,
            &transfer,
        )
        .await
        .unwrap();
    assert_eq!(fifth_result.offline.child_count, 1);
    assert_eq!(fifth_result.offline.response_count(), 1);
    assert_eq!(fifth_result.offline.event_count(), 1);
    assert_eq!(fifth_result.offline.yielded_count, 0);
    assert_eq!(
        fifth_result.offline.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(fifth_result.offline.results[0].error.is_none());
    assert!(fifth_result.placeholder_resends.is_empty());
    assert!(fifth_result.retry_resends.is_empty());
    assert!(fifth_result.media_retry.is_empty());
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-offline-combined-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-offline-combined-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("offline combined ratchet fifth")
    );
    let record_after_fifth = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        0
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_signal_provider_accepts_new_remote_ratchet() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "offline-new-ratchet")
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
    let offline_node = |id: &str, enc_type: &str, ciphertext: Bytes| {
        BinaryNode::new("offline").with_content(vec![
            BinaryNode::new("message")
                .with_attr("id", id)
                .with_attr("from", "123@s.whatsapp.net")
                .with_attr("type", "text")
                .with_content(vec![
                    BinaryNode::new("enc")
                        .with_attr("type", enc_type)
                        .with_content(ciphertext),
                ]),
        ])
    };

    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &text_plaintext("offline ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("offline ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("offline ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let first_offline = offline_node(
        "signal-offline-ratchet-1",
        "pkmsg",
        first.message_bytes.clone(),
    );
    let first_result = client
        .process_offline_node_with_signal_provider(&connection, &first_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(first_result.child_count, 1);
    assert_eq!(first_result.response_count(), 1);
    assert_eq!(first_result.event_count(), 1);
    assert_eq!(first_result.yielded_count, 0);
    assert_eq!(
        first_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(first_result.results[0].error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-offline-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-offline-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("offline ratchet first")
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
        &text_plaintext("offline ratchet fourth", 7),
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
        &text_plaintext("offline ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    let fourth_offline = offline_node(
        "signal-offline-ratchet-4",
        "msg",
        fourth.message_bytes.clone(),
    );
    let fourth_result = client
        .process_offline_node_with_signal_provider(&connection, &fourth_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(fourth_result.child_count, 1);
    assert_eq!(fourth_result.response_count(), 1);
    assert_eq!(fourth_result.event_count(), 1);
    assert_eq!(fourth_result.yielded_count, 0);
    assert_eq!(
        fourth_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(fourth_result.results[0].error.is_none());
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-offline-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-offline-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("offline ratchet fourth")
    );
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

    let old_third_offline = offline_node(
        "signal-offline-ratchet-old-3",
        "msg",
        old_third.message_bytes.clone(),
    );
    let old_third_result = client
        .process_offline_node_with_signal_provider(&connection, &old_third_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(old_third_result.child_count, 1);
    assert_eq!(old_third_result.response_count(), 1);
    assert_eq!(old_third_result.event_count(), 1);
    assert_eq!(old_third_result.yielded_count, 0);
    assert_eq!(
        old_third_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(old_third_result.results[0].error.is_none());
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(old_third_ack.attrs["id"], "signal-offline-ratchet-old-3");
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-offline-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("offline ratchet old third")
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

    let old_third_replay_offline = offline_node(
        "signal-offline-ratchet-old-3-replay",
        "msg",
        old_third.message_bytes,
    );
    let old_third_replay_result = client
        .process_offline_node_with_signal_provider(
            &connection,
            &old_third_replay_offline,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(old_third_replay_result.child_count, 1);
    assert_eq!(old_third_replay_result.response_count(), 1);
    assert_eq!(old_third_replay_result.event_count(), 0);
    assert_eq!(old_third_replay_result.yielded_count, 0);
    assert_eq!(
        old_third_replay_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        old_third_replay_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("decryption failed"))
    );
    let old_third_replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_replay_nack.tag, "ack");
    assert_eq!(
        old_third_replay_nack.attrs["id"],
        "signal-offline-ratchet-old-3-replay"
    );
    assert_eq!(old_third_replay_nack.attrs["class"], "message");
    assert_eq!(old_third_replay_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        old_third_replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_old_third_bytes
    );

    let second_offline = offline_node("signal-offline-ratchet-2", "msg", second.message_bytes);
    let second_result = client
        .process_offline_node_with_signal_provider(&connection, &second_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(second_result.child_count, 1);
    assert_eq!(second_result.response_count(), 1);
    assert_eq!(second_result.event_count(), 1);
    assert_eq!(second_result.yielded_count, 0);
    assert_eq!(
        second_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(second_result.results[0].error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-offline-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-offline-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("offline ratchet second")
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

    let fifth_offline = offline_node("signal-offline-ratchet-5", "msg", fifth.message_bytes);
    let fifth_result = client
        .process_offline_node_with_signal_provider(&connection, &fifth_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(fifth_result.child_count, 1);
    assert_eq!(fifth_result.response_count(), 1);
    assert_eq!(fifth_result.event_count(), 1);
    assert_eq!(fifth_result.yielded_count, 0);
    assert_eq!(
        fifth_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(fifth_result.results[0].error.is_none());
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-offline-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-offline-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("offline ratchet fifth")
    );
    let record_after_fifth = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_rejects_pre_key_identity_change() {
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
        "offline-identity-change",
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
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline identity change".to_owned()),
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

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-offline-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![incoming]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_signal_provider(&connection, &offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.event_count(), 0);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal provider identity changed for 123.0"))
    );
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-offline-identity-change");
    assert_eq!(nack.attrs["class"], "message");
    assert_eq!(nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(nack.attrs["error"], wa_core::NACK_PARSING_ERROR.to_string());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_canonicalizes_legacy_direct_signal_sender() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "offline-legacy-direct")
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
    let first_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline legacy encrypted hello".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        4,
    );
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
        .with_attr("id", "signal-offline-legacy-direct-1")
        .with_attr("from", legacy_sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes),
        ]);
    let first_offline = BinaryNode::new("offline").with_content(vec![first_incoming]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let first_result = client
        .process_offline_node_with_signal_provider(&connection, &first_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(first_result.child_count, 1);
    assert_eq!(first_result.response_count(), 1);
    assert_eq!(first_result.event_count(), 1);
    assert_eq!(first_result.yielded_count, 0);
    assert_eq!(
        first_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(first_result.results[0].error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-offline-legacy-direct-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], canonical_sender_jid);
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.remote_jid,
        legacy_sender_jid
    );
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-offline-legacy-direct-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("offline legacy encrypted hello")
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

    let second_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline legacy encrypted second".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        5,
    );
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    let second_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-offline-legacy-direct-2")
        .with_attr("from", legacy_sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    let second_offline = BinaryNode::new("offline").with_content(vec![second_incoming]);

    let second_result = client
        .process_offline_node_with_signal_provider(&connection, &second_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(second_result.child_count, 1);
    assert_eq!(second_result.response_count(), 1);
    assert_eq!(second_result.event_count(), 1);
    assert_eq!(second_result.yielded_count, 0);
    assert_eq!(
        second_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(second_result.results[0].error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-offline-legacy-direct-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], canonical_sender_jid);
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.remote_jid,
        legacy_sender_jid
    );
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-offline-legacy-direct-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("offline legacy encrypted second")
    );
    let receiver_record = client
        .signal_provider_state_store()
        .load_session_record(canonical_sender_jid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        wa_core::decode_signal_provider_session_record(&receiver_record)
            .unwrap()
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_accepts_signed_pre_key_only_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "offline-signed-only")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let unrelated_pre_key_id = upload.pre_key_ids[0];
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let unrelated_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(unrelated_pre_key_id)
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
        pre_key: None,
    };
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("offline signed-pre-key only".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        6,
    );
    let first = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    assert!(!first.used_one_time_pre_key);
    assert_eq!(first.message.pre_key_id, None);
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-offline-signed-only-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![incoming]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_signal_provider(&connection, &offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.event_count(), 1);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(result.results[0].error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-offline-signed-only-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-offline-signed-only-1"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("offline signed-pre-key only")
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(unrelated_pre_key_id)
            .await
            .unwrap(),
        Some(unrelated_pre_key.clone())
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );
    let record_after_first_bytes = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let receiver_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    assert_eq!(
        receiver_record.remote_ratchet_key,
        Some(first.message.message.ephemeral_key.clone())
    );
    assert_eq!(receiver_record.receiving_chain.as_ref().unwrap().counter, 1);

    let replay_pre_key = BinaryNode::new("message")
        .with_attr("id", "signal-offline-signed-only-1-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let replay_offline = BinaryNode::new("offline").with_content(vec![replay_pre_key]);
    let replay_pre_key_result = client
        .process_offline_node_with_signal_provider(&connection, &replay_offline, &mut buffer)
        .await
        .unwrap();
    assert_eq!(replay_pre_key_result.child_count, 1);
    assert_eq!(replay_pre_key_result.response_count(), 1);
    assert_eq!(replay_pre_key_result.event_count(), 0);
    assert_eq!(replay_pre_key_result.yielded_count, 0);
    assert_eq!(
        replay_pre_key_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        replay_pre_key_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 0"))
    );
    let replay_pre_key_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_pre_key_nack.tag, "ack");
    assert_eq!(
        replay_pre_key_nack.attrs["id"],
        "signal-offline-signed-only-1-replay"
    );
    assert_eq!(replay_pre_key_nack.attrs["class"], "message");
    assert_eq!(replay_pre_key_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_pre_key_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_pre_key_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(unrelated_pre_key_id)
            .await
            .unwrap(),
        Some(unrelated_pre_key.clone())
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first_bytes
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key)
    );

    let second_text = wa_proto::proto::Message {
        conversation: Some("offline signed-pre-key second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 7);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-offline-signed-only-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let second_offline = BinaryNode::new("offline").with_content(vec![incoming_second]);

    let second_result = client
        .process_offline_node_with_signal_provider(&connection, &second_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(second_result.child_count, 1);
    assert_eq!(second_result.response_count(), 1);
    assert_eq!(second_result.event_count(), 1);
    assert_eq!(second_result.yielded_count, 0);
    assert_eq!(
        second_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(second_result.results[0].error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-offline-signed-only-2");
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
        "signal-offline-signed-only-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("offline signed-pre-key second")
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(unrelated_pre_key_id)
            .await
            .unwrap(),
        Some(unrelated_pre_key)
    );
    let receiver_record = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        wa_core::decode_signal_provider_session_record(&receiver_record)
            .unwrap()
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        2
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_preserves_state_after_tampered_pre_key_decrypt()
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
        "offline-tampered-pre-key",
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
                conversation: Some("offline pre-key after tamper".to_owned()),
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

    let tampered_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-pre-key-tampered")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(tampered),
        ]);
    let tampered_offline = BinaryNode::new("offline").with_content(vec![tampered_child]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let tampered_result = client
        .process_offline_node_with_signal_provider(&connection, &tampered_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(tampered_result.child_count, 1);
    assert_eq!(tampered_result.response_count(), 1);
    assert_eq!(tampered_result.event_count(), 0);
    assert_eq!(tampered_result.yielded_count, 0);
    assert_eq!(
        tampered_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        tampered_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error: decryption failed"))
    );
    let tampered_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_nack.tag, "ack");
    assert_eq!(tampered_nack.attrs["id"], "signal-offline-pre-key-tampered");
    assert_eq!(tampered_nack.attrs["class"], "message");
    assert_eq!(tampered_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(tampered_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        tampered_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
        .with_attr("id", "signal-offline-pre-key-after-tamper")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid_offline = BinaryNode::new("offline").with_content(vec![valid_child]);
    let valid_result = client
        .process_offline_node_with_signal_provider(&connection, &valid_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(valid_result.child_count, 1);
    assert_eq!(valid_result.response_count(), 1);
    assert_eq!(valid_result.event_count(), 1);
    assert_eq!(valid_result.yielded_count, 0);
    assert_eq!(
        valid_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(valid_result.results[0].error.is_none());
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(valid_ack.attrs["id"], "signal-offline-pre-key-after-tamper");
    assert_eq!(valid_ack.attrs["class"], "message");
    assert_eq!(valid_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(valid_ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-offline-pre-key-after-tamper"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("offline pre-key after tamper")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_preserves_state_after_wrong_pre_key_material() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 2, "offline-wrong-pre-key")
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
                conversation: Some("offline pre-key after wrong material".to_owned()),
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

    let wrong_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-pre-key-wrong-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrong_pre_key_message),
        ]);
    let wrong_offline = BinaryNode::new("offline").with_content(vec![wrong_child]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let wrong_result = client
        .process_offline_node_with_signal_provider(&connection, &wrong_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(wrong_result.child_count, 1);
    assert_eq!(wrong_result.response_count(), 1);
    assert_eq!(wrong_result.event_count(), 0);
    assert_eq!(wrong_result.yielded_count, 0);
    assert_eq!(
        wrong_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        wrong_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error: decryption failed"))
    );
    let wrong_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(wrong_nack.tag, "ack");
    assert_eq!(
        wrong_nack.attrs["id"],
        "signal-offline-pre-key-wrong-material"
    );
    assert_eq!(wrong_nack.attrs["class"], "message");
    assert_eq!(wrong_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(wrong_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        wrong_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
        .with_attr("id", "signal-offline-pre-key-after-wrong-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid_offline = BinaryNode::new("offline").with_content(vec![valid_child]);
    let valid_result = client
        .process_offline_node_with_signal_provider(&connection, &valid_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(valid_result.child_count, 1);
    assert_eq!(valid_result.response_count(), 1);
    assert_eq!(valid_result.event_count(), 1);
    assert_eq!(valid_result.yielded_count, 0);
    assert_eq!(
        valid_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(valid_result.results[0].error.is_none());
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(
        valid_ack.attrs["id"],
        "signal-offline-pre-key-after-wrong-material"
    );
    assert_eq!(valid_ack.attrs["class"], "message");
    assert_eq!(valid_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(valid_ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-offline-pre-key-after-wrong-material"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("offline pre-key after wrong material")
    );
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_preserves_state_after_signed_pre_key_id_mismatch()
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
        "offline-signed-pre-key-mismatch",
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
                conversation: Some("offline pre-key after signed id mismatch".to_owned()),
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
    let expected_signed_pre_key_error = format!(
        "Signal signed pre-key id mismatch: message {}, local {}",
        receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
        receiver_credentials.signed_pre_key.key_id
    );

    let mismatch_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-pre-key-signed-id-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key),
        ]);
    let mismatch_offline = BinaryNode::new("offline").with_content(vec![mismatch_child]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let mismatch_result = client
        .process_offline_node_with_signal_provider(&connection, &mismatch_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(mismatch_result.child_count, 1);
    assert_eq!(mismatch_result.response_count(), 1);
    assert_eq!(mismatch_result.event_count(), 0);
    assert_eq!(mismatch_result.yielded_count, 0);
    assert_eq!(
        mismatch_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        mismatch_result.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains(&expected_signed_pre_key_error))
    );
    let mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(mismatch_nack.tag, "ack");
    assert_eq!(
        mismatch_nack.attrs["id"],
        "signal-offline-pre-key-signed-id-mismatch"
    );
    assert_eq!(mismatch_nack.attrs["class"], "message");
    assert_eq!(mismatch_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(mismatch_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        mismatch_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
        .with_attr("id", "signal-offline-pre-key-after-signed-id-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid_offline = BinaryNode::new("offline").with_content(vec![valid_child]);
    let valid_result = client
        .process_offline_node_with_signal_provider(&connection, &valid_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(valid_result.child_count, 1);
    assert_eq!(valid_result.response_count(), 1);
    assert_eq!(valid_result.event_count(), 1);
    assert_eq!(valid_result.yielded_count, 0);
    assert_eq!(
        valid_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(valid_result.results[0].error.is_none());
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(
        valid_ack.attrs["id"],
        "signal-offline-pre-key-after-signed-id-mismatch"
    );
    assert_eq!(valid_ack.attrs["class"], "message");
    assert_eq!(valid_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(valid_ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-offline-pre-key-after-signed-id-mismatch"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("offline pre-key after signed id mismatch")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_preserves_state_when_local_key_material_missing()
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
        "offline-missing-local-material",
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
                conversation: Some("offline pre-key after missing material".to_owned()),
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

    store
        .delete_signal_key(KeyNamespace::Credentials, "schema-version")
        .await
        .unwrap();
    let missing_child = BinaryNode::new("message")
        .with_attr("id", "signal-offline-pre-key-missing-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let missing_offline = BinaryNode::new("offline").with_content(vec![missing_child]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let missing_result = client
        .process_offline_node_with_signal_provider(&connection, &missing_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(missing_result.child_count, 1);
    assert_eq!(missing_result.response_count(), 1);
    assert_eq!(missing_result.event_count(), 0);
    assert_eq!(missing_result.yielded_count, 0);
    assert_eq!(
        missing_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(
        missing_result.results[0].error.as_deref().is_some_and(
            |error| error.contains("missing local Signal key material for pre-key decrypt")
        )
    );
    let missing_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(missing_nack.tag, "ack");
    assert_eq!(
        missing_nack.attrs["id"],
        "signal-offline-pre-key-missing-material"
    );
    assert_eq!(missing_nack.attrs["class"], "message");
    assert_eq!(missing_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(missing_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        missing_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap(),
        Some(receiver_pre_key.clone())
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
        .with_attr("id", "signal-offline-pre-key-after-missing-material")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let valid_offline = BinaryNode::new("offline").with_content(vec![valid_child]);
    let valid_result = client
        .process_offline_node_with_signal_provider(&connection, &valid_offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(valid_result.child_count, 1);
    assert_eq!(valid_result.response_count(), 1);
    assert_eq!(valid_result.event_count(), 1);
    assert_eq!(valid_result.yielded_count, 0);
    assert_eq!(
        valid_result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(valid_result.results[0].error.is_none());
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(
        valid_ack.attrs["id"],
        "signal-offline-pre-key-after-missing-material"
    );
    assert_eq!(valid_ack.attrs["class"], "message");
    assert_eq!(valid_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(valid_ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-offline-pre-key-after-missing-material"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("offline pre-key after missing material")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_with_signal_provider_decrypts_event_response_from_stored_creation_secret()
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
        "offline-signal-event-response",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];

    let event_secret = Bytes::from(vec![44u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("event-creation-offline-signal-1".to_owned()),
        participant: None,
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let creation_message = wa_core::build_event_message(wa_core::EventContent::new(
        "Launch review",
        1_700_000_000,
        event_secret.clone(),
    ))
    .unwrap();
    let creation_event = MessageEvent::new(target_event_key.clone())
        .with_payload(wa_core::encode_message(&creation_message).unwrap())
        .with_field("kind", "chat")
        .with_field("author", "999:7@s.whatsapp.net")
        .with_field("sender", "999:7@s.whatsapp.net")
        .with_field("from_me", "true");
    persist_receive_events(
        &store,
        &[Event::Batch(Box::new(wa_core::EventBatch {
            messages_upsert: vec![creation_event],
            ..wa_core::EventBatch::default()
        }))],
    )
    .await
    .unwrap();

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let receiver_pre_key = client
        .signal_provider_state_store()
        .load_local_pre_key(receiver_pre_key_id)
        .await
        .unwrap()
        .unwrap();
    let event_response_content = wa_core::build_encrypted_event_response_content_with_iv(
        wa_core::EventResponsePayload::new(
            target_key.clone(),
            wa_core::EventResponseKind::Going,
            event_secret,
            "999:7@s.whatsapp.net",
            "123@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_017_123)
        .with_extra_guest_count(4),
        Bytes::from_static(b"event-rsvpiv"),
    )
    .unwrap();
    let event_response = wa_core::build_event_response_message(event_response_content).unwrap();
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
    let plaintext = pad_random_max16_for_test(Bytes::from(event_response.encode_to_vec()), 13);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let encrypted_message_bytes = pre_key_message_outer_unknown_field(&encrypted.message_bytes);
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-offline-event-response-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted_message_bytes),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![incoming]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node_with_signal_provider(&connection, &offline, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.event_count(), 2);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Message
    );
    assert!(result.results[0].error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-offline-event-response-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-offline-event-response-1"
    );
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert!(decoded.enc_event_response_message.is_some());
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.fields["source"], "enc_event_response_message");
    assert_eq!(update.fields["event_response"], "true");
    assert_eq!(update.fields["responder_jid"], "123@s.whatsapp.net");
    assert_eq!(update.fields["response_decrypted"], "true");
    assert_eq!(update.fields["response"], "going");
    assert_eq!(update.fields["response_timestamp_ms"], "1700000017123");
    assert_eq!(update.fields["extra_guest_count"], "4");
    assert_eq!(
        update.fields["event_secret_creator_jid"],
        "999:7@s.whatsapp.net"
    );

    let stored_target = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&target_event_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_target = wa_core::decode_stored_message_event(&stored_target).unwrap();
    assert_eq!(stored_target.fields["response_decrypted"], "true");
    assert_eq!(stored_target.fields["response"], "going");
    assert_eq!(stored_target.fields["extra_guest_count"], "4");
    assert!(
        store
            .get(
                KeyNamespace::MessageUpdate,
                &wa_core::message_event_store_key(&target_event_key),
            )
            .await
            .unwrap()
            .is_none()
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
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_media_retry_downloads_pending_media() {
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
        "msg-auto",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [8u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"automatic retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/auto/old"),
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
        direct_path: Some("/auto/new".to_owned()),
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
        "https://media.test/auto/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut processor = client
        .spawn_incoming_processor_with_media_retry(
            connection.clone(),
            IncomingDecryptor,
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
    assert_eq!(ack.attrs["id"], "msg-auto");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    let processed = recv_media_retry_processed_event(&mut events).await;
    assert_eq!(processed.downloads.len(), 1);
    assert_eq!(processed.downloads[0].plaintext, b"automatic retried media");
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
async fn incoming_processor_with_media_retry_signal_provider_preserves_legacy_retry_key() {
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
        "123@c.us",
        "msg-auto-signal-legacy",
        Some("456@c.us".to_owned()),
    );
    let media_key = [6u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"automatic legacy retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/auto-legacy/old"),
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
        direct_path: Some("/auto-legacy/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[4u8; 12],
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
        "https://media.test/auto-legacy/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut processor = client
        .spawn_incoming_processor_with_media_retry_with_signal_provider(
            connection.clone(),
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
    assert_eq!(ack.attrs["id"], "msg-auto-signal-legacy");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.receipts_update.len(), 1);
    assert_eq!(batch.media_retry.len(), 1);
    assert_eq!(batch.media_retry[0].key, key);
    assert_eq!(batch.media_retry[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.media_retry[0].key.participant.as_deref(),
        Some("456@c.us")
    );
    let processed = recv_media_retry_processed_event(&mut events).await;
    assert_eq!(processed.downloads.len(), 1);
    assert_eq!(
        processed.downloads[0].plaintext,
        b"automatic legacy retried media"
    );
    assert!(processed.errors.is_empty());
    assert_eq!(processed.ignored_without_pending, 0);
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
    let retry_store_key = wa_core::media_retry_event_store_key(&batch.media_retry[0]);
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_none()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_media_retry_signal_provider_emits_offline_group_notification_append_stub()
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
        .spawn_incoming_processor_with_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-media-offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000200")
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
    assert_eq!(ack.attrs["id"], "spawn-media-offline-group-ephemeral-stub");
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
        "spawn-media-offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000200");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "spawn-media-offline-group-ephemeral-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_200));
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
            "notification-only media retry processor must not emit media retry side effects"
        );
    }
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_media_retry_signal_provider_emits_offline_group_participant_add_append_stub()
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
        .spawn_incoming_processor_with_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-media-offline-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000300")
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
        "spawn-media-offline-group-participant-add-stub"
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
        "spawn-media-offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000300");
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
        "spawn-media-offline-group-participant-add-stub"
    );
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_300));
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
            "notification-only media retry processor must not emit media retry side effects"
        );
    }
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_media_retry_replays_stored_events_on_start() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let registering_client = Client::builder(store.clone()).connect().await.unwrap();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-startup-media",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let media_key = [13u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"startup retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/startup/old"),
    )
    .unwrap();
    registering_client
        .register_pending_media_retry_persisted(
            key.clone(),
            wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(key.id.clone()),
        direct_path: Some("/startup/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[9u8; 12],
    )
    .unwrap();
    let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
        .with_encrypted_payload(payload.ciphertext, payload.iv);
    persist_receive_events(&store, &[Event::MediaRetry(vec![retry.clone()])])
        .await
        .unwrap();
    let pending_store_key = wa_core::pending_media_retry_store_key(&key);
    let retry_store_key = wa_core::media_retry_event_store_key(&retry);

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, _sink_rx, _stream_tx) = mock_connection_with_events(client.events.clone());
    let mut events = client.subscribe();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/startup/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut processor = client
        .spawn_incoming_processor_with_media_retry(
            connection.clone(),
            IncomingDecryptor,
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();

    let processed = recv_media_retry_processed_event(&mut events).await;
    assert_eq!(processed.downloads.len(), 1);
    assert_eq!(processed.downloads[0].plaintext, b"startup retried media");
    assert!(processed.errors.is_empty());
    assert_eq!(processed.ignored_without_pending, 0);
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
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

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_media_retry_signal_provider_replays_legacy_stored_events_on_start()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let registering_client = Client::builder(store.clone()).connect().await.unwrap();
    let key = wa_core::MessageEventKey::new(
        "123@c.us",
        "msg-startup-media-legacy",
        Some("456@c.us".to_owned()),
    );
    let media_key = [12u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"startup legacy retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/startup-legacy/old"),
    )
    .unwrap();
    registering_client
        .register_pending_media_retry_persisted(
            key.clone(),
            wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(key.id.clone()),
        direct_path: Some("/startup-legacy/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[2u8; 12],
    )
    .unwrap();
    let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
        .with_encrypted_payload(payload.ciphertext, payload.iv);
    persist_receive_events(&store, &[Event::MediaRetry(vec![retry.clone()])])
        .await
        .unwrap();
    let pending_store_key = wa_core::pending_media_retry_store_key(&key);
    let retry_store_key = wa_core::media_retry_event_store_key(&retry);
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &pending_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_some()
    );

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, _sink_rx, _stream_tx) = mock_connection_with_events(client.events.clone());
    let mut events = client.subscribe();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/startup-legacy/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let mut processor = client
        .spawn_incoming_processor_with_media_retry_with_signal_provider(
            connection.clone(),
            transfer,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();

    let processed = recv_media_retry_processed_event(&mut events).await;
    assert_eq!(processed.downloads.len(), 1);
    assert_eq!(
        processed.downloads[0].plaintext,
        b"startup legacy retried media"
    );
    assert!(processed.errors.is_empty());
    assert_eq!(processed.ignored_without_pending, 0);
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
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

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_media_retry_signal_provider_accepts_same_base_pre_key_wrapper() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "media-retry-same")
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
        conversation: Some("spawn media retry same-base first".to_owned()),
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
    let first_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-media-retry-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_media_retry_with_signal_provider(
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
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-media-retry-same-base-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn media retry same-base first")
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
        conversation: Some("spawn media retry same-base wrapped second".to_owned()),
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
        .with_attr("id", "signal-spawn-media-retry-same-base-2-identity-change")
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
        "signal-spawn-media-retry-same-base-2-identity-change"
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
            "media-retry same-base identity-change wrapper must not emit a typed batch"
        );
        assert!(
            !matches!(event, Event::MediaRetry(_)),
            "media-retry same-base identity-change wrapper must not emit media-retry events"
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
            "signal-spawn-media-retry-same-base-2-signed-pre-key-mismatch",
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
        "signal-spawn-media-retry-same-base-2-signed-pre-key-mismatch"
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
            "media-retry same-base signed-pre-key-id mismatch wrapper must not emit a typed batch"
        );
        assert!(
            !matches!(event, Event::MediaRetry(_)),
            "media-retry same-base signed-pre-key-id mismatch wrapper must not emit media-retry events"
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
        .with_attr("id", "signal-spawn-media-retry-same-base-2")
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
    assert_eq!(
        second_ack.attrs["id"],
        "signal-spawn-media-retry-same-base-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn media retry same-base wrapped second")
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

    let wrapped_replay = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-media-retry-same-base-2-replay")
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
        "signal-spawn-media-retry-same-base-2-replay"
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
            "media-retry same-base replay must not emit a typed batch"
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
        conversation: Some("spawn media retry same-base third".to_owned()),
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
        .with_attr("id", "signal-spawn-media-retry-same-base-3")
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
    assert_eq!(
        third_ack.attrs["id"],
        "signal-spawn-media-retry-same-base-3"
    );
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn media retry same-base third")
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
async fn incoming_processor_with_media_retry_signal_provider_accepts_new_remote_ratchet() {
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
        "media-retry-spawn-new-ratchet",
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
        &text_plaintext("spawn media retry ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn media retry ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn media retry ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let transfer = wa_core::MediaTransfer::new(ClientMediaUploadTransport::default());
    let mut processor = client
        .spawn_incoming_processor_with_media_retry_with_signal_provider(
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
            encode_binary_node(&incoming_node(
                "signal-spawn-media-retry-ratchet-1",
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
    assert_eq!(first_ack.attrs["id"], "signal-spawn-media-retry-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn media retry ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver spawn media retry ratchet reply"),
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
        &text_plaintext("spawn media retry ratchet fourth", 7),
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
        &text_plaintext("spawn media retry ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-media-retry-ratchet-4",
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
    assert_eq!(fourth_ack.attrs["id"], "signal-spawn-media-retry-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn media retry ratchet fourth")
    );
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
                "signal-spawn-media-retry-ratchet-old-3",
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
    assert_eq!(
        old_third_ack.attrs["id"],
        "signal-spawn-media-retry-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("spawn media retry ratchet old third")
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
                "signal-spawn-media-retry-ratchet-old-3-replay",
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
        "signal-spawn-media-retry-ratchet-old-3-replay"
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
            "spawn media consumed previous-chain replay must not emit a typed batch"
        );
        assert!(
            !matches!(event, Event::MediaRetry(_) | Event::MediaRetryProcessed(_)),
            "spawn media consumed previous-chain replay must not emit media retry events"
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-media-retry-ratchet-2",
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
    assert_eq!(second_ack.attrs["id"], "signal-spawn-media-retry-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn media retry ratchet second")
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
                "signal-spawn-media-retry-ratchet-5",
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
    assert_eq!(fifth_ack.attrs["id"], "signal-spawn-media-retry-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-spawn-media-retry-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("spawn media retry ratchet fifth")
    );
    let record_after_fifth = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_media_and_signal_provider_accepts_new_remote_ratchet()
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
        "placeholder-retry-media-spawn-new-ratchet",
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
        &text_plaintext("spawn placeholder retry media ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn placeholder retry media ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn placeholder retry media ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

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
            encode_binary_node(&incoming_node(
                "signal-spawn-placeholder-retry-media-ratchet-1",
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
    assert_eq!(
        first_ack.attrs["id"],
        "signal-spawn-placeholder-retry-media-ratchet-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-media-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn placeholder retry media ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver spawn placeholder retry media ratchet reply"),
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
        &text_plaintext("spawn placeholder retry media ratchet fourth", 7),
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
        &text_plaintext("spawn placeholder retry media ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-placeholder-retry-media-ratchet-4",
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
    assert_eq!(
        fourth_ack.attrs["id"],
        "signal-spawn-placeholder-retry-media-ratchet-4"
    );
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-media-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn placeholder retry media ratchet fourth")
    );
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
                "signal-spawn-placeholder-retry-media-ratchet-old-3",
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
    assert_eq!(
        old_third_ack.attrs["id"],
        "signal-spawn-placeholder-retry-media-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-media-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("spawn placeholder retry media ratchet old third")
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
                "signal-spawn-placeholder-retry-media-ratchet-old-3-replay",
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
        "signal-spawn-placeholder-retry-media-ratchet-old-3-replay"
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
            "spawn combined media consumed previous-chain replay must not emit a typed batch"
        );
        assert!(
            !matches!(event, Event::MediaRetry(_) | Event::MediaRetryProcessed(_)),
            "spawn combined media consumed previous-chain replay must not emit media retry events"
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-placeholder-retry-media-ratchet-2",
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
    assert_eq!(
        second_ack.attrs["id"],
        "signal-spawn-placeholder-retry-media-ratchet-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-media-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn placeholder retry media ratchet second")
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
                "signal-spawn-placeholder-retry-media-ratchet-5",
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
    assert_eq!(
        fifth_ack.attrs["id"],
        "signal-spawn-placeholder-retry-media-ratchet-5"
    );
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-media-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("spawn placeholder retry media ratchet fifth")
    );
    let record_after_fifth = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_fifth =
        wa_core::decode_signal_provider_session_record(&record_after_fifth).unwrap();
    assert_eq!(
        record_after_fifth.remote_ratchet_key,
        Some(fourth.message.ephemeral_key)
    );
    assert_eq!(
        record_after_fifth.receiving_chain.as_ref().unwrap().counter,
        2
    );
    assert!(record_after_fifth.message_keys.is_empty());
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        0
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    processor.abort();
    connection.close().await.unwrap();
}
