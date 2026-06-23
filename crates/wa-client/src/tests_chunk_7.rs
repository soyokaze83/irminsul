// Auto-partitioned test chunk 7 of 8 (feature `wat7`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat7 to stay within the VM RAM budget.
// Included into `mod chunk_7` in lib.rs; allow-attrs live on that module decl.
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
async fn incoming_processor_with_signal_provider_preserves_state_after_duplicate_skipped_key() {
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
        "spawn-duplicate-skipped-key",
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
        &text_plaintext("spawn duplicate skipped first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn duplicate skipped second", 13),
        &sender_identity,
    )
    .unwrap();
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn duplicate skipped third", 14),
        &sender_identity,
    )
    .unwrap();
    let fourth = wa_core::encrypt_signal_provider_session_record_message(
        &third.record,
        &text_plaintext("spawn duplicate skipped fourth", 15),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(third.message.counter, 2);
    assert_eq!(fourth.message.counter, 3);

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
                "signal-spawn-duplicate-skipped-1",
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
    assert_eq!(first_ack.attrs["id"], "signal-spawn-duplicate-skipped-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn duplicate skipped first")
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
                "signal-spawn-duplicate-skipped-4",
                "msg",
                fourth.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-spawn-duplicate-skipped-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn duplicate skipped fourth")
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
        record_after_fourth
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        4
    );
    assert_eq!(record_after_fourth.message_keys.len(), 2);
    assert_eq!(record_after_fourth.message_keys[0].counter, 1);
    assert_eq!(record_after_fourth.message_keys[1].counter, 2);
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet = record_after_fourth.message_keys[0].ratchet_key.clone();
    let skipped_ratchet_offsets = record_after_fourth_bytes
        .windows(skipped_ratchet.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == skipped_ratchet).then_some(offset))
        .collect::<Vec<_>>();
    assert!(
        skipped_ratchet_offsets.len() >= 3,
        "encoded session should contain active ratchet plus two skipped keys"
    );
    let duplicate_counter_offset = skipped_ratchet_offsets[2] + skipped_ratchet.len();
    let mut duplicate_skipped_session = record_after_fourth_bytes.to_vec();
    duplicate_skipped_session[duplicate_counter_offset..duplicate_counter_offset + 4]
        .copy_from_slice(&1u32.to_be_bytes());
    let duplicate_skipped_session = Bytes::from(duplicate_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &duplicate_skipped_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-duplicate-skipped-invalid",
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
        "signal-spawn-duplicate-skipped-invalid"
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
            "duplicate skipped key must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        duplicate_skipped_session
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
            &record_after_fourth_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-duplicate-skipped-2",
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
    assert_eq!(second_ack.attrs["id"], "signal-spawn-duplicate-skipped-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn duplicate skipped second")
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
        4
    );
    assert_eq!(record_after_second.message_keys.len(), 1);
    assert_eq!(record_after_second.message_keys[0].counter, 2);
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
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_duplicate_skipped_key()
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
        "spawn-offline-duplicate-skipped-key",
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
        &text_plaintext("spawn offline duplicate skipped first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline duplicate skipped second", 13),
        &sender_identity,
    )
    .unwrap();
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn offline duplicate skipped third", 14),
        &sender_identity,
    )
    .unwrap();
    let fourth = wa_core::encrypt_signal_provider_session_record_message(
        &third.record,
        &text_plaintext("spawn offline duplicate skipped fourth", 15),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(third.message.counter, 2);
    assert_eq!(fourth.message.counter, 3);

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
                "signal-spawn-offline-duplicate-skipped-1",
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
        "signal-spawn-offline-duplicate-skipped-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-duplicate-skipped-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline duplicate skipped first")
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
                "signal-spawn-offline-duplicate-skipped-4",
                "msg",
                fourth.message_bytes,
            )))
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
        "signal-spawn-offline-duplicate-skipped-4"
    );
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-duplicate-skipped-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn offline duplicate skipped fourth")
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
        record_after_fourth
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        4
    );
    assert_eq!(record_after_fourth.message_keys.len(), 2);
    assert_eq!(record_after_fourth.message_keys[0].counter, 1);
    assert_eq!(record_after_fourth.message_keys[1].counter, 2);
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet = record_after_fourth.message_keys[0].ratchet_key.clone();
    let skipped_ratchet_offsets = record_after_fourth_bytes
        .windows(skipped_ratchet.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == skipped_ratchet).then_some(offset))
        .collect::<Vec<_>>();
    assert!(
        skipped_ratchet_offsets.len() >= 3,
        "encoded session should contain active ratchet plus two skipped keys"
    );
    let duplicate_counter_offset = skipped_ratchet_offsets[2] + skipped_ratchet.len();
    let mut duplicate_skipped_session = record_after_fourth_bytes.to_vec();
    duplicate_skipped_session[duplicate_counter_offset..duplicate_counter_offset + 4]
        .copy_from_slice(&1u32.to_be_bytes());
    let duplicate_skipped_session = Bytes::from(duplicate_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &duplicate_skipped_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-duplicate-skipped-invalid",
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
        "signal-spawn-offline-duplicate-skipped-invalid"
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
            "offline duplicate skipped key must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        duplicate_skipped_session
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
            &record_after_fourth_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-duplicate-skipped-2",
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
        "signal-spawn-offline-duplicate-skipped-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-duplicate-skipped-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline duplicate skipped second")
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
        4
    );
    assert_eq!(record_after_second.message_keys.len(), 1);
    assert_eq!(record_after_second.message_keys[0].counter, 2);
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
async fn incoming_processor_with_signal_provider_preserves_state_after_active_counter_skipped_key()
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
        "spawn-active-counter-skipped-key",
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
        &text_plaintext("spawn active-counter skipped first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn active-counter skipped second", 13),
        &sender_identity,
    )
    .unwrap();
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn active-counter skipped third", 14),
        &sender_identity,
    )
    .unwrap();
    let fourth = wa_core::encrypt_signal_provider_session_record_message(
        &third.record,
        &text_plaintext("spawn active-counter skipped fourth", 15),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(third.message.counter, 2);
    assert_eq!(fourth.message.counter, 3);

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
                "signal-spawn-active-counter-skipped-1",
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
        "signal-spawn-active-counter-skipped-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn active-counter skipped first")
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
                "signal-spawn-active-counter-skipped-4",
                "msg",
                fourth.message_bytes,
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
        "signal-spawn-active-counter-skipped-4"
    );
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn active-counter skipped fourth")
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
        record_after_fourth
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        4
    );
    assert_eq!(record_after_fourth.message_keys.len(), 2);
    assert_eq!(record_after_fourth.message_keys[0].counter, 1);
    assert_eq!(record_after_fourth.message_keys[1].counter, 2);
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet = record_after_fourth.message_keys[0].ratchet_key.clone();
    let skipped_ratchet_offsets = record_after_fourth_bytes
        .windows(skipped_ratchet.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == skipped_ratchet).then_some(offset))
        .collect::<Vec<_>>();
    assert!(
        skipped_ratchet_offsets.len() >= 2,
        "encoded session should contain active ratchet plus a skipped key"
    );
    let active_counter_offset = skipped_ratchet_offsets[1] + skipped_ratchet.len();
    let mut active_counter_skipped_session = record_after_fourth_bytes.to_vec();
    active_counter_skipped_session[active_counter_offset..active_counter_offset + 4]
        .copy_from_slice(&4u32.to_be_bytes());
    let active_counter_skipped_session = Bytes::from(active_counter_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &active_counter_skipped_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-active-counter-skipped-invalid",
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
        "signal-spawn-active-counter-skipped-invalid"
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
            "active-counter skipped key must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        active_counter_skipped_session
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
            &record_after_fourth_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-active-counter-skipped-2",
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
        "signal-spawn-active-counter-skipped-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn active-counter skipped second")
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
        4
    );
    assert_eq!(record_after_second.message_keys.len(), 1);
    assert_eq!(record_after_second.message_keys[0].counter, 2);
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
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_active_counter_skipped_key()
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
        "spawn-offline-active-counter-skipped-key",
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
        &text_plaintext("spawn offline active-counter skipped first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline active-counter skipped second", 13),
        &sender_identity,
    )
    .unwrap();
    let third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn offline active-counter skipped third", 14),
        &sender_identity,
    )
    .unwrap();
    let fourth = wa_core::encrypt_signal_provider_session_record_message(
        &third.record,
        &text_plaintext("spawn offline active-counter skipped fourth", 15),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(third.message.counter, 2);
    assert_eq!(fourth.message.counter, 3);

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
                "signal-spawn-offline-active-counter-skipped-1",
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
        "signal-spawn-offline-active-counter-skipped-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-active-counter-skipped-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline active-counter skipped first")
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
                "signal-spawn-offline-active-counter-skipped-4",
                "msg",
                fourth.message_bytes,
            )))
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
        "signal-spawn-offline-active-counter-skipped-4"
    );
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-active-counter-skipped-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn offline active-counter skipped fourth")
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
        record_after_fourth
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        4
    );
    assert_eq!(record_after_fourth.message_keys.len(), 2);
    assert_eq!(record_after_fourth.message_keys[0].counter, 1);
    assert_eq!(record_after_fourth.message_keys[1].counter, 2);
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet = record_after_fourth.message_keys[0].ratchet_key.clone();
    let skipped_ratchet_offsets = record_after_fourth_bytes
        .windows(skipped_ratchet.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == skipped_ratchet).then_some(offset))
        .collect::<Vec<_>>();
    assert!(
        skipped_ratchet_offsets.len() >= 2,
        "encoded session should contain active ratchet plus a skipped key"
    );
    let active_counter_offset = skipped_ratchet_offsets[1] + skipped_ratchet.len();
    let mut active_counter_skipped_session = record_after_fourth_bytes.to_vec();
    active_counter_skipped_session[active_counter_offset..active_counter_offset + 4]
        .copy_from_slice(&4u32.to_be_bytes());
    let active_counter_skipped_session = Bytes::from(active_counter_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &active_counter_skipped_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-active-counter-skipped-invalid",
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
        "signal-spawn-offline-active-counter-skipped-invalid"
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
            "offline active-counter skipped key must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        active_counter_skipped_session
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
            &record_after_fourth_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-active-counter-skipped-2",
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
        "signal-spawn-offline-active-counter-skipped-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-active-counter-skipped-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline active-counter skipped second")
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
        4
    );
    assert_eq!(record_after_second.message_keys.len(), 1);
    assert_eq!(record_after_second.message_keys[0].counter, 2);
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
async fn incoming_processor_with_signal_provider_preserves_state_after_skipped_key_without_remote_ratchet()
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
        "spawn-skipped-without-remote",
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
        &text_plaintext("spawn skipped without remote first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn skipped without remote second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-skipped-without-remote-1",
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
        "signal-spawn-skipped-without-remote-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-skipped-without-remote-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn skipped without remote first")
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
    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&generate_key_pair().public));
    let skipped_message_keys = wa_core::derive_signal_message_keys(&[1u8; 32]).unwrap();
    let session_without_remote = wa_core::SignalProviderSessionRecord {
        remote_registration_id: valid_session_record.remote_registration_id,
        remote_identity_key: valid_session_record.remote_identity_key.clone(),
        root_key: valid_session_record.root_key.clone(),
        sending_chain: wa_core::SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 1,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: valid_session_record.local_ratchet_key_pair.clone(),
        previous_counter: valid_session_record.previous_counter,
        message_keys: Vec::new(),
        inbound_base_key: None,
    };
    let session_without_remote_bytes =
        wa_core::encode_signal_provider_session_record(&session_without_remote).unwrap();
    let skipped_without_remote_session =
        signal_provider_session_with_skipped_key_without_remote_ratchet(
            &session_without_remote_bytes,
            &skipped_ratchet_key,
            1,
            &skipped_message_keys,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &skipped_without_remote_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-without-remote-invalid",
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
        "signal-spawn-skipped-without-remote-invalid"
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
            "skipped key without remote ratchet must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        skipped_without_remote_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-skipped-without-remote-2",
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
        "signal-spawn-skipped-without-remote-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-skipped-without-remote-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn skipped without remote second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_skipped_key_without_remote_ratchet()
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
        "spawn-offline-skipped-without-remote",
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
        &text_plaintext("spawn offline skipped without remote first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline skipped without remote second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-offline-skipped-without-remote-1",
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
        "signal-spawn-offline-skipped-without-remote-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-skipped-without-remote-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline skipped without remote first")
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
    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let skipped_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&generate_key_pair().public));
    let skipped_message_keys = wa_core::derive_signal_message_keys(&[1u8; 32]).unwrap();
    let session_without_remote = wa_core::SignalProviderSessionRecord {
        remote_registration_id: valid_session_record.remote_registration_id,
        remote_identity_key: valid_session_record.remote_identity_key.clone(),
        root_key: valid_session_record.root_key.clone(),
        sending_chain: wa_core::SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 1,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: valid_session_record.local_ratchet_key_pair.clone(),
        previous_counter: valid_session_record.previous_counter,
        message_keys: Vec::new(),
        inbound_base_key: None,
    };
    let session_without_remote_bytes =
        wa_core::encode_signal_provider_session_record(&session_without_remote).unwrap();
    let skipped_without_remote_session =
        signal_provider_session_with_skipped_key_without_remote_ratchet(
            &session_without_remote_bytes,
            &skipped_ratchet_key,
            1,
            &skipped_message_keys,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &skipped_without_remote_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-without-remote-invalid",
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
        "signal-spawn-offline-skipped-without-remote-invalid"
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
            "offline skipped key without remote ratchet must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        skipped_without_remote_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-skipped-without-remote-2",
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
        "signal-spawn-offline-skipped-without-remote-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-skipped-without-remote-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline skipped without remote second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_receiving_chain_without_remote_ratchet()
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
        "spawn-receiving-without-remote",
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
        &text_plaintext("spawn receiving without remote first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn receiving without remote second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-receiving-without-remote-1",
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
        "signal-spawn-receiving-without-remote-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-receiving-without-remote-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn receiving without remote first")
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
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let unpaired_receiving_chain_session =
        signal_provider_session_with_receiving_chain_without_remote_ratchet(
            &record_after_first_bytes,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &unpaired_receiving_chain_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-receiving-without-remote-invalid",
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
        "signal-spawn-receiving-without-remote-invalid"
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
            "receiving chain without remote ratchet must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        unpaired_receiving_chain_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-receiving-without-remote-2",
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
        "signal-spawn-receiving-without-remote-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-receiving-without-remote-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn receiving without remote second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_receiving_chain_without_remote_ratchet()
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
        "spawn-offline-receiving-without-remote",
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
        &text_plaintext("spawn offline receiving without remote first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline receiving without remote second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-offline-receiving-without-remote-1",
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
        "signal-spawn-offline-receiving-without-remote-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-receiving-without-remote-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline receiving without remote first")
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
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let unpaired_receiving_chain_session =
        signal_provider_session_with_receiving_chain_without_remote_ratchet(
            &record_after_first_bytes,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &unpaired_receiving_chain_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-receiving-without-remote-invalid",
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
        "signal-spawn-offline-receiving-without-remote-invalid"
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
            "offline receiving chain without remote ratchet must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        unpaired_receiving_chain_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-receiving-without-remote-2",
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
        "signal-spawn-offline-receiving-without-remote-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-receiving-without-remote-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline receiving without remote second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_uninitialized_sending_chain_without_remote_ratchet()
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
        "spawn-uninitialized-sending-chain",
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
        &text_plaintext("spawn uninitialized sending chain first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn uninitialized sending chain second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-uninitialized-send-chain-1",
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
        "signal-spawn-uninitialized-send-chain-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-uninitialized-send-chain-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn uninitialized sending chain first")
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
    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let session_without_remote = wa_core::SignalProviderSessionRecord {
        remote_registration_id: valid_session_record.remote_registration_id,
        remote_identity_key: valid_session_record.remote_identity_key.clone(),
        root_key: valid_session_record.root_key.clone(),
        sending_chain: wa_core::SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 1,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: valid_session_record.local_ratchet_key_pair.clone(),
        previous_counter: valid_session_record.previous_counter,
        message_keys: Vec::new(),
        inbound_base_key: None,
    };
    let session_without_remote_bytes =
        wa_core::encode_signal_provider_session_record(&session_without_remote).unwrap();
    let uninitialized_sending_chain_session =
        signal_provider_session_with_uninitialized_sending_chain_without_remote_ratchet(
            &session_without_remote_bytes,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &uninitialized_sending_chain_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-uninitialized-send-chain-invalid",
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
        "signal-spawn-uninitialized-send-chain-invalid"
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
            "uninitialized sending chain without remote ratchet must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        uninitialized_sending_chain_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-uninitialized-send-chain-2",
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
        "signal-spawn-uninitialized-send-chain-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-uninitialized-send-chain-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn uninitialized sending chain second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_uninitialized_sending_chain_without_remote_ratchet()
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
        "spawn-offline-uninitialized-sending-chain",
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
        &text_plaintext("spawn offline uninitialized sending chain first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline uninitialized sending chain second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-offline-uninitialized-send-chain-1",
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
        "signal-spawn-offline-uninitialized-send-chain-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-uninitialized-send-chain-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline uninitialized sending chain first")
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
    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let session_without_remote = wa_core::SignalProviderSessionRecord {
        remote_registration_id: valid_session_record.remote_registration_id,
        remote_identity_key: valid_session_record.remote_identity_key.clone(),
        root_key: valid_session_record.root_key.clone(),
        sending_chain: wa_core::SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 1,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: valid_session_record.local_ratchet_key_pair.clone(),
        previous_counter: valid_session_record.previous_counter,
        message_keys: Vec::new(),
        inbound_base_key: None,
    };
    let session_without_remote_bytes =
        wa_core::encode_signal_provider_session_record(&session_without_remote).unwrap();
    let uninitialized_sending_chain_session =
        signal_provider_session_with_uninitialized_sending_chain_without_remote_ratchet(
            &session_without_remote_bytes,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &uninitialized_sending_chain_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-uninitialized-send-chain-invalid",
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
        "signal-spawn-offline-uninitialized-send-chain-invalid"
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
            "offline uninitialized sending chain without remote ratchet must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        uninitialized_sending_chain_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-uninitialized-send-chain-2",
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
        "signal-spawn-offline-uninitialized-send-chain-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-uninitialized-send-chain-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline uninitialized sending chain second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_remote_ratchet_without_receiving_chain()
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
        "spawn-remote-without-receiving-chain",
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
        &text_plaintext("spawn remote without receiving first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn remote without receiving second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-remote-without-receiving-1",
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
        "signal-spawn-remote-without-receiving-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-remote-without-receiving-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn remote without receiving first")
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
    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let session_without_remote = wa_core::SignalProviderSessionRecord {
        remote_registration_id: valid_session_record.remote_registration_id,
        remote_identity_key: valid_session_record.remote_identity_key.clone(),
        root_key: valid_session_record.root_key.clone(),
        sending_chain: wa_core::SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 1,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: valid_session_record.local_ratchet_key_pair.clone(),
        previous_counter: valid_session_record.previous_counter,
        message_keys: Vec::new(),
        inbound_base_key: None,
    };
    let session_without_remote_bytes =
        wa_core::encode_signal_provider_session_record(&session_without_remote).unwrap();
    let remote_only_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&generate_key_pair().public));
    let remote_without_receiving_chain_session =
        signal_provider_session_with_remote_ratchet_without_receiving_chain(
            &session_without_remote_bytes,
            &remote_only_ratchet_key,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &remote_without_receiving_chain_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-remote-without-receiving-invalid",
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
        "signal-spawn-remote-without-receiving-invalid"
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
            "remote ratchet without receiving chain must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        remote_without_receiving_chain_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-remote-without-receiving-2",
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
        "signal-spawn-remote-without-receiving-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-remote-without-receiving-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn remote without receiving second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_remote_ratchet_without_receiving_chain()
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
        "spawn-offline-remote-without-receiving-chain",
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
        &text_plaintext("spawn offline remote without receiving first", 12),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn offline remote without receiving second", 13),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);

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
                "signal-spawn-offline-remote-without-receiving-1",
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
        "signal-spawn-offline-remote-without-receiving-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-remote-without-receiving-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline remote without receiving first")
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
    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(sender_material.identity.public_key.clone())
    );

    let session_without_remote = wa_core::SignalProviderSessionRecord {
        remote_registration_id: valid_session_record.remote_registration_id,
        remote_identity_key: valid_session_record.remote_identity_key.clone(),
        root_key: valid_session_record.root_key.clone(),
        sending_chain: wa_core::SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 1,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: valid_session_record.local_ratchet_key_pair.clone(),
        previous_counter: valid_session_record.previous_counter,
        message_keys: Vec::new(),
        inbound_base_key: None,
    };
    let session_without_remote_bytes =
        wa_core::encode_signal_provider_session_record(&session_without_remote).unwrap();
    let remote_only_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&generate_key_pair().public));
    let remote_without_receiving_chain_session =
        signal_provider_session_with_remote_ratchet_without_receiving_chain(
            &session_without_remote_bytes,
            &remote_only_ratchet_key,
        );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &remote_without_receiving_chain_session,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-remote-without-receiving-invalid",
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
        "signal-spawn-offline-remote-without-receiving-invalid"
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
            "offline remote ratchet without receiving chain must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        remote_without_receiving_chain_session
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-remote-without-receiving-2",
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
        "signal-spawn-offline-remote-without-receiving-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-remote-without-receiving-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline remote without receiving second")
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
        2
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
async fn incoming_processor_with_signal_provider_preserves_state_after_invalid_sender_key_record() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "555@g.us";
    let sender_jid = "123:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let key_id = 77;
    let chain_key = [7u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &signing_public_key,
    )
    .unwrap();
    let valid_receiver_record =
        wa_core::process_signal_sender_key_distribution_record(None, &distribution).unwrap();
    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &valid_receiver_record)
        .await
        .unwrap();
    let sender_record = wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
        states: vec![wa_core::SignalSenderKeyState {
            key_id,
            chain_key: wa_core::SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            },
            signing_public_key: signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    })
    .unwrap();
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn group sender-key hello".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        4,
    );
    let encrypted =
        wa_core::encrypt_signal_sender_key_record_message(&sender_record, &plaintext).unwrap();
    let mismatched_private_key = generate_key_pair();
    let invalid_records = vec![
        (
            "mismatched-signing-key",
            raw_client_sender_key_record(vec![raw_client_sender_key_state(
                key_id,
                0,
                0x10,
                signing_public_key.clone(),
                Some(Bytes::copy_from_slice(
                    mismatched_private_key.private.expose(),
                )),
                &[],
            )]),
        ),
        (
            "duplicate-state",
            raw_client_sender_key_record(vec![
                raw_client_sender_key_state(key_id, 0, 0x11, signing_public_key.clone(), None, &[]),
                raw_client_sender_key_state(key_id, 1, 0x12, signing_public_key.clone(), None, &[]),
            ]),
        ),
        (
            "duplicate-skipped-iteration",
            raw_client_sender_key_record(vec![raw_client_sender_key_state(
                key_id,
                3,
                0x13,
                signing_public_key.clone(),
                None,
                &[(1, 0x21), (1, 0x22)],
            )]),
        ),
        (
            "future-skipped-iteration",
            raw_client_sender_key_record(vec![raw_client_sender_key_state(
                key_id,
                3,
                0x14,
                signing_public_key,
                None,
                &[(3, 0x23)],
            )]),
        ),
    ];
    let incoming_node = |id: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", group_jid)
            .with_attr("participant", sender_jid)
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "skmsg")
                    .with_content(ciphertext),
            ])
    };
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

    for (suffix, invalid_receiver_record) in invalid_records {
        client
            .signal_provider_state_store()
            .store_sender_key_record(&record_key, &invalid_receiver_record)
            .await
            .unwrap();
        let invalid_id = format!("signal-spawn-group-invalid-sender-key-{suffix}");
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&incoming_node(&invalid_id, encrypted.message_bytes.clone()))
                    .unwrap(),
            ))
            .await
            .unwrap();
        let invalid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(invalid_ack.tag, "ack");
        assert_eq!(invalid_ack.attrs["id"], invalid_id);
        assert_eq!(invalid_ack.attrs["class"], "message");
        assert_eq!(invalid_ack.attrs["to"], group_jid);
        assert_eq!(invalid_ack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(invalid_ack.attrs["participant"], sender_jid);
        assert_eq!(
            invalid_ack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event, Event::Batch(_)),
                "invalid sender-key record must not emit a typed batch"
            );
        }
        assert_eq!(
            client
                .signal_provider_state_store()
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            invalid_receiver_record
        );
    }

    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &valid_receiver_record)
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-group-valid-sender-key",
                encrypted.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(valid_ack.attrs["id"], "signal-spawn-group-valid-sender-key");
    assert_eq!(valid_ack.attrs["class"], "message");
    assert_eq!(valid_ack.attrs["to"], group_jid);
    assert_eq!(valid_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(valid_ack.attrs["participant"], sender_jid);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-group-valid-sender-key"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn group sender-key hello")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    let updated_record = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(updated_record, valid_receiver_record);
    assert_eq!(
        wa_core::decode_signal_sender_key_record(&updated_record)
            .unwrap()
            .states[0]
            .chain_key
            .iteration,
        1
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_preserves_state_after_offline_invalid_sender_key_record()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "555@g.us";
    let sender_jid = "123:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let key_id = 77;
    let chain_key = [7u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &signing_public_key,
    )
    .unwrap();
    let valid_receiver_record =
        wa_core::process_signal_sender_key_distribution_record(None, &distribution).unwrap();
    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &valid_receiver_record)
        .await
        .unwrap();
    let sender_record = wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
        states: vec![wa_core::SignalSenderKeyState {
            key_id,
            chain_key: wa_core::SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            },
            signing_public_key: signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    })
    .unwrap();
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline group sender-key hello".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        4,
    );
    let encrypted =
        wa_core::encrypt_signal_sender_key_record_message(&sender_record, &plaintext).unwrap();
    let mismatched_private_key = generate_key_pair();
    let invalid_records = vec![
        (
            "mismatched-signing-key",
            raw_client_sender_key_record(vec![raw_client_sender_key_state(
                key_id,
                0,
                0x10,
                signing_public_key.clone(),
                Some(Bytes::copy_from_slice(
                    mismatched_private_key.private.expose(),
                )),
                &[],
            )]),
        ),
        (
            "duplicate-state",
            raw_client_sender_key_record(vec![
                raw_client_sender_key_state(key_id, 0, 0x11, signing_public_key.clone(), None, &[]),
                raw_client_sender_key_state(key_id, 1, 0x12, signing_public_key.clone(), None, &[]),
            ]),
        ),
        (
            "duplicate-skipped-iteration",
            raw_client_sender_key_record(vec![raw_client_sender_key_state(
                key_id,
                3,
                0x13,
                signing_public_key.clone(),
                None,
                &[(1, 0x21), (1, 0x22)],
            )]),
        ),
        (
            "future-skipped-iteration",
            raw_client_sender_key_record(vec![raw_client_sender_key_state(
                key_id,
                3,
                0x14,
                signing_public_key,
                None,
                &[(3, 0x23)],
            )]),
        ),
    ];
    let incoming_node = |id: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", group_jid)
            .with_attr("participant", sender_jid)
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "skmsg")
                    .with_content(ciphertext),
            ])
    };
    let offline_node = |child: BinaryNode| BinaryNode::new("offline").with_content(vec![child]);
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

    for (suffix, invalid_receiver_record) in invalid_records {
        client
            .signal_provider_state_store()
            .store_sender_key_record(&record_key, &invalid_receiver_record)
            .await
            .unwrap();
        let invalid_id = format!("signal-spawn-offline-group-invalid-sender-key-{suffix}");
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&offline_node(incoming_node(
                    &invalid_id,
                    encrypted.message_bytes.clone(),
                )))
                .unwrap(),
            ))
            .await
            .unwrap();
        let invalid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(invalid_ack.tag, "ack");
        assert_eq!(invalid_ack.attrs["id"], invalid_id);
        assert_eq!(invalid_ack.attrs["class"], "message");
        assert_eq!(invalid_ack.attrs["to"], group_jid);
        assert_eq!(invalid_ack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(invalid_ack.attrs["participant"], sender_jid);
        assert_eq!(
            invalid_ack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event, Event::Batch(_)),
                "offline invalid sender-key record must not emit a typed batch"
            );
        }
        assert_eq!(
            client
                .signal_provider_state_store()
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            invalid_receiver_record
        );
    }

    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &valid_receiver_record)
        .await
        .unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-group-valid-sender-key",
                encrypted.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(
        valid_ack.attrs["id"],
        "signal-spawn-offline-group-valid-sender-key"
    );
    assert_eq!(valid_ack.attrs["class"], "message");
    assert_eq!(valid_ack.attrs["to"], group_jid);
    assert_eq!(valid_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(valid_ack.attrs["participant"], sender_jid);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-group-valid-sender-key"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline group sender-key hello")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    let updated_record = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(updated_record, valid_receiver_record);
    assert_eq!(
        wa_core::decode_signal_sender_key_record(&updated_record)
            .unwrap()
            .states[0]
            .chain_key
            .iteration,
        1
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_out_of_order_sender_key_messages() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "556@g.us";
    let sender_jid = "124:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let key_id = 78;
    let chain_key = [8u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &signing_public_key,
    )
    .unwrap();
    let receiver_record =
        wa_core::process_signal_sender_key_distribution_record(None, &distribution).unwrap();
    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &receiver_record)
        .await
        .unwrap();
    let sender_record = wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
        states: vec![wa_core::SignalSenderKeyState {
            key_id,
            chain_key: wa_core::SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            },
            signing_public_key,
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    })
    .unwrap();
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
    let first = wa_core::encrypt_signal_sender_key_record_message(
        &sender_record,
        &text_plaintext("spawn group sender-key first", 4),
    )
    .unwrap();
    assert_eq!(first.message.iteration, 0);
    let second = wa_core::encrypt_signal_sender_key_record_message(
        &first.record,
        &text_plaintext("spawn group sender-key second", 5),
    )
    .unwrap();
    assert_eq!(second.message.iteration, 1);
    let incoming_node = |id: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", group_jid)
            .with_attr("participant", sender_jid)
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "skmsg")
                    .with_content(ciphertext),
            ])
    };
    let assert_message_ack = |ack: &BinaryNode, id: &str| {
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], id);
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], group_jid);
        assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(ack.attrs["participant"], sender_jid);
    };

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
                "signal-spawn-group-ooo-2",
                second.message_bytes.clone(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&second_ack, "signal-spawn-group-ooo-2");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(second_batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        second_batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-group-ooo-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn group sender-key second")
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
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let decoded_after_second =
        wa_core::decode_signal_sender_key_record(&record_after_second).unwrap();
    assert_eq!(decoded_after_second.states[0].chain_key.iteration, 2);
    assert_eq!(
        decoded_after_second.states[0]
            .message_keys
            .iter()
            .map(|message_key| message_key.iteration)
            .collect::<Vec<_>>(),
        vec![0]
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-group-ooo-2-replay",
                second.message_bytes.clone(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&second_replay_nack, "signal-spawn-group-ooo-2-replay");
    assert_eq!(
        second_replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "consumed sender-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let mut invalid_first_signature = first.message_bytes.to_vec();
    *invalid_first_signature
        .last_mut()
        .expect("sender-key message has signature bytes") ^= 1;
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-group-ooo-1-invalid-signature",
                Bytes::from(invalid_first_signature),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let invalid_first_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(
        &invalid_first_nack,
        "signal-spawn-group-ooo-1-invalid-signature",
    );
    assert_eq!(
        invalid_first_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "invalid-signature skipped sender-key decrypt must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let mut failed_first_ciphertext = first.message.ciphertext.to_vec();
    failed_first_ciphertext
        .pop()
        .expect("sender-key ciphertext has bytes");
    let failed_first = wa_core::sign_signal_sender_key_message(
        key_id,
        first.message.iteration,
        Bytes::from(failed_first_ciphertext),
        signing_key.private.expose(),
    )
    .unwrap();
    let failed_first = wa_core::encode_signal_sender_key_message(&failed_first).unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-group-ooo-1-failed",
                failed_first,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let failed_first_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&failed_first_nack, "signal-spawn-group-ooo-1-failed");
    assert_eq!(
        failed_first_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "failed skipped sender-key decrypt must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-group-ooo-1",
                first.message_bytes.clone(),
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&first_ack, "signal-spawn-group-ooo-1");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(first_batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        first_batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-group-ooo-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn group sender-key first")
    );
    let stored_first_key = wa_core::message_event_store_key(&first_batch.messages_upsert[0].key);
    let stored_first = store
        .get(KeyNamespace::MessageEvent, &stored_first_key)
        .await
        .unwrap()
        .unwrap();
    let stored_first = wa_core::decode_stored_message_event(&stored_first).unwrap();
    assert_eq!(stored_first, first_batch.messages_upsert[0]);
    let record_after_first = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let decoded_after_first =
        wa_core::decode_signal_sender_key_record(&record_after_first).unwrap();
    assert_eq!(decoded_after_first.states[0].chain_key.iteration, 2);
    assert!(decoded_after_first.states[0].message_keys.is_empty());

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-group-ooo-1-replay",
                first.message_bytes,
            ))
            .unwrap(),
        ))
        .await
        .unwrap();
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&replay_nack, "signal-spawn-group-ooo-1-replay");
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "sender-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_offline_out_of_order_sender_key_messages()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "556@g.us";
    let sender_jid = "124:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let key_id = 78;
    let chain_key = [8u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &signing_public_key,
    )
    .unwrap();
    let receiver_record =
        wa_core::process_signal_sender_key_distribution_record(None, &distribution).unwrap();
    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &receiver_record)
        .await
        .unwrap();
    let sender_record = wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
        states: vec![wa_core::SignalSenderKeyState {
            key_id,
            chain_key: wa_core::SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            },
            signing_public_key,
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    })
    .unwrap();
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
    let first = wa_core::encrypt_signal_sender_key_record_message(
        &sender_record,
        &text_plaintext("spawn offline group sender-key first", 4),
    )
    .unwrap();
    assert_eq!(first.message.iteration, 0);
    let second = wa_core::encrypt_signal_sender_key_record_message(
        &first.record,
        &text_plaintext("spawn offline group sender-key second", 5),
    )
    .unwrap();
    assert_eq!(second.message.iteration, 1);
    let incoming_node = |id: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", group_jid)
            .with_attr("participant", sender_jid)
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "skmsg")
                    .with_content(ciphertext),
            ])
    };
    let offline_node = |child: BinaryNode| BinaryNode::new("offline").with_content(vec![child]);
    let assert_message_ack = |ack: &BinaryNode, id: &str| {
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], id);
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], group_jid);
        assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(ack.attrs["participant"], sender_jid);
    };

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
                "signal-spawn-offline-group-ooo-2",
                second.message_bytes.clone(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&second_ack, "signal-spawn-offline-group-ooo-2");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(second_batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        second_batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-group-ooo-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline group sender-key second")
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
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let decoded_after_second =
        wa_core::decode_signal_sender_key_record(&record_after_second).unwrap();
    assert_eq!(decoded_after_second.states[0].chain_key.iteration, 2);
    assert_eq!(
        decoded_after_second.states[0]
            .message_keys
            .iter()
            .map(|message_key| message_key.iteration)
            .collect::<Vec<_>>(),
        vec![0]
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-group-ooo-2-replay",
                second.message_bytes.clone(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let second_replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(
        &second_replay_nack,
        "signal-spawn-offline-group-ooo-2-replay",
    );
    assert_eq!(
        second_replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline consumed sender-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let mut invalid_first_signature = first.message_bytes.to_vec();
    *invalid_first_signature
        .last_mut()
        .expect("sender-key message has signature bytes") ^= 1;
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-group-ooo-1-invalid-signature",
                Bytes::from(invalid_first_signature),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let invalid_first_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(
        &invalid_first_nack,
        "signal-spawn-offline-group-ooo-1-invalid-signature",
    );
    assert_eq!(
        invalid_first_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline invalid-signature skipped sender-key decrypt must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let mut failed_first_ciphertext = first.message.ciphertext.to_vec();
    failed_first_ciphertext
        .pop()
        .expect("sender-key ciphertext has bytes");
    let failed_first = wa_core::sign_signal_sender_key_message(
        key_id,
        first.message.iteration,
        Bytes::from(failed_first_ciphertext),
        signing_key.private.expose(),
    )
    .unwrap();
    let failed_first = wa_core::encode_signal_sender_key_message(&failed_first).unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-group-ooo-1-failed",
                failed_first,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let failed_first_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(
        &failed_first_nack,
        "signal-spawn-offline-group-ooo-1-failed",
    );
    assert_eq!(
        failed_first_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline failed skipped sender-key decrypt must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-group-ooo-1",
                first.message_bytes.clone(),
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&first_ack, "signal-spawn-offline-group-ooo-1");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(first_batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        first_batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-group-ooo-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn offline group sender-key first")
    );
    let stored_first_key = wa_core::message_event_store_key(&first_batch.messages_upsert[0].key);
    let stored_first = store
        .get(KeyNamespace::MessageEvent, &stored_first_key)
        .await
        .unwrap()
        .unwrap();
    let stored_first = wa_core::decode_stored_message_event(&stored_first).unwrap();
    assert_eq!(stored_first, first_batch.messages_upsert[0]);
    let record_after_first = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let decoded_after_first =
        wa_core::decode_signal_sender_key_record(&record_after_first).unwrap();
    assert_eq!(decoded_after_first.states[0].chain_key.iteration, 2);
    assert!(decoded_after_first.states[0].message_keys.is_empty());

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&offline_node(incoming_node(
                "signal-spawn-offline-group-ooo-1-replay",
                first.message_bytes,
            )))
            .unwrap(),
        ))
        .await
        .unwrap();
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&replay_nack, "signal-spawn-offline-group-ooo-1-replay");
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "offline sender-key replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_recovers_sender_key_record_from_distribution() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "557@g.us";
    let sender_jid = "125:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let key_id = 79;
    let chain_key = [9u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &signing_public_key,
    )
    .unwrap();
    let distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&distribution).unwrap();
    let repository = client.signal_repository();
    repository
        .store_sender_key_distribution(sender_jid, group_jid, distribution_bytes.clone())
        .await
        .unwrap();
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(distribution_bytes.clone())
    );

    let sender_record = wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
        states: vec![wa_core::SignalSenderKeyState {
            key_id,
            chain_key: wa_core::SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            },
            signing_public_key,
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    })
    .unwrap();
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
    let first = wa_core::encrypt_signal_sender_key_record_message(
        &sender_record,
        &text_plaintext("spawn group distribution first", 4),
    )
    .unwrap();
    let second = wa_core::encrypt_signal_sender_key_record_message(
        &first.record,
        &text_plaintext("spawn group distribution second", 5),
    )
    .unwrap();
    let third = wa_core::encrypt_signal_sender_key_record_message(
        &second.record,
        &text_plaintext("spawn group distribution third", 6),
    )
    .unwrap();
    let incoming_node = |id: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", group_jid)
            .with_attr("participant", sender_jid)
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "skmsg")
                    .with_content(ciphertext),
            ])
    };
    let assert_message_ack = |ack: &BinaryNode, id: &str| {
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], id);
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], group_jid);
        assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(ack.attrs["participant"], sender_jid);
    };

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

    for (id, encrypted, expected_text, expected_iteration, expected_skipped) in [
        (
            "signal-spawn-group-distribution-missing",
            first.message_bytes.clone(),
            "spawn group distribution first",
            1,
            Vec::<u32>::new(),
        ),
        (
            "signal-spawn-group-distribution-deleted",
            second.message_bytes.clone(),
            "spawn group distribution second",
            2,
            vec![0],
        ),
        (
            "signal-spawn-group-distribution-corrupt",
            third.message_bytes.clone(),
            "spawn group distribution third",
            3,
            vec![0, 1],
        ),
    ] {
        if id.ends_with("deleted") {
            assert!(
                client
                    .signal_provider_state_store()
                    .delete_sender_key_record(&record_key)
                    .await
                    .unwrap()
            );
        } else if id.ends_with("corrupt") {
            client
                .signal_provider_state_store()
                .store_sender_key_record(&record_key, b"opaque-provider-sender-key")
                .await
                .unwrap();
        }

        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&incoming_node(id, encrypted.clone())).unwrap(),
            ))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&ack, id);
        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.remote_jid, group_jid);
        assert_eq!(
            batch.messages_upsert[0].key.participant.as_deref(),
            Some(sender_jid)
        );
        assert_eq!(batch.messages_upsert[0].key.id, id);
        let payload = batch.messages_upsert[0].payload.clone().unwrap();
        let decoded = wa_proto::proto::Message::decode(payload).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some(expected_text));
        let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
        let stored = store
            .get(KeyNamespace::MessageEvent, &stored_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_message_event(&stored).unwrap();
        assert_eq!(stored, batch.messages_upsert[0]);
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );
        let stored_record = client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap();
        let decoded_record = wa_core::decode_signal_sender_key_record(&stored_record).unwrap();
        assert_eq!(
            decoded_record.states[0].chain_key.iteration,
            expected_iteration
        );
        assert_eq!(
            decoded_record.states[0]
                .message_keys
                .iter()
                .map(|message_key| message_key.iteration)
                .collect::<Vec<_>>(),
            expected_skipped
        );

        let invalid_signature_id = format!("{id}-invalid-signature");
        let mut invalid_signature = encrypted.to_vec();
        *invalid_signature
            .last_mut()
            .expect("sender-key message has signature bytes") ^= 1;
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&incoming_node(
                    &invalid_signature_id,
                    Bytes::from(invalid_signature),
                ))
                .unwrap(),
            ))
            .await
            .unwrap();
        let invalid_signature_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&invalid_signature_nack, &invalid_signature_id);
        assert_eq!(
            invalid_signature_nack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event, Event::Batch(_)),
                "sender-key distribution recovery invalid signature must not emit a typed batch"
            );
        }
        assert_eq!(
            client
                .signal_provider_state_store()
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            stored_record
        );
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );

        let replay_id = format!("{id}-replay");
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&incoming_node(&replay_id, encrypted)).unwrap(),
            ))
            .await
            .unwrap();
        let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&replay_nack, &replay_id);
        assert_eq!(
            replay_nack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event, Event::Batch(_)),
                "sender-key distribution recovery replay must not emit a typed batch"
            );
        }
        assert_eq!(
            client
                .signal_provider_state_store()
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            stored_record
        );
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );
    }
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_recovers_offline_sender_key_record_from_distribution()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "557@g.us";
    let sender_jid = "125:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let key_id = 79;
    let chain_key = [9u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &signing_public_key,
    )
    .unwrap();
    let distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&distribution).unwrap();
    let repository = client.signal_repository();
    repository
        .store_sender_key_distribution(sender_jid, group_jid, distribution_bytes.clone())
        .await
        .unwrap();
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(distribution_bytes.clone())
    );

    let sender_record = wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
        states: vec![wa_core::SignalSenderKeyState {
            key_id,
            chain_key: wa_core::SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            },
            signing_public_key,
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    })
    .unwrap();
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
    let first = wa_core::encrypt_signal_sender_key_record_message(
        &sender_record,
        &text_plaintext("spawn offline group distribution first", 4),
    )
    .unwrap();
    let second = wa_core::encrypt_signal_sender_key_record_message(
        &first.record,
        &text_plaintext("spawn offline group distribution second", 5),
    )
    .unwrap();
    let third = wa_core::encrypt_signal_sender_key_record_message(
        &second.record,
        &text_plaintext("spawn offline group distribution third", 6),
    )
    .unwrap();
    let incoming_node = |id: &str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", group_jid)
            .with_attr("participant", sender_jid)
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "skmsg")
                    .with_content(ciphertext),
            ])
    };
    let offline_node = |child: BinaryNode| BinaryNode::new("offline").with_content(vec![child]);
    let assert_message_ack = |ack: &BinaryNode, id: &str| {
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], id);
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], group_jid);
        assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(ack.attrs["participant"], sender_jid);
    };

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

    for (id, encrypted, expected_text, expected_iteration, expected_skipped) in [
        (
            "signal-spawn-offline-group-distribution-missing",
            first.message_bytes.clone(),
            "spawn offline group distribution first",
            1,
            Vec::<u32>::new(),
        ),
        (
            "signal-spawn-offline-group-distribution-deleted",
            second.message_bytes.clone(),
            "spawn offline group distribution second",
            2,
            vec![0],
        ),
        (
            "signal-spawn-offline-group-distribution-corrupt",
            third.message_bytes.clone(),
            "spawn offline group distribution third",
            3,
            vec![0, 1],
        ),
    ] {
        if id.ends_with("deleted") {
            assert!(
                client
                    .signal_provider_state_store()
                    .delete_sender_key_record(&record_key)
                    .await
                    .unwrap()
            );
        } else if id.ends_with("corrupt") {
            client
                .signal_provider_state_store()
                .store_sender_key_record(&record_key, b"opaque-provider-sender-key")
                .await
                .unwrap();
        }

        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&offline_node(incoming_node(id, encrypted.clone()))).unwrap(),
            ))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&ack, id);
        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.remote_jid, group_jid);
        assert_eq!(
            batch.messages_upsert[0].key.participant.as_deref(),
            Some(sender_jid)
        );
        assert_eq!(batch.messages_upsert[0].key.id, id);
        let payload = batch.messages_upsert[0].payload.clone().unwrap();
        let decoded = wa_proto::proto::Message::decode(payload).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some(expected_text));
        let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
        let stored = store
            .get(KeyNamespace::MessageEvent, &stored_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_message_event(&stored).unwrap();
        assert_eq!(stored, batch.messages_upsert[0]);
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );
        let stored_record = client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap();
        let decoded_record = wa_core::decode_signal_sender_key_record(&stored_record).unwrap();
        assert_eq!(
            decoded_record.states[0].chain_key.iteration,
            expected_iteration
        );
        assert_eq!(
            decoded_record.states[0]
                .message_keys
                .iter()
                .map(|message_key| message_key.iteration)
                .collect::<Vec<_>>(),
            expected_skipped
        );

        let invalid_signature_id = format!("{id}-invalid-signature");
        let mut invalid_signature = encrypted.to_vec();
        *invalid_signature
            .last_mut()
            .expect("sender-key message has signature bytes") ^= 1;
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&offline_node(incoming_node(
                    &invalid_signature_id,
                    Bytes::from(invalid_signature),
                )))
                .unwrap(),
            ))
            .await
            .unwrap();
        let invalid_signature_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&invalid_signature_nack, &invalid_signature_id);
        assert_eq!(
            invalid_signature_nack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event, Event::Batch(_)),
                "offline sender-key distribution recovery invalid signature must not emit a typed batch"
            );
        }
        assert_eq!(
            client
                .signal_provider_state_store()
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            stored_record
        );
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );

        let replay_id = format!("{id}-replay");
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&offline_node(incoming_node(&replay_id, encrypted))).unwrap(),
            ))
            .await
            .unwrap();
        let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&replay_nack, &replay_id);
        assert_eq!(
            replay_nack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event, Event::Batch(_)),
                "offline sender-key distribution recovery replay must not emit a typed batch"
            );
        }
        assert_eq!(
            client
                .signal_provider_state_store()
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            stored_record
        );
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );
    }
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_recovers_stale_sender_key_record_from_distribution()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "558@g.us";
    let sender_jid = "126:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let stale_signing_key = generate_key_pair();
    let stale_distribution = wa_core::build_signal_sender_key_distribution_message(
        80,
        0,
        &[10u8; 32],
        &prefixed_signal_public_key(&stale_signing_key.public),
    )
    .unwrap();
    let stale_record =
        wa_core::process_signal_sender_key_distribution_record(None, &stale_distribution).unwrap();
    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &stale_record)
        .await
        .unwrap();

    let fresh_signing_key = generate_key_pair();
    let fresh_signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&fresh_signing_key.public));
    let fresh_key_id = 81;
    let fresh_chain_key = [11u8; 32];
    let fresh_distribution = wa_core::build_signal_sender_key_distribution_message(
        fresh_key_id,
        0,
        &fresh_chain_key,
        &fresh_signing_public_key,
    )
    .unwrap();
    let fresh_distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&fresh_distribution).unwrap();
    let repository = client.signal_repository();
    repository
        .store_sender_key_distribution(sender_jid, group_jid, fresh_distribution_bytes.clone())
        .await
        .unwrap();
    let fresh_sender_record =
        wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
            states: vec![wa_core::SignalSenderKeyState {
                key_id: fresh_key_id,
                chain_key: wa_core::SignalSenderChainKey {
                    key: SecretBytes::from(fresh_chain_key.to_vec()),
                    iteration: 0,
                },
                signing_public_key: fresh_signing_public_key.clone(),
                signing_private_key: Some(SecretBytes::from(
                    fresh_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn group stale distribution recovered".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        4,
    );
    let encrypted =
        wa_core::encrypt_signal_sender_key_record_message(&fresh_sender_record, &plaintext)
            .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-group-stale-distribution-recovery")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(encrypted.message_bytes.clone()),
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
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-group-stale-distribution-recovery"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], group_jid);
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], sender_jid);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-group-stale-distribution-recovery"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn group stale distribution recovered")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fresh_distribution_bytes.clone())
    );
    let repaired_bytes = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let repaired = wa_core::decode_signal_sender_key_record(&repaired_bytes).unwrap();
    assert_eq!(repaired.states.len(), 2);
    assert_eq!(repaired.states[0].key_id, fresh_key_id);
    assert_eq!(repaired.states[0].chain_key.iteration, 1);
    assert_eq!(
        repaired.states[0].signing_public_key,
        fresh_distribution.signing_key
    );
    assert_eq!(repaired.states[1].key_id, stale_distribution.key_id);
    assert_eq!(
        repaired.states[1].signing_public_key,
        stale_distribution.signing_key
    );

    let mut invalid_signature = encrypted.message_bytes.to_vec();
    *invalid_signature
        .last_mut()
        .expect("sender-key message has signature bytes") ^= 1;
    let invalid_signature = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-group-stale-distribution-recovery-invalid-signature",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(Bytes::from(invalid_signature)),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&invalid_signature).unwrap(),
        ))
        .await
        .unwrap();
    let invalid_signature_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_signature_nack.tag, "ack");
    assert_eq!(
        invalid_signature_nack.attrs["id"],
        "signal-spawn-group-stale-distribution-recovery-invalid-signature"
    );
    assert_eq!(invalid_signature_nack.attrs["class"], "message");
    assert_eq!(invalid_signature_nack.attrs["to"], group_jid);
    assert_eq!(invalid_signature_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(invalid_signature_nack.attrs["participant"], sender_jid);
    assert_eq!(
        invalid_signature_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "spawn stale sender-key distribution invalid signature must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        repaired_bytes
    );
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fresh_distribution_bytes.clone())
    );

    let replay = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-group-stale-distribution-recovery-replay",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(encrypted.message_bytes),
        ]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&replay).unwrap()))
        .await
        .unwrap();
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(
        replay_nack.attrs["id"],
        "signal-spawn-group-stale-distribution-recovery-replay"
    );
    assert_eq!(replay_nack.attrs["class"], "message");
    assert_eq!(replay_nack.attrs["to"], group_jid);
    assert_eq!(replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(replay_nack.attrs["participant"], sender_jid);
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "spawn stale sender-key distribution replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        repaired_bytes
    );
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fresh_distribution_bytes)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_recovers_offline_stale_sender_key_record_from_distribution()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "558@g.us";
    let sender_jid = "126:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{sender_jid}");
    let stale_signing_key = generate_key_pair();
    let stale_distribution = wa_core::build_signal_sender_key_distribution_message(
        80,
        0,
        &[10u8; 32],
        &prefixed_signal_public_key(&stale_signing_key.public),
    )
    .unwrap();
    let stale_record =
        wa_core::process_signal_sender_key_distribution_record(None, &stale_distribution).unwrap();
    client
        .signal_provider_state_store()
        .store_sender_key_record(&record_key, &stale_record)
        .await
        .unwrap();

    let fresh_signing_key = generate_key_pair();
    let fresh_signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&fresh_signing_key.public));
    let fresh_key_id = 81;
    let fresh_chain_key = [11u8; 32];
    let fresh_distribution = wa_core::build_signal_sender_key_distribution_message(
        fresh_key_id,
        0,
        &fresh_chain_key,
        &fresh_signing_public_key,
    )
    .unwrap();
    let fresh_distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&fresh_distribution).unwrap();
    let repository = client.signal_repository();
    repository
        .store_sender_key_distribution(sender_jid, group_jid, fresh_distribution_bytes.clone())
        .await
        .unwrap();
    let fresh_sender_record =
        wa_core::encode_signal_sender_key_record(&wa_core::SignalSenderKeyRecord {
            states: vec![wa_core::SignalSenderKeyState {
                key_id: fresh_key_id,
                chain_key: wa_core::SignalSenderChainKey {
                    key: SecretBytes::from(fresh_chain_key.to_vec()),
                    iteration: 0,
                },
                signing_public_key: fresh_signing_public_key.clone(),
                signing_private_key: Some(SecretBytes::from(
                    fresh_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline group stale distribution recovered".to_owned()),
                ..wa_proto::proto::Message::default()
            }
            .encode_to_vec(),
        ),
        4,
    );
    let encrypted =
        wa_core::encrypt_signal_sender_key_record_message(&fresh_sender_record, &plaintext)
            .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-group-stale-distribution-recovery",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(encrypted.message_bytes.clone()),
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
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-group-stale-distribution-recovery"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], group_jid);
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], sender_jid);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-group-stale-distribution-recovery"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline group stale distribution recovered")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fresh_distribution_bytes.clone())
    );
    let repaired_bytes = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let repaired = wa_core::decode_signal_sender_key_record(&repaired_bytes).unwrap();
    assert_eq!(repaired.states.len(), 2);
    assert_eq!(repaired.states[0].key_id, fresh_key_id);
    assert_eq!(repaired.states[0].chain_key.iteration, 1);
    assert_eq!(
        repaired.states[0].signing_public_key,
        fresh_distribution.signing_key
    );
    assert_eq!(repaired.states[1].key_id, stale_distribution.key_id);
    assert_eq!(
        repaired.states[1].signing_public_key,
        stale_distribution.signing_key
    );

    let mut invalid_signature = encrypted.message_bytes.to_vec();
    *invalid_signature
        .last_mut()
        .expect("sender-key message has signature bytes") ^= 1;
    let invalid_signature = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-group-stale-distribution-recovery-invalid-signature",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(Bytes::from(invalid_signature)),
        ]);
    let invalid_signature = BinaryNode::new("offline").with_content(vec![invalid_signature]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&invalid_signature).unwrap(),
        ))
        .await
        .unwrap();
    let invalid_signature_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_signature_nack.tag, "ack");
    assert_eq!(
        invalid_signature_nack.attrs["id"],
        "signal-spawn-offline-group-stale-distribution-recovery-invalid-signature"
    );
    assert_eq!(invalid_signature_nack.attrs["class"], "message");
    assert_eq!(invalid_signature_nack.attrs["to"], group_jid);
    assert_eq!(invalid_signature_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(invalid_signature_nack.attrs["participant"], sender_jid);
    assert_eq!(
        invalid_signature_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "spawn offline stale sender-key distribution invalid signature must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        repaired_bytes
    );
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fresh_distribution_bytes.clone())
    );

    let replay = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-group-stale-distribution-recovery-replay",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(encrypted.message_bytes),
        ]);
    let replay = BinaryNode::new("offline").with_content(vec![replay]);
    stream_tx
        .send(InboundFrame::new(encode_binary_node(&replay).unwrap()))
        .await
        .unwrap();
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(
        replay_nack.attrs["id"],
        "signal-spawn-offline-group-stale-distribution-recovery-replay"
    );
    assert_eq!(replay_nack.attrs["class"], "message");
    assert_eq!(replay_nack.attrs["to"], group_jid);
    assert_eq!(replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(replay_nack.attrs["participant"], sender_jid);
    assert_eq!(
        replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "spawn offline stale sender-key distribution replay must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        repaired_bytes
    );
    assert_eq!(
        repository
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fresh_distribution_bytes)
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_canonicalizes_legacy_sender_key_distribution_message()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "559@g.us";
    let sender_jid = "127:7@c.us";
    let canonical_sender_jid = "127:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{canonical_sender_jid}");
    let legacy_record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let fast_signing_key = generate_key_pair();
    let key_id = 82;
    let fast_key_id = 83;
    let chain_key = [12u8; 32];
    let fast_chain_key = [13u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &prefixed_signal_public_key(&signing_key.public),
    )
    .unwrap();
    let distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&distribution).unwrap();
    let fast_distribution = wa_core::build_signal_sender_key_distribution_message(
        fast_key_id,
        0,
        &fast_chain_key,
        &prefixed_signal_public_key(&fast_signing_key.public),
    )
    .unwrap();
    let fast_distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&fast_distribution).unwrap();
    let message = wa_proto::proto::Message {
        conversation: Some("spawn group sender-key distribution".to_owned()),
        sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(distribution_bytes),
            },
        ),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(fast_distribution_bytes.clone()),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-group-distribution-message")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(message.encode_to_vec())),
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
    assert_eq!(ack.attrs["id"], "signal-spawn-group-distribution-message");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], group_jid);
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], canonical_sender_jid);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    let event = &batch.messages_upsert[0];
    assert_eq!(event.key.remote_jid, group_jid);
    assert_eq!(event.key.participant.as_deref(), Some(canonical_sender_jid));
    assert_eq!(event.key.id, "signal-spawn-group-distribution-message");
    assert_eq!(event.fields["payload_kind"], "plaintext");
    assert_eq!(event.fields["sender_key_distribution_count"], "2");
    let payload = event.payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn group sender-key distribution")
    );
    assert!(decoded.sender_key_distribution_message.is_some());
    assert!(
        decoded
            .fast_ratchet_key_sender_key_distribution_message
            .is_some()
    );
    let stored_key = wa_core::message_event_store_key(&event.key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, *event);
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fast_distribution_bytes.clone())
    );
    let stored_record = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let stored_record = wa_core::decode_signal_sender_key_record(&stored_record).unwrap();
    assert_eq!(stored_record.states.len(), 2);
    assert_eq!(stored_record.states[0].key_id, fast_key_id);
    assert_eq!(stored_record.states[0].chain_key.iteration, 0);
    assert_eq!(
        stored_record.states[0].chain_key.key.expose(),
        fast_distribution.chain_key.expose()
    );
    assert_eq!(
        stored_record.states[0].signing_public_key,
        fast_distribution.signing_key
    );
    assert_eq!(stored_record.states[0].signing_private_key, None);
    assert_eq!(stored_record.states[1].key_id, key_id);
    assert_eq!(stored_record.states[1].chain_key.iteration, 0);
    assert_eq!(
        stored_record.states[1].chain_key.key.expose(),
        distribution.chain_key.expose()
    );
    assert_eq!(
        stored_record.states[1].signing_public_key,
        distribution.signing_key
    );
    assert_eq!(stored_record.states[1].signing_private_key, None);
    assert!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&legacy_record_key)
            .await
            .unwrap()
            .is_none()
    );

    let advanced_fast_distribution = wa_core::build_signal_sender_key_distribution_message(
        fast_key_id,
        5,
        &[14u8; 32],
        &fast_signing_key.public,
    )
    .unwrap();
    let advanced_fast_distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&advanced_fast_distribution)
            .unwrap();
    let advanced_message = wa_proto::proto::Message {
        conversation: Some("spawn group sender-key distribution advance".to_owned()),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(
                    advanced_fast_distribution_bytes.clone(),
                ),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let advanced_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-group-distribution-message-advance")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext")
                .with_content(Bytes::from(advanced_message.encode_to_vec())),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&advanced_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let advanced_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(advanced_ack.tag, "ack");
    assert_eq!(
        advanced_ack.attrs["id"],
        "signal-spawn-group-distribution-message-advance"
    );
    assert_eq!(advanced_ack.attrs["class"], "message");
    assert_eq!(advanced_ack.attrs["to"], group_jid);
    assert_eq!(advanced_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(advanced_ack.attrs["participant"], canonical_sender_jid);
    let advanced_batch = recv_batch_event(&mut events).await;
    assert_eq!(advanced_batch.messages_upsert.len(), 1);
    assert_eq!(
        advanced_batch.messages_upsert[0].key.id,
        "signal-spawn-group-distribution-message-advance"
    );
    assert_eq!(
        advanced_batch.messages_upsert[0].fields["sender_key_distribution_count"],
        "1"
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    let advanced_record_bytes = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let advanced_record = wa_core::decode_signal_sender_key_record(&advanced_record_bytes).unwrap();
    assert_eq!(advanced_record.states.len(), 2);
    assert_eq!(advanced_record.states[0].key_id, fast_key_id);
    assert_eq!(advanced_record.states[0].chain_key.iteration, 5);
    assert_eq!(
        advanced_record.states[0].chain_key.key.expose(),
        advanced_fast_distribution.chain_key.expose()
    );
    assert_eq!(advanced_record.states[1], stored_record.states[1]);

    let invalid_distribution_message = wa_proto::proto::Message {
        conversation: Some("spawn group sender-key distribution invalid".to_owned()),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(Bytes::from_static(
                    b"invalid-sender-key-distribution",
                )),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let invalid_distribution_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-group-distribution-message-invalid")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![BinaryNode::new("plaintext").with_content(
            Bytes::from(invalid_distribution_message.encode_to_vec()),
        )]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&invalid_distribution_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let invalid_distribution_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_distribution_nack.tag, "ack");
    assert_eq!(
        invalid_distribution_nack.attrs["id"],
        "signal-spawn-group-distribution-message-invalid"
    );
    assert_eq!(invalid_distribution_nack.attrs["class"], "message");
    assert_eq!(invalid_distribution_nack.attrs["to"], group_jid);
    assert_eq!(
        invalid_distribution_nack.attrs["from"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(
        invalid_distribution_nack.attrs["participant"],
        canonical_sender_jid
    );
    assert_eq!(
        invalid_distribution_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "invalid spawned sender-key distribution must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        advanced_record_bytes
    );

    let stale_message = wa_proto::proto::Message {
        conversation: Some("spawn group sender-key distribution stale".to_owned()),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(fast_distribution_bytes),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let stale_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-group-distribution-message-stale")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(stale_message.encode_to_vec())),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&stale_incoming).unwrap(),
        ))
        .await
        .unwrap();
    let stale_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(stale_ack.tag, "ack");
    assert_eq!(
        stale_ack.attrs["id"],
        "signal-spawn-group-distribution-message-stale"
    );
    assert_eq!(stale_ack.attrs["class"], "message");
    assert_eq!(stale_ack.attrs["to"], group_jid);
    assert_eq!(stale_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(stale_ack.attrs["participant"], canonical_sender_jid);
    let stale_batch = recv_batch_event(&mut events).await;
    assert_eq!(stale_batch.messages_upsert.len(), 1);
    assert_eq!(
        stale_batch.messages_upsert[0].key.id,
        "signal-spawn-group-distribution-message-stale"
    );
    assert_eq!(
        stale_batch.messages_upsert[0].fields["sender_key_distribution_count"],
        "1"
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        advanced_record_bytes
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_canonicalizes_offline_legacy_sender_key_distribution_message()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let group_jid = "559@g.us";
    let sender_jid = "127:7@c.us";
    let canonical_sender_jid = "127:7@s.whatsapp.net";
    let record_key = format!("{group_jid}|{canonical_sender_jid}");
    let legacy_record_key = format!("{group_jid}|{sender_jid}");
    let signing_key = generate_key_pair();
    let fast_signing_key = generate_key_pair();
    let key_id = 82;
    let fast_key_id = 83;
    let chain_key = [12u8; 32];
    let fast_chain_key = [13u8; 32];
    let distribution = wa_core::build_signal_sender_key_distribution_message(
        key_id,
        0,
        &chain_key,
        &prefixed_signal_public_key(&signing_key.public),
    )
    .unwrap();
    let distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&distribution).unwrap();
    let fast_distribution = wa_core::build_signal_sender_key_distribution_message(
        fast_key_id,
        0,
        &fast_chain_key,
        &prefixed_signal_public_key(&fast_signing_key.public),
    )
    .unwrap();
    let fast_distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&fast_distribution).unwrap();
    let message = wa_proto::proto::Message {
        conversation: Some("spawn offline group sender-key distribution".to_owned()),
        sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(distribution_bytes),
            },
        ),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(fast_distribution_bytes.clone()),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-group-distribution-message")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(message.encode_to_vec())),
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
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-offline-group-distribution-message"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], group_jid);
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], canonical_sender_jid);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    let event = &batch.messages_upsert[0];
    assert_eq!(event.key.remote_jid, group_jid);
    assert_eq!(event.key.participant.as_deref(), Some(canonical_sender_jid));
    assert_eq!(
        event.key.id,
        "signal-spawn-offline-group-distribution-message"
    );
    assert_eq!(event.fields["payload_kind"], "plaintext");
    assert_eq!(event.fields["sender_key_distribution_count"], "2");
    let payload = event.payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline group sender-key distribution")
    );
    assert!(decoded.sender_key_distribution_message.is_some());
    assert!(
        decoded
            .fast_ratchet_key_sender_key_distribution_message
            .is_some()
    );
    let stored_key = wa_core::message_event_store_key(&event.key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, *event);
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(fast_distribution_bytes.clone())
    );
    let stored_record = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let stored_record = wa_core::decode_signal_sender_key_record(&stored_record).unwrap();
    assert_eq!(stored_record.states.len(), 2);
    assert_eq!(stored_record.states[0].key_id, fast_key_id);
    assert_eq!(stored_record.states[0].chain_key.iteration, 0);
    assert_eq!(
        stored_record.states[0].chain_key.key.expose(),
        fast_distribution.chain_key.expose()
    );
    assert_eq!(
        stored_record.states[0].signing_public_key,
        fast_distribution.signing_key
    );
    assert_eq!(stored_record.states[0].signing_private_key, None);
    assert_eq!(stored_record.states[1].key_id, key_id);
    assert_eq!(stored_record.states[1].chain_key.iteration, 0);
    assert_eq!(
        stored_record.states[1].chain_key.key.expose(),
        distribution.chain_key.expose()
    );
    assert_eq!(
        stored_record.states[1].signing_public_key,
        distribution.signing_key
    );
    assert_eq!(stored_record.states[1].signing_private_key, None);
    assert!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&legacy_record_key)
            .await
            .unwrap()
            .is_none()
    );

    let advanced_fast_distribution = wa_core::build_signal_sender_key_distribution_message(
        fast_key_id,
        5,
        &[14u8; 32],
        &fast_signing_key.public,
    )
    .unwrap();
    let advanced_fast_distribution_bytes =
        wa_core::encode_signal_sender_key_distribution_message(&advanced_fast_distribution)
            .unwrap();
    let advanced_message = wa_proto::proto::Message {
        conversation: Some("spawn offline group sender-key distribution advance".to_owned()),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(
                    advanced_fast_distribution_bytes.clone(),
                ),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let advanced_incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-group-distribution-message-advance",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext")
                .with_content(Bytes::from(advanced_message.encode_to_vec())),
        ]);
    let advanced_offline = BinaryNode::new("offline").with_content(vec![advanced_incoming]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&advanced_offline).unwrap(),
        ))
        .await
        .unwrap();
    let advanced_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(advanced_ack.tag, "ack");
    assert_eq!(
        advanced_ack.attrs["id"],
        "signal-spawn-offline-group-distribution-message-advance"
    );
    assert_eq!(advanced_ack.attrs["class"], "message");
    assert_eq!(advanced_ack.attrs["to"], group_jid);
    assert_eq!(advanced_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(advanced_ack.attrs["participant"], canonical_sender_jid);
    let advanced_batch = recv_batch_event(&mut events).await;
    assert_eq!(advanced_batch.messages_upsert.len(), 1);
    assert_eq!(
        advanced_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-group-distribution-message-advance"
    );
    assert_eq!(
        advanced_batch.messages_upsert[0].fields["sender_key_distribution_count"],
        "1"
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    let advanced_record_bytes = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let advanced_record = wa_core::decode_signal_sender_key_record(&advanced_record_bytes).unwrap();
    assert_eq!(advanced_record.states.len(), 2);
    assert_eq!(advanced_record.states[0].key_id, fast_key_id);
    assert_eq!(advanced_record.states[0].chain_key.iteration, 5);
    assert_eq!(
        advanced_record.states[0].chain_key.key.expose(),
        advanced_fast_distribution.chain_key.expose()
    );
    assert_eq!(advanced_record.states[1], stored_record.states[1]);

    let invalid_distribution_message = wa_proto::proto::Message {
        conversation: Some("spawn offline group sender-key distribution invalid".to_owned()),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(Bytes::from_static(
                    b"invalid-sender-key-distribution",
                )),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let invalid_distribution_incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-group-distribution-message-invalid",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![BinaryNode::new("plaintext").with_content(
            Bytes::from(invalid_distribution_message.encode_to_vec()),
        )]);
    let invalid_distribution_offline =
        BinaryNode::new("offline").with_content(vec![invalid_distribution_incoming]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&invalid_distribution_offline).unwrap(),
        ))
        .await
        .unwrap();
    let invalid_distribution_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_distribution_nack.tag, "ack");
    assert_eq!(
        invalid_distribution_nack.attrs["id"],
        "signal-spawn-offline-group-distribution-message-invalid"
    );
    assert_eq!(invalid_distribution_nack.attrs["class"], "message");
    assert_eq!(invalid_distribution_nack.attrs["to"], group_jid);
    assert_eq!(
        invalid_distribution_nack.attrs["from"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(
        invalid_distribution_nack.attrs["participant"],
        canonical_sender_jid
    );
    assert_eq!(
        invalid_distribution_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "invalid spawned offline sender-key distribution must not emit a typed batch"
        );
    }
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        advanced_record_bytes
    );

    let stale_message = wa_proto::proto::Message {
        conversation: Some("spawn offline group sender-key distribution stale".to_owned()),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(fast_distribution_bytes),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let stale_incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-spawn-offline-group-distribution-message-stale",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(stale_message.encode_to_vec())),
        ]);
    let stale_offline = BinaryNode::new("offline").with_content(vec![stale_incoming]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&stale_offline).unwrap(),
        ))
        .await
        .unwrap();
    let stale_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(stale_ack.tag, "ack");
    assert_eq!(
        stale_ack.attrs["id"],
        "signal-spawn-offline-group-distribution-message-stale"
    );
    assert_eq!(stale_ack.attrs["class"], "message");
    assert_eq!(stale_ack.attrs["to"], group_jid);
    assert_eq!(stale_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(stale_ack.attrs["participant"], canonical_sender_jid);
    let stale_batch = recv_batch_event(&mut events).await;
    assert_eq!(stale_batch.messages_upsert.len(), 1);
    assert_eq!(
        stale_batch.messages_upsert[0].key.id,
        "signal-spawn-offline-group-distribution-message-stale"
    );
    assert_eq!(
        stale_batch.messages_upsert[0].fields["sender_key_distribution_count"],
        "1"
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes.clone())
    );
    assert_eq!(
        client
            .signal_repository()
            .get_sender_key_distribution(canonical_sender_jid, group_jid)
            .await
            .unwrap(),
        Some(advanced_fast_distribution_bytes)
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        advanced_record_bytes
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_accepts_signed_pre_key_only_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "spawn-signed-only")
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
                conversation: Some("spawn signed-pre-key only".to_owned()),
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
        &plaintext,
    )
    .unwrap();
    assert!(!first.used_one_time_pre_key);
    assert_eq!(first.message.pre_key_id, None);
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-signed-only-1")
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
    assert_eq!(ack.attrs["id"], "signal-spawn-signed-only-1");
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
        "signal-spawn-signed-only-1"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn signed-pre-key only")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
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
        .with_attr("id", "signal-spawn-signed-only-1-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&replay_pre_key).unwrap(),
        ))
        .await
        .unwrap();

    let replay_pre_key_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_pre_key_nack.tag, "ack");
    assert_eq!(
        replay_pre_key_nack.attrs["id"],
        "signal-spawn-signed-only-1-replay"
    );
    assert_eq!(replay_pre_key_nack.attrs["class"], "message");
    assert_eq!(replay_pre_key_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_pre_key_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_pre_key_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "replayed signed-only pre-key message must not emit a typed batch"
        );
    }
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
        conversation: Some("spawn signed-pre-key second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 9);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-signed-only-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
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
    assert_eq!(second_ack.attrs["id"], "signal-spawn-signed-only-2");
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
        "signal-spawn-signed-only-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn signed-pre-key second")
    );
    let stored_second_key = wa_core::message_event_store_key(&second_batch.messages_upsert[0].key);
    let stored_second = store
        .get(KeyNamespace::MessageEvent, &stored_second_key)
        .await
        .unwrap()
        .unwrap();
    let stored_second = wa_core::decode_stored_message_event(&stored_second).unwrap();
    assert_eq!(stored_second, second_batch.messages_upsert[0]);
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_accepts_offline_signed_pre_key_only_message() {
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
        "spawn-offline-signed-only",
    )
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
                conversation: Some("spawn offline signed-pre-key only".to_owned()),
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
    assert!(!first.used_one_time_pre_key);
    assert_eq!(first.message.pre_key_id, None);
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-signed-only-1")
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
    assert_eq!(ack.attrs["id"], "signal-spawn-offline-signed-only-1");
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
        "signal-spawn-offline-signed-only-1"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn offline signed-pre-key only")
    );
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
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
        .with_attr("id", "signal-spawn-offline-signed-only-1-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let replay_offline = BinaryNode::new("offline").with_content(vec![replay_pre_key]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&replay_offline).unwrap(),
        ))
        .await
        .unwrap();

    let replay_pre_key_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_pre_key_nack.tag, "ack");
    assert_eq!(
        replay_pre_key_nack.attrs["id"],
        "signal-spawn-offline-signed-only-1-replay"
    );
    assert_eq!(replay_pre_key_nack.attrs["class"], "message");
    assert_eq!(replay_pre_key_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(replay_pre_key_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        replay_pre_key_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, Event::Batch(_)),
            "replayed offline signed-only pre-key message must not emit a typed batch"
        );
    }
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
        conversation: Some("spawn offline signed-pre-key second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 11);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-signed-only-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes),
        ]);
    let second_offline = BinaryNode::new("offline").with_content(vec![incoming_second]);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&second_offline).unwrap(),
        ))
        .await
        .unwrap();

    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-spawn-offline-signed-only-2");
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
        "signal-spawn-offline-signed-only-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn offline signed-pre-key second")
    );
    let stored_second_key = wa_core::message_event_store_key(&second_batch.messages_upsert[0].key);
    let stored_second = store
        .get(KeyNamespace::MessageEvent, &stored_second_key)
        .await
        .unwrap()
        .unwrap();
    let stored_second = wa_core::decode_stored_message_event(&stored_second).unwrap();
    assert_eq!(stored_second, second_batch.messages_upsert[0]);
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_poll_update_from_stored_creation_secret()
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
        "spawn-signal-poll-update",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];

    let poll_secret = Bytes::from(vec![39u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("poll-creation-spawn-signal-1".to_owned()),
        participant: None,
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let creation_message = wa_core::build_poll_message(wa_core::PollContent::new(
        "Launch?",
        ["Approve", "Hold"],
        1,
        poll_secret.clone(),
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
    let poll_update_content = wa_core::build_encrypted_poll_update_content_with_iv(
        wa_core::PollVoteContent::from_option_names(
            target_key.clone(),
            ["Approve"],
            poll_secret,
            "999:7@s.whatsapp.net",
            "123@s.whatsapp.net",
        )
        .unwrap(),
        Bytes::from_static(b"poll-vote-iv"),
    )
    .unwrap()
    .with_sender_timestamp_ms(1_700_000_014_123);
    let poll_update = wa_core::build_poll_update_message(poll_update_content).unwrap();
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
    let plaintext = pad_random_max16_for_test(Bytes::from(poll_update.encode_to_vec()), 10);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-poll-update-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "poll")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes),
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
    assert_eq!(ack.attrs["id"], "signal-spawn-poll-update-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-poll-update-1"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert!(decoded.poll_update_message.is_some());
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.fields["source"], "poll_update_message");
    assert_eq!(update.fields["poll_update"], "true");
    assert_eq!(update.fields["voter_jid"], "123@s.whatsapp.net");
    assert_eq!(update.fields["vote_decrypted"], "true");
    assert_eq!(update.fields["selected_options_count"], "1");
    assert_eq!(
        update.fields["poll_secret_creator_jid"],
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
    assert_eq!(stored_target.fields["vote_decrypted"], "true");
    assert_eq!(stored_target.fields["selected_options_count"], "1");
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_offline_poll_update_from_stored_creation_secret()
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
        "spawn-offline-signal-poll-update",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];

    let poll_secret = Bytes::from(vec![42u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("poll-creation-spawn-offline-signal-1".to_owned()),
        participant: None,
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let creation_message = wa_core::build_poll_message(wa_core::PollContent::new(
        "Launch?",
        ["Approve", "Hold"],
        1,
        poll_secret.clone(),
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
    let poll_update_content = wa_core::build_encrypted_poll_update_content_with_iv(
        wa_core::PollVoteContent::from_option_names(
            target_key.clone(),
            ["Approve"],
            poll_secret,
            "999:7@s.whatsapp.net",
            "123@s.whatsapp.net",
        )
        .unwrap(),
        Bytes::from_static(b"poll-vote-iv"),
    )
    .unwrap()
    .with_sender_timestamp_ms(1_700_000_017_123);
    let poll_update = wa_core::build_poll_update_message(poll_update_content).unwrap();
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
    let plaintext = pad_random_max16_for_test(Bytes::from(poll_update.encode_to_vec()), 12);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-poll-update-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "poll")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes),
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
    assert_eq!(ack.attrs["id"], "signal-spawn-offline-poll-update-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-poll-update-1"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert!(decoded.poll_update_message.is_some());
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.fields["source"], "poll_update_message");
    assert_eq!(update.fields["poll_update"], "true");
    assert_eq!(update.fields["voter_jid"], "123@s.whatsapp.net");
    assert_eq!(update.fields["vote_decrypted"], "true");
    assert_eq!(update.fields["selected_options_count"], "1");
    assert_eq!(update.fields["selected_option_hashes_hex"].len(), 64);
    assert_eq!(
        update.fields["poll_secret_creator_jid"],
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
    assert_eq!(stored_target.fields["vote_decrypted"], "true");
    assert_eq!(stored_target.fields["selected_options_count"], "1");
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_event_response_from_stored_creation_secret()
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
        "spawn-signal-event-response",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];

    let event_secret = Bytes::from(vec![40u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("event-creation-spawn-signal-1".to_owned()),
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
        .with_timestamp_ms(1_700_000_015_123)
        .with_extra_guest_count(1),
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
    let plaintext = pad_random_max16_for_test(Bytes::from(event_response.encode_to_vec()), 11);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-event-response-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes),
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
    assert_eq!(ack.attrs["id"], "signal-spawn-event-response-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-event-response-1"
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
    assert_eq!(update.fields["response_timestamp_ms"], "1700000015123");
    assert_eq!(update.fields["extra_guest_count"], "1");
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
    assert_eq!(stored_target.fields["extra_guest_count"], "1");
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_decrypts_offline_event_response_from_stored_creation_secret()
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
        "spawn-offline-signal-event-response",
    )
    .await
    .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];

    let event_secret = Bytes::from(vec![41u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("event-creation-spawn-offline-signal-1".to_owned()),
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
            wa_core::EventResponseKind::Maybe,
            event_secret,
            "999:7@s.whatsapp.net",
            "123@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_016_123)
        .with_extra_guest_count(3),
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
    let plaintext = pad_random_max16_for_test(Bytes::from(event_response.encode_to_vec()), 12);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-event-response-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes),
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
    assert_eq!(ack.attrs["id"], "signal-spawn-offline-event-response-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-offline-event-response-1"
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
    assert_eq!(update.fields["response"], "maybe");
    assert_eq!(update.fields["response_timestamp_ms"], "1700000016123");
    assert_eq!(update.fields["extra_guest_count"], "3");
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
    assert_eq!(stored_target.fields["response"], "maybe");
    assert_eq!(stored_target.fields["extra_guest_count"], "3");
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_signal_provider_rejects_offline_missing_one_time_pre_key() {
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
        "spawn-offline-missing-pre-key",
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
    let encrypted_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline missing pre-key".to_owned()),
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

    let failed_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-missing-pre-key")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![failed_child]);
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

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-offline-missing-pre-key");
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
        conversation: Some("processor survived offline failure".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let follow_up = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-after-offline-missing-pre-key")
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
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-after-offline-missing-pre-key"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-after-offline-missing-pre-key"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("processor survived offline failure")
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
async fn incoming_processor_with_signal_provider_rejects_offline_pre_key_identity_change() {
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
        "spawn-offline-identity-change",
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
    let encrypted_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("spawn offline identity change".to_owned()),
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
        &encrypted_plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let failed_child = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-offline-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![failed_child]);
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

    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-spawn-offline-identity-change");
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
        conversation: Some("processor survived offline identity change".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let follow_up = BinaryNode::new("message")
        .with_attr("id", "signal-spawn-after-offline-identity-change")
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
    assert_eq!(
        ack.attrs["id"],
        "signal-spawn-after-offline-identity-change"
    );
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-spawn-after-offline-identity-change"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("processor survived offline identity change")
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
async fn incoming_processor_with_placeholder_resend_requests_unavailable_stub() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_resend(
            connection.clone(),
            IncomingDecryptor,
            RelayEncryptor::default(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "missing-spawn")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-spawn");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "missing-spawn");
    assert_eq!(
        batch.messages_upsert[0].fields["kind"],
        "placeholder_unavailable"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["unavailable_type"],
        "temporary_unavailable"
    );

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
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&session_response_for_query(&encrypt_query)).unwrap(),
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
    assert!(
        client
            .placeholder_resend_tracker()
            .contains("missing-spawn", current_unix_timestamp_ms())
            .unwrap()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_resend_with_signal_provider_requests_stub() {
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
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "missing-spawn-signal")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "missing-spawn-signal", None)
            .unwrap();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-spawn-signal");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "missing-spawn-signal");
    assert_eq!(
        batch.messages_upsert[0].fields["kind"],
        "placeholder_unavailable"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["unavailable_type"],
        "temporary_unavailable"
    );

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
            .contains("missing-spawn-signal", current_unix_timestamp_ms())
            .unwrap()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_resend_signal_provider_emits_offline_group_notification_append_stub()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-placeholder-offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000210")
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
        "spawn-placeholder-offline-group-ephemeral-stub"
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
        "spawn-placeholder-offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000210");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(
        stub.key.id,
        "spawn-placeholder-offline-group-ephemeral-stub"
    );
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_210));
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_resend_signal_provider_emits_offline_group_participant_add_append_stub()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-placeholder-offline-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000310")
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
        "spawn-placeholder-offline-group-participant-add-stub"
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
        "spawn-placeholder-offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000310");
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
        "spawn-placeholder-offline-group-participant-add-stub"
    );
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_310));
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
async fn incoming_processor_with_placeholder_resend_with_signal_provider_preserves_legacy_missing_key()
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
    let remote_one_time_pre_key_id = 96;
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "missing-spawn-signal-legacy")
        .with_attr("from", "123@c.us")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key =
        wa_core::build_message_key("123@c.us", false, "missing-spawn-signal-legacy", None).unwrap();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-spawn-signal-legacy");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@c.us");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "missing-spawn-signal-legacy"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["kind"],
        "placeholder_unavailable"
    );
    assert_eq!(
        batch.messages_upsert[0].fields["unavailable_type"],
        "temporary_unavailable"
    );

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
            .contains("missing-spawn-signal-legacy", current_unix_timestamp_ms())
            .unwrap()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_resend_signal_provider_accepts_same_base_pre_key_wrapper()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "placeholder-same-base")
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
        conversation: Some("spawn placeholder same-base first".to_owned()),
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
        .with_attr("id", "signal-spawn-placeholder-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_resend_with_signal_provider(
            connection.clone(),
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
        "signal-spawn-placeholder-same-base-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn placeholder same-base first")
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
        conversation: Some("spawn placeholder same-base wrapped second".to_owned()),
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
        .with_attr("id", "signal-spawn-placeholder-same-base-2-identity-change")
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
        "signal-spawn-placeholder-same-base-2-identity-change"
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
            "placeholder same-base identity-change wrapper must not emit a typed batch"
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
            "signal-spawn-placeholder-same-base-2-signed-pre-key-mismatch",
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
        "signal-spawn-placeholder-same-base-2-signed-pre-key-mismatch"
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
            "placeholder same-base signed-pre-key-id mismatch wrapper must not emit a typed batch"
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
        .with_attr("id", "signal-spawn-placeholder-same-base-2")
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
        "signal-spawn-placeholder-same-base-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn placeholder same-base wrapped second")
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
        .with_attr("id", "signal-spawn-placeholder-same-base-2-replay")
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
        "signal-spawn-placeholder-same-base-2-replay"
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
            "placeholder same-base replay must not emit a typed batch"
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
        conversation: Some("spawn placeholder same-base third".to_owned()),
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
        .with_attr("id", "signal-spawn-placeholder-same-base-3")
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
        "signal-spawn-placeholder-same-base-3"
    );
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn placeholder same-base third")
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
async fn incoming_processor_with_placeholder_resend_signal_provider_accepts_new_remote_ratchet() {
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
        "placeholder-spawn-new-ratchet",
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
        &text_plaintext("spawn placeholder ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn placeholder ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn placeholder ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_resend_with_signal_provider(
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
                "signal-spawn-placeholder-ratchet-1",
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
    assert_eq!(first_ack.attrs["id"], "signal-spawn-placeholder-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn placeholder ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver spawn placeholder ratchet reply"),
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
        &text_plaintext("spawn placeholder ratchet fourth", 7),
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
        &text_plaintext("spawn placeholder ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-placeholder-ratchet-4",
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
    assert_eq!(fourth_ack.attrs["id"], "signal-spawn-placeholder-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn placeholder ratchet fourth")
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
                "signal-spawn-placeholder-ratchet-old-3",
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
        "signal-spawn-placeholder-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("spawn placeholder ratchet old third")
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
                "signal-spawn-placeholder-ratchet-old-3-replay",
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
        "signal-spawn-placeholder-ratchet-old-3-replay"
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
            "spawn placeholder consumed previous-chain replay must not emit a typed batch"
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
                "signal-spawn-placeholder-ratchet-2",
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
    assert_eq!(second_ack.attrs["id"], "signal-spawn-placeholder-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn placeholder ratchet second")
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
                "signal-spawn-placeholder-ratchet-5",
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
    assert_eq!(fifth_ack.attrs["id"], "signal-spawn-placeholder-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("spawn placeholder ratchet fifth")
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
async fn incoming_processor_persists_linked_profile_mappings() {
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
    let incoming = BinaryNode::new("notification")
        .with_attr("id", "auto-linked")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "mex")
        .with_content(vec![BinaryNode::new("update")
            .with_attr("op_name", "NotificationLinkedProfilesUpdates")
            .with_content(
                br#"{"data":{"xwa2_notify_linked_profiles":{"jid":"abc@lid","added_profiles":["123@c.us"]}}}"#.to_vec(),
            )]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "auto-linked");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

    let mappings = recv_lid_mapping_event(&mut events).await;
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
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_emits_business_notification_alias_metadata() {
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
        .with_attr("id", "auto-biz-alias")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "business")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000430")
        .with_content(vec![
            BinaryNode::new("cover_photo")
                .with_attr("media-id", "cover-2")
                .with_content(vec![
                    BinaryNode::new("image").with_content(vec![0xab, 0xcd]),
                ]),
        ]);

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
    assert_eq!(ack.attrs["id"], "auto-biz-alias");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.business_notifications.len(), 1);
    let event = &batch.business_notifications[0];
    assert_eq!(event.from, "server@s.whatsapp.net");
    assert_eq!(event.notification_id, "auto-biz-alias");
    assert_eq!(event.event_type, "cover_photo");
    assert_eq!(event.fields["notification_type"], "business");
    assert_eq!(event.fields["timestamp"], "1700000430");
    assert_eq!(event.fields["actor"], "111@lid");
    assert_eq!(event.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(event.fields["actor_username"], "actor-one");
    assert_eq!(event.fields["attr_media_id"], "cover-2");
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
async fn incoming_processor_emits_business_notification_alias_children() {
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
        .with_attr("id", "auto-biz-alias-children")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "business")
        .with_attr("participant", "111@lid")
        .with_attr("phoneNumber", "111@s.whatsapp.net")
        .with_attr("senderUsername", "actor-two")
        .with_attr("t", "1700000435")
        .with_content(vec![
            BinaryNode::new("product_catalog_update")
                .with_attr("catalog-id", "cat-3")
                .with_content(vec![
                    BinaryNode::new("product")
                        .with_attr("id", "sku-3")
                        .with_attr("retailer-id", "ret-3")
                        .with_content(vec![BinaryNode::new("name").with_content("Spawn Widget")]),
                ]),
            BinaryNode::new("collection_update")
                .with_attr("collection-id", "collection-3")
                .with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("id", "collection-3")
                        .with_content(vec![BinaryNode::new("name").with_content("Featured")]),
                ]),
            BinaryNode::new("cart_update")
                .with_attr("cart-id", "cart-3")
                .with_content(vec![
                    BinaryNode::new("item")
                        .with_attr("sku", "sku-3")
                        .with_attr("quantity", "2"),
                ]),
        ]);
    let frame = encode_binary_node(&notification).unwrap();
    let decoded_notification = decode_inbound_binary_node(&frame).unwrap().node;

    stream_tx.send(InboundFrame::new(frame)).await.unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "auto-biz-alias-children");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, decoded_notification);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.business_notifications.len(), 3);
    assert!(batch.messages_upsert.is_empty());
    let product = batch
        .business_notifications
        .iter()
        .find(|event| event.event_type == "product_catalog_update")
        .unwrap();
    assert_eq!(product.from, "server@s.whatsapp.net");
    assert_eq!(product.notification_id, "auto-biz-alias-children");
    assert_eq!(product.fields["notification_type"], "business");
    assert_eq!(product.fields["timestamp"], "1700000435");
    assert_eq!(product.fields["actor"], "111@lid");
    assert_eq!(product.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(product.fields["actor_username"], "actor-two");
    assert_eq!(product.fields["attr_catalog_id"], "cat-3");
    assert_eq!(product.fields["child_product_id"], "sku-3");
    assert_eq!(product.fields["child_product_retailer_id"], "ret-3");
    assert_eq!(
        product.fields["child_product_child_name_text"],
        "Spawn Widget"
    );
    let collection = batch
        .business_notifications
        .iter()
        .find(|event| event.event_type == "collection_update")
        .unwrap();
    assert_eq!(collection.fields["attr_collection_id"], "collection-3");
    assert_eq!(collection.fields["child_collection_id"], "collection-3");
    assert_eq!(
        collection.fields["child_collection_child_name_text"],
        "Featured"
    );
    let cart = batch
        .business_notifications
        .iter()
        .find(|event| event.event_type == "cart_update")
        .unwrap();
    assert_eq!(cart.fields["attr_cart_id"], "cart-3");
    assert_eq!(cart.fields["child_item_sku"], "sku-3");
    assert_eq!(cart.fields["child_item_quantity"], "2");
    for event in &batch.business_notifications {
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
    }
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
async fn incoming_processor_emits_newsletter_notification_events() {
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
    let plaintext = wa_proto::proto::Message {
        conversation: Some("spawn newsletter text".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let notification = BinaryNode::new("notification")
        .with_attr("id", "auto-newsletter-live")
        .with_attr("from", "abc@newsletter")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("type", "newsletter")
        .with_content(vec![
            BinaryNode::new("reaction")
                .with_attr("message_id", "server-11")
                .with_content(vec![BinaryNode::new("reaction").with_content("+")]),
            BinaryNode::new("view")
                .with_attr("message_id", "server-12")
                .with_content("43"),
            BinaryNode::new("participant")
                .with_attr("jid", "222@s.whatsapp.net")
                .with_attr("action", "promote")
                .with_attr("role", "ADMIN"),
            BinaryNode::new("update").with_content(vec![BinaryNode::new("settings").with_content(
                vec![
                    BinaryNode::new("name").with_content("Spawn Updates"),
                    BinaryNode::new("description").with_content("Spawn notes"),
                ],
            )]),
            BinaryNode::new("message")
                .with_attr("message_id", "server-13")
                .with_attr("t", "1700000450")
                .with_content(vec![
                    BinaryNode::new("plaintext")
                        .with_content(Bytes::from(plaintext.encode_to_vec())),
                ]),
        ]);
    let frame = encode_binary_node(&notification).unwrap();
    let decoded_notification = decode_inbound_binary_node(&frame).unwrap().node;

    stream_tx.send(InboundFrame::new(frame)).await.unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "auto-newsletter-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "abc@newsletter");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, decoded_notification);
    let Event::NewsletterReactionUpdate(reactions) = events.recv().await.unwrap() else {
        panic!("expected newsletter reaction update");
    };
    assert_eq!(reactions.len(), 1);
    let reaction = &reactions[0];
    assert_eq!(reaction.id, "abc@newsletter");
    assert_eq!(reaction.server_id, "server-11");
    assert_eq!(reaction.code.as_deref(), Some("+"));
    assert_eq!(reaction.count, Some(1));

    let Event::NewsletterViewUpdate(views) = events.recv().await.unwrap() else {
        panic!("expected newsletter view update");
    };
    assert_eq!(views.len(), 1);
    let view = &views[0];
    assert_eq!(view.id, "abc@newsletter");
    assert_eq!(view.server_id, "server-12");
    assert_eq!(view.count, 43);

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
    assert_eq!(setting.fields["name"], "Spawn Updates");
    assert_eq!(setting.fields["description"], "Spawn notes");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert!(batch.messages_update.is_empty());
    let message = &batch.messages_upsert[0];
    assert_eq!(message.key.remote_jid, "abc@newsletter");
    assert_eq!(message.key.id, "server-13");
    assert!(message.key.participant.is_none());
    assert_eq!(message.timestamp, Some(1_700_000_450));
    assert_eq!(message.fields["kind"], "newsletter");
    assert_eq!(message.fields["payload_kind"], "plaintext");
    assert_eq!(message.fields["source"], "newsletter_notification");
    assert_eq!(message.fields["from_me"], "false");
    let decoded = wa_proto::proto::Message::decode(message.payload.clone().unwrap()).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("spawn newsletter text")
    );

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
async fn incoming_processor_emits_newsletter_mex_settings_update() {
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
        .with_attr("id", "auto-newsletter-mex-settings")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "mex")
        .with_content(vec![BinaryNode::new("update").with_content(
            br#"{"data":{"NotificationNewsletterUpdate":{"updates":[{"newsletter_id":"abc@newsletter","settings":{"name":{"text":"MEX Updates"},"description":"MEX notes"}}]}}}"#.to_vec(),
        )]);

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
    assert_eq!(ack.attrs["id"], "auto-newsletter-mex-settings");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let Event::NewsletterSettingsUpdate(settings) = events.recv().await.unwrap() else {
        panic!("expected newsletter settings update");
    };
    assert_eq!(settings.len(), 1);
    let setting = &settings[0];
    assert_eq!(setting.id, "abc@newsletter");
    assert_eq!(setting.fields["name"], "MEX Updates");
    assert_eq!(setting.fields["description"], "MEX notes");

    let stored = store
        .get(
            KeyNamespace::NewsletterSettingsEvent,
            &wa_core::newsletter_settings_update_event_store_key(setting),
        )
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_newsletter_settings_update_event(&stored).unwrap();
    assert_eq!(stored, *setting);
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
async fn incoming_processor_emits_newsletter_mex_admin_promotion_update() {
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
        .with_attr("id", "auto-newsletter-mex-admin")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "mex")
        .with_content(vec![BinaryNode::new("update").with_content(
            br#"{"data":{"NotificationNewsletterAdminPromote":{"updates":[{"newsletterId":"abc@newsletter","participantJid":"444@s.whatsapp.net"}]}}}"#.to_vec(),
        )]);

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
    assert_eq!(ack.attrs["id"], "auto-newsletter-mex-admin");
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
            "444@s.whatsapp.net",
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
async fn incoming_processor_does_not_reprocess_processed_node_events() {
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
    let notification = BinaryNode::new("notification")
        .with_attr("id", "notify-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "devices");

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
    assert_eq!(ack.attrs["id"], "notify-1");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(recv_node_event(&mut events).await, notification);
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
async fn incoming_processor_emits_group_notification_message_stub() {
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
        .with_attr("id", "auto-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000150")
        .with_content(vec![
            BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
        ]);

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
    assert_eq!(ack.attrs["id"], "auto-group-ephemeral-stub");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(group.fields["notification_id"], "auto-group-ephemeral-stub");
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000150");
    assert_eq!(group.fields["ephemeral_duration"], "86400");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "auto-group-ephemeral-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_150));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
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
async fn incoming_processor_emits_group_participant_add_message_stub() {
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
        .with_attr("id", "auto-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000260")
        .with_content(vec![BinaryNode::new("add").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
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
    assert_eq!(ack.attrs["id"], "auto-group-participant-add-stub");
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
        "auto-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000260");
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
    assert_eq!(stub.key.id, "auto-group-participant-add-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_260));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
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
