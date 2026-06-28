// Auto-partitioned test chunk 1 of 8 (feature `wat1`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat1 to stay within the VM RAM budget.
// Included into `mod chunk_1` in lib.rs; allow-attrs live on that module decl.
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

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn connect_wires_query_manager_timeout() {
    let config = ClientConfig {
        default_query_timeout: Some(Duration::from_millis(1)),
        ..ClientConfig::default()
    };

    let client = Client::builder(wa_store::MemoryAuthStore::new())
        .config(config)
        .connect()
        .await
        .unwrap();

    let waiter = client.query_manager().register("timeout").unwrap();
    assert!(matches!(
        waiter.wait().await,
        Err(wa_core::CoreError::TimedOut)
    ));
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn connect_initializes_credentials_once() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();

    assert_eq!(client.credentials(), &stored);

    let second = Client::builder(store.clone()).connect().await.unwrap();
    assert_eq!(second.credentials(), &stored);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn connection_validation_restores_registered_session() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("12345:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let validation = client.connection_validation().unwrap();

    assert!(matches!(
        validation.payload,
        ValidationPayload::Login { user_jid } if user_jid == "12345:7@s.whatsapp.net"
    ));
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn connection_validation_rejects_registered_session_without_account_jid() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();

    let client = Client::builder(store.clone()).connect().await.unwrap();

    assert!(client.connection_validation().is_err());
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn exposes_store_backed_signal_repository() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let repository = client.signal_repository();

    let validation = wa_core::SignalRepository::validate_session(&repository, "123@s.whatsapp.net")
        .await
        .unwrap();
    assert!(!validation.exists);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn exposes_store_backed_signal_provider_state_store() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();

    provider_store
        .store_session_record("123:7@s.whatsapp.net", b"native-session")
        .await
        .unwrap();

    assert_eq!(
        provider_store
            .load_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap()
            .as_deref(),
        Some(&b"native-session"[..])
    );

    let material = provider_store
        .load_local_key_material()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        material.registration_id,
        client.credentials().registration_id
    );
    assert_eq!(
        material.identity.key_pair.public,
        client.credentials().signed_identity_key.public
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn exposes_store_backed_signal_sender_key_provider_with_account_jid() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    assert!(client.signal_sender_key_provider().is_err());
    assert!(client.signal_provider().is_err());

    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider = client.signal_sender_key_provider().unwrap();
    assert!(client.signal_provider().is_ok());
    let repository = client.signal_repository();
    let provider_store = client.signal_provider_state_store();
    assert!(
        repository
            .mutation_locks()
            .ptr_eq(provider_store.mutation_locks())
    );
    assert!(
        provider
            .state_store()
            .mutation_locks()
            .ptr_eq(provider_store.mutation_locks())
    );
    assert!(
        provider.state_store().mutation_locks().ptr_eq(
            client
                .signal_provider()
                .unwrap()
                .state_store()
                .mutation_locks()
        )
    );
    let result = wa_core::SignalCryptoProvider::encrypt_signal_message(
        &provider,
        wa_core::SignalEncryptionRequest {
            recipient_jid: "555@g.us".to_owned(),
            plaintext: Bytes::from_static(b"group"),
            session: None,
        },
    )
    .await;
    assert!(matches!(
        result,
        Err(wa_core::CoreError::Protocol(message))
            if message == "missing Signal sender-key record"
    ));
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn execute_usync_query_sends_node_and_parses_result() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let query = USyncQuery::new()
        .with_contact_protocol()
        .with_user(wa_core::USyncUser::new().with_phone("+123"));
    let query_fut = client.execute_usync_query(&connection, &query);
    tokio::pin!(query_fut);

    let sent_frame = tokio::select! {
        result = &mut query_fut => panic!("USync query completed before mock response: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.attrs["xmlns"], "usync");
    let tag = sent.attrs["id"].clone();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", tag)
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![
                                    BinaryNode::new("contact").with_attr("type", "in")
                                ]),
                        ]),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let result = query_fut.await.unwrap().unwrap();
    assert_eq!(result.list[0].id, "123@s.whatsapp.net");
    assert_eq!(result.list[0].contact, Some(true));

    let failed_query_fut = client.execute_usync_query(&connection, &query);
    tokio::pin!(failed_query_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            error_result_for(&node, "403", "not allowed")
        },
        &mut failed_query_fut,
    )
    .await;
    let err = failed_query_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("USync query failed (403): not allowed")
    );
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn on_whatsapp_sends_contact_query_and_maps_results() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let lookup_fut = client.on_whatsapp(&connection, ["+1 234-567"]);
    tokio::pin!(lookup_fut);

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
                                .with_attr("jid", "1234567@s.whatsapp.net")
                                .with_content(vec![
                                    BinaryNode::new("contact").with_attr("type", "in"),
                                ]),
                        ]),
                ])])
        },
        &mut lookup_fut,
    )
    .await;

    assert_eq!(
        lookup_fut.await.unwrap(),
        vec![OnWhatsAppResult {
            jid: "1234567@s.whatsapp.net".to_owned(),
            exists: true,
        }]
    );
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn send_text_to_devices_writes_relay_stanza() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let relay = client
        .send_text_to_devices(
            &connection,
            "123@s.whatsapp.net",
            "hello",
            &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
            &encryptor,
            MessageRelayOptions::new().with_message_id("msg-1"),
        )
        .await
        .unwrap();

    assert_eq!(relay.message_id, "msg-1");
    let sent_frame = sink_rx.recv().await.unwrap();
    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "msg-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "text");
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message stanza has no children");
    };
    assert_eq!(content[0].tag, "participants");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "123:1@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        plaintext
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("hello")
    );
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn send_group_sender_key_text_writes_root_skmsg_stanza() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::sender_key();

    let relay = client
        .send_group_sender_key_text(
            &connection,
            "123@g.us",
            "hello group",
            &encryptor,
            MessageRelayOptions::new()
                .with_message_id("group-msg-1")
                .with_encryption_attribute("decrypt-fail", "hide"),
        )
        .await
        .unwrap();

    assert_eq!(relay.message_id, "group-msg-1");
    assert_eq!(relay.recipient_count, 1);
    assert!(!relay.should_include_device_identity);
    let sent_frame = sink_rx.recv().await.unwrap();
    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "group-msg-1");
    assert_eq!(sent.attrs["to"], "123@g.us");
    assert_eq!(sent.attrs["type"], "text");
    assert!(!sent.attrs.contains_key("phash"));
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message stanza has no children");
    };
    assert_eq!(content.len(), 1);
    assert_eq!(content[0].tag, "enc");
    assert_eq!(content[0].attrs["v"], "2");
    assert_eq!(content[0].attrs["type"], "skmsg");
    assert_eq!(content[0].attrs["decrypt-fail"], "hide");

    let Some(wa_binary::BinaryNodeContent::Bytes(ciphertext)) = &content[0].content else {
        panic!("sender-key enc node should contain ciphertext bytes");
    };
    let plaintext = wa_proto::proto::Message::decode(ciphertext.clone()).unwrap();
    assert_eq!(
        plaintext
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("hello group")
    );

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "123@g.us");
    assert_eq!(&calls[0].1, ciphertext);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn group_sender_key_relay_attaches_reporting_token_for_secret_messages() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::sender_key();

    let relay = client
        .send_group_sender_key_message(
            &connection,
            "123@g.us",
            MessageContent::poll(PollContent::new(
                "Lunch?",
                ["Rice", "Noodles"],
                1,
                Bytes::from(vec![9u8; 32]),
            )),
            &encryptor,
            MessageRelayOptions::new().with_message_id("group-reporting-1"),
        )
        .await
        .unwrap();

    assert_eq!(relay.message_id, "group-reporting-1");
    let sent_frame = sink_rx.recv().await.unwrap();
    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.attrs["to"], "123@g.us");
    assert_eq!(sent.attrs["type"], "poll");
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message stanza has no children");
    };
    assert_eq!(content[0].tag, "enc");
    assert_eq!(content[0].attrs["type"], "skmsg");
    let reporting = content
        .iter()
        .find(|node| node.tag == "reporting")
        .expect("group sender-key relay should carry reporting token");
    let Some(wa_binary::BinaryNodeContent::Nodes(children)) = &reporting.content else {
        panic!("reporting node should contain children");
    };
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].tag, "reporting_token");
    assert_eq!(children[0].attrs.get("v").map(String::as_str), Some("2"));
    let Some(wa_binary::BinaryNodeContent::Bytes(token)) = &children[0].content else {
        panic!("reporting token should contain bytes");
    };
    assert_eq!(token.len(), 16);
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn send_group_sender_key_message_relays_media_root_skmsg_stanza() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::sender_key();
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![1u8; 32]),
        Bytes::from(vec![2u8; 32]),
        Bytes::from(vec![3u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/group-image")
    .with_direct_path("/v/t62.7118-24/group-image")
    .with_media_key_timestamp(1_700_000_000);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("group photo".to_owned());

    let relay = client
        .send_group_sender_key_message(
            &connection,
            "123@g.us",
            MessageContent::image(image),
            &encryptor,
            MessageRelayOptions::new()
                .with_message_id("group-media-1")
                .with_encryption_attribute("decrypt-fail", "hide"),
        )
        .await
        .unwrap();

    assert_eq!(relay.message_id, "group-media-1");
    assert_eq!(relay.recipient_count, 1);
    assert!(!relay.should_include_device_identity);
    let sent_frame = sink_rx.recv().await.unwrap();
    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "group-media-1");
    assert_eq!(sent.attrs["to"], "123@g.us");
    assert_eq!(sent.attrs["type"], "media");
    assert!(!sent.attrs.contains_key("phash"));
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message stanza has no children");
    };
    assert_eq!(content.len(), 1);
    assert_eq!(content[0].tag, "enc");
    assert_eq!(content[0].attrs["v"], "2");
    assert_eq!(content[0].attrs["type"], "skmsg");
    assert_eq!(content[0].attrs["decrypt-fail"], "hide");

    let Some(wa_binary::BinaryNodeContent::Bytes(ciphertext)) = &content[0].content else {
        panic!("sender-key enc node should contain ciphertext bytes");
    };
    let plaintext = wa_proto::proto::Message::decode(ciphertext.clone()).unwrap();
    let image = plaintext.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("group photo"));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/group-image")
    );

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "123@g.us");
    assert_eq!(&calls[0].1, ciphertext);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn relay_group_sender_key_distribution_to_devices_initializes_record_and_writes_stanza() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let relay = client
        .relay_group_sender_key_distribution_to_devices(
            &connection,
            "123@g.us",
            &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
            &encryptor,
            MessageRelayOptions::new().with_message_id("dist-1"),
        )
        .await
        .unwrap();

    assert_eq!(relay.message_id, "dist-1");
    assert_eq!(relay.recipient_count, 1);
    let sent_frame = sink_rx.recv().await.unwrap();
    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "dist-1");
    assert_eq!(sent.attrs["to"], "123@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message stanza has no children");
    };
    assert_eq!(content[0].tag, "participants");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "123:1@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let distribution = plaintext.sender_key_distribution_message.unwrap();
    assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
    let distribution_bytes = distribution
        .axolotl_sender_key_distribution_message
        .clone()
        .unwrap();
    let decoded_distribution =
        wa_core::decode_signal_sender_key_distribution_message(&distribution_bytes).unwrap();
    assert_eq!(decoded_distribution.iteration, 0);

    let stored_distribution = client
        .signal_sender_key_provider()
        .unwrap()
        .load_or_create_sender_key_distribution("123@g.us")
        .await
        .unwrap();
    assert!(!stored_distribution.created);
    assert_eq!(stored_distribution.distribution_bytes, distribution_bytes);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_text_with_distribution_fetches_participants_and_writes_relays() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "111@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "group hello",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-1"),
        MessageRelayOptions::new().with_message_id("group-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "999@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.distribution.message_id, "dist-1");
    assert_eq!(relay.message.message_id, "group-1");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(distribution_node.attrs["id"], "dist-1");
    assert_eq!(distribution_node.attrs["to"], "123@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(distribution_children)) =
        &distribution_node.content
    else {
        panic!("distribution relay should contain participants");
    };
    assert_eq!(distribution_children[0].tag, "participants");

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node.tag, "message");
    assert_eq!(group_node.attrs["id"], "group-1");
    assert_eq!(group_node.attrs["to"], "123@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(group_children)) = &group_node.content else {
        panic!("group relay should contain root enc");
    };
    assert_eq!(group_children.len(), 1);
    assert_eq!(group_children[0].tag, "enc");
    assert_eq!(group_children[0].attrs["type"], "skmsg");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    let distribution_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let distribution = distribution_plaintext
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
    assert!(
        distribution
            .axolotl_sender_key_distribution_message
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_fails_when_device_lookup_has_no_recipients() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "empty group devices",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-empty-devices"),
        MessageRelayOptions::new().with_message_id("group-empty-devices"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user").with_attr("jid", "111@s.whatsapp.net"),
                        BinaryNode::new("user").with_attr("jid", "999@s.whatsapp.net"),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(
        err,
        wa_core::CoreError::Protocol(message)
            if message == "group sender-key distribution requires at least one recipient device"
    ));
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(encryptor.calls.lock().unwrap().is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_stops_when_session_assertion_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "missing group session",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-session-fail"),
        MessageRelayOptions::new().with_message_id("group-session-fail"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("111@s.whatsapp.net".to_owned(), None)]
            );
            error_result_for(&node, "401", "session denied")
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("E2E session query failed (401): session denied")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(encryptor.calls.lock().unwrap().is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_stops_when_participant_encryption_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["111@s.whatsapp.net", "222@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = FailingAfterEncryptor::new(2, "group distribution encrypt failed");
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "group partial distribution",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-encrypt-fail"),
        MessageRelayOptions::new().with_message_id("group-encrypt-fail"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_attr("s_t", "1")
                        .with_attr("creation", "1")
                        .with_content(vec![
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                            BinaryNode::new("participant").with_attr("jid", "222@s.whatsapp.net"),
                        ]),
                ])
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "222@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "222@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("group distribution encrypt failed")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "222@s.whatsapp.net"]
    );
    let stored_distribution = client
        .signal_sender_key_provider()
        .unwrap()
        .load_or_create_sender_key_distribution("123@g.us")
        .await
        .unwrap();
    assert!(!stored_distribution.created);
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "dist-encrypt-fail".to_owned(),
            "group-encrypt-fail".to_owned(),
        ],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some("123@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: false,
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.jobs.is_empty());
    assert_eq!(
        prepared.missing_message_ids,
        vec!["dist-encrypt-fail", "group-encrypt-fail"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_stops_when_distribution_relay_send_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["111@s.whatsapp.net", "222@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 2);
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "group distribution relay send failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-send-fail"),
        MessageRelayOptions::new().with_message_id("group-after-dist-send-fail"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_attr("s_t", "1")
                        .with_attr("creation", "1")
                        .with_content(vec![
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                            BinaryNode::new("participant").with_attr("jid", "222@s.whatsapp.net"),
                        ]),
                ])
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "222@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "222@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "222@s.whatsapp.net"]
    );
    for call in &calls {
        let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
        assert!(plaintext.sender_key_distribution_message.as_ref().is_some());
    }
    let stored_distribution = client
        .signal_sender_key_provider()
        .unwrap()
        .load_or_create_sender_key_distribution("123@g.us")
        .await
        .unwrap();
    assert!(!stored_distribution.created);
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "dist-send-fail".to_owned(),
            "group-after-dist-send-fail".to_owned(),
        ],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some("123@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: false,
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.jobs.is_empty());
    assert_eq!(
        prepared.missing_message_ids,
        vec!["dist-send-fail", "group-after-dist-send-fail"]
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_with_signal_codec_stops_after_linked_device_encrypt_without_retry_cache()
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
    let remote_one_time_pre_key_id = 104;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let codec = client.signal_message_codec().unwrap();
    let encryptor = ClosingAfterEncryptor::new(codec, connection.clone(), 2);
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "group signal linked relay failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-signal-send-fail-linked"),
        MessageRelayOptions::new().with_message_id("group-after-dist-signal-send-fail"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let audience_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(audience_plaintext.device_sent_message.is_none());
    let audience_distribution = audience_plaintext.sender_key_distribution_message.unwrap();
    assert_eq!(audience_distribution.group_id.as_deref(), Some("123@g.us"));
    let distribution_bytes = audience_distribution
        .axolotl_sender_key_distribution_message
        .unwrap();

    let own_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let device_sent = own_plaintext.device_sent_message.unwrap();
    assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
    let own_distribution = device_sent
        .message
        .unwrap()
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(own_distribution.group_id.as_deref(), Some("123@g.us"));
    assert_eq!(
        own_distribution
            .axolotl_sender_key_distribution_message
            .unwrap(),
        distribution_bytes
    );
    assert!(wa_core::decode_signal_sender_key_distribution_message(&distribution_bytes).is_ok());
    for jid in ["111@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
    let stored_distribution = client
        .signal_sender_key_provider()
        .unwrap()
        .load_or_create_sender_key_distribution("123@g.us")
        .await
        .unwrap();
    assert!(!stored_distribution.created);

    let snapshot = client
        .retry_session_snapshot("111@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(
        snapshot.registration_id,
        Some(remote_credentials.registration_id)
    );
    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec![
                    "dist-signal-send-fail-linked".to_owned(),
                    "group-after-dist-signal-send-fail".to_owned(),
                ],
                from_jid: Some("111@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("999:7@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@g.us".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: Some(remote_credentials.registration_id),
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.jobs.is_empty());
    assert_eq!(
        prepared.missing_message_ids,
        vec![
            "dist-signal-send-fail-linked",
            "group-after-dist-signal-send-fail"
        ]
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_finalizes_distribution_when_group_relay_send_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["111@s.whatsapp.net", "222@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let device_encryptor = RelayEncryptor::default();
    let sender_key_codec = client.signal_message_codec().unwrap();
    let sender_key_encryptor = ClosingAfterEncryptor::new(sender_key_codec, connection.clone(), 1);
    let send_fut = client.relay_group_sender_key_proto_message_with_encryptors(
        &connection,
        "123@g.us",
        wa_proto::proto::Message {
            conversation: Some("group root relay send failure".to_owned()),
            ..wa_proto::proto::Message::default()
        },
        &device_encryptor,
        &sender_key_encryptor,
        (
            MessageRelayOptions::new().with_message_id("dist-before-group-send-fail"),
            MessageRelayOptions::new().with_message_id("group-send-fail"),
        ),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_attr("s_t", "1")
                        .with_attr("creation", "1")
                        .with_content(vec![
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                            BinaryNode::new("participant").with_attr("jid", "222@s.whatsapp.net"),
                        ]),
                ])
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "222@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "222@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group sender-key send should enqueue distribution stanza")
        .expect("connection sink should keep distribution frame");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(distribution_node.attrs["id"], "dist-before-group-send-fail");
    assert_eq!(distribution_node.attrs["to"], "123@g.us");
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));

    let device_calls = device_encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        device_calls
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "222@s.whatsapp.net"]
    );
    for call in &device_calls {
        let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
        assert!(plaintext.sender_key_distribution_message.as_ref().is_some());
    }
    let sender_key_calls = sender_key_encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        sender_key_calls
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@g.us"]
    );
    let group_plaintext = wa_proto::proto::Message::decode(sender_key_calls[0].1.clone()).unwrap();
    assert_eq!(
        group_plaintext.conversation.as_deref(),
        Some("group root relay send failure")
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "dist-before-group-send-fail".to_owned(),
            "group-send-fail".to_owned(),
        ],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some("123@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: false,
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared.is_complete());
    assert_eq!(prepared.missing_message_ids, vec!["group-send-fail"]);
    assert_eq!(prepared.jobs.len(), 1);
    assert_eq!(prepared.jobs[0].message_id, "dist-before-group-send-fail");
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_signal_finalizes_distribution_when_group_relay_send_fails() {
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
    let remote_one_time_pre_key_id = 105;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let distribution_encryptor = client.signal_message_codec().unwrap();
    let sender_key_codec = client.signal_message_codec().unwrap();
    let sender_key_encryptor = ClosingAfterEncryptor::new(sender_key_codec, connection.clone(), 1);
    let send_fut = client.relay_group_sender_key_proto_message_with_encryptors(
        &connection,
        "123@g.us",
        wa_proto::proto::Message {
            conversation: Some("group signal root relay send failure".to_owned()),
            ..wa_proto::proto::Message::default()
        },
        &distribution_encryptor,
        &sender_key_encryptor,
        (
            MessageRelayOptions::new().with_message_id("dist-signal-before-group-send-fail"),
            MessageRelayOptions::new().with_message_id("group-signal-send-fail"),
        ),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group sender-key send should enqueue distribution stanza")
        .expect("connection sink should keep distribution frame");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(
        distribution_node.attrs["id"],
        "dist-signal-before-group-send-fail"
    );
    assert_eq!(distribution_node.attrs["to"], "123@g.us");
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));

    let participants = test_children(test_child(&distribution_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut distribution_bytes = None;
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&distribution_node, jid);
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
        let distribution = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
            device_sent.message.unwrap().sender_key_distribution_message
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.sender_key_distribution_message
        }
        .unwrap();
        assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
        let bytes = distribution
            .axolotl_sender_key_distribution_message
            .unwrap();
        if let Some(existing) = distribution_bytes.as_ref() {
            assert_eq!(existing, &bytes);
        } else {
            distribution_bytes = Some(bytes);
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
    let distribution_bytes = distribution_bytes.unwrap();
    assert!(wa_core::decode_signal_sender_key_distribution_message(&distribution_bytes).is_ok());

    let sender_key_calls = sender_key_encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        sender_key_calls
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@g.us"]
    );
    let group_plaintext = wa_proto::proto::Message::decode(sender_key_calls[0].1.clone()).unwrap();
    assert_eq!(
        group_plaintext.conversation.as_deref(),
        Some("group signal root relay send failure")
    );

    let snapshot = client
        .retry_session_snapshot("111@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(
        snapshot.registration_id,
        Some(remote_credentials.registration_id)
    );
    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec![
                    "dist-signal-before-group-send-fail".to_owned(),
                    "group-signal-send-fail".to_owned(),
                ],
                from_jid: Some("111@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("999:7@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@g.us".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: Some(remote_credentials.registration_id),
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared.is_complete());
    assert_eq!(prepared.missing_message_ids, vec!["group-signal-send-fail"]);
    assert_eq!(prepared.jobs.len(), 1);
    assert_eq!(
        prepared.jobs[0].message_id,
        "dist-signal-before-group-send-fail"
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_signal_finalizes_distribution_when_group_encrypt_fails() {
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
    let remote_one_time_pre_key_id = 106;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let distribution_encryptor = client.signal_message_codec().unwrap();
    let sender_key_encryptor = FailingAfterEncryptor::new(1, "group signal root encrypt failed");
    let send_fut = client.relay_group_sender_key_proto_message_with_encryptors(
        &connection,
        "123@g.us",
        wa_proto::proto::Message {
            conversation: Some("group signal root encrypt failure".to_owned()),
            ..wa_proto::proto::Message::default()
        },
        &distribution_encryptor,
        &sender_key_encryptor,
        (
            MessageRelayOptions::new().with_message_id("dist-signal-before-group-encrypt-fail"),
            MessageRelayOptions::new().with_message_id("group-signal-encrypt-after-dist-sent"),
        ),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(err.to_string().contains("group signal root encrypt failed"));
    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group sender-key send should enqueue distribution stanza")
        .expect("connection sink should keep distribution frame");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(
        distribution_node.attrs["id"],
        "dist-signal-before-group-encrypt-fail"
    );
    assert_eq!(distribution_node.attrs["to"], "123@g.us");
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    let participants = test_children(test_child(&distribution_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut distribution_bytes = None;
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&distribution_node, jid);
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
        let distribution = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
            device_sent.message.unwrap().sender_key_distribution_message
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.sender_key_distribution_message
        }
        .unwrap();
        assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
        let bytes = distribution
            .axolotl_sender_key_distribution_message
            .unwrap();
        if let Some(existing) = distribution_bytes.as_ref() {
            assert_eq!(existing, &bytes);
        } else {
            distribution_bytes = Some(bytes);
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
    let distribution_bytes = distribution_bytes.unwrap();
    assert!(wa_core::decode_signal_sender_key_distribution_message(&distribution_bytes).is_ok());

    let sender_key_calls = sender_key_encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        sender_key_calls
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@g.us"]
    );
    let group_plaintext = wa_proto::proto::Message::decode(sender_key_calls[0].1.clone()).unwrap();
    assert_eq!(
        group_plaintext.conversation.as_deref(),
        Some("group signal root encrypt failure")
    );

    let snapshot = client
        .retry_session_snapshot("111@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(
        snapshot.registration_id,
        Some(remote_credentials.registration_id)
    );
    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec![
                    "dist-signal-before-group-encrypt-fail".to_owned(),
                    "group-signal-encrypt-after-dist-sent".to_owned(),
                ],
                from_jid: Some("111@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("999:7@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@g.us".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: Some(remote_credentials.registration_id),
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared.is_complete());
    assert_eq!(
        prepared.missing_message_ids,
        vec!["group-signal-encrypt-after-dist-sent"]
    );
    assert_eq!(prepared.jobs.len(), 1);
    assert_eq!(
        prepared.jobs[0].message_id,
        "dist-signal-before-group-encrypt-fail"
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_finalizes_distribution_when_group_encrypt_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["111@s.whatsapp.net", "222@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let device_encryptor = RelayEncryptor::default();
    let sender_key_encryptor = FailingAfterEncryptor::new(1, "group root encrypt failed");
    let send_fut = client.relay_group_sender_key_proto_message_with_encryptors(
        &connection,
        "123@g.us",
        wa_proto::proto::Message {
            conversation: Some("group root encrypt failure".to_owned()),
            ..wa_proto::proto::Message::default()
        },
        &device_encryptor,
        &sender_key_encryptor,
        (
            MessageRelayOptions::new().with_message_id("dist-before-group-encrypt-fail"),
            MessageRelayOptions::new().with_message_id("group-encrypt-after-dist-sent"),
        ),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_attr("s_t", "1")
                        .with_attr("creation", "1")
                        .with_content(vec![
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                            BinaryNode::new("participant").with_attr("jid", "222@s.whatsapp.net"),
                        ]),
                ])
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "222@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "222@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(err.to_string().contains("group root encrypt failed"));
    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group sender-key send should enqueue distribution stanza")
        .expect("connection sink should keep distribution frame");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(
        distribution_node.attrs["id"],
        "dist-before-group-encrypt-fail"
    );
    assert_eq!(distribution_node.attrs["to"], "123@g.us");
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    let device_calls = device_encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        device_calls
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "222@s.whatsapp.net"]
    );
    for call in &device_calls {
        let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
        assert!(plaintext.sender_key_distribution_message.as_ref().is_some());
    }
    let sender_key_calls = sender_key_encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        sender_key_calls
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@g.us"]
    );
    let group_plaintext = wa_proto::proto::Message::decode(sender_key_calls[0].1.clone()).unwrap();
    assert_eq!(
        group_plaintext.conversation.as_deref(),
        Some("group root encrypt failure")
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "dist-before-group-encrypt-fail".to_owned(),
            "group-encrypt-after-dist-sent".to_owned(),
        ],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some("123@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: false,
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared.is_complete());
    assert_eq!(
        prepared.missing_message_ids,
        vec!["group-encrypt-after-dist-sent"]
    );
    assert_eq!(prepared.jobs.len(), 1);
    assert_eq!(
        prepared.jobs[0].message_id,
        "dist-before-group-encrypt-fail"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_normalizes_legacy_c_us_participant_aliases() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "111@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "group alias hello",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-cus-normalized"),
        MessageRelayOptions::new().with_message_id("group-cus-normalized"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_attr("s_t", "1")
                        .with_attr("creation", "1")
                        .with_content(vec![
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@c.us")
                                .with_attr("phoneNumber", "111@s.whatsapp.net"),
                        ]),
                ])
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@c.us")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "999@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.distribution.message_id, "dist-cus-normalized");
    assert_eq!(relay.message.message_id, "group-cus-normalized");
    assert_eq!(relay.distribution.recipient_count, 1);

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let enc = test_participant_enc_node(&distribution_node, "111@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "msg");

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node.attrs["to"], "123@g.us");
    assert_eq!(test_child(&group_node, "enc").attrs["type"], "skmsg");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_distribution_deduplicates_own_pn_lid_linked_device_aliases() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["111@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_group_sender_key_text_with_distribution(
        &connection,
        "123@g.us",
        "group own alias hello",
        &encryptor,
        MessageRelayOptions::new().with_message_id("dist-own-alias-dedup-1"),
        MessageRelayOptions::new().with_message_id("group-own-alias-dedup-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
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
                            .with_attr("jid", "111@s.whatsapp.net")
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
        &mut send_fut,
    )
    .await;

    let relay = tokio::time::timeout(Duration::from_secs(1), &mut send_fut)
        .await
        .expect("group sender-key send should not query sessions for duplicate own LID alias")
        .unwrap();
    assert_eq!(relay.distribution.message_id, "dist-own-alias-dedup-1");
    assert_eq!(relay.message.message_id, "group-own-alias-dedup-1");
    assert_eq!(relay.distribution.recipient_count, 2);

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let Some(wa_binary::BinaryNodeContent::Nodes(distribution_children)) =
        &distribution_node.content
    else {
        panic!("distribution relay should contain participants");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(participants)) = &distribution_children[0].content
    else {
        panic!("distribution relay should contain participant nodes");
    };
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node.attrs["to"], "123@g.us");
    assert_eq!(test_child(&group_node, "enc").attrs["type"], "skmsg");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    let audience_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(audience_plaintext.device_sent_message.is_none());
    assert!(audience_plaintext.sender_key_distribution_message.is_some());
    let own_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let device_sent = own_plaintext.device_sent_message.unwrap();
    assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
    assert!(
        device_sent
            .message
            .unwrap()
            .sender_key_distribution_message
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_message_with_signal_provider_encrypts_media_distribution_and_root() {
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
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![1u8; 32]),
        Bytes::from(vec![2u8; 32]),
        Bytes::from(vec![3u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/group-signal-image")
    .with_direct_path("/v/t62.7118-24/group-signal-image")
    .with_media_key_timestamp(1_700_000_000);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed group photo".to_owned());
    let send_fut = client.send_group_sender_key_message_with_signal_provider(
        &connection,
        "123@g.us",
        MessageContent::image(image),
        MessageRelayOptions::new().with_message_id("dist-signal-media-1"),
        MessageRelayOptions::new().with_message_id("group-signal-media-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("111@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.distribution.message_id, "dist-signal-media-1");
    assert_eq!(relay.message.message_id, "group-signal-media-1");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node, relay.distribution.node);
    let enc = test_participant_enc_node(&distribution_node, "111@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let distribution_ciphertext = test_node_bytes(enc).unwrap();
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted_distribution = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &distribution_ciphertext,
    )
    .unwrap();
    let distribution_plaintext =
        wa_core::unpad_random_max16(&decrypted_distribution.plaintext).unwrap();
    let distribution_message = wa_proto::proto::Message::decode(distribution_plaintext).unwrap();
    let distribution = distribution_message
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
    let distribution_bytes = distribution
        .axolotl_sender_key_distribution_message
        .unwrap();
    let decoded_distribution =
        wa_core::decode_signal_sender_key_distribution_message(&distribution_bytes).unwrap();

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node, relay.message.node);
    assert_eq!(group_node.attrs["type"], "media");
    let enc = test_child(&group_node, "enc");
    assert_eq!(enc.attrs["type"], "skmsg");
    let group_ciphertext = test_node_bytes(enc).unwrap();
    let sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &decoded_distribution)
            .unwrap();
    let decrypted_group = wa_core::decrypt_signal_sender_key_record_message(
        &sender_key_record,
        &group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let group_plaintext = wa_core::unpad_random_max16(&decrypted_group.plaintext).unwrap();
    let group_message = wa_proto::proto::Message::decode(group_plaintext).unwrap();
    let image = group_message.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("store-backed group photo"));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/group-signal-image")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_signal_encrypts_media_distribution_to_own_linked_device() {
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
    let remote_one_time_pre_key_id = 117;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![22u8; 32]),
        Bytes::from(vec![23u8; 32]),
        Bytes::from(vec![24u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/group-signal-linked-image")
    .with_direct_path("/v/t62.7118-24/group-signal-linked-image")
    .with_media_key_timestamp(1_700_000_007);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed linked group photo".to_owned());
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_group_sender_key_message_with_signal_provider(
        &connection,
        "123@g.us",
        MessageContent::image(image),
        MessageRelayOptions::new().with_message_id("dist-signal-media-linked-1"),
        MessageRelayOptions::new().with_message_id("group-signal-media-linked-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
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
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "999@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.distribution.message_id, "dist-signal-media-linked-1");
    assert_eq!(relay.distribution.recipient_count, 2);
    assert_eq!(relay.message.message_id, "group-signal-media-linked-1");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node, relay.distribution.node);
    let participants = test_children(test_child(&distribution_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut distribution_bytes = None;
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&distribution_node, jid);
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
        let distribution = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
            device_sent.message.unwrap().sender_key_distribution_message
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.sender_key_distribution_message
        }
        .unwrap();
        assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
        let bytes = distribution
            .axolotl_sender_key_distribution_message
            .unwrap();
        if let Some(existing) = distribution_bytes.as_ref() {
            assert_eq!(existing, &bytes);
        } else {
            distribution_bytes = Some(bytes);
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
    let decoded_distribution = wa_core::decode_signal_sender_key_distribution_message(
        distribution_bytes.as_ref().unwrap(),
    )
    .unwrap();

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node, relay.message.node);
    assert_eq!(group_node.attrs["to"], "123@g.us");
    assert_eq!(group_node.attrs["type"], "media");
    let enc = test_child(&group_node, "enc");
    assert_eq!(enc.attrs["type"], "skmsg");
    let group_ciphertext = test_node_bytes(enc).unwrap();
    let sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &decoded_distribution)
            .unwrap();
    let decrypted_group = wa_core::decrypt_signal_sender_key_record_message(
        &sender_key_record,
        &group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let group_plaintext = wa_core::unpad_random_max16(&decrypted_group.plaintext).unwrap();
    let group_message = wa_proto::proto::Message::decode(group_plaintext).unwrap();
    let image = group_message.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(
        image.caption.as_deref(),
        Some("store-backed linked group photo")
    );
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/group-signal-linked-image")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_media_signal_reuses_established_sessions_for_own_linked_device() {
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
    let remote_one_time_pre_key_id = 118;
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let first_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![25u8; 32]),
        Bytes::from(vec![26u8; 32]),
        Bytes::from(vec![27u8; 32]),
        3_072,
    )
    .with_url("https://media.example.invalid/group-signal-established-first-image")
    .with_direct_path("/v/t62.7118-24/group-signal-established-first-image")
    .with_media_key_timestamp(1_700_000_008);
    let mut first_image = wa_core::ImageContent::new(first_media, "image/jpeg");
    first_image.caption = Some("first linked group photo".to_owned());
    let first_send = client.send_group_sender_key_message_with_signal_provider(
        &connection,
        "123@g.us",
        MessageContent::image(first_image),
        MessageRelayOptions::new().with_message_id("dist-signal-media-established-1"),
        MessageRelayOptions::new().with_message_id("group-signal-media-established-1"),
    );
    tokio::pin!(first_send);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut first_send,
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
                    "111@s.whatsapp.net".to_owned(),
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
                            .with_attr("jid", "111@s.whatsapp.net")
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
        &mut first_send,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut first_send,
    )
    .await;

    let first_relay = first_send.await.unwrap();
    assert_eq!(
        first_relay.distribution.message_id,
        "dist-signal-media-established-1"
    );
    assert_eq!(first_relay.distribution.recipient_count, 2);
    assert_eq!(
        first_relay.message.message_id,
        "group-signal-media-established-1"
    );
    let first_distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_distribution_node, first_relay.distribution.node);
    let first_participants =
        test_children(test_child(&first_distribution_node, "participants"), "to");
    assert_eq!(
        first_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let first_remote_ciphertext = test_node_bytes(test_participant_enc_node(
        &first_distribution_node,
        "111@s.whatsapp.net",
    ))
    .unwrap();
    let first_remote_pre_key =
        wa_core::decode_signal_pre_key_whisper_message(&first_remote_ciphertext).unwrap();
    assert_eq!(
        first_remote_pre_key.pre_key_id,
        Some(remote_one_time_pre_key_id)
    );
    assert_eq!(first_remote_pre_key.message.counter, 0);
    let first_remote_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_remote_ciphertext,
    )
    .unwrap();
    let first_remote_unpadded =
        wa_core::unpad_random_max16(&first_remote_decrypted.plaintext).unwrap();
    let first_remote_decoded = wa_proto::proto::Message::decode(first_remote_unpadded).unwrap();
    assert!(first_remote_decoded.device_sent_message.is_none());
    let first_remote_distribution = first_remote_decoded
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(
        first_remote_distribution.group_id.as_deref(),
        Some("123@g.us")
    );
    let first_distribution_bytes = first_remote_distribution
        .axolotl_sender_key_distribution_message
        .unwrap();

    let first_own_ciphertext = test_node_bytes(test_participant_enc_node(
        &first_distribution_node,
        "999:8@s.whatsapp.net",
    ))
    .unwrap();
    let first_own_pre_key =
        wa_core::decode_signal_pre_key_whisper_message(&first_own_ciphertext).unwrap();
    assert_eq!(
        first_own_pre_key.pre_key_id,
        Some(remote_one_time_pre_key_id)
    );
    assert_eq!(first_own_pre_key.message.counter, 0);
    let first_own_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_own_ciphertext,
    )
    .unwrap();
    let first_own_unpadded = wa_core::unpad_random_max16(&first_own_decrypted.plaintext).unwrap();
    let first_own_decoded = wa_proto::proto::Message::decode(first_own_unpadded).unwrap();
    let first_device_sent = first_own_decoded.device_sent_message.unwrap();
    assert_eq!(
        first_device_sent.destination_jid.as_deref(),
        Some("123@g.us")
    );
    let first_own_distribution = first_device_sent
        .message
        .unwrap()
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(first_own_distribution.group_id.as_deref(), Some("123@g.us"));
    assert_eq!(
        first_own_distribution
            .axolotl_sender_key_distribution_message
            .unwrap(),
        first_distribution_bytes
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("ownlid:8@lid")
            .await
            .unwrap()
            .is_none()
    );

    let first_distribution =
        wa_core::decode_signal_sender_key_distribution_message(&first_distribution_bytes).unwrap();
    let first_group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_group_node, first_relay.message.node);
    assert_eq!(first_group_node.attrs["type"], "media");
    let first_group_enc = test_child(&first_group_node, "enc");
    assert_eq!(first_group_enc.attrs["type"], "skmsg");
    let first_group_ciphertext = test_node_bytes(first_group_enc).unwrap();
    let first_sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &first_distribution).unwrap();
    let first_group_decrypted = wa_core::decrypt_signal_sender_key_record_message(
        &first_sender_key_record,
        &first_group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let first_group_plaintext =
        wa_core::unpad_random_max16(&first_group_decrypted.plaintext).unwrap();
    let first_group_message = wa_proto::proto::Message::decode(first_group_plaintext).unwrap();
    let first_group_image = first_group_message.image_message.unwrap();
    assert_eq!(
        first_group_image.caption.as_deref(),
        Some("first linked group photo")
    );
    assert_eq!(
        first_group_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/group-signal-established-first-image")
    );

    let second_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![28u8; 32]),
        Bytes::from(vec![29u8; 32]),
        Bytes::from(vec![30u8; 32]),
        4_096,
    )
    .with_url("https://media.example.invalid/group-signal-established-second-image")
    .with_direct_path("/v/t62.7118-24/group-signal-established-second-image")
    .with_media_key_timestamp(1_700_000_009);
    let mut second_image = wa_core::ImageContent::new(second_media, "image/jpeg");
    second_image.caption = Some("second linked group photo".to_owned());
    let second_send = client.send_group_sender_key_message_with_signal_provider(
        &connection,
        "123@g.us",
        MessageContent::image(second_image),
        MessageRelayOptions::new().with_message_id("dist-signal-media-established-2"),
        MessageRelayOptions::new().with_message_id("group-signal-media-established-2"),
    );
    tokio::pin!(second_send);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut second_send,
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
                    "111@s.whatsapp.net".to_owned(),
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
                            .with_attr("jid", "111@s.whatsapp.net")
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
        &mut second_send,
    )
    .await;

    let second_relay = tokio::time::timeout(Duration::from_secs(1), &mut second_send)
        .await
        .expect(
            "second group media sender-key distribution should reuse provider sessions without key-bundle query",
        )
        .unwrap();
    assert_eq!(
        second_relay.distribution.message_id,
        "dist-signal-media-established-2"
    );
    assert_eq!(second_relay.distribution.recipient_count, 2);
    assert_eq!(
        second_relay.message.message_id,
        "group-signal-media-established-2"
    );
    let second_distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_distribution_node, second_relay.distribution.node);
    let second_participants =
        test_children(test_child(&second_distribution_node, "participants"), "to");
    assert_eq!(
        second_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let mut second_distribution_bytes = None;
    for (jid, first_record, expected_device_sent) in [
        ("111@s.whatsapp.net", &first_remote_decrypted.record, false),
        ("999:8@s.whatsapp.net", &first_own_decrypted.record, true),
    ] {
        let enc = test_participant_enc_node(&second_distribution_node, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        let distribution = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
            device_sent.message.unwrap().sender_key_distribution_message
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.sender_key_distribution_message
        }
        .unwrap();
        assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
        let bytes = distribution
            .axolotl_sender_key_distribution_message
            .unwrap();
        if let Some(existing) = second_distribution_bytes.as_ref() {
            assert_eq!(existing, &bytes);
        } else {
            second_distribution_bytes = Some(bytes);
        }
    }

    let second_distribution = wa_core::decode_signal_sender_key_distribution_message(
        second_distribution_bytes.as_ref().unwrap(),
    )
    .unwrap();
    let second_group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_group_node, second_relay.message.node);
    assert_eq!(second_group_node.attrs["to"], "123@g.us");
    assert_eq!(second_group_node.attrs["type"], "media");
    let second_group_enc = test_child(&second_group_node, "enc");
    assert_eq!(second_group_enc.attrs["type"], "skmsg");
    let second_group_ciphertext = test_node_bytes(second_group_enc).unwrap();
    let second_sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &second_distribution).unwrap();
    let second_group_decrypted = wa_core::decrypt_signal_sender_key_record_message(
        &second_sender_key_record,
        &second_group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let second_group_plaintext =
        wa_core::unpad_random_max16(&second_group_decrypted.plaintext).unwrap();
    let second_group_message = wa_proto::proto::Message::decode(second_group_plaintext).unwrap();
    let second_group_image = second_group_message.image_message.unwrap();
    assert_eq!(
        second_group_image.caption.as_deref(),
        Some("second linked group photo")
    );
    assert_eq!(
        second_group_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/group-signal-established-second-image")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("ownlid:8@lid")
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_text_with_signal_provider_encrypts_distribution_and_root() {
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
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_group_sender_key_text_with_signal_provider(
        &connection,
        "123@g.us",
        "store-backed group hello",
        MessageRelayOptions::new().with_message_id("dist-signal-1"),
        MessageRelayOptions::new().with_message_id("group-signal-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("111@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.distribution.message_id, "dist-signal-1");
    assert_eq!(relay.message.message_id, "group-signal-1");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node, relay.distribution.node);
    let enc = test_participant_enc_node(&distribution_node, "111@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let distribution_ciphertext = test_node_bytes(enc).unwrap();
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted_distribution = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &distribution_ciphertext,
    )
    .unwrap();
    let distribution_plaintext =
        wa_core::unpad_random_max16(&decrypted_distribution.plaintext).unwrap();
    let distribution_message = wa_proto::proto::Message::decode(distribution_plaintext).unwrap();
    let distribution = distribution_message
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
    let distribution_bytes = distribution
        .axolotl_sender_key_distribution_message
        .unwrap();
    let decoded_distribution =
        wa_core::decode_signal_sender_key_distribution_message(&distribution_bytes).unwrap();

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node, relay.message.node);
    let enc = test_child(&group_node, "enc");
    assert_eq!(enc.attrs["type"], "skmsg");
    let group_ciphertext = test_node_bytes(enc).unwrap();
    let sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &decoded_distribution)
            .unwrap();
    let decrypted_group = wa_core::decrypt_signal_sender_key_record_message(
        &sender_key_record,
        &group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let group_plaintext = wa_core::unpad_random_max16(&decrypted_group.plaintext).unwrap();
    let group_message = wa_proto::proto::Message::decode(group_plaintext).unwrap();
    assert_eq!(
        group_message
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("store-backed group hello")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_signal_normalizes_legacy_c_us_participant_aliases() {
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
    let remote_one_time_pre_key_id = 109;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_group_sender_key_text_with_signal_provider(
        &connection,
        "123@g.us",
        "store-backed c.us group hello",
        MessageRelayOptions::new().with_message_id("dist-signal-cus-normalized"),
        MessageRelayOptions::new().with_message_id("group-signal-cus-normalized"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_attr("s_t", "1")
                        .with_attr("creation", "1")
                        .with_content(vec![
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@c.us")
                                .with_attr("phoneNumber", "111@s.whatsapp.net"),
                        ]),
                ])
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@c.us")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("111@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.distribution.message_id, "dist-signal-cus-normalized");
    assert_eq!(relay.distribution.recipient_count, 1);
    assert_eq!(relay.message.message_id, "group-signal-cus-normalized");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node, relay.distribution.node);
    let participants = test_children(test_child(&distribution_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net"]
    );

    let enc = test_participant_enc_node(&distribution_node, "111@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let distribution_ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message =
        wa_core::decode_signal_pre_key_whisper_message(&distribution_ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted_distribution = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &distribution_ciphertext,
    )
    .unwrap();
    let distribution_plaintext =
        wa_core::unpad_random_max16(&decrypted_distribution.plaintext).unwrap();
    let distribution_message = wa_proto::proto::Message::decode(distribution_plaintext).unwrap();
    assert!(distribution_message.device_sent_message.is_none());
    let distribution = distribution_message
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
    let distribution_bytes = distribution
        .axolotl_sender_key_distribution_message
        .unwrap();
    let decoded_distribution =
        wa_core::decode_signal_sender_key_distribution_message(&distribution_bytes).unwrap();
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node, relay.message.node);
    assert_eq!(group_node.attrs["to"], "123@g.us");
    let enc = test_child(&group_node, "enc");
    assert_eq!(enc.attrs["type"], "skmsg");
    let group_ciphertext = test_node_bytes(enc).unwrap();
    let sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &decoded_distribution)
            .unwrap();
    let decrypted_group = wa_core::decrypt_signal_sender_key_record_message(
        &sender_key_record,
        &group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let group_plaintext = wa_core::unpad_random_max16(&decrypted_group.plaintext).unwrap();
    let group_message = wa_proto::proto::Message::decode(group_plaintext).unwrap();
    assert_eq!(
        group_message
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("store-backed c.us group hello")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_signal_encrypts_distribution_to_own_linked_device() {
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
    let remote_one_time_pre_key_id = 101;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_group_sender_key_text_with_signal_provider(
        &connection,
        "123@g.us",
        "store-backed linked group hello",
        MessageRelayOptions::new().with_message_id("dist-signal-linked-1"),
        MessageRelayOptions::new().with_message_id("group-signal-linked-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.distribution.message_id, "dist-signal-linked-1");
    assert_eq!(relay.distribution.recipient_count, 2);
    assert_eq!(relay.message.message_id, "group-signal-linked-1");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node, relay.distribution.node);
    let participants = test_children(test_child(&distribution_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut distribution_bytes = None;
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&distribution_node, jid);
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
        let distribution = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
            device_sent.message.unwrap().sender_key_distribution_message
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.sender_key_distribution_message
        }
        .unwrap();
        assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
        let bytes = distribution
            .axolotl_sender_key_distribution_message
            .unwrap();
        if let Some(existing) = distribution_bytes.as_ref() {
            assert_eq!(existing, &bytes);
        } else {
            distribution_bytes = Some(bytes);
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
    let decoded_distribution = wa_core::decode_signal_sender_key_distribution_message(
        distribution_bytes.as_ref().unwrap(),
    )
    .unwrap();

    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node, relay.message.node);
    assert_eq!(group_node.attrs["to"], "123@g.us");
    let enc = test_child(&group_node, "enc");
    assert_eq!(enc.attrs["type"], "skmsg");
    let group_ciphertext = test_node_bytes(enc).unwrap();
    let sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &decoded_distribution)
            .unwrap();
    let decrypted_group = wa_core::decrypt_signal_sender_key_record_message(
        &sender_key_record,
        &group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let group_plaintext = wa_core::unpad_random_max16(&decrypted_group.plaintext).unwrap();
    let group_message = wa_proto::proto::Message::decode(group_plaintext).unwrap();
    assert_eq!(
        group_message.extended_text_message.unwrap().text.as_deref(),
        Some("store-backed linked group hello")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_signal_deduplicates_own_pn_lid_linked_device_aliases() {
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
    let remote_one_time_pre_key_id = 107;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_group_sender_key_text_with_signal_provider(
        &connection,
        "123@g.us",
        "store-backed group own alias hello",
        MessageRelayOptions::new().with_message_id("dist-signal-own-alias-dedup-1"),
        MessageRelayOptions::new().with_message_id("group-signal-own-alias-dedup-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut send_fut,
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
                    "111@s.whatsapp.net".to_owned(),
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
                            .with_attr("jid", "111@s.whatsapp.net")
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(
        relay.distribution.message_id,
        "dist-signal-own-alias-dedup-1"
    );
    assert_eq!(relay.distribution.recipient_count, 2);
    assert_eq!(relay.message.message_id, "group-signal-own-alias-dedup-1");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node, relay.distribution.node);
    let participants = test_children(test_child(&distribution_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut distribution_bytes = None;
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&distribution_node, jid);
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
        let distribution = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
            device_sent.message.unwrap().sender_key_distribution_message
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.sender_key_distribution_message
        }
        .unwrap();
        assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
        let bytes = distribution
            .axolotl_sender_key_distribution_message
            .unwrap();
        if let Some(existing) = distribution_bytes.as_ref() {
            assert_eq!(existing, &bytes);
        } else {
            distribution_bytes = Some(bytes);
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

    let decoded_distribution = wa_core::decode_signal_sender_key_distribution_message(
        distribution_bytes.as_ref().unwrap(),
    )
    .unwrap();
    let group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(group_node, relay.message.node);
    assert_eq!(group_node.attrs["to"], "123@g.us");
    let enc = test_child(&group_node, "enc");
    assert_eq!(enc.attrs["type"], "skmsg");
    let group_ciphertext = test_node_bytes(enc).unwrap();
    let sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &decoded_distribution)
            .unwrap();
    let decrypted_group = wa_core::decrypt_signal_sender_key_record_message(
        &sender_key_record,
        &group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let group_plaintext = wa_core::unpad_random_max16(&decrypted_group.plaintext).unwrap();
    let group_message = wa_proto::proto::Message::decode(group_plaintext).unwrap();
    assert_eq!(
        group_message.extended_text_message.unwrap().text.as_deref(),
        Some("store-backed group own alias hello")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_group_sender_key_signal_reuses_established_sessions_for_own_linked_device() {
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
    let remote_one_time_pre_key_id = 102;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let first_send = client.send_group_sender_key_text_with_signal_provider(
        &connection,
        "123@g.us",
        "first linked group signal",
        MessageRelayOptions::new().with_message_id("dist-signal-linked-established-1"),
        MessageRelayOptions::new().with_message_id("group-signal-linked-established-1"),
    );
    tokio::pin!(first_send);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut first_send,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                    ]),
                ])])
        },
        &mut first_send,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("111@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut first_send,
    )
    .await;

    let first_relay = first_send.await.unwrap();
    assert_eq!(
        first_relay.distribution.message_id,
        "dist-signal-linked-established-1"
    );
    assert_eq!(first_relay.distribution.recipient_count, 2);
    assert_eq!(
        first_relay.message.message_id,
        "group-signal-linked-established-1"
    );
    let first_distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_distribution_node, first_relay.distribution.node);
    let first_participants =
        test_children(test_child(&first_distribution_node, "participants"), "to");
    assert_eq!(
        first_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let first_remote_ciphertext = test_node_bytes(test_participant_enc_node(
        &first_distribution_node,
        "111@s.whatsapp.net",
    ))
    .unwrap();
    let first_remote_pre_key =
        wa_core::decode_signal_pre_key_whisper_message(&first_remote_ciphertext).unwrap();
    assert_eq!(
        first_remote_pre_key.pre_key_id,
        Some(remote_one_time_pre_key_id)
    );
    assert_eq!(first_remote_pre_key.message.counter, 0);
    let first_remote_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_remote_ciphertext,
    )
    .unwrap();
    let first_remote_unpadded =
        wa_core::unpad_random_max16(&first_remote_decrypted.plaintext).unwrap();
    let first_remote_decoded = wa_proto::proto::Message::decode(first_remote_unpadded).unwrap();
    assert!(first_remote_decoded.device_sent_message.is_none());
    let first_remote_distribution = first_remote_decoded
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(
        first_remote_distribution.group_id.as_deref(),
        Some("123@g.us")
    );
    let first_distribution_bytes = first_remote_distribution
        .axolotl_sender_key_distribution_message
        .unwrap();

    let first_own_ciphertext = test_node_bytes(test_participant_enc_node(
        &first_distribution_node,
        "999:8@s.whatsapp.net",
    ))
    .unwrap();
    let first_own_pre_key =
        wa_core::decode_signal_pre_key_whisper_message(&first_own_ciphertext).unwrap();
    assert_eq!(
        first_own_pre_key.pre_key_id,
        Some(remote_one_time_pre_key_id)
    );
    assert_eq!(first_own_pre_key.message.counter, 0);
    let first_own_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_own_ciphertext,
    )
    .unwrap();
    let first_own_unpadded = wa_core::unpad_random_max16(&first_own_decrypted.plaintext).unwrap();
    let first_own_decoded = wa_proto::proto::Message::decode(first_own_unpadded).unwrap();
    let first_device_sent = first_own_decoded.device_sent_message.unwrap();
    assert_eq!(
        first_device_sent.destination_jid.as_deref(),
        Some("123@g.us")
    );
    let first_own_distribution = first_device_sent
        .message
        .unwrap()
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(first_own_distribution.group_id.as_deref(), Some("123@g.us"));
    assert_eq!(
        first_own_distribution
            .axolotl_sender_key_distribution_message
            .unwrap(),
        first_distribution_bytes
    );

    let first_distribution =
        wa_core::decode_signal_sender_key_distribution_message(&first_distribution_bytes).unwrap();
    let first_group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_group_node, first_relay.message.node);
    let first_group_enc = test_child(&first_group_node, "enc");
    assert_eq!(first_group_enc.attrs["type"], "skmsg");
    let first_group_ciphertext = test_node_bytes(first_group_enc).unwrap();
    let first_sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &first_distribution).unwrap();
    let first_group_decrypted = wa_core::decrypt_signal_sender_key_record_message(
        &first_sender_key_record,
        &first_group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let first_group_plaintext =
        wa_core::unpad_random_max16(&first_group_decrypted.plaintext).unwrap();
    let first_group_message = wa_proto::proto::Message::decode(first_group_plaintext).unwrap();
    assert_eq!(
        first_group_message
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("first linked group signal")
    );

    let second_send = client.send_group_sender_key_text_with_signal_provider(
        &connection,
        "123@g.us",
        "second linked group signal",
        MessageRelayOptions::new().with_message_id("dist-signal-linked-established-2"),
        MessageRelayOptions::new().with_message_id("group-signal-linked-established-2"),
    );
    tokio::pin!(second_send);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            group_metadata_response(&node, "123", "Team")
        },
        &mut second_send,
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
                    "111@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "111@s.whatsapp.net")
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
                    ]),
                ])])
        },
        &mut second_send,
    )
    .await;

    let second_relay = tokio::time::timeout(Duration::from_secs(1), &mut second_send)
        .await
        .expect(
            "second group sender-key distribution should reuse provider sessions without key-bundle query",
        )
        .unwrap();
    assert_eq!(
        second_relay.distribution.message_id,
        "dist-signal-linked-established-2"
    );
    assert_eq!(second_relay.distribution.recipient_count, 2);
    assert_eq!(
        second_relay.message.message_id,
        "group-signal-linked-established-2"
    );
    let second_distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_distribution_node, second_relay.distribution.node);
    let second_participants =
        test_children(test_child(&second_distribution_node, "participants"), "to");
    assert_eq!(
        second_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let mut second_distribution_bytes = None;
    for (jid, first_record, expected_device_sent) in [
        ("111@s.whatsapp.net", &first_remote_decrypted.record, false),
        ("999:8@s.whatsapp.net", &first_own_decrypted.record, true),
    ] {
        let enc = test_participant_enc_node(&second_distribution_node, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        let distribution = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(device_sent.destination_jid.as_deref(), Some("123@g.us"));
            device_sent.message.unwrap().sender_key_distribution_message
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.sender_key_distribution_message
        }
        .unwrap();
        assert_eq!(distribution.group_id.as_deref(), Some("123@g.us"));
        let bytes = distribution
            .axolotl_sender_key_distribution_message
            .unwrap();
        if let Some(existing) = second_distribution_bytes.as_ref() {
            assert_eq!(existing, &bytes);
        } else {
            second_distribution_bytes = Some(bytes);
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

    let second_distribution = wa_core::decode_signal_sender_key_distribution_message(
        second_distribution_bytes.as_ref().unwrap(),
    )
    .unwrap();
    let second_group_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_group_node, second_relay.message.node);
    assert_eq!(second_group_node.attrs["to"], "123@g.us");
    let second_group_enc = test_child(&second_group_node, "enc");
    assert_eq!(second_group_enc.attrs["type"], "skmsg");
    let second_group_ciphertext = test_node_bytes(second_group_enc).unwrap();
    let second_sender_key_record =
        wa_core::process_signal_sender_key_distribution_record(None, &second_distribution).unwrap();
    let second_group_decrypted = wa_core::decrypt_signal_sender_key_record_message(
        &second_sender_key_record,
        &second_group_ciphertext,
        &XEdDsaNoiseCertificateVerifier,
    )
    .unwrap();
    let second_group_plaintext =
        wa_core::unpad_random_max16(&second_group_decrypted.plaintext).unwrap();
    let second_group_message = wa_proto::proto::Message::decode(second_group_plaintext).unwrap();
    assert_eq!(
        second_group_message
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("second linked group signal")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_to_devices_adds_stored_device_identity_for_pre_key_ciphertext() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.signed_device_identity = Some(Bytes::from_static(b"stored-identity"));
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::pre_key();

    let relay = client
        .send_text_to_devices(
            &connection,
            "123@s.whatsapp.net",
            "hello",
            &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
            &encryptor,
            MessageRelayOptions::new().with_message_id("msg-1"),
        )
        .await
        .unwrap();

    assert!(relay.should_include_device_identity);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message stanza has no children");
    };
    assert_eq!(content.len(), 2);
    assert_eq!(content[1].tag, "device-identity");
    assert_eq!(
        content[1].content,
        Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
            b"stored-identity"
        )))
    );
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn relay_reaction_to_devices_writes_reaction_stanza() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let key = wa_core::build_message_key("123@s.whatsapp.net", false, "target-1", None).unwrap();

    let relay = client
        .relay_message_to_devices(
            &connection,
            "123@s.whatsapp.net",
            MessageContent::reaction(wa_core::ReactionContent::new(key.clone(), "")),
            &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
            &encryptor,
            MessageRelayOptions::new().with_message_id("msg-1"),
        )
        .await
        .unwrap();

    assert_eq!(relay.message_id, "msg-1");
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["type"], "reaction");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let reaction = plaintext.reaction_message.unwrap();
    assert_eq!(reaction.key.unwrap(), key);
    assert_eq!(reaction.text.as_deref(), Some(""));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_discovers_devices_and_wraps_own_devices() {
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
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"trusted-contact-token"),
        )
        .unwrap()
        .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "hello",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "10"),
                                ])],
                            )]),
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
                        BinaryNode::new("user")
                            .with_attr("jid", "ownlid@lid")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "13"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "9")
                                        .with_attr("key-index", "14")
                                        .with_attr("is_hosted", "true"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(node.attrs["to"], wa_core::SERVER_JID);
            assert_eq!(
                encrypt_key_query_user_attrs(&node)
                    .into_iter()
                    .map(|(jid, _)| jid)
                    .collect::<Vec<_>>(),
                vec![
                    "123@s.whatsapp.net".to_owned(),
                    "123:1@s.whatsapp.net".to_owned(),
                    "999@s.whatsapp.net".to_owned(),
                    "999:8@s.whatsapp.net".to_owned(),
                    "ownlid:9@hosted.lid".to_owned(),
                ]
            );
            session_response_for_query(&node)
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "msg-1");
    assert_eq!(relay.recipient_count, 5);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "msg-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message should contain child nodes");
    };
    assert!(content.iter().any(|node| {
        node.tag == "tctoken"
            && node.content
                == Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
                    b"trusted-contact-token",
                )))
    }));

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec![
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "999@s.whatsapp.net",
            "999:8@s.whatsapp.net",
            "ownlid:9@hosted.lid",
        ]
    );
    for call in calls.iter().take(2) {
        let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
        assert_eq!(
            plaintext
                .extended_text_message
                .as_ref()
                .unwrap()
                .text
                .as_deref(),
            Some("hello")
        );
        assert!(plaintext.device_sent_message.is_none());
    }
    for call in calls.iter().skip(2) {
        let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
        let device_sent = plaintext.device_sent_message.unwrap();
        assert_eq!(
            device_sent.destination_jid.as_deref(),
            Some("123@s.whatsapp.net")
        );
        assert_eq!(
            device_sent
                .message
                .unwrap()
                .extended_text_message
                .unwrap()
                .text
                .as_deref(),
            Some("hello")
        );
    }
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_fails_when_device_lookup_has_no_recipients() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "empty direct devices",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-empty-devices"),
    );
    tokio::pin!(send_fut);

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
                        BinaryNode::new("user").with_attr("jid", "123@s.whatsapp.net"),
                        BinaryNode::new("user").with_attr("jid", "999@s.whatsapp.net"),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(
        err,
        wa_core::CoreError::Protocol(message)
            if message == "message send requires at least one recipient device"
    ));
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(encryptor.calls.lock().unwrap().is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_stops_when_session_assertion_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "missing direct session",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-session-fail"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            error_result_for(&node, "401", "session denied")
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("E2E session query failed (401): session denied")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(encryptor.calls.lock().unwrap().is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_stops_when_participant_encryption_fails_without_retry_cache() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["123@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = FailingAfterEncryptor::new(2, "direct participant encrypt failed");
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "direct partial fanout",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-encrypt-fail"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("direct participant encrypt failed")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["msg-encrypt-fail".to_owned()],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some("123@s.whatsapp.net".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: false,
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.jobs.is_empty());
    assert_eq!(prepared.missing_message_ids, vec!["msg-encrypt-fail"]);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_does_not_schedule_tc_token_when_participant_encryption_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    for jid in ["123@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = FailingAfterEncryptor::new(2, "direct tc-token encrypt failed");
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "direct tctoken failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-tc-encrypt-fail"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(err.to_string().contains("direct tc-token encrypt failed"));
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sink_rx.recv())
            .await
            .is_err(),
        "failed direct send should not spawn a post-send tctoken issue query"
    );
    assert!(
        client
            .try_begin_tc_token_issuance("123@s.whatsapp.net")
            .unwrap(),
        "failed direct send should not leave tctoken issuance in flight"
    );
    client.finish_tc_token_issuance("123@s.whatsapp.net");
    assert!(
        wa_core::load_tc_token(&store, "123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_stops_when_relay_send_fails_without_retry_cache() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["123@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 2);
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "direct relay send failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-send-fail"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    for call in &calls {
        let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
        let visible_text = plaintext
            .extended_text_message
            .as_ref()
            .and_then(|message| message.text.as_deref())
            .or_else(|| {
                plaintext
                    .device_sent_message
                    .as_ref()
                    .and_then(|device_sent| device_sent.message.as_ref())
                    .and_then(|message| message.extended_text_message.as_ref())
                    .and_then(|message| message.text.as_deref())
            });
        assert_eq!(visible_text, Some("direct relay send failure"));
    }
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["msg-send-fail".to_owned()],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some("123@s.whatsapp.net".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: false,
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.jobs.is_empty());
    assert_eq!(prepared.missing_message_ids, vec!["msg-send-fail"]);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_does_not_schedule_tc_token_when_relay_send_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    for jid in ["123@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 2);
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "direct tctoken relay send failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-tc-send-fail"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    match tokio::time::timeout(Duration::from_millis(100), sink_rx.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(frame)) => {
            let node = decode_inbound_binary_node(&frame).unwrap().node;
            panic!(
                "failed direct relay send should not spawn outbound node: {}",
                node.tag
            );
        }
    }
    assert!(
        client
            .try_begin_tc_token_issuance("123@s.whatsapp.net")
            .unwrap(),
        "failed direct relay send should not leave tctoken issuance in flight"
    );
    client.finish_tc_token_issuance("123@s.whatsapp.net");
    assert!(
        wa_core::load_tc_token(&store, "123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_normalizes_legacy_c_us_remote_before_lookup_and_relay() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"canonical-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
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
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_text(
        &connection,
        "123@c.us",
        "legacy alias hello",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-cus-normalized"),
    );
    tokio::pin!(send_fut);

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
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@c.us")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "msg-cus-normalized");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("message should contain child nodes");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(participants)) = &content[0].content else {
        panic!("message should contain participant nodes");
    };
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0].attrs["jid"], "123@s.whatsapp.net");
    assert!(content.iter().any(|node| {
        node.tag == "tctoken"
            && test_node_bytes(node) == Some(Bytes::from_static(b"canonical-token"))
    }));

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "123@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        plaintext
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("legacy alias hello")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_poll_and_event_facades_use_direct_relay_path() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let poll_fut = client.send_poll(
        &connection,
        "123@s.whatsapp.net",
        PollContent::new("Lunch?", ["Rice", "Noodles"], 1, Bytes::from(vec![7u8; 32])),
        &encryptor,
        MessageRelayOptions::new().with_message_id("poll-send-1"),
    );
    tokio::pin!(poll_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut poll_fut,
    )
    .await;

    let poll_relay = poll_fut.await.unwrap();
    assert_eq!(poll_relay.message_id, "poll-send-1");
    assert_eq!(poll_relay.recipient_count, 1);
    let poll_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(poll_sent.attrs["type"], "poll");
    assert_eq!(test_child(&poll_sent, "reporting").tag, "reporting");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let poll_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(poll_plaintext.poll_creation_message_v3.is_some());
    assert_eq!(
        poll_plaintext
            .message_context_info
            .as_ref()
            .unwrap()
            .message_secret
            .as_ref()
            .unwrap()
            .len(),
        32
    );
    drop(calls);

    let event_fut = client.send_event(
        &connection,
        "123@s.whatsapp.net",
        EventContent::new("Standup", 1_700_000_000, Bytes::from(vec![8u8; 32]))
            .with_join_link("https://call.example.invalid/team"),
        &encryptor,
        MessageRelayOptions::new().with_message_id("event-send-1"),
    );
    tokio::pin!(event_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut event_fut,
    )
    .await;

    let event_relay = event_fut.await.unwrap();
    assert_eq!(event_relay.message_id, "event-send-1");
    assert_eq!(event_relay.recipient_count, 1);
    let event_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(event_sent.attrs["type"], "event");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    let event_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let event = event_plaintext.event_message.unwrap();
    assert_eq!(event.name.as_deref(), Some("Standup"));
    assert_eq!(
        event.join_link.as_deref(),
        Some("https://call.example.invalid/team")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_poll_update_and_event_response_facades_use_direct_relay_path() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::sender_marker("123@s.whatsapp.net", current_unix_timestamp())
            .unwrap(),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let poll_key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("poll-parent-1".to_owned()),
        participant: None,
    };
    let poll_update_fut = client.send_poll_update(
        &connection,
        "123@s.whatsapp.net",
        PollUpdateContent::new(
            poll_key.clone(),
            Bytes::from_static(b"encrypted-vote"),
            Bytes::from_static(b"vote-iv"),
        )
        .with_sender_timestamp_ms(1_700_000_001),
        &encryptor,
        MessageRelayOptions::new().with_message_id("poll-update-send-1"),
    );
    tokio::pin!(poll_update_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut poll_update_fut,
    )
    .await;

    let poll_update_relay = poll_update_fut.await.unwrap();
    assert_eq!(poll_update_relay.message_id, "poll-update-send-1");
    let poll_update_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(poll_update_sent.attrs["type"], "poll");
    assert!(test_children(&poll_update_sent, "reporting").is_empty());

    let event_key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("event-parent-1".to_owned()),
        participant: None,
    };
    let event_response_fut = client.send_event_response(
        &connection,
        "123@s.whatsapp.net",
        EventResponseContent::new(
            event_key.clone(),
            Bytes::from_static(b"encrypted-response"),
            Bytes::from_static(b"response-iv"),
        ),
        &encryptor,
        MessageRelayOptions::new().with_message_id("event-response-send-1"),
    );
    tokio::pin!(event_response_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut event_response_fut,
    )
    .await;

    let event_response_relay = event_response_fut.await.unwrap();
    assert_eq!(event_response_relay.message_id, "event-response-send-1");
    let event_response_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(event_response_sent.attrs["type"], "text");
    assert!(test_children(&event_response_sent, "reporting").is_empty());

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    let poll_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let poll_update = poll_plaintext.poll_update_message.unwrap();
    assert_eq!(
        poll_update.poll_creation_message_key.as_ref(),
        Some(&poll_key)
    );
    assert_eq!(poll_update.sender_timestamp_ms, Some(1_700_000_001));
    let vote = poll_update.vote.unwrap();
    assert_eq!(vote.enc_payload.as_deref(), Some(&b"encrypted-vote"[..]));
    assert_eq!(vote.enc_iv.as_deref(), Some(&b"vote-iv"[..]));

    let event_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let event_response = event_plaintext.enc_event_response_message.unwrap();
    assert_eq!(
        event_response.event_creation_message_key.as_ref(),
        Some(&event_key)
    );
    assert_eq!(
        event_response.enc_payload.as_deref(),
        Some(&b"encrypted-response"[..])
    );
    assert_eq!(event_response.enc_iv.as_deref(), Some(&b"response-iv"[..]));

    let poll_secret = Bytes::from(vec![3u8; 32]);
    let poll_vote_fut = client.send_poll_vote(
        &connection,
        "123@s.whatsapp.net",
        PollVoteContent::from_option_names(
            poll_key.clone(),
            ["Ship"],
            poll_secret.clone(),
            "123@s.whatsapp.net",
            "999:7@s.whatsapp.net",
        )
        .unwrap()
        .with_sender_timestamp_ms(1_700_000_003),
        &encryptor,
        MessageRelayOptions::new().with_message_id("poll-vote-send-1"),
    );
    tokio::pin!(poll_vote_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut poll_vote_fut,
    )
    .await;

    let poll_vote_relay = poll_vote_fut.await.unwrap();
    assert_eq!(poll_vote_relay.message_id, "poll-vote-send-1");
    let poll_vote_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(poll_vote_sent.attrs["type"], "poll");

    let event_secret = Bytes::from(vec![4u8; 32]);
    let event_payload_fut = client.send_event_response_payload(
        &connection,
        "123@s.whatsapp.net",
        EventResponsePayload::new(
            event_key.clone(),
            wa_core::EventResponseKind::Maybe,
            event_secret.clone(),
            "123@s.whatsapp.net",
            "999:7@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_004)
        .with_extra_guest_count(1),
        &encryptor,
        MessageRelayOptions::new().with_message_id("event-response-payload-send-1"),
    );
    tokio::pin!(event_payload_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut event_payload_fut,
    )
    .await;

    let event_payload_relay = event_payload_fut.await.unwrap();
    assert_eq!(
        event_payload_relay.message_id,
        "event-response-payload-send-1"
    );
    let event_payload_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(event_payload_sent.attrs["type"], "text");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 4);
    let poll_vote_plaintext = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    let poll_update = poll_vote_plaintext.poll_update_message.unwrap();
    assert_eq!(poll_update.sender_timestamp_ms, Some(1_700_000_003));
    let vote = poll_update.vote.unwrap();
    assert_eq!(vote.enc_iv.as_ref().unwrap().len(), 12);
    let decrypted_vote = wa_core::decrypt_poll_vote_message(
        &vote,
        "poll-parent-1",
        "123@s.whatsapp.net",
        "999@s.whatsapp.net",
        &poll_secret,
    )
    .unwrap();
    assert_eq!(
        decrypted_vote.selected_options,
        vec![Bytes::copy_from_slice(&wa_crypto::sha256_hash(b"Ship"))]
    );

    let event_payload_plaintext = wa_proto::proto::Message::decode(calls[3].1.clone()).unwrap();
    let encrypted_event = event_payload_plaintext.enc_event_response_message.unwrap();
    assert_eq!(encrypted_event.enc_iv.as_ref().unwrap().len(), 12);
    let decrypted_event = wa_core::decrypt_event_response_message(
        &encrypted_event,
        "event-parent-1",
        "123@s.whatsapp.net",
        "999@s.whatsapp.net",
        &event_secret,
    )
    .unwrap();
    assert_eq!(
        decrypted_event.response,
        Some(wa_proto::proto::message::event_response_message::EventResponseType::Maybe as i32)
    );
    assert_eq!(decrypted_event.timestamp_ms, Some(1_700_000_004));
    assert_eq!(decrypted_event.extra_guest_count, Some(1));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_content_facades_relay_contact_location_and_media_content() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let contact_fut = client.send_contact(
        &connection,
        "123@s.whatsapp.net",
        wa_core::ContactContent::new("Ada Lovelace", "BEGIN:VCARD\nFN:Ada Lovelace\nEND:VCARD"),
        &encryptor,
        MessageRelayOptions::new().with_message_id("contact-send-1"),
    );
    tokio::pin!(contact_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut contact_fut).await;
    let contact_relay = contact_fut.await.unwrap();
    assert_eq!(contact_relay.message_id, "contact-send-1");
    assert_eq!(contact_relay.recipient_count, 1);
    let contact_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(contact_sent.attrs["type"], "text");

    let contacts_fut = client.send_contacts(
        &connection,
        "123@s.whatsapp.net",
        wa_core::ContactsContent::new(
            "Project contacts",
            [
                wa_core::ContactContent::new(
                    "Grace Hopper",
                    "BEGIN:VCARD\nFN:Grace Hopper\nEND:VCARD",
                ),
                wa_core::ContactContent::new(
                    "Katherine Johnson",
                    "BEGIN:VCARD\nFN:Katherine Johnson\nEND:VCARD",
                ),
            ],
        ),
        &encryptor,
        MessageRelayOptions::new().with_message_id("contacts-send-1"),
    );
    tokio::pin!(contacts_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut contacts_fut).await;
    let contacts_relay = contacts_fut.await.unwrap();
    assert_eq!(contacts_relay.message_id, "contacts-send-1");
    assert_eq!(contacts_relay.recipient_count, 1);
    let contacts_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(contacts_sent.attrs["type"], "text");

    let location_fut = client.send_location(
        &connection,
        "123@s.whatsapp.net",
        wa_core::LocationContent::new(37.7786, -122.3893)
            .with_name("Bayfront")
            .with_address("San Francisco"),
        &encryptor,
        MessageRelayOptions::new().with_message_id("location-send-1"),
    );
    tokio::pin!(location_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut location_fut).await;
    let location_relay = location_fut.await.unwrap();
    assert_eq!(location_relay.message_id, "location-send-1");
    assert_eq!(location_relay.recipient_count, 1);
    let location_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(location_sent.attrs["type"], "text");

    let live_location_fut = client.send_live_location(
        &connection,
        "123@s.whatsapp.net",
        wa_core::LiveLocationContent {
            accuracy_in_meters: Some(5),
            caption: Some("On my way".to_owned()),
            sequence_number: Some(3),
            time_offset: Some(60),
            ..wa_core::LiveLocationContent::new(37.779, -122.389)
        },
        &encryptor,
        MessageRelayOptions::new().with_message_id("live-location-send-1"),
    );
    tokio::pin!(live_location_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut live_location_fut).await;
    let live_location_relay = live_location_fut.await.unwrap();
    assert_eq!(live_location_relay.message_id, "live-location-send-1");
    assert_eq!(live_location_relay.recipient_count, 1);
    let live_location_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(live_location_sent.attrs["type"], "text");

    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![1u8; 32]),
        Bytes::from(vec![2u8; 32]),
        Bytes::from(vec![3u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/image")
    .with_direct_path("/v/t62.7118-24/image")
    .with_media_key_timestamp(1_700_000_000);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("launch photo".to_owned());
    let image_fut = client.send_image(
        &connection,
        "123@s.whatsapp.net",
        image,
        &encryptor,
        MessageRelayOptions::new().with_message_id("image-send-1"),
    );
    tokio::pin!(image_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut image_fut).await;
    let image_relay = image_fut.await.unwrap();
    assert_eq!(image_relay.message_id, "image-send-1");
    assert_eq!(image_relay.recipient_count, 1);
    let image_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(image_sent.attrs["type"], "media");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 5);
    let contact = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let contact = contact.contact_message.unwrap();
    assert_eq!(contact.display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(
        contact.vcard.as_deref(),
        Some("BEGIN:VCARD\nFN:Ada Lovelace\nEND:VCARD")
    );

    let contacts = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let contacts = contacts.contacts_array_message.unwrap();
    assert_eq!(contacts.display_name.as_deref(), Some("Project contacts"));
    assert_eq!(contacts.contacts.len(), 2);
    assert_eq!(
        contacts.contacts[0].display_name.as_deref(),
        Some("Grace Hopper")
    );
    assert_eq!(
        contacts.contacts[1].display_name.as_deref(),
        Some("Katherine Johnson")
    );

    let location = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    let location = location.location_message.unwrap();
    assert_eq!(location.name.as_deref(), Some("Bayfront"));
    assert_eq!(location.address.as_deref(), Some("San Francisco"));
    assert_eq!(location.degrees_latitude, Some(37.7786));
    assert_eq!(location.degrees_longitude, Some(-122.3893));

    let live_location = wa_proto::proto::Message::decode(calls[3].1.clone()).unwrap();
    let live_location = live_location.live_location_message.unwrap();
    assert_eq!(live_location.caption.as_deref(), Some("On my way"));
    assert_eq!(live_location.accuracy_in_meters, Some(5));
    assert_eq!(live_location.sequence_number, Some(3));
    assert_eq!(live_location.time_offset, Some(60));
    assert_eq!(live_location.degrees_latitude, Some(37.779));
    assert_eq!(live_location.degrees_longitude, Some(-122.389));

    let image = wa_proto::proto::Message::decode(calls[4].1.clone()).unwrap();
    let image = image.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("launch photo"));
    assert_eq!(image.direct_path.as_deref(), Some("/v/t62.7118-24/image"));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_media_facades_relay_video_and_document_content() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let video_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![22u8; 32]),
        Bytes::from(vec![23u8; 32]),
        Bytes::from(vec![24u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/video")
    .with_direct_path("/v/t62.7118-24/video")
    .with_media_key_timestamp(1_700_000_001);
    let mut video = wa_core::VideoContent::new(video_media, "video/mp4");
    video.caption = Some("launch clip".to_owned());
    video.seconds = Some(9);
    video.height = Some(720);
    video.width = Some(1_280);
    let video_fut = client.send_video(
        &connection,
        "123@s.whatsapp.net",
        video,
        &encryptor,
        MessageRelayOptions::new().with_message_id("video-send-1"),
    );
    tokio::pin!(video_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut video_fut).await;
    let video_relay = video_fut.await.unwrap();
    assert_eq!(video_relay.message_id, "video-send-1");
    assert_eq!(video_relay.recipient_count, 1);
    let video_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(video_sent.attrs["type"], "media");

    let document_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![25u8; 32]),
        Bytes::from(vec![26u8; 32]),
        Bytes::from(vec![27u8; 32]),
        4_096,
    )
    .with_url("https://media.example.invalid/document")
    .with_direct_path("/v/t62.7118-24/document")
    .with_media_key_timestamp(1_700_000_002);
    let mut document = wa_core::DocumentContent::new(document_media, "application/pdf");
    document.title = Some("Launch Brief".to_owned());
    document.file_name = Some("launch-brief.pdf".to_owned());
    document.caption = Some("launch document".to_owned());
    document.page_count = Some(4);
    let document_fut = client.send_document(
        &connection,
        "123@s.whatsapp.net",
        document,
        &encryptor,
        MessageRelayOptions::new().with_message_id("document-send-1"),
    );
    tokio::pin!(document_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut document_fut).await;
    let document_relay = document_fut.await.unwrap();
    assert_eq!(document_relay.message_id, "document-send-1");
    assert_eq!(document_relay.recipient_count, 1);
    let document_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(document_sent.attrs["type"], "media");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    let video = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let video = video.video_message.unwrap();
    assert_eq!(video.mimetype.as_deref(), Some("video/mp4"));
    assert_eq!(video.caption.as_deref(), Some("launch clip"));
    assert_eq!(video.seconds, Some(9));
    assert_eq!(video.height, Some(720));
    assert_eq!(video.width, Some(1_280));
    assert_eq!(video.direct_path.as_deref(), Some("/v/t62.7118-24/video"));

    let document = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let document = document.document_message.unwrap();
    assert_eq!(document.mimetype.as_deref(), Some("application/pdf"));
    assert_eq!(document.title.as_deref(), Some("Launch Brief"));
    assert_eq!(document.file_name.as_deref(), Some("launch-brief.pdf"));
    assert_eq!(document.caption.as_deref(), Some("launch document"));
    assert_eq!(document.page_count, Some(4));
    assert_eq!(
        document.direct_path.as_deref(),
        Some("/v/t62.7118-24/document")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_gif_facade_relay_gif_playback_video_content() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let gif_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![37u8; 32]),
        Bytes::from(vec![38u8; 32]),
        Bytes::from(vec![39u8; 32]),
        3_072,
    )
    .with_url("https://media.example.invalid/gif")
    .with_direct_path("/v/t62.7118-24/gif")
    .with_media_key_timestamp(1_700_000_006);
    let mut gif = wa_core::VideoContent::new(gif_media, "video/mp4");
    gif.caption = Some("loop clip".to_owned());
    gif.seconds = Some(5);
    gif.height = Some(360);
    gif.width = Some(640);
    let gif_fut = client.send_gif(
        &connection,
        "123@s.whatsapp.net",
        gif,
        &encryptor,
        MessageRelayOptions::new().with_message_id("gif-send-1"),
    );
    tokio::pin!(gif_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut gif_fut).await;
    let gif_relay = gif_fut.await.unwrap();
    assert_eq!(gif_relay.message_id, "gif-send-1");
    assert_eq!(gif_relay.recipient_count, 1);
    let gif_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(gif_sent.attrs["type"], "media");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let gif = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(gif.ptv_message.is_none());
    let gif = gif.video_message.unwrap();
    assert_eq!(gif.mimetype.as_deref(), Some("video/mp4"));
    assert_eq!(gif.caption.as_deref(), Some("loop clip"));
    assert_eq!(gif.gif_playback, Some(true));
    assert_eq!(gif.seconds, Some(5));
    assert_eq!(gif.height, Some(360));
    assert_eq!(gif.width, Some(640));
    assert_eq!(gif.direct_path.as_deref(), Some("/v/t62.7118-24/gif"));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_view_once_media_facades_relay_image_and_video_content() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![43u8; 32]),
        Bytes::from(vec![44u8; 32]),
        Bytes::from(vec![45u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/view-once-image")
    .with_direct_path("/v/t62.7118-24/view-once-image")
    .with_media_key_timestamp(1_700_000_008);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("open once".to_owned());
    let image_fut = client.send_view_once_image(
        &connection,
        "123@s.whatsapp.net",
        image,
        &encryptor,
        MessageRelayOptions::new().with_message_id("view-once-image-send-1"),
    );
    tokio::pin!(image_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut image_fut).await;
    let image_relay = image_fut.await.unwrap();
    assert_eq!(image_relay.message_id, "view-once-image-send-1");
    assert_eq!(image_relay.recipient_count, 1);
    let image_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(image_sent.attrs["type"], "media");

    let video_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![46u8; 32]),
        Bytes::from(vec![47u8; 32]),
        Bytes::from(vec![48u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/view-once-video")
    .with_direct_path("/v/t62.7118-24/view-once-video")
    .with_media_key_timestamp(1_700_000_009);
    let mut video = wa_core::VideoContent::new(video_media, "video/mp4");
    video.caption = Some("watch once".to_owned());
    video.seconds = Some(10);
    video.height = Some(720);
    video.width = Some(1_280);
    let video_fut = client.send_view_once_video(
        &connection,
        "123@s.whatsapp.net",
        video,
        &encryptor,
        MessageRelayOptions::new().with_message_id("view-once-video-send-1"),
    );
    tokio::pin!(video_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut video_fut).await;
    let video_relay = video_fut.await.unwrap();
    assert_eq!(video_relay.message_id, "view-once-video-send-1");
    assert_eq!(video_relay.recipient_count, 1);
    let video_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(video_sent.attrs["type"], "media");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    let image = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(image.image_message.is_none());
    let inner = image
        .view_once_message
        .as_ref()
        .and_then(|wrapper| wrapper.message.as_deref())
        .unwrap();
    let image = inner.image_message.as_ref().unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("open once"));
    assert_eq!(image.view_once, Some(true));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/view-once-image")
    );

    let video = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    assert!(video.video_message.is_none());
    let inner = video
        .view_once_message
        .as_ref()
        .and_then(|wrapper| wrapper.message.as_deref())
        .unwrap();
    let video = inner.video_message.as_ref().unwrap();
    assert_eq!(video.mimetype.as_deref(), Some("video/mp4"));
    assert_eq!(video.caption.as_deref(), Some("watch once"));
    assert_eq!(video.view_once, Some(true));
    assert_eq!(video.seconds, Some(10));
    assert_eq!(video.height, Some(720));
    assert_eq!(video.width, Some(1_280));
    assert_eq!(
        video.direct_path.as_deref(),
        Some("/v/t62.7118-24/view-once-video")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_media_facades_relay_audio_and_sticker_content() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let audio_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![28u8; 32]),
        Bytes::from(vec![29u8; 32]),
        Bytes::from(vec![30u8; 32]),
        1_536,
    )
    .with_url("https://media.example.invalid/audio")
    .with_direct_path("/v/t62.7118-24/audio")
    .with_media_key_timestamp(1_700_000_003);
    let mut audio = wa_core::AudioContent::new(audio_media, "audio/ogg");
    audio.seconds = Some(12);
    audio.ptt = true;
    audio.waveform = Some(Bytes::from_static(b"waveform"));
    let audio_fut = client.send_audio(
        &connection,
        "123@s.whatsapp.net",
        audio,
        &encryptor,
        MessageRelayOptions::new().with_message_id("audio-send-1"),
    );
    tokio::pin!(audio_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut audio_fut).await;
    let audio_relay = audio_fut.await.unwrap();
    assert_eq!(audio_relay.message_id, "audio-send-1");
    assert_eq!(audio_relay.recipient_count, 1);
    let audio_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(audio_sent.attrs["type"], "media");

    let sticker_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![31u8; 32]),
        Bytes::from(vec![32u8; 32]),
        Bytes::from(vec![33u8; 32]),
        512,
    )
    .with_url("https://media.example.invalid/sticker")
    .with_direct_path("/v/t62.7118-24/sticker")
    .with_media_key_timestamp(1_700_000_004);
    let mut sticker = wa_core::StickerContent::new(sticker_media, "image/webp");
    sticker.height = Some(512);
    sticker.width = Some(512);
    sticker.is_animated = true;
    let sticker_fut = client.send_sticker(
        &connection,
        "123@s.whatsapp.net",
        sticker,
        &encryptor,
        MessageRelayOptions::new().with_message_id("sticker-send-1"),
    );
    tokio::pin!(sticker_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut sticker_fut).await;
    let sticker_relay = sticker_fut.await.unwrap();
    assert_eq!(sticker_relay.message_id, "sticker-send-1");
    assert_eq!(sticker_relay.recipient_count, 1);
    let sticker_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sticker_sent.attrs["type"], "media");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    let audio = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let audio = audio.audio_message.unwrap();
    assert_eq!(audio.mimetype.as_deref(), Some("audio/ogg"));
    assert_eq!(audio.seconds, Some(12));
    assert_eq!(audio.ptt, Some(true));
    assert_eq!(audio.waveform.as_deref(), Some(&b"waveform"[..]));
    assert_eq!(audio.direct_path.as_deref(), Some("/v/t62.7118-24/audio"));

    let sticker = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let sticker = sticker.sticker_message.unwrap();
    assert_eq!(sticker.mimetype.as_deref(), Some("image/webp"));
    assert_eq!(sticker.height, Some(512));
    assert_eq!(sticker.width, Some(512));
    assert_eq!(sticker.is_animated, Some(true));
    assert_eq!(
        sticker.direct_path.as_deref(),
        Some("/v/t62.7118-24/sticker")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_ptt_facade_relay_push_to_talk_audio_content() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let ptt_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![40u8; 32]),
        Bytes::from(vec![41u8; 32]),
        Bytes::from(vec![42u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/ptt")
    .with_direct_path("/v/t62.7118-24/ptt")
    .with_media_key_timestamp(1_700_000_007);
    let mut ptt = wa_core::AudioContent::new(ptt_media, "audio/ogg; codecs=opus");
    ptt.seconds = Some(4);
    ptt.waveform = Some(Bytes::from_static(b"ptt-waveform"));
    let ptt_fut = client.send_ptt(
        &connection,
        "123@s.whatsapp.net",
        ptt,
        &encryptor,
        MessageRelayOptions::new().with_message_id("ptt-send-1"),
    );
    tokio::pin!(ptt_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut ptt_fut).await;
    let ptt_relay = ptt_fut.await.unwrap();
    assert_eq!(ptt_relay.message_id, "ptt-send-1");
    assert_eq!(ptt_relay.recipient_count, 1);
    let ptt_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ptt_sent.attrs["type"], "media");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let ptt = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let ptt = ptt.audio_message.unwrap();
    assert_eq!(ptt.mimetype.as_deref(), Some("audio/ogg; codecs=opus"));
    assert_eq!(ptt.seconds, Some(4));
    assert_eq!(ptt.ptt, Some(true));
    assert_eq!(ptt.waveform.as_deref(), Some(&b"ptt-waveform"[..]));
    assert_eq!(ptt.direct_path.as_deref(), Some("/v/t62.7118-24/ptt"));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_ptv_facade_relay_video_note_content() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let ptv_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![34u8; 32]),
        Bytes::from(vec![35u8; 32]),
        Bytes::from(vec![36u8; 32]),
        2_560,
    )
    .with_url("https://media.example.invalid/ptv")
    .with_direct_path("/v/t62.7118-24/ptv")
    .with_media_key_timestamp(1_700_000_005);
    let mut ptv = wa_core::VideoContent::new(ptv_media, "video/mp4");
    ptv.seconds = Some(7);
    ptv.height = Some(640);
    ptv.width = Some(640);
    let ptv_fut = client.send_ptv(
        &connection,
        "123@s.whatsapp.net",
        ptv,
        &encryptor,
        MessageRelayOptions::new().with_message_id("ptv-send-1"),
    );
    tokio::pin!(ptv_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut ptv_fut).await;
    let ptv_relay = ptv_fut.await.unwrap();
    assert_eq!(ptv_relay.message_id, "ptv-send-1");
    assert_eq!(ptv_relay.recipient_count, 1);
    let ptv_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ptv_sent.attrs["type"], "media");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let ptv = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(ptv.video_message.is_none());
    let ptv = ptv.ptv_message.unwrap();
    assert_eq!(ptv.mimetype.as_deref(), Some("video/mp4"));
    assert_eq!(ptv.seconds, Some(7));
    assert_eq!(ptv.height, Some(640));
    assert_eq!(ptv.width, Some(640));
    assert_eq!(ptv.direct_path.as_deref(), Some("/v/t62.7118-24/ptv"));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_direct_content_facades_with_signal_provider_encrypt_contact_and_location() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"signal-facade-token"),
        )
        .unwrap()
        .with_timestamp_seconds(now)
        .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 91;

    let contact_fut = client.send_contact_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        wa_core::ContactContent::new("Ada Signal", "BEGIN:VCARD\nFN:Ada Signal\nEND:VCARD"),
        MessageRelayOptions::new().with_message_id("signal-contact-1"),
    );
    tokio::pin!(contact_fut);

    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut contact_fut).await;
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
                vec!["123@s.whatsapp.net".to_owned()]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut contact_fut,
    )
    .await;
    let contact_relay = contact_fut.await.unwrap();
    assert_eq!(contact_relay.message_id, "signal-contact-1");
    assert_eq!(contact_relay.recipient_count, 1);
    let contact_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let contact_enc = test_participant_enc_node(&contact_sent, "123@s.whatsapp.net");
    assert_eq!(contact_enc.attrs["type"], "pkmsg");
    let contact_ciphertext = test_node_bytes(contact_enc).unwrap();

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let contact_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &contact_ciphertext,
    )
    .unwrap();
    let contact_plaintext = wa_core::unpad_random_max16(&contact_decrypted.plaintext).unwrap();
    let contact_message = wa_proto::proto::Message::decode(contact_plaintext).unwrap();
    let contact = contact_message.contact_message.unwrap();
    assert_eq!(contact.display_name.as_deref(), Some("Ada Signal"));
    assert_eq!(
        contact.vcard.as_deref(),
        Some("BEGIN:VCARD\nFN:Ada Signal\nEND:VCARD")
    );

    let location_fut = client.send_location_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        wa_core::LocationContent::new(51.5074, -0.1278)
            .with_name("Signal Square")
            .with_address("London"),
        MessageRelayOptions::new().with_message_id("signal-location-1"),
    );
    tokio::pin!(location_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut location_fut).await;
    let location_relay = location_fut.await.unwrap();
    assert_eq!(location_relay.message_id, "signal-location-1");
    assert_eq!(location_relay.recipient_count, 1);
    let location_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let location_enc = test_participant_enc_node(&location_sent, "123@s.whatsapp.net");
    assert_eq!(location_enc.attrs["type"], "msg");
    let location_ciphertext = test_node_bytes(location_enc).unwrap();
    let location_decrypted = wa_core::decrypt_signal_provider_session_record_message(
        &contact_decrypted.record,
        &location_ciphertext,
        &remote_material.identity.public_key,
    )
    .unwrap();
    let location_plaintext = wa_core::unpad_random_max16(&location_decrypted.plaintext).unwrap();
    let location_message = wa_proto::proto::Message::decode(location_plaintext).unwrap();
    let location = location_message.location_message.unwrap();
    assert_eq!(location.name.as_deref(), Some("Signal Square"));
    assert_eq!(location.address.as_deref(), Some("London"));
    assert_eq!(location.degrees_latitude, Some(51.5074));
    assert_eq!(location.degrees_longitude, Some(-0.1278));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_with_signal_provider_fetches_session_and_writes_pre_key_ciphertext() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 91;
    let send_fut = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "hello signal",
        MessageRelayOptions::new().with_message_id("signal-msg-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
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
                vec!["123@s.whatsapp.net".to_owned()]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-msg-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "signal-msg-1");
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));
    assert_eq!(
        pre_key_message.signed_pre_key_id,
        remote_credentials.signed_pre_key.key_id
    );
    let provider_session_info = client
        .signal_provider_state_store()
        .load_session_info("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(provider_session_info.base_key, pre_key_message.base_key);
    let repository = client.signal_repository();
    let descriptor_session_info =
        wa_core::SignalRepository::get_session_info(&repository, "123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
    assert_ne!(
        descriptor_session_info.base_key,
        provider_session_info.base_key
    );
    let snapshot_with_descriptor = client
        .retry_session_snapshot("123@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(
        snapshot_with_descriptor.base_key,
        Some(provider_session_info.base_key.clone())
    );
    assert_eq!(
        snapshot_with_descriptor.signal_address.as_deref(),
        Some("123.0")
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    assert_eq!(
        decoded
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("hello signal")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    let signal_address = wa_core::signal_protocol_address("123@s.whatsapp.net")
        .unwrap()
        .to_string();
    store
        .delete_signal_key(KeyNamespace::Session, &signal_address)
        .await
        .unwrap();
    assert!(
        store
            .get_signal_key(KeyNamespace::Session, &signal_address)
            .await
            .unwrap()
            .is_none()
    );
    let snapshot = client
        .retry_session_snapshot("123@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(
        snapshot.registration_id,
        Some(remote_credentials.registration_id)
    );
    assert!(snapshot.base_key.is_some());
    assert_eq!(snapshot.signal_address.as_deref(), Some("123.0"));

    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec!["signal-msg-1".to_owned()],
                from_jid: Some("123@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("123@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@s.whatsapp.net".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: Some(remote_credentials.registration_id.wrapping_add(1)),
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert!(matches!(
        plan.session_action,
        wa_core::RetrySessionAction::DeleteAndRefresh { .. }
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_with_signal_provider_normalizes_legacy_c_us_remote_before_lookup_and_relay() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"canonical-signal-token"),
        )
        .unwrap()
        .with_timestamp_seconds(now)
        .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 111;
    let send_fut = client.send_text_with_signal_provider(
        &connection,
        "123@c.us",
        "store-backed legacy alias hello",
        MessageRelayOptions::new().with_message_id("signal-msg-cus-normalized"),
    );
    tokio::pin!(send_fut);

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
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@c.us")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                ])],
                            )]),
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-msg-cus-normalized");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "text");
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net"]
    );
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("signal message should contain child nodes");
    };
    assert!(content.iter().any(|node| {
        node.tag == "tctoken"
            && test_node_bytes(node) == Some(Bytes::from_static(b"canonical-signal-token"))
    }));

    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    assert!(decoded.device_sent_message.is_none());
    assert_eq!(
        decoded
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("store-backed legacy alias hello")
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
async fn send_text_with_signal_provider_encrypts_remote_and_own_linked_device_payloads() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 97;
    let send_fut = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "hello linked signal",
        MessageRelayOptions::new().with_message_id("signal-linked-success"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-linked-success");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "signal-linked-success");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "text");
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("hello linked signal")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("hello linked signal")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_with_signal_provider_deduplicates_own_pn_lid_linked_device_aliases() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 123;
    let send_fut = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "direct own alias signal",
        MessageRelayOptions::new().with_message_id("signal-direct-own-alias-dedup-1"),
    );
    tokio::pin!(send_fut);

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
        &mut send_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-direct-own-alias-dedup-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "signal-direct-own-alias-dedup-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "text");
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("direct own alias signal")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("direct own alias signal")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_with_signal_provider_reuses_established_session_for_second_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 91;
    let first_send = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "first signal",
        MessageRelayOptions::new().with_message_id("signal-established-1"),
    );
    tokio::pin!(first_send);

    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut first_send).await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut first_send,
    )
    .await;

    let first_relay = first_send.await.unwrap();
    assert_eq!(first_relay.message_id, "signal-established-1");
    let first_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let first_enc = test_participant_enc_node(&first_node, "123@s.whatsapp.net");
    assert_eq!(first_enc.attrs["type"], "pkmsg");
    let first_ciphertext = test_node_bytes(first_enc).unwrap();
    let first_pre_key = wa_core::decode_signal_pre_key_whisper_message(&first_ciphertext).unwrap();
    assert_eq!(first_pre_key.pre_key_id, Some(remote_one_time_pre_key_id));
    assert_eq!(first_pre_key.message.counter, 0);
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let first_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_ciphertext,
    )
    .unwrap();
    let first_unpadded = wa_core::unpad_random_max16(&first_decrypted.plaintext).unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_unpadded).unwrap();
    assert_eq!(
        first_decoded
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("first signal")
    );

    let privacy_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("first send should schedule post-send privacy token issue")
        .unwrap();
    let privacy = decode_inbound_binary_node(&privacy_frame).unwrap().node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    let requested_token = test_child(test_child(&privacy, "tokens"), "token");
    assert_eq!(requested_token.attrs["jid"], "123@s.whatsapp.net");
    assert_eq!(requested_token.attrs["type"], "trusted_contact");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", privacy.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_attr("t", requested_token.attrs["t"].clone())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"established-session-token")),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let second_send = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "second signal",
        MessageRelayOptions::new().with_message_id("signal-established-2"),
    );
    tokio::pin!(second_send);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut second_send).await;

    let second_relay = tokio::time::timeout(Duration::from_secs(1), &mut second_send)
        .await
        .expect("second send should reuse provider session without key-bundle query")
        .unwrap();
    assert_eq!(second_relay.message_id, "signal-established-2");
    let second_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_node, second_relay.node);
    let second_enc = test_participant_enc_node(&second_node, "123@s.whatsapp.net");
    assert_eq!(second_enc.attrs["type"], "msg");
    let second_ciphertext = test_node_bytes(second_enc).unwrap();
    let second_decrypted = wa_core::decrypt_signal_provider_session_record_message(
        &first_decrypted.record,
        &second_ciphertext,
        &remote_material.identity.public_key,
    )
    .unwrap();
    assert_eq!(second_decrypted.message.counter, 1);
    let second_unpadded = wa_core::unpad_random_max16(&second_decrypted.plaintext).unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_unpadded).unwrap();
    assert_eq!(
        second_decoded
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("second signal")
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
async fn send_text_with_signal_provider_reuses_established_sessions_for_own_linked_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 98;
    let first_send = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "first linked signal",
        MessageRelayOptions::new().with_message_id("signal-linked-established-1"),
    );
    tokio::pin!(first_send);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut first_send,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut first_send,
    )
    .await;

    let first_relay = first_send.await.unwrap();
    assert_eq!(first_relay.message_id, "signal-linked-established-1");
    assert_eq!(first_relay.recipient_count, 2);
    let first_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let first_remote_ciphertext =
        test_node_bytes(test_participant_enc_node(&first_node, "123@s.whatsapp.net")).unwrap();
    let first_remote_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_remote_ciphertext,
    )
    .unwrap();
    let first_remote_unpadded =
        wa_core::unpad_random_max16(&first_remote_decrypted.plaintext).unwrap();
    let first_remote_decoded = wa_proto::proto::Message::decode(first_remote_unpadded).unwrap();
    assert_eq!(
        first_remote_decoded
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("first linked signal")
    );

    let first_own_ciphertext = test_node_bytes(test_participant_enc_node(
        &first_node,
        "999:8@s.whatsapp.net",
    ))
    .unwrap();
    let first_own_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_own_ciphertext,
    )
    .unwrap();
    let first_own_unpadded = wa_core::unpad_random_max16(&first_own_decrypted.plaintext).unwrap();
    let first_own_decoded = wa_proto::proto::Message::decode(first_own_unpadded).unwrap();
    let first_device_sent = first_own_decoded.device_sent_message.unwrap();
    assert_eq!(
        first_device_sent.destination_jid.as_deref(),
        Some("123@s.whatsapp.net")
    );
    assert_eq!(
        first_device_sent
            .message
            .unwrap()
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("first linked signal")
    );

    let privacy_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("first linked send should schedule post-send privacy token issue")
        .unwrap();
    let privacy = decode_inbound_binary_node(&privacy_frame).unwrap().node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    let requested_token = test_child(test_child(&privacy, "tokens"), "token");
    assert_eq!(requested_token.attrs["jid"], "123@s.whatsapp.net");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", privacy.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_attr("t", requested_token.attrs["t"].clone())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"linked-established-token")),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let second_send = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "second linked signal",
        MessageRelayOptions::new().with_message_id("signal-linked-established-2"),
    );
    tokio::pin!(second_send);
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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut second_send,
    )
    .await;

    let second_relay = tokio::time::timeout(Duration::from_secs(1), &mut second_send)
        .await
        .expect("second linked send should reuse both provider sessions without key-bundle query")
        .unwrap();
    assert_eq!(second_relay.message_id, "signal-linked-established-2");
    assert_eq!(second_relay.recipient_count, 2);
    let second_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_node, second_relay.node);
    for (jid, first_record, expected_device_sent) in [
        ("123@s.whatsapp.net", &first_remote_decrypted.record, false),
        ("999:8@s.whatsapp.net", &first_own_decrypted.record, true),
    ] {
        let enc = test_participant_enc_node(&second_node, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("second linked signal")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("second linked signal")
            );
        }
    }
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_with_signal_codec_stops_when_relay_send_fails_without_retry_cache() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 95;
    let codec = client.signal_message_codec().unwrap();
    let encryptor = ClosingAfterEncryptor::new(codec, connection.clone(), 1);
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "signal relay send failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("signal-send-fail"),
    );
    tokio::pin!(send_fut);

    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut send_fut).await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net"]
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));

    let snapshot = client
        .retry_session_snapshot("123@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(
        snapshot.registration_id,
        Some(remote_credentials.registration_id)
    );
    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec!["signal-send-fail".to_owned()],
                from_jid: Some("123@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("999:7@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@s.whatsapp.net".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: Some(remote_credentials.registration_id),
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.jobs.is_empty());
    assert_eq!(prepared.missing_message_ids, vec!["signal-send-fail"]);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_with_signal_codec_stops_after_linked_device_encrypt_without_retry_cache() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 96;
    let codec = client.signal_message_codec().unwrap();
    let encryptor = ClosingAfterEncryptor::new(codec, connection.clone(), 2);
    let send_fut = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "signal linked relay send failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("signal-send-fail-linked"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let err = send_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    for jid in ["123@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));

    let snapshot = client
        .retry_session_snapshot("123@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(
        snapshot.registration_id,
        Some(remote_credentials.registration_id)
    );
    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec!["signal-send-fail-linked".to_owned()],
                from_jid: Some("123@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("999:7@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@s.whatsapp.net".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: Some(remote_credentials.registration_id),
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.jobs.is_empty());
    assert_eq!(
        prepared.missing_message_ids,
        vec!["signal-send-fail-linked"]
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_image_with_signal_provider_encrypts_media_payload() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 91;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![1u8; 32]),
        Bytes::from(vec![2u8; 32]),
        Bytes::from(vec![3u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/signal-image")
    .with_direct_path("/v/t62.7118-24/signal-image")
    .with_media_key_timestamp(1_700_000_000);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed direct photo".to_owned());
    let send_fut = client.send_image_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        image,
        MessageRelayOptions::new().with_message_id("signal-media-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-media-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    let image = decoded.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("store-backed direct photo"));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/signal-image")
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
async fn send_gif_with_signal_provider_encrypts_gif_playback_payload() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 93;
    let gif_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![7u8; 32]),
        Bytes::from(vec![8u8; 32]),
        Bytes::from(vec![9u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/signal-gif")
    .with_direct_path("/v/t62.7118-24/signal-gif")
    .with_media_key_timestamp(1_700_000_002);
    let mut gif = wa_core::VideoContent::new(gif_media, "video/mp4");
    gif.caption = Some("store-backed gif".to_owned());
    gif.seconds = Some(6);
    gif.height = Some(480);
    gif.width = Some(480);
    let send_fut = client.send_gif_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        gif,
        MessageRelayOptions::new().with_message_id("signal-gif-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-gif-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    assert!(decoded.ptv_message.is_none());
    let gif = decoded.video_message.unwrap();
    assert_eq!(gif.mimetype.as_deref(), Some("video/mp4"));
    assert_eq!(gif.caption.as_deref(), Some("store-backed gif"));
    assert_eq!(gif.gif_playback, Some(true));
    assert_eq!(gif.seconds, Some(6));
    assert_eq!(gif.height, Some(480));
    assert_eq!(gif.width, Some(480));
    assert_eq!(
        gif.direct_path.as_deref(),
        Some("/v/t62.7118-24/signal-gif")
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
async fn send_view_once_image_with_signal_provider_encrypts_wrapped_media_payload() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 95;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![16u8; 32]),
        Bytes::from(vec![17u8; 32]),
        Bytes::from(vec![18u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/signal-view-once-image")
    .with_direct_path("/v/t62.7118-24/signal-view-once-image")
    .with_media_key_timestamp(1_700_000_004);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed view once".to_owned());
    let send_fut = client.send_view_once_image_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        image,
        MessageRelayOptions::new().with_message_id("signal-view-once-image-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-view-once-image-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    assert!(decoded.image_message.is_none());
    let inner = decoded
        .view_once_message
        .as_ref()
        .and_then(|wrapper| wrapper.message.as_deref())
        .unwrap();
    let image = inner.image_message.as_ref().unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("store-backed view once"));
    assert_eq!(image.view_once, Some(true));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/signal-view-once-image")
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
async fn send_ptt_with_signal_provider_encrypts_push_to_talk_payload() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 94;
    let ptt_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![10u8; 32]),
        Bytes::from(vec![11u8; 32]),
        Bytes::from(vec![12u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/signal-ptt")
    .with_direct_path("/v/t62.7118-24/signal-ptt")
    .with_media_key_timestamp(1_700_000_003);
    let mut ptt = wa_core::AudioContent::new(ptt_media, "audio/ogg; codecs=opus");
    ptt.seconds = Some(5);
    ptt.waveform = Some(Bytes::from_static(b"signal-ptt-waveform"));
    let send_fut = client.send_ptt_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        ptt,
        MessageRelayOptions::new().with_message_id("signal-ptt-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-ptt-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    let ptt = decoded.audio_message.unwrap();
    assert_eq!(ptt.mimetype.as_deref(), Some("audio/ogg; codecs=opus"));
    assert_eq!(ptt.seconds, Some(5));
    assert_eq!(ptt.ptt, Some(true));
    assert_eq!(ptt.waveform.as_deref(), Some(&b"signal-ptt-waveform"[..]));
    assert_eq!(
        ptt.direct_path.as_deref(),
        Some("/v/t62.7118-24/signal-ptt")
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
async fn send_ptv_with_signal_provider_encrypts_video_note_payload() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 92;
    let ptv_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![4u8; 32]),
        Bytes::from(vec![5u8; 32]),
        Bytes::from(vec![6u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/signal-ptv")
    .with_direct_path("/v/t62.7118-24/signal-ptv")
    .with_media_key_timestamp(1_700_000_001);
    let mut ptv = wa_core::VideoContent::new(ptv_media, "video/mp4");
    ptv.seconds = Some(8);
    ptv.height = Some(640);
    ptv.width = Some(640);
    let send_fut = client.send_ptv_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        ptv,
        MessageRelayOptions::new().with_message_id("signal-ptv-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-ptv-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    assert!(decoded.video_message.is_none());
    let ptv = decoded.ptv_message.unwrap();
    assert_eq!(ptv.mimetype.as_deref(), Some("video/mp4"));
    assert_eq!(ptv.seconds, Some(8));
    assert_eq!(ptv.height, Some(640));
    assert_eq!(ptv.width, Some(640));
    assert_eq!(
        ptv.direct_path.as_deref(),
        Some("/v/t62.7118-24/signal-ptv")
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
async fn send_message_with_signal_provider_encrypts_media_and_own_linked_device_payloads() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 115;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![13u8; 32]),
        Bytes::from(vec![14u8; 32]),
        Bytes::from(vec![15u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/signal-linked-image")
    .with_direct_path("/v/t62.7118-24/signal-linked-image")
    .with_media_key_timestamp(1_700_000_004);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed linked direct photo".to_owned());
    let send_fut = client.send_message_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        MessageContent::image(image),
        MessageRelayOptions::new().with_message_id("signal-media-linked-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-media-linked-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "signal-media-linked-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
        let image = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            device_sent.message.unwrap().image_message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.image_message.unwrap()
        };
        assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(
            image.caption.as_deref(),
            Some("store-backed linked direct photo")
        );
        assert_eq!(
            image.direct_path.as_deref(),
            Some("/v/t62.7118-24/signal-linked-image")
        );
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_media_signal_reuses_established_sessions_for_own_linked_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 116;

    let first_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![16u8; 32]),
        Bytes::from(vec![17u8; 32]),
        Bytes::from(vec![18u8; 32]),
        3_072,
    )
    .with_url("https://media.example.invalid/signal-established-first-image")
    .with_direct_path("/v/t62.7118-24/signal-established-first-image")
    .with_media_key_timestamp(1_700_000_005);
    let mut first_image = wa_core::ImageContent::new(first_media, "image/jpeg");
    first_image.caption = Some("first linked direct photo".to_owned());
    let first_send = client.send_message_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        MessageContent::image(first_image),
        MessageRelayOptions::new().with_message_id("signal-media-established-1"),
    );
    tokio::pin!(first_send);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut first_send,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut first_send,
    )
    .await;

    let first_relay = first_send.await.unwrap();
    assert_eq!(first_relay.message_id, "signal-media-established-1");
    assert_eq!(first_relay.recipient_count, 2);
    let first_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_node, first_relay.node);
    assert_eq!(first_node.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_node.attrs["type"], "media");
    let first_participants = test_children(test_child(&first_node, "participants"), "to");
    assert_eq!(
        first_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);

    let first_remote_ciphertext =
        test_node_bytes(test_participant_enc_node(&first_node, "123@s.whatsapp.net")).unwrap();
    let first_remote_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_remote_ciphertext,
    )
    .unwrap();
    let first_remote_unpadded =
        wa_core::unpad_random_max16(&first_remote_decrypted.plaintext).unwrap();
    let first_remote_decoded = wa_proto::proto::Message::decode(first_remote_unpadded).unwrap();
    let first_remote_image = first_remote_decoded.image_message.unwrap();
    assert_eq!(
        first_remote_image.caption.as_deref(),
        Some("first linked direct photo")
    );
    assert_eq!(
        first_remote_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/signal-established-first-image")
    );

    let first_own_ciphertext = test_node_bytes(test_participant_enc_node(
        &first_node,
        "999:8@s.whatsapp.net",
    ))
    .unwrap();
    let first_own_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_own_ciphertext,
    )
    .unwrap();
    let first_own_unpadded = wa_core::unpad_random_max16(&first_own_decrypted.plaintext).unwrap();
    let first_own_decoded = wa_proto::proto::Message::decode(first_own_unpadded).unwrap();
    let first_device_sent = first_own_decoded.device_sent_message.unwrap();
    assert_eq!(
        first_device_sent.destination_jid.as_deref(),
        Some("123@s.whatsapp.net")
    );
    let first_own_image = first_device_sent.message.unwrap().image_message.unwrap();
    assert_eq!(
        first_own_image.caption.as_deref(),
        Some("first linked direct photo")
    );
    assert_eq!(
        first_own_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/signal-established-first-image")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("ownlid:8@lid")
            .await
            .unwrap()
            .is_none()
    );

    let privacy_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("first linked media send should schedule post-send privacy token issue")
        .unwrap();
    let privacy = decode_inbound_binary_node(&privacy_frame).unwrap().node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    let requested_token = test_child(test_child(&privacy, "tokens"), "token");
    assert_eq!(requested_token.attrs["jid"], "123@s.whatsapp.net");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", privacy.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_attr("t", requested_token.attrs["t"].clone())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"linked-media-token")),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let second_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![19u8; 32]),
        Bytes::from(vec![20u8; 32]),
        Bytes::from(vec![21u8; 32]),
        4_096,
    )
    .with_url("https://media.example.invalid/signal-established-second-image")
    .with_direct_path("/v/t62.7118-24/signal-established-second-image")
    .with_media_key_timestamp(1_700_000_006);
    let mut second_image = wa_core::ImageContent::new(second_media, "image/jpeg");
    second_image.caption = Some("second linked direct photo".to_owned());
    let second_send = client.send_message_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        MessageContent::image(second_image),
        MessageRelayOptions::new().with_message_id("signal-media-established-2"),
    );
    tokio::pin!(second_send);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut second_send,
    )
    .await;

    let second_relay = tokio::time::timeout(Duration::from_secs(1), &mut second_send)
        .await
        .expect(
            "second linked media send should reuse both provider sessions without key-bundle query",
        )
        .unwrap();
    assert_eq!(second_relay.message_id, "signal-media-established-2");
    assert_eq!(second_relay.recipient_count, 2);
    let second_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_node, second_relay.node);
    assert_eq!(second_node.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_node.attrs["type"], "media");
    assert!(second_node.attrs.contains_key("phash"));
    let participants = test_children(test_child(&second_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    for (jid, first_record, expected_device_sent) in [
        ("123@s.whatsapp.net", &first_remote_decrypted.record, false),
        ("999:8@s.whatsapp.net", &first_own_decrypted.record, true),
    ] {
        let enc = test_participant_enc_node(&second_node, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        let image = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            device_sent.message.unwrap().image_message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.image_message.unwrap()
        };
        assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(image.caption.as_deref(), Some("second linked direct photo"));
        assert_eq!(
            image.direct_path.as_deref(),
            Some("/v/t62.7118-24/signal-established-second-image")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_text_with_signal_provider_mirrors_mapped_lid_session_to_pn_recipient() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 91;
    let send_fut = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "hello mapped signal",
        MessageRelayOptions::new().with_message_id("signal-mapped-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("lid123@lid".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "signal-mapped-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));
    let repository = client.signal_repository();
    assert!(
        wa_core::SignalRepository::validate_session(&repository, "lid123@lid")
            .await
            .unwrap()
            .exists
    );
    assert!(
        wa_core::SignalRepository::validate_session(&repository, "123@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    assert_eq!(
        decoded
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("hello mapped signal")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_reaction_and_protocol_facades_use_direct_relay_path() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent-token"))
            .unwrap()
            .with_timestamp_seconds(now)
            .with_sender_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let remote_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "target-1", None).unwrap();
    let own_key =
        wa_core::build_message_key("123@s.whatsapp.net", true, "own-target-1", None).unwrap();

    let reaction_fut = client.send_reaction(
        &connection,
        "123@s.whatsapp.net",
        ReactionContent::new(remote_key.clone(), "+"),
        &encryptor,
        MessageRelayOptions::new().with_message_id("reaction-send-1"),
    );
    tokio::pin!(reaction_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut reaction_fut).await;
    let reaction_relay = reaction_fut.await.unwrap();
    assert_eq!(reaction_relay.message_id, "reaction-send-1");
    let reaction_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(reaction_sent.attrs["type"], "reaction");

    let edit_fut = client.send_edit(
        &connection,
        "123@s.whatsapp.net",
        EditContent {
            key: own_key.clone(),
            message: wa_core::build_text_message("edited").unwrap(),
            timestamp_ms: Some(1_700_000_001),
        },
        &encryptor,
        MessageRelayOptions::new().with_message_id("edit-send-1"),
    );
    tokio::pin!(edit_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut edit_fut).await;
    let edit_relay = edit_fut.await.unwrap();
    assert_eq!(edit_relay.message_id, "edit-send-1");
    let edit_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(edit_sent.attrs["type"], "text");

    let delete_fut = client.send_delete(
        &connection,
        "123@s.whatsapp.net",
        DeleteContent {
            key: own_key.clone(),
        },
        &encryptor,
        MessageRelayOptions::new().with_message_id("delete-send-1"),
    );
    tokio::pin!(delete_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut delete_fut).await;
    let delete_relay = delete_fut.await.unwrap();
    assert_eq!(delete_relay.message_id, "delete-send-1");
    let delete_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(delete_sent.attrs["type"], "text");

    let pin_fut = client.send_pin(
        &connection,
        "123@s.whatsapp.net",
        PinContent {
            key: own_key.clone(),
            action: wa_core::PinAction::Pin,
            sender_timestamp_ms: Some(1_700_000_002),
        },
        &encryptor,
        MessageRelayOptions::new().with_message_id("pin-send-1"),
    );
    tokio::pin!(pin_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut pin_fut).await;
    let pin_relay = pin_fut.await.unwrap();
    assert_eq!(pin_relay.message_id, "pin-send-1");
    let pin_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(pin_sent.attrs["type"], "text");

    let disappearing_fut = client.send_disappearing_mode(
        &connection,
        "123@s.whatsapp.net",
        DisappearingModeContent::new(86_400),
        &encryptor,
        MessageRelayOptions::new().with_message_id("disappearing-send-1"),
    );
    tokio::pin!(disappearing_fut);
    respond_to_single_remote_device_query(&mut sink_rx, &stream_tx, &mut disappearing_fut).await;
    let disappearing_relay = disappearing_fut.await.unwrap();
    assert_eq!(disappearing_relay.message_id, "disappearing-send-1");
    let disappearing_sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(disappearing_sent.attrs["type"], "text");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 5);
    let reaction = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let reaction = reaction.reaction_message.unwrap();
    assert_eq!(reaction.key.as_ref(), Some(&remote_key));
    assert_eq!(reaction.text.as_deref(), Some("+"));

    let edit = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let edit_protocol = edit.protocol_message.unwrap();
    assert_eq!(
        edit_protocol.r#type,
        Some(wa_proto::proto::message::protocol_message::Type::MessageEdit as i32)
    );
    assert!(edit_protocol.edited_message.is_some());

    let delete = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    assert_eq!(
        delete.protocol_message.unwrap().r#type,
        Some(wa_proto::proto::message::protocol_message::Type::Revoke as i32)
    );

    let pin = wa_proto::proto::Message::decode(calls[3].1.clone()).unwrap();
    assert_eq!(
        pin.pin_in_chat_message.unwrap().r#type,
        Some(wa_proto::proto::message::pin_in_chat_message::Type::PinForAll as i32)
    );

    let disappearing = wa_proto::proto::Message::decode(calls[4].1.clone()).unwrap();
    let inner = disappearing
        .ephemeral_message
        .as_ref()
        .and_then(|wrapper| wrapper.message.as_deref())
        .unwrap();
    let protocol = inner.protocol_message.as_ref().unwrap();
    assert_eq!(
        protocol.r#type,
        Some(wa_proto::proto::message::protocol_message::Type::EphemeralSetting as i32)
    );
    assert_eq!(protocol.ephemeral_expiration, Some(86_400));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_poll_with_signal_provider_encrypts_poll_and_attaches_reporting() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 92;
    let send_fut = client.send_poll_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        PollContent::new("Deploy?", ["Ship", "Hold"], 1, Bytes::from(vec![9u8; 32])),
        MessageRelayOptions::new().with_message_id("poll-signal-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "poll-signal-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "poll-signal-1");
    assert_eq!(sent.attrs["type"], "poll");
    assert_eq!(test_child(&sent, "reporting").tag, "reporting");
    let enc = test_participant_enc_node(&sent, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let ciphertext = test_node_bytes(enc).unwrap();
    let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
    assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &ciphertext,
    )
    .unwrap();
    let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
    let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
    let poll = decoded.poll_creation_message_v3.unwrap();
    assert_eq!(poll.name.as_deref(), Some("Deploy?"));
    assert_eq!(poll.options.len(), 2);
    assert_eq!(
        decoded
            .message_context_info
            .as_ref()
            .unwrap()
            .message_secret
            .as_ref()
            .unwrap()
            .len(),
        32
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_poll_with_signal_provider_encrypts_poll_and_own_linked_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 119;
    let send_fut = client.send_poll_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        PollContent::new(
            "Roll out?",
            ["Now", "Later"],
            1,
            Bytes::from(vec![31u8; 32]),
        ),
        MessageRelayOptions::new().with_message_id("poll-signal-linked-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "poll-signal-linked-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "poll-signal-linked-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "poll");
    assert_eq!(test_child(&sent, "reporting").tag, "reporting");
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
        let poll_message = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let poll = poll_message.poll_creation_message_v3.unwrap();
        assert_eq!(poll.name.as_deref(), Some("Roll out?"));
        assert_eq!(poll.options.len(), 2);
        assert_eq!(
            poll_message
                .message_context_info
                .as_ref()
                .unwrap()
                .message_secret
                .as_ref()
                .unwrap()
                .len(),
            32
        );
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_poll_update_with_signal_provider_encrypts_update_and_own_linked_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 123;
    let poll_key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("poll-parent-raw-signal-1".to_owned()),
        participant: None,
    };
    let send_fut = client.send_poll_update_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        PollUpdateContent::new(
            poll_key.clone(),
            Bytes::from_static(b"raw-encrypted-vote"),
            Bytes::from_static(b"raw-vote-iv"),
        )
        .with_sender_timestamp_ms(1_700_000_127),
        MessageRelayOptions::new().with_message_id("poll-update-signal-linked-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "poll-update-signal-linked-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "poll-update-signal-linked-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "poll");
    assert!(test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
        let poll_message = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let poll_update = poll_message.poll_update_message.unwrap();
        assert_eq!(
            poll_update.poll_creation_message_key.as_ref(),
            Some(&poll_key)
        );
        assert_eq!(poll_update.sender_timestamp_ms, Some(1_700_000_127));
        assert!(poll_update.metadata.is_some());
        let vote = poll_update.vote.unwrap();
        assert_eq!(
            vote.enc_payload.as_deref(),
            Some(&b"raw-encrypted-vote"[..])
        );
        assert_eq!(vote.enc_iv.as_deref(), Some(&b"raw-vote-iv"[..]));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_poll_vote_with_signal_provider_encrypts_vote_and_own_linked_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 122;
    let poll_key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("poll-parent-signal-1".to_owned()),
        participant: None,
    };
    let poll_secret = Bytes::from(vec![34u8; 32]);
    let send_fut = client.send_poll_vote_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        PollVoteContent::from_option_names(
            poll_key.clone(),
            ["Approve"],
            poll_secret.clone(),
            "123@s.whatsapp.net",
            "999:7@s.whatsapp.net",
        )
        .unwrap()
        .with_sender_timestamp_ms(1_700_000_126),
        MessageRelayOptions::new().with_message_id("poll-vote-signal-linked-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "poll-vote-signal-linked-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "poll-vote-signal-linked-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "poll");
    assert!(test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
        let poll_message = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let poll_update = poll_message.poll_update_message.unwrap();
        assert_eq!(
            poll_update.poll_creation_message_key.as_ref(),
            Some(&poll_key)
        );
        assert_eq!(poll_update.sender_timestamp_ms, Some(1_700_000_126));
        assert!(poll_update.metadata.is_some());
        let vote = poll_update.vote.unwrap();
        assert_eq!(vote.enc_iv.as_ref().unwrap().len(), 12);
        let decrypted_vote = wa_core::decrypt_poll_vote_message(
            &vote,
            "poll-parent-signal-1",
            "123@s.whatsapp.net",
            "999@s.whatsapp.net",
            &poll_secret,
        )
        .unwrap();
        assert_eq!(
            decrypted_vote.selected_options,
            vec![Bytes::copy_from_slice(&wa_crypto::sha256_hash(b"Approve"))]
        );
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_event_with_signal_provider_encrypts_event_and_own_linked_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 120;
    let send_fut = client.send_event_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        EventContent::new("Launch review", 1_700_000_123, Bytes::from(vec![32u8; 32]))
            .with_join_link("https://call.example.invalid/launch"),
        MessageRelayOptions::new().with_message_id("event-signal-linked-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "event-signal-linked-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "event-signal-linked-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "event");
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
        let event_message = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let event = event_message.event_message.unwrap();
        assert_eq!(event.name.as_deref(), Some("Launch review"));
        assert_eq!(
            event.join_link.as_deref(),
            Some("https://call.example.invalid/launch")
        );
        assert_eq!(
            event_message
                .message_context_info
                .as_ref()
                .unwrap()
                .message_secret
                .as_ref()
                .unwrap()
                .len(),
            32
        );
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_event_response_with_signal_provider_encrypts_response_and_own_linked_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 124;
    let event_key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("event-parent-raw-signal-1".to_owned()),
        participant: None,
    };
    let send_fut = client.send_event_response_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        EventResponseContent::new(
            event_key.clone(),
            Bytes::from_static(b"raw-encrypted-response"),
            Bytes::from_static(b"raw-response-iv"),
        ),
        MessageRelayOptions::new().with_message_id("event-response-raw-signal-linked-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "event-response-raw-signal-linked-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "event-response-raw-signal-linked-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "text");
    assert!(test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
        let response_message = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let encrypted_response = response_message.enc_event_response_message.unwrap();
        assert_eq!(
            encrypted_response.event_creation_message_key.as_ref(),
            Some(&event_key)
        );
        assert_eq!(
            encrypted_response.enc_payload.as_deref(),
            Some(&b"raw-encrypted-response"[..])
        );
        assert_eq!(
            encrypted_response.enc_iv.as_deref(),
            Some(&b"raw-response-iv"[..])
        );
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_event_response_payload_with_signal_provider_encrypts_response_and_own_linked_device()
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
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_one_time_pre_key_id = 121;
    let event_key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("event-parent-signal-1".to_owned()),
        participant: None,
    };
    let event_secret = Bytes::from(vec![33u8; 32]);
    let send_fut = client.send_event_response_payload_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        EventResponsePayload::new(
            event_key.clone(),
            wa_core::EventResponseKind::Going,
            event_secret.clone(),
            "123@s.whatsapp.net",
            "999:7@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_125)
        .with_extra_guest_count(2),
        MessageRelayOptions::new().with_message_id("event-response-signal-linked-1"),
    );
    tokio::pin!(send_fut);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "event-response-signal-linked-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["id"], "event-response-signal-linked-1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "text");
    assert!(test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
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
        let enc = test_participant_enc_node(&sent, jid);
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
        let response_message = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let encrypted_response = response_message.enc_event_response_message.unwrap();
        assert_eq!(
            encrypted_response.event_creation_message_key.as_ref(),
            Some(&event_key)
        );
        assert_eq!(encrypted_response.enc_iv.as_ref().unwrap().len(), 12);
        let response = wa_core::decrypt_event_response_message(
            &encrypted_response,
            "event-parent-signal-1",
            "123@s.whatsapp.net",
            "999@s.whatsapp.net",
            &event_secret,
        )
        .unwrap();
        assert_eq!(
            response.response,
            Some(wa_proto::proto::message::event_response_message::EventResponseType::Going as i32)
        );
        assert_eq!(response.timestamp_ms, Some(1_700_000_125));
        assert_eq!(response.extra_guest_count, Some(2));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_session_snapshot_treats_malformed_provider_session_as_missing() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_provider_state_store()
        .store_session_record("123@s.whatsapp.net", b"not-a-provider-session")
        .await
        .unwrap();

    let snapshot = client
        .retry_session_snapshot("123@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(snapshot, wa_core::RetrySessionSnapshot::missing());

    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec!["retry-malformed-provider".to_owned()],
                from_jid: Some("123@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("123@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@s.whatsapp.net".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: None,
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(
        plan.session_action,
        wa_core::RetrySessionAction::Refresh {
            reason: "retry receipt without key bundle".to_owned()
        }
    );

    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .signal_provider_state_store()
        .store_session_record("123@s.whatsapp.net", b"still-not-a-provider-session")
        .await
        .unwrap();
    let fallback_snapshot = client
        .retry_session_snapshot("123@s.whatsapp.net")
        .await
        .unwrap();
    assert!(fallback_snapshot.has_session);
    assert_eq!(fallback_snapshot.registration_id, Some(0x0102_0304));
    assert!(fallback_snapshot.base_key.is_some());
    assert_eq!(fallback_snapshot.signal_address.as_deref(), Some("123.0"));
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_session_snapshot_normalizes_signal_address_for_base_key_collision() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();

    let bare_snapshot = client
        .retry_session_snapshot("123@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(bare_snapshot.signal_address.as_deref(), Some("123.0"));
    let device_zero_snapshot = client
        .retry_session_snapshot("123:0@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(
        device_zero_snapshot.signal_address.as_deref(),
        Some("123.0")
    );
    assert_eq!(device_zero_snapshot.base_key, bare_snapshot.base_key);

    let mut receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-normalized-address".to_owned()],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("123@s.whatsapp.net".to_owned()),
        chat_jid: Some("123@s.whatsapp.net".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 2,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: false,
    };
    let first_plan = client
        .plan_retry_resend(&receipt, bare_snapshot, current_unix_timestamp_ms())
        .unwrap();
    assert!(matches!(
        first_plan.session_action,
        wa_core::RetrySessionAction::DeleteAndRefresh { .. }
    ));

    receipt.from_jid = Some("123:0@s.whatsapp.net".to_owned());
    receipt.retry.count = 3;
    let second_plan = client
        .plan_retry_resend(
            &receipt,
            device_zero_snapshot,
            current_unix_timestamp_ms() + 1,
        )
        .unwrap();
    assert_eq!(
        second_plan.session_action,
        wa_core::RetrySessionAction::DeleteAndRefresh {
            reason: "base key collision across retries".to_owned()
        }
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_session_snapshot_uses_mapped_lid_descriptor_session_for_pn_participant() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "lid123:1@lid".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();

    let snapshot = client
        .retry_session_snapshot("123:1@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(snapshot.registration_id, Some(0x0102_0304));
    assert!(snapshot.base_key.is_some());
    assert_eq!(snapshot.signal_address.as_deref(), Some("lid123_1.1"));
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_session_snapshot_ignores_mapped_lid_descriptor_identity_mismatch() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "lid123:1@lid".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let mapped_address = wa_core::signal_protocol_address("lid123:1@lid")
        .unwrap()
        .to_string();
    store
        .set_signal_key(KeyNamespace::IdentityKey, &mapped_address, &[9u8; 32])
        .await
        .unwrap();

    let snapshot = client
        .retry_session_snapshot("123:1@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(snapshot, wa_core::RetrySessionSnapshot::missing());

    let plan = client
        .plan_retry_resend(
            &wa_core::RetryReceipt {
                message_ids: vec!["retry-mapped-stale-descriptor".to_owned()],
                from_jid: Some("123:1@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: Some("123:1@s.whatsapp.net".to_owned()),
                recipient: Some("123:1@s.whatsapp.net".to_owned()),
                chat_jid: Some("123@s.whatsapp.net".to_owned()),
                retry: wa_core::RetryReceiptRetry {
                    count: 1,
                    original_stanza_id: None,
                    timestamp: None,
                    version: None,
                    error: None,
                },
                registration_id: None,
                has_key_bundle: false,
            },
            snapshot,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(
        plan.session_action,
        wa_core::RetrySessionAction::Refresh {
            reason: "retry receipt without key bundle".to_owned()
        }
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_session_snapshot_uses_mapped_lid_provider_session_for_pn_participant() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let remote_credentials = wa_core::create_initial_credentials().unwrap();
    let remote_one_time_pre_key = generate_key_pair();
    let remote_session = wa_core::SignalSession {
        registration_id: remote_credentials.registration_id,
        identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
        signed_pre_key: wa_core::SignalSignedPreKey {
            key_id: remote_credentials.signed_pre_key.key_id,
            public_key: Bytes::copy_from_slice(&remote_credentials.signed_pre_key.key_pair.public),
            signature: remote_credentials.signed_pre_key.signature.clone(),
        },
        pre_key: Some(wa_core::SignalPreKey {
            key_id: 91,
            public_key: Bytes::copy_from_slice(&remote_one_time_pre_key.public),
        }),
    };
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "lid123:1@lid".to_owned(),
            session: remote_session,
        })
        .await
        .unwrap();
    let codec = client.signal_message_codec().unwrap();
    let encrypted = codec
        .encrypt_message("lid123:1@lid", Bytes::from_static(b"seed provider session"))
        .await
        .unwrap();
    assert_eq!(
        encrypted.ciphertext_type,
        wa_core::MessageCiphertextType::PreKey
    );
    let mapped_address = wa_core::signal_protocol_address("lid123:1@lid")
        .unwrap()
        .to_string();
    store
        .delete_signal_key(KeyNamespace::Session, &mapped_address)
        .await
        .unwrap();

    let snapshot = client
        .retry_session_snapshot("123:1@s.whatsapp.net")
        .await
        .unwrap();
    assert!(snapshot.has_session);
    assert_eq!(
        snapshot.registration_id,
        Some(remote_credentials.registration_id)
    );
    assert!(snapshot.base_key.is_some());
    assert_eq!(snapshot.signal_address.as_deref(), Some("lid123_1.1"));
}
