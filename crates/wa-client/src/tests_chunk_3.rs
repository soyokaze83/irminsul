// Auto-partitioned test chunk 3 of 8 (feature `wat3`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat3 to stay within the VM RAM budget.
// Included into `mod chunk_3` in lib.rs; allow-attrs live on that module decl.
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
async fn execute_retry_resends_finalizes_first_all_device_replay_when_second_session_assertion_fails()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["123:1@s.whatsapp.net", "999:8@s.whatsapp.net"] {
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
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-all-first-before-session-fail",
            wa_proto::proto::Message {
                conversation: Some("first all-device before session failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-all-session-fail-second",
            wa_proto::proto::Message {
                conversation: Some("second all-device session assertion fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "retry-all-first-before-session-fail".to_owned(),
            "retry-all-session-fail-second".to_owned(),
        ],
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
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 2);

    let encryptor = DeletingSessionsAfterEncryptor::new(
        client.signal_repository(),
        2,
        ["123:1@s.whatsapp.net", "999:8@s.whatsapp.net"],
    );
    let retry_fut = client.execute_retry_resends(&connection, &prepared, &encryptor);
    tokio::pin!(retry_fut);

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
            retry_all_devices_with_own_linked_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let first_replay_frame = tokio::select! {
        result = &mut retry_fut => panic!("all-device retry completed before first replay stanza: {result:?}"),
        sent = sink_rx.recv() => sent.expect("connection sink should stay open"),
    };
    let first_replay_node = decode_inbound_binary_node(&first_replay_frame)
        .unwrap()
        .node;
    assert_eq!(
        first_replay_node.attrs["id"],
        "retry-all-first-before-session-fail"
    );
    assert_eq!(first_replay_node.attrs["to"], "123@s.whatsapp.net");

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
            retry_all_devices_with_own_linked_device_response(&node)
        },
        &mut retry_fut,
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
                    ("123:1@s.whatsapp.net".to_owned(), None),
                    ("999:8@s.whatsapp.net".to_owned(), None),
                ]
            );
            error_result_for(&node, "401", "session denied")
        },
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("E2E session query failed (401): session denied")
    );
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["123:1@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first all-device before session failure")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 1);
    assert_eq!(stats.failed_retries, 0);

    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared_after_failure.is_complete());
    assert_eq!(
        prepared_after_failure.missing_message_ids,
        vec!["retry-all-first-before-session-fail"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "retry-all-session-fail-second"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_finalizes_first_all_device_replay_when_second_relay_send_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["123:1@s.whatsapp.net", "999:8@s.whatsapp.net"] {
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
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-all-first-before-send-fail",
            wa_proto::proto::Message {
                conversation: Some("first all-device before send failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-all-send-fail-second",
            wa_proto::proto::Message {
                conversation: Some("second all-device relay send fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "retry-all-first-before-send-fail".to_owned(),
            "retry-all-send-fail-second".to_owned(),
        ],
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
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 2);

    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 4);
    let retry_fut = client.execute_retry_resends(&connection, &prepared, &encryptor);
    tokio::pin!(retry_fut);

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
            retry_all_devices_with_own_linked_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let first_replay_frame = tokio::select! {
        result = &mut retry_fut => panic!("all-device retry completed before first replay stanza: {result:?}"),
        sent = sink_rx.recv() => sent.expect("connection sink should keep first replay frame"),
    };
    let first_replay_node = decode_inbound_binary_node(&first_replay_frame)
        .unwrap()
        .node;
    assert_eq!(
        first_replay_node.attrs["id"],
        "retry-all-first-before-send-fail"
    );
    assert_eq!(first_replay_node.attrs["to"], "123@s.whatsapp.net");

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
            retry_all_devices_with_own_linked_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec![
            "123:1@s.whatsapp.net",
            "999:8@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "999:8@s.whatsapp.net",
        ]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first all-device before send failure")
    );
    let second_replay_plaintext = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    assert_eq!(
        second_replay_plaintext.conversation.as_deref(),
        Some("second all-device relay send fails")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 1);
    assert_eq!(stats.failed_retries, 0);

    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared_after_failure.is_complete());
    assert_eq!(
        prepared_after_failure.missing_message_ids,
        vec!["retry-all-first-before-send-fail"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "retry-all-send-fail-second"
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_with_signal_provider_replays_cached_message() {
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
    let remote_one_time_pre_key_id = 97;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-signal-exec",
            wa_proto::proto::Message {
                conversation: Some("cached signal retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-signal-exec".to_owned()],
        from_jid: Some("123:1@s.whatsapp.net".to_owned()),
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
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "123:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);
    let retry_fut = client.execute_retry_resends_with_signal_provider(&connection, &prepared);
    tokio::pin!(retry_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123:1@s.whatsapp.net".to_owned(), None)]
            );
            valid_session_response_for_query(
                &node,
                &remote_credentials,
                &remote_one_time_pre_key,
                remote_one_time_pre_key_id,
            )
        },
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "retry-signal-exec");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "retry-signal-exec");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "cached signal retry",
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
async fn execute_retry_resends_with_signal_provider_deduplicates_own_pn_lid_all_devices() {
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
    let remote_one_time_pre_key_id = 124;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-signal-own-alias-all-devices",
            wa_proto::proto::Message {
                conversation: Some("cached signal own alias retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-signal-own-alias-all-devices".to_owned()],
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
    };
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.remote_jid, "123@s.whatsapp.net");
    assert_eq!(plan.participant_jid, "123@s.whatsapp.net");
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let retry_fut = client.execute_retry_resends_with_signal_provider(&connection, &prepared);
    tokio::pin!(retry_fut);
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
        &mut retry_fut,
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
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "retry-signal-own-alias-all-devices");
    assert_eq!(relays[0].recipient_count, 2);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "retry-signal-own-alias-all-devices");
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
                Some("cached signal own alias retry")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.conversation.as_deref(),
                Some("cached signal own alias retry")
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
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_success.jobs.is_empty());
    assert_eq!(
        prepared_after_success.missing_message_ids,
        vec!["retry-signal-own-alias-all-devices"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_retry_resend_refreshes_session_and_replays_cached_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    repository
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let message = wa_proto::proto::Message {
        conversation: Some("retry me".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-live",
            message,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-live")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry")
                .with_attr("count", "2")
                .with_attr("error", "7"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_retry_resend(
        &connection,
        &receipt,
        &IncomingDecryptor,
        &encryptor,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => panic!("retry processing completed before ACK: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-live");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(encrypt_key_query_user_attrs(&node).len(), 1);
            session_response_for_query(&node)
        },
        &mut process_fut,
    )
    .await;

    let outcome = process_fut.await.unwrap();
    assert_eq!(outcome.inbound.action, wa_core::InboundNodeAction::Receipt);
    let retry = outcome.retry_resend.unwrap();
    assert_eq!(retry.receipt.message_ids, vec!["retry-live"]);
    assert_eq!(
        retry.plan.session_action,
        wa_core::RetrySessionAction::DeleteAndRefresh {
            reason: "registration id mismatch: stored 16909060, received 16909061".to_owned(),
        }
    );
    assert_eq!(
        retry.session_action.deleted_sessions,
        vec!["123:1@s.whatsapp.net"]
    );
    assert!(retry.session_action.refreshed_sessions);
    assert!(retry.preparation.is_complete());
    assert_eq!(retry.relays.len(), 1);
    assert_eq!(retry.relays[0].message_id, "retry-live");

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-live");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
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
async fn process_incoming_node_with_retry_resend_with_signal_provider_writes_pkmsg() {
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
    let remote_one_time_pre_key_id = 98;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-signal-live",
            wa_proto::proto::Message {
                conversation: Some("live signal retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-signal-live")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_retry_resend_with_signal_provider(
        &connection,
        &receipt,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => panic!("retry processing completed before ACK: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-signal-live");
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

    let outcome = process_fut.await.unwrap();
    assert_eq!(outcome.inbound.action, wa_core::InboundNodeAction::Receipt);
    let retry = outcome.retry_resend.unwrap();
    assert_eq!(retry.receipt.message_ids, vec!["retry-signal-live"]);
    assert_eq!(
        retry.plan.session_action,
        wa_core::RetrySessionAction::Refresh {
            reason: "retry receipt without key bundle".to_owned(),
        }
    );
    assert!(retry.session_action.refreshed_sessions);
    assert_eq!(retry.relays.len(), 1);
    assert_eq!(retry.relays[0].message_id, "retry-signal-live");

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-signal-live");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "live signal retry",
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
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
async fn process_incoming_node_with_retry_resend_signal_provider_deduplicates_own_pn_lid_all_devices()
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
    let remote_one_time_pre_key_id = 125;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-signal-live-own-alias-all-devices",
            wa_proto::proto::Message {
                conversation: Some("live signal own alias retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-signal-live-own-alias-all-devices")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![BinaryNode::new("retry").with_attr("count", "1")]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_retry_resend_with_signal_provider(
        &connection,
        &receipt,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => panic!("all-device retry processing completed before ACK: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-signal-live-own-alias-all-devices");
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

    let outcome = process_fut.await.unwrap();
    assert_eq!(outcome.inbound.action, wa_core::InboundNodeAction::Receipt);
    let retry = outcome.retry_resend.unwrap();
    assert_eq!(
        retry.receipt.message_ids,
        vec!["retry-signal-live-own-alias-all-devices"]
    );
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
        "retry-signal-live-own-alias-all-devices"
    );
    assert_eq!(retry.relays[0].recipient_count, 2);

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(
        resent.attrs["id"],
        "retry-signal-live-own-alias-all-devices"
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
                Some("live signal own alias retry")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.conversation.as_deref(),
                Some("live signal own alias retry")
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
        vec!["retry-signal-live-own-alias-all-devices"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_retry_resend_signal_provider_normalizes_legacy_retry_receipt() {
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
    let remote_one_time_pre_key_id = 90;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-direct-signal-legacy",
            wa_proto::proto::Message {
                conversation: Some("direct signal legacy retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-direct-signal-legacy")
        .with_attr("from", "123:1@c.us")
        .with_attr("recipient", "123@c.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0311, 4).unwrap()),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_retry_resend_with_signal_provider(
        &connection,
        &receipt,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => panic!("legacy retry processing completed before ACK: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-direct-signal-legacy");
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

    let outcome = process_fut.await.unwrap();
    assert_eq!(outcome.inbound.action, wa_core::InboundNodeAction::Receipt);
    let retry = outcome.retry_resend.unwrap();
    assert_eq!(
        retry.receipt.message_ids,
        vec!["retry-direct-signal-legacy"]
    );
    assert_eq!(retry.plan.remote_jid, "123@s.whatsapp.net");
    assert_eq!(retry.plan.participant_jid, "123:1@s.whatsapp.net");
    assert_eq!(retry.relays.len(), 1);
    assert_eq!(retry.relays[0].message_id, "retry-direct-signal-legacy");

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-direct-signal-legacy");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "direct signal legacy retry",
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    let prepared_after_success = client
        .prepare_retry_resends(&retry.plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_success.jobs.is_empty());
    assert_eq!(
        prepared_after_success.missing_message_ids,
        vec!["retry-direct-signal-legacy"]
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
async fn process_incoming_node_with_retry_resend_signal_provider_accepts_same_base_pre_key_wrapper()
{
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "retry-direct-same-base")
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
                conversation: Some("retry direct same-base first".to_owned()),
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
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let first_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-retry-direct-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &first_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        first_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(first_result.inbound.event_count, 1);
    assert!(first_result.inbound.error.is_none());
    assert!(first_result.retry_resend.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-retry-direct-same-base-1");
    assert_eq!(first_ack.attrs["class"], "message");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-retry-direct-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("retry direct same-base first")
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
                conversation: Some("retry direct same-base wrapped second".to_owned()),
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
        .with_attr("id", "signal-retry-direct-same-base-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    let changed_identity_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &changed_identity_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        changed_identity_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(changed_identity_result.inbound.event_count, 0);
    assert!(changed_identity_result.retry_resend.is_none());
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
        "signal-retry-direct-same-base-2-identity-change"
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
            "signal-retry-direct-same-base-2-signed-pre-key-mismatch",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    let signed_pre_key_mismatch_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &signed_pre_key_mismatch_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        signed_pre_key_mismatch_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(signed_pre_key_mismatch_result.inbound.event_count, 0);
    assert!(signed_pre_key_mismatch_result.retry_resend.is_none());
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
        "signal-retry-direct-same-base-2-signed-pre-key-mismatch"
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
        .with_attr("id", "signal-retry-direct-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    let second_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &second_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        second_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(second_result.inbound.event_count, 1);
    assert!(second_result.inbound.error.is_none());
    assert!(second_result.retry_resend.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-retry-direct-same-base-2");
    assert_eq!(second_ack.attrs["class"], "message");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-retry-direct-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("retry direct same-base wrapped second")
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
        .with_attr("id", "signal-retry-direct-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    let replay_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &replay_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        replay_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(replay_result.inbound.event_count, 0);
    assert!(replay_result.retry_resend.is_none());
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
        "signal-retry-direct-same-base-2-replay"
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
                conversation: Some("retry direct same-base third".to_owned()),
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
        .with_attr("id", "signal-retry-direct-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    let third_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &third_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        third_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(third_result.inbound.event_count, 1);
    assert!(third_result.inbound.error.is_none());
    assert!(third_result.retry_resend.is_none());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-retry-direct-same-base-3");
    assert_eq!(third_ack.attrs["class"], "message");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-retry-direct-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("retry direct same-base third")
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
async fn process_incoming_node_with_retry_resend_signal_provider_accepts_new_remote_ratchet() {
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
        "retry-direct-new-ratchet",
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
        &text_plaintext("retry ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("retry ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("retry ratchet old third", 6),
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

    let first_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-retry-ratchet-1",
                "pkmsg",
                first.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        first_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(first_result.inbound.event_count, 1);
    assert!(first_result.inbound.error.is_none());
    assert!(first_result.retry_resend.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-retry-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-retry-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("retry ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver retry ratchet reply"),
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
        &text_plaintext("retry ratchet fourth", 7),
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
        &text_plaintext("retry ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    let fourth_result = client
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-retry-ratchet-4",
                "msg",
                fourth.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        fourth_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(fourth_result.inbound.event_count, 1);
    assert!(fourth_result.inbound.error.is_none());
    assert!(fourth_result.retry_resend.is_none());
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-retry-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-retry-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("retry ratchet fourth")
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
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-retry-ratchet-old-3",
                "msg",
                old_third.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        old_third_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(old_third_result.inbound.event_count, 1);
    assert!(old_third_result.inbound.error.is_none());
    assert!(old_third_result.retry_resend.is_none());
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(old_third_ack.attrs["id"], "signal-retry-ratchet-old-3");
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-retry-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("retry ratchet old third")
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
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-retry-ratchet-old-3-replay",
                "msg",
                old_third.message_bytes,
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        old_third_replay_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(old_third_replay_result.inbound.event_count, 0);
    assert!(old_third_replay_result.retry_resend.is_none());
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
        "signal-retry-ratchet-old-3-replay"
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
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &incoming_node("signal-retry-ratchet-2", "msg", second.message_bytes),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        second_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(second_result.inbound.event_count, 1);
    assert!(second_result.inbound.error.is_none());
    assert!(second_result.retry_resend.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-retry-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-retry-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("retry ratchet second")
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
        .process_incoming_node_with_retry_resend_with_signal_provider(
            &connection,
            &incoming_node("signal-retry-ratchet-5", "msg", fifth.message_bytes),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        fifth_result.inbound.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(fifth_result.inbound.event_count, 1);
    assert!(fifth_result.inbound.error.is_none());
    assert!(fifth_result.retry_resend.is_none());
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-retry-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-retry-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("retry ratchet fifth")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_group_retry_with_signal_provider_redistributes_sender_key_and_replays_message() {
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
    let remote_one_time_pre_key_id = 99;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-signal-retry",
            wa_proto::proto::Message {
                conversation: Some("signal group retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "group-signal-retry")
        .with_attr("from", "555@g.us")
        .with_attr("participant", "123:1@c.us")
        .with_attr("recipient", "555@g.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_retry_resend_with_signal_provider(
        &connection,
        &receipt,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => panic!("group retry completed before ACK: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "group-signal-retry");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "555@g.us");

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

    let outcome = process_fut.await.unwrap();
    let retry = outcome.retry_resend.unwrap();
    assert_eq!(retry.plan.participant_jid, "123:1@s.whatsapp.net");
    assert_eq!(
        retry.plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "123:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    assert!(retry.plan.should_clear_group_sender_key);
    assert_eq!(retry.sender_key_distribution_relays.len(), 1);
    assert_eq!(retry.sender_key_distribution_relays[0].recipient_count, 1);
    assert_eq!(retry.relays.len(), 1);
    assert_eq!(retry.relays[0].message_id, "group-signal-retry");

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(distribution_node.attrs["to"], "555@g.us");
    let enc = test_participant_enc_node(&distribution_node, "123:1@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "pkmsg");
    let distribution_ciphertext = test_node_bytes(enc).unwrap();
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let distribution_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &distribution_ciphertext,
    )
    .unwrap();
    let distribution_plaintext =
        wa_core::unpad_random_max16(&distribution_decrypted.plaintext).unwrap();
    let distribution_message = wa_proto::proto::Message::decode(distribution_plaintext).unwrap();
    let distribution = distribution_message
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(distribution.group_id.as_deref(), Some("555@g.us"));
    assert!(
        distribution
            .axolotl_sender_key_distribution_message
            .is_some()
    );

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "group-signal-retry");
    assert_eq!(resent.attrs["to"], "555@g.us");
    let enc = test_participant_enc_node(&resent, "123:1@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "msg");
    let replay_ciphertext = test_node_bytes(enc).unwrap();
    let replay_decrypted = wa_core::decrypt_signal_provider_session_record_message(
        &distribution_decrypted.record,
        &replay_ciphertext,
        &remote_material.identity.public_key,
    )
    .unwrap();
    let replay_plaintext = wa_core::unpad_random_max16(&replay_decrypted.plaintext).unwrap();
    let replay_message = wa_proto::proto::Message::decode(replay_plaintext).unwrap();
    assert_eq!(
        replay_message.conversation.as_deref(),
        Some("signal group retry")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_retry_resend_injects_inline_key_bundle() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::pre_key();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-bundle",
            wa_proto::proto::Message {
                conversation: Some("bundle retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-bundle")
        .with_attr("from", "123:1@c.us")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
            BinaryNode::new("keys").with_content(vec![
                BinaryNode::new("type")
                    .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                BinaryNode::new("skey").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                    BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                ]),
                BinaryNode::new("key").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                ]),
                BinaryNode::new("device-identity")
                    .with_content(Bytes::from_static(b"retry-device-identity")),
            ]),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let outcome = client
        .process_incoming_node_with_retry_resend(
            &connection,
            &receipt,
            &IncomingDecryptor,
            &encryptor,
            &mut buffer,
        )
        .await
        .unwrap();

    let ack_frame = sink_rx.recv().await.unwrap();
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.attrs["id"], "retry-bundle");
    assert_eq!(ack.attrs["class"], "receipt");

    let resent_frame = sink_rx.recv().await.unwrap();
    let resent = decode_inbound_binary_node(&resent_frame).unwrap().node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-bundle");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    let Some(wa_binary::BinaryNodeContent::Nodes(resent_children)) = &resent.content else {
        panic!("retry resend should contain child nodes");
    };
    let device_identity = resent_children
        .iter()
        .find(|node| node.tag == "device-identity")
        .expect("retry resend should reissue key-bundle device identity");
    assert_eq!(
        device_identity.content,
        Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
            b"retry-device-identity"
        )))
    );

    let retry = outcome.retry_resend.unwrap();
    assert_eq!(
        retry.plan.session_action,
        wa_core::RetrySessionAction::InjectBundle
    );
    assert_eq!(retry.plan.participant_jid, "123:1@s.whatsapp.net");
    assert_eq!(
        retry.plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "123:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    assert!(retry.session_action.injected_bundle);
    let injected_bundle = retry.session_action.injected_key_bundle.as_ref().unwrap();
    assert_eq!(injected_bundle.session.jid, "123:1@s.whatsapp.net");
    assert_eq!(
        injected_bundle.device_identity.as_deref(),
        Some(&b"retry-device-identity"[..])
    );
    assert!(!retry.session_action.refreshed_sessions);
    assert!(retry.session_action.deleted_sessions.is_empty());
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(feature = "noise")]
#[test]
fn parses_retry_inline_key_bundle_with_canonical_participant_jid() {
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-group-bundle")
        .with_attr("from", "555@g.us")
        .with_attr("participant", "123:1@c.us")
        .with_attr("recipient", "555@g.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
            BinaryNode::new("keys").with_content(vec![
                BinaryNode::new("type")
                    .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                BinaryNode::new("skey").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                    BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                ]),
                BinaryNode::new("key").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                ]),
            ]),
        ]);

    let parsed = parse_retry_receipt_with_bundle(&receipt).unwrap().unwrap();
    assert_eq!(parsed.receipt.requester_jid().unwrap(), "123:1@c.us");
    let bundle = parsed.key_bundle.unwrap();
    assert_eq!(bundle.session.jid, "123:1@s.whatsapp.net");
    assert_eq!(bundle.session.session.registration_id, 0x0102_0304);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_retry_resend_ignores_empty_retry_device_identity() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::pre_key();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-empty-device-identity",
            wa_proto::proto::Message {
                conversation: Some("empty device identity retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-empty-device-identity")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
            BinaryNode::new("keys").with_content(vec![
                BinaryNode::new("type")
                    .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                BinaryNode::new("skey").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                    BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                ]),
                BinaryNode::new("key").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                ]),
                BinaryNode::new("device-identity").with_content(Bytes::new()),
            ]),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let outcome = client
        .process_incoming_node_with_retry_resend(
            &connection,
            &receipt,
            &IncomingDecryptor,
            &encryptor,
            &mut buffer,
        )
        .await
        .unwrap();

    let ack_frame = sink_rx.recv().await.unwrap();
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.attrs["id"], "retry-empty-device-identity");
    assert_eq!(ack.attrs["class"], "receipt");

    let resent_frame = sink_rx.recv().await.unwrap();
    let resent = decode_inbound_binary_node(&resent_frame).unwrap().node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-empty-device-identity");
    let Some(wa_binary::BinaryNodeContent::Nodes(resent_children)) = &resent.content else {
        panic!("retry resend should contain child nodes");
    };
    assert!(
        resent_children
            .iter()
            .all(|node| node.tag != "device-identity")
    );

    let retry = outcome.retry_resend.unwrap();
    assert_eq!(
        retry.plan.session_action,
        wa_core::RetrySessionAction::InjectBundle
    );
    assert!(retry.session_action.injected_bundle);
    let injected_bundle = retry.session_action.injected_key_bundle.as_ref().unwrap();
    assert_eq!(injected_bundle.session.jid, "123:1@s.whatsapp.net");
    assert_eq!(injected_bundle.device_identity, None);
    assert!(!retry.session_action.refreshed_sessions);
    assert!(retry.session_action.deleted_sessions.is_empty());
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_retry_resend_refreshes_malformed_inline_key_bundle() {
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
    let provider_store = client.signal_provider_state_store();
    for jid in ["lid123:1@lid", "123:1@s.whatsapp.net"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    client
        .cache_recent_message_for_retry(
            "lid123@lid",
            "retry-malformed-bundle",
            wa_proto::proto::Message {
                conversation: Some("malformed bundle retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-malformed-bundle")
        .with_attr("from", "lid123:1@lid")
        .with_attr("recipient", "lid123@lid")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
            BinaryNode::new("keys").with_content(vec![
                BinaryNode::new("type").with_content(Bytes::from_static(b"bad")),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
            ]),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_retry_resend(
        &connection,
        &receipt,
        &IncomingDecryptor,
        &encryptor,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => {
            panic!("retry processing completed before ACK: {result:?}")
        }
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.attrs["id"], "retry-malformed-bundle");
    assert_eq!(ack.attrs["class"], "receipt");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("lid123:1@lid".to_owned(), Some("identity".to_owned()))]
            );
            session_response_for_query(&node)
        },
        &mut process_fut,
    )
    .await;

    let outcome = process_fut.await.unwrap();
    let retry = outcome.retry_resend.unwrap();
    assert_eq!(
        retry.plan.session_action,
        wa_core::RetrySessionAction::InjectBundle
    );
    assert!(!retry.session_action.injected_bundle);
    assert_eq!(retry.session_action.injected_key_bundle, None);
    assert_eq!(
        retry.session_action.deleted_sessions,
        vec!["lid123:1@lid".to_owned(), "123:1@s.whatsapp.net".to_owned()]
    );
    assert!(retry.session_action.refreshed_sessions);

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-malformed-bundle");
    let Some(wa_binary::BinaryNodeContent::Nodes(resent_children)) = &resent.content else {
        panic!("retry resend should contain child nodes");
    };
    assert!(
        resent_children
            .iter()
            .all(|node| node.tag != "device-identity")
    );
    for jid in ["lid123:1@lid", "123:1@s.whatsapp.net"] {
        assert!(
            provider_store
                .load_session_record(jid)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record(jid)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        client
            .signal_repository()
            .validate_session("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_retry_resend_clears_group_sender_key_memory() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    store
        .set(KeyNamespace::SenderKeyMemory, "555@g.us", b"sender-memory")
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-retry",
            wa_proto::proto::Message {
                conversation: Some("group retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "group-retry")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "555@g.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
            BinaryNode::new("keys").with_content(vec![
                BinaryNode::new("type")
                    .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                BinaryNode::new("skey").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                    BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                ]),
                BinaryNode::new("key").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                ]),
            ]),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let outcome = client
        .process_incoming_node_with_retry_resend(
            &connection,
            &receipt,
            &IncomingDecryptor,
            &encryptor,
            &mut buffer,
        )
        .await
        .unwrap();

    assert!(
        outcome
            .retry_resend
            .as_ref()
            .unwrap()
            .plan
            .should_clear_group_sender_key
    );
    assert!(
        outcome
            .retry_resend
            .as_ref()
            .unwrap()
            .cleared_group_sender_key_memory
    );
    assert_eq!(
        outcome
            .retry_resend
            .as_ref()
            .unwrap()
            .sender_key_distribution_relays
            .len(),
        1
    );
    assert!(
        store
            .get(KeyNamespace::SenderKeyMemory, "555@g.us")
            .await
            .unwrap()
            .is_none()
    );
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "group-retry");
    assert_eq!(ack.attrs["class"], "receipt");
    let distribution = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution.tag, "message");
    assert_eq!(distribution.attrs["to"], "555@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(distribution_children)) = &distribution.content
    else {
        panic!("sender-key distribution relay should contain participants");
    };
    assert_eq!(distribution_children[0].tag, "participants");
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "group-retry");
    assert_eq!(resent.attrs["to"], "555@g.us");
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["123:1@s.whatsapp.net", "123:1@s.whatsapp.net"]
    );
    let distribution_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let distribution = distribution_plaintext
        .sender_key_distribution_message
        .unwrap();
    assert_eq!(distribution.group_id.as_deref(), Some("555@g.us"));
    assert!(
        distribution
            .axolotl_sender_key_distribution_message
            .is_some()
    );
    let resent_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    assert_eq!(
        resent_plaintext.conversation.as_deref(),
        Some("group retry")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_group_retry_receipt_distributes_sender_key_to_primary_requester_devices() {
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
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-primary-retry",
            wa_proto::proto::Message {
                conversation: Some("group retry primary".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-primary-retry-2",
            wa_proto::proto::Message {
                conversation: Some("group retry primary second".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "group-primary-retry".to_owned(),
            "group-primary-retry-2".to_owned(),
        ],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("555@g.us".to_owned()),
        chat_jid: Some("555@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: true,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-group-device-identity")),
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::pre_key();
    let retry_fut =
        client.handle_retry_receipt_with_bundle(&connection, &receipt, Some(bundle), &encryptor);
    tokio::pin!(retry_fut);

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
            group_retry_primary_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let outcome = tokio::time::timeout(Duration::from_secs(1), &mut retry_fut)
        .await
        .expect("group retry should complete without another device query")
        .unwrap();
    assert_eq!(outcome.sender_key_distribution_relays.len(), 1);
    assert_eq!(outcome.sender_key_distribution_relays[0].recipient_count, 2);
    assert_eq!(outcome.relays.len(), 2);
    assert_eq!(outcome.relays[0].recipient_count, 2);
    assert_eq!(outcome.relays[1].recipient_count, 2);

    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should relay sender-key distribution")
        .expect("connection sink should stay open");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(distribution_node.attrs["to"], "555@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(distribution_children)) =
        &distribution_node.content
    else {
        panic!("sender-key distribution relay should contain participants");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(distribution_participants)) =
        &distribution_children[0].content
    else {
        panic!("sender-key distribution should contain participant nodes");
    };
    assert_eq!(
        distribution_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "123:1@s.whatsapp.net"]
    );
    let distribution_identity = distribution_children
        .iter()
        .find(|node| node.tag == "device-identity")
        .expect("sender-key distribution should reissue key-bundle device identity");
    assert_eq!(
        distribution_identity.content,
        Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
            b"retry-group-device-identity"
        )))
    );

    let resent_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should replay first cached message without another device query")
        .expect("connection sink should stay open");
    let resent = decode_inbound_binary_node(&resent_frame).unwrap().node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "group-primary-retry");
    assert_eq!(resent.attrs["to"], "555@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(resent_children)) = &resent.content else {
        panic!("group retry resend should contain child nodes");
    };
    let resent_identity = resent_children
        .iter()
        .find(|node| node.tag == "device-identity")
        .expect("group retry resend should reissue key-bundle device identity");
    assert_eq!(
        resent_identity.content,
        Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
            b"retry-group-device-identity"
        )))
    );
    let resent_second_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should replay second cached message without another device query")
        .expect("connection sink should stay open");
    let resent_second = decode_inbound_binary_node(&resent_second_frame)
        .unwrap()
        .node;
    assert_eq!(resent_second.tag, "message");
    assert_eq!(resent_second.attrs["id"], "group-primary-retry-2");
    assert_eq!(resent_second.attrs["to"], "555@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(resent_second_children)) = &resent_second.content
    else {
        panic!("second group retry resend should contain child nodes");
    };
    let resent_second_identity = resent_second_children
        .iter()
        .find(|node| node.tag == "device-identity")
        .expect("second group retry resend should reissue key-bundle device identity");
    assert_eq!(
        resent_second_identity.content,
        Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
            b"retry-group-device-identity"
        )))
    );
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec![
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
        ]
    );
    let distribution_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(
        distribution_plaintext
            .sender_key_distribution_message
            .is_some()
    );
    let resent_plaintext = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    assert_eq!(
        resent_plaintext.conversation.as_deref(),
        Some("group retry primary")
    );
    let resent_second_plaintext = wa_proto::proto::Message::decode(calls[4].1.clone()).unwrap();
    assert_eq!(
        resent_second_plaintext.conversation.as_deref(),
        Some("group retry primary second")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_group_retry_receipt_keeps_cached_message_when_sender_key_redistribution_fails() {
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
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-redistribution-fails",
            wa_proto::proto::Message {
                conversation: Some("retry after failed redistribution".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["group-redistribution-fails".to_owned()],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("555@g.us".to_owned()),
        chat_jid: Some("555@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: true,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-failing-device-identity")),
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = FailingEncryptor::new("retry sender-key redistribution encrypt failed");
    let retry_fut =
        client.handle_retry_receipt_with_bundle(&connection, &receipt, Some(bundle), &encryptor);
    tokio::pin!(retry_fut);

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
            group_retry_primary_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("retry sender-key redistribution encrypt failed")
    );
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 0);
    assert_eq!(stats.failed_retries, 0);
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_failure.is_complete());
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "group-redistribution-fails"
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_group_retry_receipt_keeps_cached_message_when_later_redistribution_encrypt_fails() {
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
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-late-redistribution-fails",
            wa_proto::proto::Message {
                conversation: Some("retry after late redistribution failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["group-late-redistribution-fails".to_owned()],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("555@g.us".to_owned()),
        chat_jid: Some("555@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: true,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-late-failing-device-identity")),
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor =
        FailingAfterEncryptor::new(2, "retry sender-key redistribution late encrypt failed");
    let retry_fut =
        client.handle_retry_receipt_with_bundle(&connection, &receipt, Some(bundle), &encryptor);
    tokio::pin!(retry_fut);

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
            group_retry_primary_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("retry sender-key redistribution late encrypt failed")
    );
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "123:1@s.whatsapp.net"]
    );
    let distribution_plaintext =
        wa_proto::proto::Message::decode(encryptor.calls.lock().unwrap()[0].1.clone()).unwrap();
    assert!(
        distribution_plaintext
            .sender_key_distribution_message
            .is_some()
    );
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 0);
    assert_eq!(stats.failed_retries, 0);
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_failure.is_complete());
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "group-late-redistribution-fails"
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_group_retry_receipt_keeps_cached_message_when_later_replay_encrypt_fails_after_redistribution()
 {
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
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-replay-late-fails",
            wa_proto::proto::Message {
                conversation: Some("retry replay after distribution failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["group-replay-late-fails".to_owned()],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("555@g.us".to_owned()),
        chat_jid: Some("555@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: true,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-replay-failing-device-identity")),
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = FailingAfterEncryptor::new(4, "retry group replay late encrypt failed");
    let retry_fut =
        client.handle_retry_receipt_with_bundle(&connection, &receipt, Some(bundle), &encryptor);
    tokio::pin!(retry_fut);

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
            group_retry_primary_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("retry group replay late encrypt failed")
    );
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec![
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
        ]
    );
    let distribution_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(
        distribution_plaintext
            .sender_key_distribution_message
            .is_some()
    );
    let replay_plaintext = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    assert_eq!(
        replay_plaintext.conversation.as_deref(),
        Some("retry replay after distribution failure")
    );

    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should send redistribution before replay failure")
        .expect("connection sink should stay open");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.tag, "message");
    assert_eq!(distribution_node.attrs["to"], "555@g.us");
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 0);
    assert_eq!(stats.failed_retries, 0);
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_failure.is_complete());
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "group-replay-late-fails"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_group_retry_receipt_finalizes_first_cached_replay_when_second_replay_encrypt_fails()
{
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
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-replay-first-sent",
            wa_proto::proto::Message {
                conversation: Some("first replay succeeds".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-replay-second-fails",
            wa_proto::proto::Message {
                conversation: Some("second replay fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "group-replay-first-sent".to_owned(),
            "group-replay-second-fails".to_owned(),
        ],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("555@g.us".to_owned()),
        chat_jid: Some("555@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: true,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-second-replay-failing-identity")),
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = FailingAfterEncryptor::new(6, "retry second replay late encrypt failed");
    let retry_fut =
        client.handle_retry_receipt_with_bundle(&connection, &receipt, Some(bundle), &encryptor);
    tokio::pin!(retry_fut);

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
            group_retry_primary_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("retry second replay late encrypt failed")
    );
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec![
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
        ]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first replay succeeds")
    );
    let second_replay_plaintext = wa_proto::proto::Message::decode(calls[4].1.clone()).unwrap();
    assert_eq!(
        second_replay_plaintext.conversation.as_deref(),
        Some("second replay fails")
    );

    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should send redistribution before replay")
        .expect("connection sink should stay open");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.attrs["to"], "555@g.us");
    let first_replay_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should send first cached replay before second fails")
        .expect("connection sink should stay open");
    let first_replay_node = decode_inbound_binary_node(&first_replay_frame)
        .unwrap()
        .node;
    assert_eq!(first_replay_node.attrs["id"], "group-replay-first-sent");
    assert_eq!(first_replay_node.attrs["to"], "555@g.us");
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 1);
    assert_eq!(stats.failed_retries, 0);
    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared_after_failure.is_complete());
    assert_eq!(
        prepared_after_failure.missing_message_ids,
        vec!["group-replay-first-sent"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "group-replay-second-fails"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_group_retry_receipt_finalizes_first_cached_replay_when_second_replay_send_fails() {
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
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-replay-first-before-send-fail",
            wa_proto::proto::Message {
                conversation: Some("first group replay before send failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-replay-send-fail-second",
            wa_proto::proto::Message {
                conversation: Some("second group replay send fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "group-replay-first-before-send-fail".to_owned(),
            "group-replay-send-fail-second".to_owned(),
        ],
        from_jid: Some("123@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("555@g.us".to_owned()),
        chat_jid: Some("555@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: true,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-group-send-fail-identity")),
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 6);
    let retry_fut =
        client.handle_retry_receipt_with_bundle(&connection, &receipt, Some(bundle), &encryptor);
    tokio::pin!(retry_fut);

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
            group_retry_primary_device_response(&node)
        },
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec![
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
        ]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first group replay before send failure")
    );
    let second_replay_plaintext = wa_proto::proto::Message::decode(calls[4].1.clone()).unwrap();
    assert_eq!(
        second_replay_plaintext.conversation.as_deref(),
        Some("second group replay send fails")
    );

    let distribution_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should send redistribution before replay")
        .expect("connection sink should stay open");
    let distribution_node = decode_inbound_binary_node(&distribution_frame)
        .unwrap()
        .node;
    assert_eq!(distribution_node.attrs["to"], "555@g.us");
    let first_replay_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("group retry should send first cached replay before second send fails")
        .expect("connection sink should keep first replay frame");
    let first_replay_node = decode_inbound_binary_node(&first_replay_frame)
        .unwrap()
        .node;
    assert_eq!(
        first_replay_node.attrs["id"],
        "group-replay-first-before-send-fail"
    );
    assert_eq!(first_replay_node.attrs["to"], "555@g.us");
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 1);
    assert_eq!(stats.failed_retries, 0);

    let plan = client
        .plan_retry_resend(
            &receipt,
            wa_core::RetrySessionSnapshot::missing(),
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(!prepared_after_failure.is_complete());
    assert_eq!(
        prepared_after_failure.missing_message_ids,
        vec!["group-replay-first-before-send-fail"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "group-replay-send-fail-second"
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_group_retry_receipt_normalizes_legacy_c_us_primary_requester_devices() {
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
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "555@g.us",
            "group-cus-primary-retry",
            wa_proto::proto::Message {
                conversation: Some("group retry c.us primary".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["group-cus-primary-retry".to_owned()],
        from_jid: Some("123@c.us".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("555@g.us".to_owned()),
        chat_jid: Some("555@g.us".to_owned()),
        retry: wa_core::RetryReceiptRetry {
            count: 1,
            original_stanza_id: None,
            timestamp: None,
            version: None,
            error: None,
        },
        registration_id: None,
        has_key_bundle: true,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-cus-device-identity")),
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::pre_key();
    let retry_fut =
        client.handle_retry_receipt_with_bundle(&connection, &receipt, Some(bundle), &encryptor);
    tokio::pin!(retry_fut);

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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "11"),
                                ])],
                            )]),
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "11"),
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
        &mut retry_fut,
    )
    .await;

    let outcome = retry_fut.await.unwrap();
    assert_eq!(outcome.sender_key_distribution_relays.len(), 1);
    assert_eq!(outcome.sender_key_distribution_relays[0].recipient_count, 2);
    assert_eq!(outcome.relays.len(), 1);
    assert_eq!(outcome.relays[0].recipient_count, 2);

    let distribution_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(distribution_node.attrs["to"], "555@g.us");
    let Some(wa_binary::BinaryNodeContent::Nodes(distribution_children)) =
        &distribution_node.content
    else {
        panic!("sender-key distribution relay should contain participants");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(distribution_participants)) =
        &distribution_children[0].content
    else {
        panic!("sender-key distribution should contain participant nodes");
    };
    assert_eq!(
        distribution_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["123@s.whatsapp.net", "123:1@s.whatsapp.net"]
    );

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "group-cus-primary-retry");
    assert_eq!(resent.attrs["to"], "555@g.us");
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec![
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
            "123@s.whatsapp.net",
            "123:1@s.whatsapp.net",
        ]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_retry_resend_replays_raw_retry_receipt() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    repository
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-spawn",
            wa_proto::proto::Message {
                conversation: Some("spawn retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_retry_resend(
            connection.clone(),
            IncomingDecryptor,
            RelayEncryptor::default(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-spawn")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry")
                .with_attr("count", "2")
                .with_attr("error", "7"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-spawn");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

    let refresh_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(refresh_query.attrs["xmlns"], "encrypt");
    assert_eq!(encrypt_key_query_user_attrs(&refresh_query).len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&session_response_for_query(&refresh_query)).unwrap(),
        ))
        .await
        .unwrap();

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-spawn");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
    );
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_retry_resend_signal_provider_normalizes_legacy_retry_receipt() {
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
    let remote_one_time_pre_key_id = 95;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-spawn-signal-legacy",
            wa_proto::proto::Message {
                conversation: Some("spawn signal legacy retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-spawn-signal-legacy")
        .with_attr("from", "123:1@c.us")
        .with_attr("recipient", "123@c.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0306, 4).unwrap()),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-spawn-signal-legacy");
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
    assert_eq!(resent.attrs["id"], "retry-spawn-signal-legacy");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "spawn signal legacy retry",
    );
    assert!(
        client
            .signal_repository()
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    let provider_store = client.signal_provider_state_store();
    assert!(
        provider_store
            .load_session_record("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
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
        vec!["retry-spawn-signal-legacy"]
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
async fn incoming_processor_with_retry_resend_signal_provider_deduplicates_own_pn_lid_all_devices()
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
    let remote_one_time_pre_key_id = 127;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-spawn-signal-own-alias-all-devices",
            wa_proto::proto::Message {
                conversation: Some("spawn signal own alias retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-spawn-signal-own-alias-all-devices")
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
    assert_eq!(ack.attrs["id"], "retry-spawn-signal-own-alias-all-devices");
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
        "retry-spawn-signal-own-alias-all-devices"
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
                Some("spawn signal own alias retry")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.conversation.as_deref(),
                Some("spawn signal own alias retry")
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
        vec!["retry-spawn-signal-own-alias-all-devices"]
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
async fn incoming_processor_with_retry_resend_signal_provider_accepts_same_base_pre_key_wrapper() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "retry-same-base")
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
        conversation: Some("spawn retry same-base first".to_owned()),
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
        .with_attr("id", "signal-spawn-retry-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_retry_resend_with_signal_provider(
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
    assert_eq!(first_ack.attrs["id"], "signal-spawn-retry-same-base-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn retry same-base first")
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
        conversation: Some("spawn retry same-base wrapped second".to_owned()),
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
        .with_attr("id", "signal-spawn-retry-same-base-2-identity-change")
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
        "signal-spawn-retry-same-base-2-identity-change"
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
            "retry-resend same-base identity-change wrapper must not emit a typed batch"
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
    assert!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries
            == 0
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
            "signal-spawn-retry-same-base-2-signed-pre-key-mismatch",
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
        "signal-spawn-retry-same-base-2-signed-pre-key-mismatch"
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
            "retry-resend same-base signed-pre-key-id mismatch wrapper must not emit a typed batch"
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
    assert!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries
            == 0
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
        .with_attr("id", "signal-spawn-retry-same-base-2")
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
    assert_eq!(second_ack.attrs["id"], "signal-spawn-retry-same-base-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn retry same-base wrapped second")
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
        .with_attr("id", "signal-spawn-retry-same-base-2-replay")
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
        "signal-spawn-retry-same-base-2-replay"
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
            "retry-resend same-base replay must not emit a typed batch"
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
        conversation: Some("spawn retry same-base third".to_owned()),
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
        .with_attr("id", "signal-spawn-retry-same-base-3")
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
    assert_eq!(third_ack.attrs["id"], "signal-spawn-retry-same-base-3");
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn retry same-base third")
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
    assert!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries
            == 0
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_retry_resend_signal_provider_accepts_new_remote_ratchet() {
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
        "retry-spawn-new-ratchet",
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
        &text_plaintext("spawn retry ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn retry ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn retry ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_retry_resend_with_signal_provider(
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
                "signal-spawn-retry-ratchet-1",
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
    assert_eq!(first_ack.attrs["id"], "signal-spawn-retry-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn retry ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver spawn retry ratchet reply"),
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
        &text_plaintext("spawn retry ratchet fourth", 7),
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
        &text_plaintext("spawn retry ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-retry-ratchet-4",
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
    assert_eq!(fourth_ack.attrs["id"], "signal-spawn-retry-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn retry ratchet fourth")
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
                "signal-spawn-retry-ratchet-old-3",
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
        "signal-spawn-retry-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("spawn retry ratchet old third")
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
                "signal-spawn-retry-ratchet-old-3-replay",
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
        "signal-spawn-retry-ratchet-old-3-replay"
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
            "spawn retry consumed previous-chain replay must not emit a typed batch"
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
                "signal-spawn-retry-ratchet-2",
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
    assert_eq!(second_ack.attrs["id"], "signal-spawn-retry-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn retry ratchet second")
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
                "signal-spawn-retry-ratchet-5",
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
    assert_eq!(fifth_ack.attrs["id"], "signal-spawn-retry-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-spawn-retry-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("spawn retry ratchet fifth")
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

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_retry_resend_injects_inline_key_bundle() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-spawn-bundle",
            wa_proto::proto::Message {
                conversation: Some("spawn bundle retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_retry_resend(
            connection.clone(),
            IncomingDecryptor,
            RelayEncryptor::default(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-spawn-bundle")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
            BinaryNode::new("keys").with_content(vec![
                BinaryNode::new("type")
                    .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                BinaryNode::new("skey").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                    BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                ]),
                BinaryNode::new("key").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                ]),
            ]),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "retry-spawn-bundle");
    assert_eq!(ack.attrs["class"], "receipt");

    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.tag, "message");
    assert_eq!(resent.attrs["id"], "retry-spawn-bundle");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
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
async fn incoming_processor_with_retry_resend_signal_provider_emits_offline_group_notification_append_stub()
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
        .spawn_incoming_processor_with_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-retry-offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000220")
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
    assert_eq!(ack.attrs["id"], "spawn-retry-offline-group-ephemeral-stub");
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
        "spawn-retry-offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000220");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "spawn-retry-offline-group-ephemeral-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_220));
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
async fn incoming_processor_with_retry_resend_signal_provider_emits_offline_group_participant_add_append_stub()
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
        .spawn_incoming_processor_with_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-retry-offline-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000320")
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
        "spawn-retry-offline-group-participant-add-stub"
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
        "spawn-retry-offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000320");
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
        "spawn-retry-offline-group-participant-add-stub"
    );
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_320));
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
async fn incoming_processor_with_placeholder_retry_signal_provider_emits_offline_group_notification_append_stub()
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
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "spawn-placeholder-retry-offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000230")
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
        "spawn-placeholder-retry-offline-group-ephemeral-stub"
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
        "spawn-placeholder-retry-offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000230");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(
        stub.key.id,
        "spawn-placeholder-retry-offline-group-ephemeral-stub"
    );
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_230));
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
async fn incoming_processor_with_placeholder_retry_signal_provider_emits_offline_group_participant_add_append_stub()
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
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr(
            "id",
            "spawn-placeholder-retry-offline-group-participant-add-stub",
        )
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000330")
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
        "spawn-placeholder-retry-offline-group-participant-add-stub"
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
        "spawn-placeholder-retry-offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000330");
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
        "spawn-placeholder-retry-offline-group-participant-add-stub"
    );
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_330));
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
async fn incoming_processor_with_placeholder_retry_signal_provider_deduplicates_own_pn_lid_all_devices()
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
    let remote_one_time_pre_key_id = 131;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-spawn-placeholder-own-alias-all-devices",
            wa_proto::proto::Message {
                conversation: Some("spawn placeholder own alias retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-spawn-placeholder-own-alias-all-devices")
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
        "retry-spawn-placeholder-own-alias-all-devices"
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
        "retry-spawn-placeholder-own-alias-all-devices"
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
                Some("spawn placeholder own alias retry")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.conversation.as_deref(),
                Some("spawn placeholder own alias retry")
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
        vec!["retry-spawn-placeholder-own-alias-all-devices"]
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
async fn incoming_processor_with_placeholder_retry_signal_provider_accepts_same_base_pre_key_wrapper()
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
        "placeholder-retry-same-base",
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
    let first_text = wa_proto::proto::Message {
        conversation: Some("spawn placeholder retry same-base first".to_owned()),
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
        .with_attr("id", "signal-spawn-placeholder-retry-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
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
        "signal-spawn-placeholder-retry-same-base-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn placeholder retry same-base first")
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
        conversation: Some("spawn placeholder retry same-base wrapped second".to_owned()),
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
        .with_attr(
            "id",
            "signal-spawn-placeholder-retry-same-base-2-identity-change",
        )
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
        "signal-spawn-placeholder-retry-same-base-2-identity-change"
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
            "placeholder-retry same-base identity-change wrapper must not emit a typed batch"
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
    assert!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries
            == 0
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
            "signal-spawn-placeholder-retry-same-base-2-signed-pre-key-mismatch",
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
        "signal-spawn-placeholder-retry-same-base-2-signed-pre-key-mismatch"
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
            "placeholder-retry same-base signed-pre-key-id mismatch wrapper must not emit a typed batch"
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
    assert!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries
            == 0
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
        .with_attr("id", "signal-spawn-placeholder-retry-same-base-2")
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
        "signal-spawn-placeholder-retry-same-base-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn placeholder retry same-base wrapped second")
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
        .with_attr("id", "signal-spawn-placeholder-retry-same-base-2-replay")
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
        "signal-spawn-placeholder-retry-same-base-2-replay"
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
            "placeholder-retry same-base replay must not emit a typed batch"
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
        conversation: Some("spawn placeholder retry same-base third".to_owned()),
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
        .with_attr("id", "signal-spawn-placeholder-retry-same-base-3")
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
        "signal-spawn-placeholder-retry-same-base-3"
    );
    assert_eq!(third_ack.attrs["class"], "message");
    assert_eq!(third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(third_ack.attrs["from"], "999:7@s.whatsapp.net");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("spawn placeholder retry same-base third")
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
    assert!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries
            == 0
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_with_placeholder_retry_signal_provider_accepts_new_remote_ratchet() {
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
        "placeholder-retry-spawn-new-ratchet",
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
        &text_plaintext("spawn placeholder retry ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("spawn placeholder retry ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("spawn placeholder retry ratchet old third", 6),
        &sender_identity,
    )
    .unwrap();
    assert_eq!(second.message.counter, 1);
    assert_eq!(old_third.message.counter, 2);

    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
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
                "signal-spawn-placeholder-retry-ratchet-1",
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
        "signal-spawn-placeholder-retry-ratchet-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("spawn placeholder retry ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver spawn placeholder retry ratchet reply"),
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
        &text_plaintext("spawn placeholder retry ratchet fourth", 7),
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
        &text_plaintext("spawn placeholder retry ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&incoming_node(
                "signal-spawn-placeholder-retry-ratchet-4",
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
        "signal-spawn-placeholder-retry-ratchet-4"
    );
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("spawn placeholder retry ratchet fourth")
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
                "signal-spawn-placeholder-retry-ratchet-old-3",
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
        "signal-spawn-placeholder-retry-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("spawn placeholder retry ratchet old third")
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
                "signal-spawn-placeholder-retry-ratchet-old-3-replay",
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
        "signal-spawn-placeholder-retry-ratchet-old-3-replay"
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
            "spawn placeholder+retry consumed previous-chain replay must not emit a typed batch"
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
                "signal-spawn-placeholder-retry-ratchet-2",
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
        "signal-spawn-placeholder-retry-ratchet-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("spawn placeholder retry ratchet second")
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
                "signal-spawn-placeholder-retry-ratchet-5",
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
        "signal-spawn-placeholder-retry-ratchet-5"
    );
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-spawn-placeholder-retry-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("spawn placeholder retry ratchet fifth")
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

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_combines_signal_placeholder_and_retry_resend() {
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
    let remote_one_time_pre_key_id = 97;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-combined-signal",
            wa_proto::proto::Message {
                conversation: Some("combined signal retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-combined-signal")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("recipient", "123@s.whatsapp.net")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
        .await
        .unwrap();

    let retry_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(retry_ack.tag, "ack");
    assert_eq!(retry_ack.attrs["id"], "retry-combined-signal");
    assert_eq!(retry_ack.attrs["class"], "receipt");
    assert_eq!(retry_ack.attrs["to"], "123:1@s.whatsapp.net");

    let retry_encrypt_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(retry_encrypt_query.attrs["xmlns"], "encrypt");
    assert_eq!(
        encrypt_key_query_user_attrs(&retry_encrypt_query),
        vec![(
            "123:1@s.whatsapp.net".to_owned(),
            Some("identity".to_owned())
        )]
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&valid_session_response_for_query(
                &retry_encrypt_query,
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
    assert_eq!(resent.attrs["id"], "retry-combined-signal");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "combined signal retry",
    );
    assert_eq!(
        client
            .message_retry_statistics()
            .unwrap()
            .successful_retries,
        1
    );

    let mut events = client.subscribe();
    let placeholder = BinaryNode::new("message")
        .with_attr("id", "missing-combined-signal")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "missing-combined-signal", None)
            .unwrap();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&placeholder).unwrap()))
        .await
        .unwrap();

    let placeholder_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(placeholder_ack.tag, "ack");
    assert_eq!(placeholder_ack.attrs["id"], "missing-combined-signal");
    assert_eq!(placeholder_ack.attrs["class"], "message");
    assert_eq!(placeholder_ack.attrs["to"], "123@s.whatsapp.net");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "missing-combined-signal");
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

    let placeholder_encrypt_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(placeholder_encrypt_query.attrs["xmlns"], "encrypt");
    assert_eq!(
        encrypt_key_query_user_attrs(&placeholder_encrypt_query)
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
                &placeholder_encrypt_query,
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
            .contains("missing-combined-signal", current_unix_timestamp_ms())
            .unwrap()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_combined_placeholder_retry_with_signal_provider_normalizes_legacy_retry_receipt()
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
    let remote_one_time_pre_key_id = 92;
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-combined-signal-legacy",
            wa_proto::proto::Message {
                conversation: Some("combined signal legacy retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let receipt = BinaryNode::new("receipt")
        .with_attr("id", "retry-combined-signal-legacy")
        .with_attr("from", "123:1@c.us")
        .with_attr("recipient", "123@c.us")
        .with_attr("type", "retry")
        .with_content(vec![
            BinaryNode::new("retry").with_attr("count", "1"),
            BinaryNode::new("registration")
                .with_content(wa_core::encode_big_endian(0x0102_0309, 4).unwrap()),
        ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "retry-combined-signal-legacy");
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
    assert_eq!(resent.attrs["id"], "retry-combined-signal-legacy");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert_signal_conversation_relay(
        &resent,
        "123:1@s.whatsapp.net",
        &remote_credentials,
        &remote_one_time_pre_key,
        remote_one_time_pre_key_id,
        "combined signal legacy retry",
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
        vec!["retry-combined-signal-legacy"]
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
async fn incoming_processor_combined_placeholder_retry_with_signal_provider_preserves_legacy_missing_key()
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
    let remote_one_time_pre_key_id = 97;
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
            connection.clone(),
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let placeholder = BinaryNode::new("message")
        .with_attr("id", "missing-combined-signal-legacy")
        .with_attr("from", "123@c.us")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key =
        wa_core::build_message_key("123@c.us", false, "missing-combined-signal-legacy", None)
            .unwrap();

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&placeholder).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-combined-signal-legacy");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@c.us");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.remote_jid, "123@c.us");
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "missing-combined-signal-legacy"
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
        .expect("combined placeholder event should be persisted");
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
                "missing-combined-signal-legacy",
                current_unix_timestamp_ms()
            )
            .unwrap()
    );

    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_sends_peer_data_operation_message() {
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
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "missing-1", None).unwrap();
    let conflicting_key =
        wa_core::build_message_key("456@s.whatsapp.net", false, "missing-1", None).unwrap();
    let conflicting = client
        .request_placeholder_resend(
            &connection,
            [missing_key.clone(), conflicting_key],
            &encryptor,
            MessageRelayOptions::new().with_message_id("pdo-conflicting-duplicate"),
        )
        .await
        .unwrap_err();
    assert!(
        conflicting
            .to_string()
            .contains("placeholder resend duplicate message id missing-1 has conflicting keys")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let request_fut = client.request_placeholder_resend(
        &connection,
        [missing_key.clone(), missing_key.clone()],
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-1"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
        &mut request_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(node.attrs["type"], "get");
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
            session_response_for_query(&node)
        },
        &mut request_fut,
    )
    .await;

    let relay = request_fut.await.unwrap();
    assert_eq!(relay.message_id, "pdo-1");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "pdo-1");
    assert_eq!(sent.attrs["to"], "999@s.whatsapp.net");
    assert_eq!(sent.attrs["category"], "peer");
    assert_eq!(sent.attrs["push_priority"], "high_force");
    let Some(wa_binary::BinaryNodeContent::Nodes(children)) = &sent.content else {
        panic!("placeholder resend stanza should have children");
    };
    assert!(children.iter().any(|node| {
        node.tag == "meta" && node.attrs.get("appdata").map(String::as_str) == Some("default")
    }));

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["999@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    for call in calls {
        let plaintext = wa_proto::proto::Message::decode(call.1).unwrap();
        let device_sent = plaintext.device_sent_message.unwrap();
        assert_eq!(
            device_sent.destination_jid.as_deref(),
            Some("999@s.whatsapp.net")
        );
        let protocol = device_sent.message.unwrap().protocol_message.unwrap();
        assert_eq!(
            protocol.r#type,
            Some(
                wa_proto::proto::message::protocol_message::Type::PeerDataOperationRequestMessage
                    as i32
            )
        );
        let request = protocol.peer_data_operation_request_message.unwrap();
        assert_eq!(
            request.peer_data_operation_request_type,
            Some(
                wa_proto::proto::message::PeerDataOperationRequestType::PlaceholderMessageResend
                    as i32,
            )
        );
        assert_eq!(request.placeholder_message_resend_request.len(), 1);
        assert_eq!(
            request.placeholder_message_resend_request[0].message_key,
            Some(missing_key.clone())
        );
    }
    assert!(
        client
            .placeholder_resend_tracker()
            .contains("missing-1", current_unix_timestamp_ms())
            .unwrap()
    );

    let duplicate = client
        .request_placeholder_resend(
            &connection,
            [missing_key],
            &encryptor,
            MessageRelayOptions::new().with_message_id("pdo-duplicate"),
        )
        .await
        .unwrap_err();
    assert!(
        duplicate
            .to_string()
            .contains("placeholder resend already pending for message id missing-1")
    );
    assert!(
        client
            .placeholder_resend_tracker()
            .contains("missing-1", current_unix_timestamp_ms())
            .unwrap()
    );

    let events = vec![
        MessageEvent::new(wa_core::MessageEventKey::new(
            "123@s.whatsapp.net",
            "missing-1",
            None,
        ))
        .with_field("kind", "placeholder_resend"),
        MessageEvent::new(wa_core::MessageEventKey::new(
            "123@s.whatsapp.net",
            "other",
            None,
        ))
        .with_field("kind", "message"),
    ];
    assert_eq!(
        client.resolve_placeholder_resend_events(&events).unwrap(),
        1
    );
    assert!(
        !client
            .placeholder_resend_tracker()
            .contains("missing-1", current_unix_timestamp_ms())
            .unwrap()
    );
    assert_eq!(
        client.resolve_placeholder_resend_events(&events).unwrap(),
        0
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_rolls_back_batch_when_later_key_is_pending() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let tracker = client.placeholder_resend_tracker();
    let now_ms = current_unix_timestamp_ms();
    assert!(tracker.begin_request("already-pending", now_ms).unwrap());

    let fresh_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "fresh-pending", None).unwrap();
    let pending_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "already-pending", None).unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let err = client
        .request_placeholder_resend(
            &connection,
            [fresh_key, pending_key],
            &RelayEncryptor::default(),
            MessageRelayOptions::new().with_message_id("pdo-pending-batch"),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("placeholder resend already pending for message id already-pending")
    );
    assert!(
        !tracker
            .contains("fresh-pending", current_unix_timestamp_ms())
            .unwrap()
    );
    assert!(
        tracker
            .contains("already-pending", current_unix_timestamp_ms())
            .unwrap()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_rolls_back_tracker_when_relay_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "relay-fails", None).unwrap();
    let encryptor = FailingEncryptor::new("placeholder resend encrypt failed");
    let request_fut = client.request_placeholder_resend(
        &connection,
        [missing_key],
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-relay-fails"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut request_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(
                encrypt_key_query_user_attrs(&node)
                    .into_iter()
                    .map(|(jid, _)| jid)
                    .collect::<Vec<_>>(),
                vec!["999@s.whatsapp.net".to_owned()]
            );
            session_response_for_query(&node)
        },
        &mut request_fut,
    )
    .await;

    let err = request_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("placeholder resend encrypt failed")
    );
    assert!(
        !client
            .placeholder_resend_tracker()
            .contains("relay-fails", current_unix_timestamp_ms())
            .unwrap()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_rolls_back_tracker_when_later_participant_encrypt_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["999@s.whatsapp.net", "999:8@s.whatsapp.net"] {
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
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "relay-fails-late", None).unwrap();
    let encryptor = FailingAfterEncryptor::new(2, "placeholder resend late encrypt failed");
    let request_fut = client.request_placeholder_resend(
        &connection,
        [missing_key],
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-relay-fails-late"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut request_fut,
    )
    .await;

    let err = request_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("placeholder resend late encrypt failed")
    );
    assert!(
        !client
            .placeholder_resend_tracker()
            .contains("relay-fails-late", current_unix_timestamp_ms())
            .unwrap()
    );
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["999@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_rolls_back_tracker_when_relay_send_fails_after_encryption() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["999@s.whatsapp.net", "999:8@s.whatsapp.net"] {
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
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "relay-send-fails", None).unwrap();
    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 2);
    let request_fut = client.request_placeholder_resend(
        &connection,
        [missing_key.clone()],
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-send-fails"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut request_fut,
    )
    .await;

    let err = request_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    assert!(
        !client
            .placeholder_resend_tracker()
            .contains("relay-send-fails", current_unix_timestamp_ms())
            .unwrap()
    );
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["999@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    for call in calls {
        let plaintext = wa_proto::proto::Message::decode(call.1).unwrap();
        let device_sent = plaintext.device_sent_message.unwrap();
        assert_eq!(
            device_sent.destination_jid.as_deref(),
            Some("999@s.whatsapp.net")
        );
        let protocol = device_sent.message.unwrap().protocol_message.unwrap();
        assert_eq!(
            protocol.r#type,
            Some(
                wa_proto::proto::message::protocol_message::Type::PeerDataOperationRequestMessage
                    as i32
            )
        );
        let request = protocol.peer_data_operation_request_message.unwrap();
        assert_eq!(
            request.peer_data_operation_request_type,
            Some(
                wa_proto::proto::message::PeerDataOperationRequestType::PlaceholderMessageResend
                    as i32,
            )
        );
        assert_eq!(request.placeholder_message_resend_request.len(), 1);
        assert_eq!(
            request.placeholder_message_resend_request[0].message_key,
            Some(missing_key.clone())
        );
    }
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_rolls_back_tracker_when_device_lookup_has_no_recipients() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "no-recipient-devices", None)
            .unwrap();
    let encryptor = RelayEncryptor::default();
    let request_fut = client.request_placeholder_resend(
        &connection,
        [missing_key],
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-empty-devices"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user").with_attr("jid", "999@s.whatsapp.net"),
                        BinaryNode::new("user").with_attr("jid", "999:7@s.whatsapp.net"),
                    ]),
                ])])
        },
        &mut request_fut,
    )
    .await;

    let err = request_fut.await.unwrap_err();
    assert!(matches!(
        err,
        wa_core::CoreError::Protocol(message)
            if message == "message send requires at least one recipient device"
    ));
    assert!(
        !client
            .placeholder_resend_tracker()
            .contains("no-recipient-devices", current_unix_timestamp_ms())
            .unwrap()
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
async fn request_placeholder_resend_rolls_back_tracker_when_session_assertion_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "session-fails", None).unwrap();
    let encryptor = RelayEncryptor::default();
    let request_fut = client.request_placeholder_resend(
        &connection,
        [missing_key],
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-session-fails"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut request_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("999@s.whatsapp.net".to_owned(), None)]
            );
            error_result_for(&node, "401", "session denied")
        },
        &mut request_fut,
    )
    .await;

    let err = request_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("E2E session query failed (401): session denied")
    );
    assert!(
        !client
            .placeholder_resend_tracker()
            .contains("session-fails", current_unix_timestamp_ms())
            .unwrap()
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
async fn request_placeholder_resend_for_web_message_requests_eligible_unavailable_stub() {
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
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "missing-auto", None).unwrap();
    let web_message = wa_core::WebMessageInfo {
        key: Some(missing_key),
        message_timestamp: Some(current_unix_timestamp()),
        message_stub_type: Some(wa_proto::proto::web_message_info::StubType::Ciphertext as i32),
        message_stub_parameters: vec![wa_core::PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()],
        ..wa_core::WebMessageInfo::default()
    };
    let request_fut = client.request_placeholder_resend_for_web_message(
        &connection,
        &web_message,
        None,
        Some("temporary_unavailable"),
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-auto"),
    );
    tokio::pin!(request_fut);

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
        &mut request_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            session_response_for_query(&node)
        },
        &mut request_fut,
    )
    .await;

    let relay = request_fut.await.unwrap().unwrap();
    assert_eq!(relay.message_id, "pdo-auto");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "pdo-auto");
    assert_eq!(sent.attrs["category"], "peer");
    assert!(
        client
            .placeholder_resend_tracker()
            .contains("missing-auto", current_unix_timestamp_ms())
            .unwrap()
    );

    let duplicate = client
        .request_placeholder_resend_for_web_message(
            &connection,
            &web_message,
            None,
            Some("temporary_unavailable"),
            &encryptor,
            MessageRelayOptions::new().with_message_id("pdo-auto-duplicate"),
        )
        .await
        .unwrap();
    assert!(duplicate.is_none());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_for_web_message_rolls_back_tracker_when_relay_send_fails() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in ["999@s.whatsapp.net", "999:8@s.whatsapp.net"] {
        client
            .signal_repository()
            .inject_e2e_session(wa_core::SessionInjection {
                jid: jid.to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
    }
    let missing_id = "missing-auto-send-fails";
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, missing_id, None).unwrap();
    let web_message = wa_core::WebMessageInfo {
        key: Some(missing_key.clone()),
        message_timestamp: Some(current_unix_timestamp()),
        message_stub_type: Some(wa_proto::proto::web_message_info::StubType::Ciphertext as i32),
        message_stub_parameters: vec![wa_core::PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()],
        ..wa_core::WebMessageInfo::default()
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 2);
    let request_fut = client.request_placeholder_resend_for_web_message(
        &connection,
        &web_message,
        None,
        Some("temporary_unavailable"),
        &encryptor,
        MessageRelayOptions::new().with_message_id("pdo-auto-send-fails"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut request_fut,
    )
    .await;

    let err = request_fut.await.unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    assert!(
        !client
            .placeholder_resend_tracker()
            .contains(missing_id, current_unix_timestamp_ms())
            .unwrap()
    );
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["999@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));

    let (retry_connection, mut retry_sink_rx, retry_stream_tx) = mock_connection();
    let retry_encryptor = RelayEncryptor::default();
    let retry_fut = client.request_placeholder_resend_for_web_message(
        &retry_connection,
        &web_message,
        None,
        Some("temporary_unavailable"),
        &retry_encryptor,
        MessageRelayOptions::new().with_message_id("pdo-auto-retry-after-fail"),
    );
    tokio::pin!(retry_fut);

    respond_to_next_query(
        &mut retry_sink_rx,
        &retry_stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "8"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut retry_fut,
    )
    .await;

    let relay = retry_fut.await.unwrap().unwrap();
    assert_eq!(relay.message_id, "pdo-auto-retry-after-fail");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&retry_sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "pdo-auto-retry-after-fail");
    assert_eq!(sent.attrs["category"], "peer");
    assert!(
        client
            .placeholder_resend_tracker()
            .contains(missing_id, current_unix_timestamp_ms())
            .unwrap()
    );
    assert_eq!(
        retry_encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["999@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    retry_connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn request_placeholder_resend_for_web_message_with_signal_provider_writes_pkmsg() {
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
    let missing_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "missing-signal-auto", None)
            .unwrap();
    let expected_key = missing_key.clone();
    let web_message = wa_core::WebMessageInfo {
        key: Some(missing_key),
        message_timestamp: Some(current_unix_timestamp()),
        message_stub_type: Some(wa_proto::proto::web_message_info::StubType::Ciphertext as i32),
        message_stub_parameters: vec![wa_core::PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()],
        ..wa_core::WebMessageInfo::default()
    };
    let request_fut = client.request_placeholder_resend_for_web_message_with_signal_provider(
        &connection,
        &web_message,
        None,
        Some("temporary_unavailable"),
        MessageRelayOptions::new().with_message_id("pdo-signal-auto"),
    );
    tokio::pin!(request_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "devices");
            assert_eq!(
                usync_query_user_jids(&node),
                vec![
                    "999@s.whatsapp.net".to_owned(),
                    "999:7@s.whatsapp.net".to_owned(),
                ]
            );
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
        &mut request_fut,
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
        &mut request_fut,
    )
    .await;

    let relay = request_fut.await.unwrap().unwrap();
    assert_eq!(relay.message_id, "pdo-signal-auto");
    assert_eq!(relay.recipient_count, 2);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "pdo-signal-auto");
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
            .contains("missing-signal-auto", current_unix_timestamp_ms())
            .unwrap()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn placeholder_resend_cleanup_purges_expired_requests() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let tracker = client.placeholder_resend_tracker();
    let now = current_unix_timestamp_ms();

    tracker.begin_request("fresh-manual", now).unwrap();
    tracker.begin_request("expired-manual", 0).unwrap();
    assert_eq!(client.purge_expired_placeholder_resends().unwrap(), 1);
    assert!(tracker.resolve("expired-manual").unwrap().is_none());
    assert!(tracker.resolve("fresh-manual").unwrap().is_some());

    tracker.begin_request("expired-background", 0).unwrap();
    let mut cleanup = client
        .spawn_placeholder_resend_cleanup(Duration::from_millis(5))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(tracker.resolve("expired-background").unwrap().is_none());
    cleanup.abort();

    let invalid = match client.spawn_placeholder_resend_cleanup(Duration::ZERO) {
        Ok(_) => panic!("zero cleanup interval should be rejected"),
        Err(err) => err,
    };
    assert!(
        invalid
            .to_string()
            .contains("placeholder resend cleanup interval must be non-zero")
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn assert_sessions_fetches_missing_sessions_and_persists_them() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    repository
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "existing:2@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let assert_fut = client.assert_sessions(
        &connection,
        [
            "123:1@s.whatsapp.net",
            "existing:2@s.whatsapp.net",
            "lidtarget:3@lid",
            "123:1@s.whatsapp.net",
        ],
        false,
    );
    tokio::pin!(assert_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("lid123:1@lid".to_owned(), None),
                    ("lidtarget:3@lid".to_owned(), None),
                ]
            );
            session_response_for_query(&node)
        },
        &mut assert_fut,
    )
    .await;

    assert!(assert_fut.await.unwrap());
    assert!(
        repository
            .validate_session("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(
        repository
            .validate_session("lidtarget:3@lid")
            .await
            .unwrap()
            .exists
    );

    let force_fut = client.assert_sessions(&connection, ["existing:2@s.whatsapp.net"], true);
    tokio::pin!(force_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![(
                    "existing:2@s.whatsapp.net".to_owned(),
                    Some("identity".to_owned()),
                )]
            );
            session_response_for_query(&node)
        },
        &mut force_fut,
    )
    .await;

    assert!(force_fut.await.unwrap());

    let failed_fut = client.assert_sessions(&connection, ["failed:3@s.whatsapp.net"], false);
    tokio::pin!(failed_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("failed:3@s.whatsapp.net".to_owned(), None)]
            );
            error_result_for(&node, "401", "session denied")
        },
        &mut failed_fut,
    )
    .await;

    let err = failed_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("E2E session query failed (401): session denied")
    );
    assert!(
        !repository
            .validate_session("failed:3@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn assert_sessions_normalizes_legacy_c_us_device_aliases_before_query() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let assert_fut = client.assert_sessions(
        &connection,
        ["123:1@c.us", "123:1@s.whatsapp.net", "123@c.us"],
        false,
    );
    tokio::pin!(assert_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![
                    ("123:1@s.whatsapp.net".to_owned(), None),
                    ("123@s.whatsapp.net".to_owned(), None),
                ]
            );
            session_response_for_query(&node)
        },
        &mut assert_fut,
    )
    .await;

    assert!(assert_fut.await.unwrap());
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(
        repository
            .validate_session("123@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn assert_sessions_reuses_existing_mapped_lid_descriptor_session_for_pn_recipient() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    repository
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "lid123:1@lid".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();

    assert!(
        !tokio::time::timeout(
            Duration::from_secs(1),
            client.assert_sessions(&connection, ["123:1@s.whatsapp.net"], false),
        )
        .await
        .unwrap()
        .unwrap()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(
        repository
            .validate_session("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn assert_sessions_fetches_when_mapped_lid_descriptor_identity_mismatches() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let repository = client.signal_repository();
    repository
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
    assert!(
        !repository
            .validate_session("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let assert_fut = client.assert_sessions(&connection, ["123:1@s.whatsapp.net"], false);
    tokio::pin!(assert_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("lid123:1@lid".to_owned(), None)]
            );
            session_response_for_query(&node)
        },
        &mut assert_fut,
    )
    .await;

    assert!(assert_fut.await.unwrap());
    assert!(
        repository
            .validate_session("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    assert!(
        repository
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn assert_sessions_reuses_existing_mapped_lid_provider_session_for_pn_recipient() {
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
    let repository = client.signal_repository();
    repository
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
    assert!(
        !repository
            .validate_session("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    assert!(
        client
            .signal_provider_state_store()
            .validate_session_record("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    let (connection, mut sink_rx, _stream_tx) = mock_connection();

    assert!(
        !tokio::time::timeout(
            Duration::from_secs(1),
            client.assert_sessions(&connection, ["123:1@s.whatsapp.net"], false),
        )
        .await
        .unwrap()
        .unwrap()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let provider_state = client.signal_provider_state_store();
    assert!(
        provider_state
            .validate_session_record("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(
        provider_state
            .load_identity_record("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn identity_change_refresh_schedules_tc_token_reissue() {
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
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"old-peer-token"))
            .unwrap()
            .with_timestamp_seconds(sender_timestamp)
            .with_sender_timestamp_seconds(sender_timestamp),
    )
    .await
    .unwrap();

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let repository = client.signal_repository();
    repository
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "identity-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "encrypt")
        .with_content(vec![
            BinaryNode::new("identity").with_content(Bytes::from_static(b"changed")),
        ]);

    let handler_client = client.clone();
    let handler_connection = connection.clone();
    let handle_task = tokio::spawn(async move {
        handler_client
            .handle_identity_change_notification(&handler_connection, &notification)
            .await
    });

    let mut saw_privacy = false;
    let mut saw_encrypt = false;
    for _ in 0..2 {
        let frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let node = decode_inbound_binary_node(&frame).unwrap().node;
        match node.attrs.get("xmlns").map(String::as_str) {
            Some("privacy") => {
                saw_privacy = true;
                let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &node.content else {
                    panic!("privacy query should have child nodes");
                };
                let tokens = iq_children
                    .iter()
                    .find(|child| child.tag == "tokens")
                    .unwrap();
                let Some(wa_binary::BinaryNodeContent::Nodes(token_children)) = &tokens.content
                else {
                    panic!("tokens node should have token children");
                };
                assert_eq!(token_children.len(), 1);
                assert_eq!(token_children[0].attrs["jid"], "123@s.whatsapp.net");
                assert_eq!(token_children[0].attrs["type"], "trusted_contact");
                assert_eq!(
                    token_children[0].attrs["t"].parse::<u64>().unwrap(),
                    sender_timestamp
                );
                stream_tx
                    .send(InboundFrame::new(
                        encode_binary_node(
                            &BinaryNode::new("iq")
                                .with_attr("id", node.attrs["id"].clone())
                                .with_attr("type", "result")
                                .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                                        BinaryNode::new("token")
                                            .with_attr("jid", "ignored@s.whatsapp.net")
                                            .with_attr(
                                                "t",
                                                (sender_timestamp + 1).to_string(),
                                            )
                                            .with_attr("type", "trusted_contact")
                                            .with_content(Bytes::from_static(
                                                b"identity-peer-token",
                                            )),
                                    ])]),
                        )
                        .unwrap(),
                    ))
                    .await
                    .unwrap();
            }
            Some("encrypt") => {
                saw_encrypt = true;
                assert_eq!(
                    encrypt_key_query_user_attrs(&node),
                    vec![("123@s.whatsapp.net".to_owned(), Some("identity".to_owned()))]
                );
                stream_tx
                    .send(InboundFrame::new(
                        encode_binary_node(&session_response_for_query(&node)).unwrap(),
                    ))
                    .await
                    .unwrap();
            }
            other => panic!("unexpected query xmlns: {other:?}"),
        }
    }

    let outcome = handle_task.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        IdentityChangeOutcome::SessionRefreshed {
            token_reissue_scheduled: true
        }
    );
    assert!(saw_privacy);
    assert!(saw_encrypt);

    let mut loaded = None;
    for _ in 0..20 {
        loaded = wa_core::load_tc_token(&store, "123@s.whatsapp.net")
            .await
            .unwrap();
        if loaded
            .as_ref()
            .is_some_and(|record| record.token == Bytes::from_static(b"identity-peer-token"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loaded = loaded.unwrap();
    assert_eq!(loaded.token, Bytes::from_static(b"identity-peer-token"));
    assert_eq!(loaded.timestamp_seconds, Some(sender_timestamp + 1));
    assert_eq!(loaded.sender_timestamp_seconds, Some(sender_timestamp));
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn send_receipts_groups_message_keys_and_writes_nodes() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let keys = vec![
        MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("m1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        },
        MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("m2".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        },
        MessageKey {
            remote_jid: Some("999@s.whatsapp.net".to_owned()),
            from_me: Some(true),
            id: Some("own".to_owned()),
            participant: None,
        },
    ];

    let receipts = client
        .send_receipts(&connection, &keys, MessageReceiptType::Read, Some(10))
        .await
        .unwrap();

    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].message_ids, vec!["m1", "m2"]);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "receipt");
    assert_eq!(sent.attrs["id"], "m1");
    assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(sent.attrs["participant"], "456@s.whatsapp.net");
    assert_eq!(sent.attrs["type"], "read");
    assert_eq!(sent.attrs["t"], "10");
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("receipt should contain list");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(items)) = &content[0].content else {
        panic!("receipt list should contain item nodes");
    };
    assert_eq!(items[0].attrs["id"], "m2");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_ack_and_nack_write_ack_nodes() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let received = BinaryNode::new("message")
        .with_attr("id", "msg-1")
        .with_attr("from", "123:1@s.whatsapp.net")
        .with_attr("participant", "456@s.whatsapp.net")
        .with_attr("type", "text");

    let ack = client.send_ack(&connection, &received, None).await.unwrap();
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, ack);

    let nack = client
        .send_nack(&connection, &received, wa_core::NackReason::ParsingError)
        .await
        .unwrap();
    assert_eq!(nack.attrs["error"], "487");
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, nack);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn reject_call_queries_call_reject_stanza() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let reject_fut = client.reject_call(&connection, "call-1", "123@s.whatsapp.net");
    tokio::pin!(reject_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.tag, "call");
            assert_eq!(node.attrs["from"], "999:2@s.whatsapp.net");
            assert_eq!(node.attrs["to"], "123@s.whatsapp.net");
            assert!(node.attrs.contains_key("id"));
            let reject = test_child(&node, "reject");
            assert_eq!(reject.attrs["call-id"], "call-1");
            assert_eq!(reject.attrs["call-creator"], "123@s.whatsapp.net");
            assert_eq!(reject.attrs["count"], "0");
            empty_result_for(&node)
        },
        &mut reject_fut,
    )
    .await;
    let response = reject_fut.await.unwrap();
    assert_eq!(response.tag, "iq");
    assert_eq!(response.attrs["type"], "result");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_sends_ack_and_emits_message_event() {
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
    let text = wa_proto::proto::Message {
        conversation: Some("hello".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "msg-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(text.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "msg-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(batch.messages_upsert[0].key.id, "msg-1");
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(decoded.conversation.as_deref(), Some("hello"));
    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[0]);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_emits_group_notification_message_stub() {
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
        .with_attr("id", "group-ephemeral-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000140")
        .with_content(vec![
            BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
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
    assert_eq!(ack.attrs["id"], "group-ephemeral-stub-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(group.fields["notification_id"], "group-ephemeral-stub-live");
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000140");
    assert_eq!(group.fields["ephemeral_duration"], "86400");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-ephemeral-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_140));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_emits_group_ephemeral_disable_append_stub() {
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
        .with_attr("id", "offline-group-ephemeral-disable-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000145")
        .with_attr("offline", "1")
        .with_content(vec![BinaryNode::new("not_ephemeral")]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node(&connection, &offline, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.event_count(), 2);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Notification
    );
    assert!(result.results[0].error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "offline-group-ephemeral-disable-stub");
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
        "offline-group-ephemeral-disable-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000145");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["ephemeral_duration"], "0");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-ephemeral-disable-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_145));
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
    assert_eq!(stub.fields["message_stub_parameters"], r#"["0"]"#);
    assert_eq!(stub.fields["payload_kind"], "protocol_message");
    let decoded = wa_proto::proto::Message::decode(stub.payload.clone().unwrap()).unwrap();
    let protocol = decoded.protocol_message.unwrap();
    assert_eq!(
        protocol.r#type,
        Some(wa_proto::proto::message::protocol_message::Type::EphemeralSetting as i32)
    );
    assert_eq!(protocol.ephemeral_expiration, Some(0));

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
async fn process_incoming_node_emits_group_create_snapshot_message_stub() {
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
        .with_attr("id", "group-create-snapshot-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "owner-user")
        .with_attr("t", "1700000220")
        .with_content(vec![
            BinaryNode::new("create")
                .with_attr("id", "123")
                .with_attr("subject", "Launch")
                .with_attr("notify", "Launch Team")
                .with_attr("addressing_mode", "lid")
                .with_attr("s_o", "111@lid")
                .with_attr("s_o_pn", "111@s.whatsapp.net")
                .with_attr("s_o_username", "owner-user")
                .with_attr("s_t", "1700000100")
                .with_attr("creation", "1700000000")
                .with_attr("creator", "111@lid")
                .with_attr("creator_pn", "111@s.whatsapp.net")
                .with_attr("creator_username", "owner-user")
                .with_attr("creator_country_code", "1")
                .with_attr("size", "2")
                .with_content(vec![
                    BinaryNode::new("description")
                        .with_attr("id", "desc-create")
                        .with_attr("participant", "111@lid")
                        .with_content(vec![BinaryNode::new("body").with_content("Created group")]),
                    BinaryNode::new("announcement"),
                    BinaryNode::new("locked"),
                    BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
                    BinaryNode::new("linked_parent").with_attr("jid", "999@g.us"),
                    BinaryNode::new("participant")
                        .with_attr("jid", "111@lid")
                        .with_attr("type", "superadmin")
                        .with_attr("phone_number", "111@s.whatsapp.net")
                        .with_attr("participant_username", "one"),
                    BinaryNode::new("participant")
                        .with_attr("jid", "222@lid")
                        .with_attr("type", "admin")
                        .with_attr("phone_number", "222@s.whatsapp.net")
                        .with_attr("username", "two"),
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
    assert_eq!(ack.attrs["id"], "group-create-snapshot-stub-live");
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
        "group-create-snapshot-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "owner-user");
    assert_eq!(group.fields["timestamp"], "1700000220");
    assert_eq!(group.fields["group_created"], "true");
    assert_eq!(group.fields["group_id"], "123");
    assert_eq!(group.fields["notify"], "Launch Team");
    assert_eq!(group.fields["addressing_mode"], "lid");
    assert_eq!(group.fields["subject"], "Launch");
    assert_eq!(group.fields["subject_owner"], "111@lid");
    assert_eq!(group.fields["subject_owner_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["subject_owner_username"], "owner-user");
    assert_eq!(group.fields["subject_time"], "1700000100");
    assert_eq!(group.fields["creation"], "1700000000");
    assert_eq!(group.fields["owner"], "111@lid");
    assert_eq!(group.fields["owner_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["owner_username"], "owner-user");
    assert_eq!(group.fields["owner_country_code"], "1");
    assert_eq!(group.fields["size"], "2");
    assert_eq!(group.fields["description"], "Created group");
    assert_eq!(group.fields["description_id"], "desc-create");
    assert_eq!(group.fields["description_owner"], "111@lid");
    assert_eq!(group.fields["announce"], "true");
    assert_eq!(group.fields["restrict"], "true");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["linked_parent"], "999@g.us");
    assert_eq!(group.fields["participants"], "111@lid,222@lid");
    assert_eq!(group.fields["participants_count"], "2");
    assert_eq!(
        group.fields["participants_roles"],
        "111@lid=superadmin,222@lid=admin"
    );
    assert_eq!(
        group.fields["participants_phone_numbers"],
        "111@lid=111@s.whatsapp.net,222@lid=222@s.whatsapp.net"
    );
    assert_eq!(
        group.fields["participants_usernames"],
        "111@lid=one,222@lid=two"
    );
    assert_eq!(group.fields["participants_admins"], "222@lid");
    assert_eq!(group.fields["participants_admins_count"], "1");
    assert_eq!(group.fields["participants_superadmins"], "111@lid");
    assert_eq!(group.fields["participants_superadmins_count"], "1");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-create-snapshot-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_220));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupCreate as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_create");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["Launch"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_incoming_node_emits_group_picture_icon_stub_and_contact_update() {
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
        .with_attr("id", "group-picture-icon-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "picture")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000230")
        .with_content(vec![
            BinaryNode::new("set")
                .with_attr("id", "pic-1")
                .with_attr("hash", "hash-1")
                .with_attr("author", "111@lid")
                .with_attr("author_pn", "111@s.whatsapp.net")
                .with_attr("author_username", "actor-one")
                .with_attr("t", "1700000300"),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &notification, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    assert_eq!(result.event_count, 3);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "group-picture-icon-stub-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert_eq!(group_batch.contacts_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(
        group.fields["notification_id"],
        "group-picture-icon-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "picture");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000230");
    assert_eq!(group.fields["picture"], "changed");
    assert_eq!(group.fields["picture_changed"], "true");
    assert_eq!(group.fields["picture_id"], "pic-1");
    assert_eq!(group.fields["picture_hash"], "hash-1");
    assert_eq!(group.fields["picture_time"], "1700000300");
    assert_eq!(group.fields["picture_author"], "111@lid");
    assert_eq!(group.fields["picture_author_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["picture_author_username"], "actor-one");
    assert!(!group.fields.contains_key("picture_removed"));

    let contact = &group_batch.contacts_update[0];
    assert_eq!(contact.jid, "123@g.us");
    assert_eq!(contact.fields["img_url"], "changed");
    assert_eq!(contact.fields["source"], "picture_notification");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-picture-icon-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_230));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "picture");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeIcon as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_icon");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["pic-1"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, *group);
    let stored_contact = store
        .get(KeyNamespace::ContactEvent, &contact.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_contact = wa_core::decode_stored_contact_event(&stored_contact).unwrap();
    assert_eq!(stored_contact, *contact);
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
async fn process_offline_node_emits_group_picture_remove_icon_append_stub_and_contact_update() {
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
        .with_attr("id", "offline-group-picture-icon-remove-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "picture")
        .with_attr("participant", "222@lid")
        .with_attr("participant_pn", "222@s.whatsapp.net")
        .with_attr("participant_username", "actor-two")
        .with_attr("t", "1700000240")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("delete")
                .with_attr("hash", "old-hash")
                .with_attr("author", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "actor-two"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node(&connection, &offline, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.event_count(), 3);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Notification
    );
    assert!(result.results[0].error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "offline-group-picture-icon-remove-stub");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert_eq!(group_batch.contacts_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(
        group.fields["notification_id"],
        "offline-group-picture-icon-remove-stub"
    );
    assert_eq!(group.fields["notification_type"], "picture");
    assert_eq!(group.fields["actor"], "222@lid");
    assert_eq!(group.fields["actor_pn"], "222@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-two");
    assert_eq!(group.fields["timestamp"], "1700000240");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["picture"], "removed");
    assert_eq!(group.fields["picture_removed"], "true");
    assert_eq!(group.fields["picture_hash"], "old-hash");
    assert_eq!(group.fields["picture_author"], "222@lid");
    assert_eq!(group.fields["picture_author_pn"], "222@s.whatsapp.net");
    assert_eq!(group.fields["picture_author_username"], "actor-two");
    assert!(!group.fields.contains_key("picture_changed"));
    assert!(!group.fields.contains_key("picture_id"));

    let contact = &group_batch.contacts_update[0];
    assert_eq!(contact.jid, "123@g.us");
    assert_eq!(contact.fields["img_url"], "removed");
    assert_eq!(contact.fields["source"], "picture_notification");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-picture-icon-remove-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("222@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_240));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "picture");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeIcon as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_icon");
    assert!(!stub.fields.contains_key("message_stub_parameters"));
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, *group);
    let stored_contact = store
        .get(KeyNamespace::ContactEvent, &contact.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_contact = wa_core::decode_stored_contact_event(&stored_contact).unwrap();
    assert_eq!(stored_contact, *contact);
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
async fn process_incoming_node_emits_group_description_message_stub() {
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
        .with_attr("id", "group-description-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000250")
        .with_content(vec![
            BinaryNode::new("description")
                .with_attr("id", "desc-new")
                .with_attr("participant", "222@lid")
                .with_attr("participant_pn", "222@s.whatsapp.net")
                .with_attr("participant_username", "two")
                .with_attr("t", "1700000260")
                .with_content(vec![BinaryNode::new("body").with_content("Alias body")]),
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
    assert_eq!(ack.attrs["id"], "group-description-stub-live");
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
        "group-description-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000250");
    assert_eq!(group.fields["description"], "Alias body");
    assert_eq!(group.fields["description_id"], "desc-new");
    assert_eq!(group.fields["description_owner"], "222@lid");
    assert_eq!(group.fields["description_owner_pn"], "222@s.whatsapp.net");
    assert_eq!(group.fields["description_owner_username"], "two");
    assert_eq!(group.fields["description_time"], "1700000260");
    assert!(!group.fields.contains_key("description_deleted"));

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-description-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_250));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeDescription as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_description");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["Alias body"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_offline_node_emits_group_description_delete_append_stub() {
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
        .with_attr("id", "offline-group-description-delete-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000270")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("description")
                .with_attr("id", "desc-old")
                .with_attr("participant", "222@lid")
                .with_attr("participant_pn", "222@s.whatsapp.net")
                .with_attr("participant_username", "two")
                .with_attr("delete", "true")
                .with_attr("t", "1700000280"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node(&connection, &offline, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.event_count(), 2);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Notification
    );
    assert!(result.results[0].error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "offline-group-description-delete-stub");
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
        "offline-group-description-delete-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000270");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["description_deleted"], "true");
    assert_eq!(group.fields["description_id"], "desc-old");
    assert_eq!(group.fields["description_owner"], "222@lid");
    assert_eq!(group.fields["description_owner_pn"], "222@s.whatsapp.net");
    assert_eq!(group.fields["description_owner_username"], "two");
    assert_eq!(group.fields["description_time"], "1700000280");
    assert!(!group.fields.contains_key("description"));

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-description-delete-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_270));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeDescription as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_description");
    assert!(!stub.fields.contains_key("message_stub_parameters"));
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_incoming_node_emits_group_subject_message_stub() {
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
        .with_attr("id", "group-subject-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000290")
        .with_content(vec![
            BinaryNode::new("subject")
                .with_attr("author", "222@lid")
                .with_attr("author_pn", "222@s.whatsapp.net")
                .with_attr("author_username", "two")
                .with_attr("s_t", "1700000300")
                .with_content("Alias subject"),
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
    assert_eq!(ack.attrs["id"], "group-subject-stub-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(group.fields["notification_id"], "group-subject-stub-live");
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000290");
    assert_eq!(group.fields["subject"], "Alias subject");
    assert_eq!(group.fields["subject_owner"], "222@lid");
    assert_eq!(group.fields["subject_owner_pn"], "222@s.whatsapp.net");
    assert_eq!(group.fields["subject_owner_username"], "two");
    assert_eq!(group.fields["subject_time"], "1700000300");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-subject-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_290));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeSubject as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_subject");
    assert_eq!(
        stub.fields["message_stub_parameters"],
        r#"["Alias subject"]"#
    );
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_offline_node_emits_group_announcement_append_stub() {
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
        .with_attr("id", "offline-group-announcement-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000310")
        .with_attr("offline", "1")
        .with_content(vec![BinaryNode::new("not_announcement")]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node(&connection, &offline, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.event_count(), 2);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Notification
    );
    assert!(result.results[0].error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "offline-group-announcement-stub");
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
        "offline-group-announcement-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000310");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["announce"], "false");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-announcement-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_310));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeAnnounce as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_announce");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["off"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_incoming_node_emits_group_announcement_message_stub() {
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
        .with_attr("id", "group-announcement-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000315")
        .with_content(vec![BinaryNode::new("announcement")]);
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
    assert_eq!(ack.attrs["id"], "group-announcement-stub-live");
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
        "group-announcement-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000315");
    assert_eq!(group.fields["announce"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-announcement-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_315));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeAnnounce as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_announce");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["on"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_incoming_node_emits_group_restrict_message_stub() {
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
        .with_attr("id", "group-restrict-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000320")
        .with_content(vec![BinaryNode::new("locked")]);
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
    assert_eq!(ack.attrs["id"], "group-restrict-stub-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(group.fields["notification_id"], "group-restrict-stub-live");
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000320");
    assert_eq!(group.fields["restrict"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-restrict-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_320));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeRestrict as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_restrict");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["on"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_incoming_node_emits_group_unlocked_message_stub() {
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
        .with_attr("id", "group-unlocked-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000325")
        .with_content(vec![BinaryNode::new("unlocked")]);
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
    assert_eq!(ack.attrs["id"], "group-unlocked-stub-live");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(group.fields["notification_id"], "group-unlocked-stub-live");
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000325");
    assert_eq!(group.fields["restrict"], "false");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-unlocked-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_325));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeRestrict as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_restrict");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["off"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_offline_node_emits_group_join_approval_mode_append_stub() {
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
        .with_attr("id", "offline-group-join-approval-mode-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000330")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("membership_approval_mode").with_content(vec![
                BinaryNode::new("group_join").with_attr("state", "off"),
            ]),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_offline_node(&connection, &offline, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 1);
    assert_eq!(result.event_count(), 2);
    assert_eq!(result.response_count(), 1);
    assert_eq!(result.yielded_count, 0);
    assert_eq!(
        result.results[0].action,
        wa_core::InboundNodeAction::Notification
    );
    assert!(result.results[0].error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "offline-group-join-approval-mode-stub");
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
        "offline-group-join-approval-mode-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000330");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["join_approval_mode"], "off");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-join-approval-mode-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_330));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupMembershipJoinApprovalMode as i32)
            .to_string()
    );
    assert_eq!(
        stub.fields["stub_type"],
        "group_membership_join_approval_mode"
    );
    assert_eq!(stub.fields["message_stub_parameters"], r#"["off"]"#);
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
async fn process_incoming_node_emits_group_member_add_mode_message_stub() {
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
        .with_attr("id", "group-member-add-mode-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000340")
        .with_content(vec![
            BinaryNode::new("member_add_mode").with_content("all_member_add"),
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
    assert_eq!(ack.attrs["id"], "group-member-add-mode-stub-live");
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
        "group-member-add-mode-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000340");
    assert_eq!(group.fields["member_add_mode"], "all_member_add");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-member-add-mode-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_340));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupMemberAddMode as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_member_add_mode");
    assert_eq!(
        stub.fields["message_stub_parameters"],
        r#"["all_member_add"]"#
    );
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());

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
