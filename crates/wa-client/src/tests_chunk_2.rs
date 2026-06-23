// Auto-partitioned test chunk 2 of 8 (feature `wat2`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat2 to stay within the VM RAM budget.
// Included into `mod chunk_2` in lib.rs; allow-attrs live on that module decl.
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
async fn retry_session_snapshot_ignores_mapped_lid_provider_identity_mismatch() {
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
    let wrong_identity =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&generate_key_pair().public));
    assert_ne!(
        wrong_identity,
        Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public)
    );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            &mapped_address,
            &wrong_identity,
        )
        .await
        .unwrap();

    let provider_validation = client
        .signal_provider_state_store()
        .validate_session_record("lid123:1@lid")
        .await
        .unwrap();
    assert_eq!(
        provider_validation.reason.as_deref(),
        Some("provider identity mismatch")
    );
    let snapshot = client
        .retry_session_snapshot("123:1@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(snapshot, wa_core::RetrySessionSnapshot::missing());
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_delete_and_refresh_clears_pn_and_mapped_lid_provider_sessions() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();
    for jid in ["123@s.whatsapp.net", "lid123@lid"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let plan = wa_core::RetryReceiptPlan {
        remote_jid: "123@s.whatsapp.net".to_owned(),
        message_ids: vec!["retry-clear-sessions".to_owned()],
        participant_jid: "123@s.whatsapp.net".to_owned(),
        retry_count: 2,
        resend_target: wa_core::RetryResendTarget::AllDevices,
        session_action: wa_core::RetrySessionAction::DeleteAndRefresh {
            reason: "base key collision across retries".to_owned(),
        },
        should_clear_group_sender_key: false,
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let action_fut = client.apply_retry_session_action(&connection, &plan, None);
    tokio::pin!(action_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("lid123@lid".to_owned(), Some("identity".to_owned()))]
            );
            session_response_for_query(&node)
        },
        &mut action_fut,
    )
    .await;

    let outcome = action_fut.await.unwrap();
    assert_eq!(
        outcome.deleted_sessions,
        vec!["123@s.whatsapp.net".to_owned(), "lid123@lid".to_owned()]
    );
    assert!(outcome.refreshed_sessions);
    for jid in ["123@s.whatsapp.net", "lid123@lid"] {
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
            .validate_session("lid123@lid")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_delete_and_refresh_clears_lid_and_mapped_pn_provider_sessions() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();
    for jid in ["lid123@lid", "123@s.whatsapp.net"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let plan = wa_core::RetryReceiptPlan {
        remote_jid: "lid123@lid".to_owned(),
        message_ids: vec!["retry-clear-lid-sessions".to_owned()],
        participant_jid: "lid123@lid".to_owned(),
        retry_count: 2,
        resend_target: wa_core::RetryResendTarget::AllDevices,
        session_action: wa_core::RetrySessionAction::DeleteAndRefresh {
            reason: "base key collision across retries".to_owned(),
        },
        should_clear_group_sender_key: false,
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let action_fut = client.apply_retry_session_action(&connection, &plan, None);
    tokio::pin!(action_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("lid123@lid".to_owned(), Some("identity".to_owned()))]
            );
            session_response_for_query(&node)
        },
        &mut action_fut,
    )
    .await;

    let outcome = action_fut.await.unwrap();
    assert_eq!(
        outcome.deleted_sessions,
        vec!["lid123@lid".to_owned(), "123@s.whatsapp.net".to_owned()]
    );
    assert!(outcome.refreshed_sessions);
    for jid in ["lid123@lid", "123@s.whatsapp.net"] {
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
            .validate_session("lid123@lid")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_delete_and_refresh_clears_hosted_device_provider_aliases() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@hosted".to_owned(),
            lid: "lid123@hosted.lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();
    for jid in ["123:99@hosted", "lid123:99@hosted.lid"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let plan = wa_core::RetryReceiptPlan {
        remote_jid: "123:99@hosted".to_owned(),
        message_ids: vec!["retry-clear-hosted-sessions".to_owned()],
        participant_jid: "123:99@hosted".to_owned(),
        retry_count: 2,
        resend_target: wa_core::RetryResendTarget::AllDevices,
        session_action: wa_core::RetrySessionAction::DeleteAndRefresh {
            reason: "base key collision across retries".to_owned(),
        },
        should_clear_group_sender_key: false,
    };
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let action_fut = client.apply_retry_session_action(&connection, &plan, None);
    tokio::pin!(action_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![(
                    "lid123:99@hosted.lid".to_owned(),
                    Some("identity".to_owned())
                )]
            );
            session_response_for_query(&node)
        },
        &mut action_fut,
    )
    .await;

    let outcome = action_fut.await.unwrap();
    assert_eq!(
        outcome.deleted_sessions,
        vec![
            "123:99@hosted".to_owned(),
            "lid123:99@hosted.lid".to_owned()
        ]
    );
    assert!(outcome.refreshed_sessions);
    for jid in ["123:99@hosted", "lid123:99@hosted.lid"] {
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
            .validate_session("lid123:99@hosted.lid")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_inline_key_bundle_clears_mapped_lid_provider_session() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();
    for jid in ["123@s.whatsapp.net", "lid123@lid"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let plan = wa_core::RetryReceiptPlan {
        remote_jid: "123@s.whatsapp.net".to_owned(),
        message_ids: vec!["retry-inline-bundle".to_owned()],
        participant_jid: "123@s.whatsapp.net".to_owned(),
        retry_count: 1,
        resend_target: wa_core::RetryResendTarget::AllDevices,
        session_action: wa_core::RetrySessionAction::InjectBundle,
        should_clear_group_sender_key: false,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-device-identity")),
    };
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let outcome = client
        .apply_retry_session_action(&connection, &plan, Some(bundle))
        .await
        .unwrap();

    assert!(outcome.injected_bundle);
    assert!(!outcome.refreshed_sessions);
    assert_eq!(outcome.deleted_sessions, vec!["lid123@lid".to_owned()]);
    assert!(
        client
            .signal_repository()
            .validate_session("123@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(
        !client
            .signal_repository()
            .validate_session("lid123@lid")
            .await
            .unwrap()
            .exists
    );
    for jid in ["123@s.whatsapp.net", "lid123@lid"] {
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_inline_key_bundle_normalizes_legacy_c_us_alias_cleanup() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();
    for jid in ["123:1@s.whatsapp.net", "lid123:1@lid"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let plan = wa_core::RetryReceiptPlan {
        remote_jid: "123@s.whatsapp.net".to_owned(),
        message_ids: vec!["retry-inline-c-us-bundle".to_owned()],
        participant_jid: "123:1@c.us".to_owned(),
        retry_count: 1,
        resend_target: wa_core::RetryResendTarget::Participant {
            jid: "123:1@c.us".to_owned(),
            count: 1,
        },
        session_action: wa_core::RetrySessionAction::InjectBundle,
        should_clear_group_sender_key: false,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "123:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-device-identity")),
    };
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let outcome = client
        .apply_retry_session_action(&connection, &plan, Some(bundle))
        .await
        .unwrap();

    assert!(outcome.injected_bundle);
    assert!(!outcome.refreshed_sessions);
    assert_eq!(outcome.deleted_sessions, vec!["lid123:1@lid".to_owned()]);
    assert!(
        client
            .signal_repository()
            .validate_session("123:1@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    assert!(
        !client
            .signal_repository()
            .validate_session("lid123:1@lid")
            .await
            .unwrap()
            .exists
    );
    for jid in ["123:1@s.whatsapp.net", "lid123:1@lid"] {
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_inline_key_bundle_clears_mapped_pn_provider_session() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "lid123@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();
    for jid in ["lid123@lid", "123@s.whatsapp.net"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let plan = wa_core::RetryReceiptPlan {
        remote_jid: "lid123@lid".to_owned(),
        message_ids: vec!["retry-inline-lid-bundle".to_owned()],
        participant_jid: "lid123@lid".to_owned(),
        retry_count: 1,
        resend_target: wa_core::RetryResendTarget::AllDevices,
        session_action: wa_core::RetrySessionAction::InjectBundle,
        should_clear_group_sender_key: false,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "lid123@lid".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-device-identity")),
    };
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let outcome = client
        .apply_retry_session_action(&connection, &plan, Some(bundle))
        .await
        .unwrap();

    assert!(outcome.injected_bundle);
    assert!(!outcome.refreshed_sessions);
    assert_eq!(
        outcome.deleted_sessions,
        vec!["123@s.whatsapp.net".to_owned()]
    );
    assert!(
        client
            .signal_repository()
            .validate_session("lid123@lid")
            .await
            .unwrap()
            .exists
    );
    assert!(
        !client
            .signal_repository()
            .validate_session("123@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    for jid in ["lid123@lid", "123@s.whatsapp.net"] {
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_inline_key_bundle_clears_hosted_device_provider_alias() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@hosted".to_owned(),
            lid: "lid123@hosted.lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let provider_store = client.signal_provider_state_store();
    for jid in ["lid123:99@hosted.lid", "123:99@hosted"] {
        provider_store
            .store_session_record(jid, b"opaque-provider-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record(jid, b"opaque-provider-identity")
            .await
            .unwrap();
    }

    let plan = wa_core::RetryReceiptPlan {
        remote_jid: "lid123:99@hosted.lid".to_owned(),
        message_ids: vec!["retry-inline-hosted-bundle".to_owned()],
        participant_jid: "lid123:99@hosted.lid".to_owned(),
        retry_count: 1,
        resend_target: wa_core::RetryResendTarget::AllDevices,
        session_action: wa_core::RetrySessionAction::InjectBundle,
        should_clear_group_sender_key: false,
    };
    let bundle = wa_core::RetryReceiptSessionBundle {
        session: wa_core::SessionInjection {
            jid: "lid123:99@hosted.lid".to_owned(),
            session: test_signal_session(),
        },
        device_identity: Some(Bytes::from_static(b"retry-device-identity")),
    };
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let outcome = client
        .apply_retry_session_action(&connection, &plan, Some(bundle))
        .await
        .unwrap();

    assert!(outcome.injected_bundle);
    assert!(!outcome.refreshed_sessions);
    assert_eq!(outcome.deleted_sessions, vec!["123:99@hosted".to_owned()]);
    assert!(
        client
            .signal_repository()
            .validate_session("lid123:99@hosted.lid")
            .await
            .unwrap()
            .exists
    );
    assert!(
        !client
            .signal_repository()
            .validate_session("123:99@hosted")
            .await
            .unwrap()
            .exists
    );
    for jid in ["lid123:99@hosted.lid", "123:99@hosted"] {
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_rejects_non_user_targets_before_device_lookup() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _) = mock_connection();
    let encryptor = RelayEncryptor::default();

    let group_err = client
        .send_status_text(
            &connection,
            ["11111-22222@g.us"],
            "invalid story",
            &encryptor,
            MessageRelayOptions::new().with_message_id("status-invalid-group"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        group_err,
        wa_core::CoreError::Payload(message)
            if message == "status target must be a user JID: 11111-22222@g.us"
    ));

    let broadcast_err = client
        .send_status_text(
            &connection,
            [wa_core::STATUS_BROADCAST_JID],
            "invalid story",
            &encryptor,
            MessageRelayOptions::new().with_message_id("status-invalid-broadcast"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        broadcast_err,
        wa_core::CoreError::Payload(message)
            if message == "status target must be a user JID: status@broadcast"
    ));

    let device_err = client
        .send_status_text(
            &connection,
            ["111:7@s.whatsapp.net"],
            "invalid story",
            &encryptor,
            MessageRelayOptions::new().with_message_id("status-invalid-device"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        device_err,
        wa_core::CoreError::Payload(message)
            if message == "status target must be a user JID: 111:7@s.whatsapp.net"
    ));

    let malformed_device_err = client
        .send_status_text(
            &connection,
            ["111:abc@s.whatsapp.net"],
            "invalid story",
            &encryptor,
            MessageRelayOptions::new().with_message_id("status-invalid-malformed-device"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        malformed_device_err,
        wa_core::CoreError::Payload(message)
            if message == "status target must be a user JID: 111:abc@s.whatsapp.net"
    ));

    let empty_err = client
        .send_status_text(
            &connection,
            [""],
            "invalid story",
            &encryptor,
            MessageRelayOptions::new().with_message_id("status-invalid-empty"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        empty_err,
        wa_core::CoreError::Payload(message) if message == "invalid status target JID: "
    ));

    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_with_signal_provider_rejects_non_user_targets_before_device_lookup() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _) = mock_connection();

    for (target, message_id, expected_error) in [
        (
            "11111-22222@g.us",
            "status-signal-invalid-group",
            "status target must be a user JID: 11111-22222@g.us",
        ),
        (
            wa_core::STATUS_BROADCAST_JID,
            "status-signal-invalid-broadcast",
            "status target must be a user JID: status@broadcast",
        ),
        (
            "111:7@s.whatsapp.net",
            "status-signal-invalid-device",
            "status target must be a user JID: 111:7@s.whatsapp.net",
        ),
        (
            "111:abc@s.whatsapp.net",
            "status-signal-invalid-malformed-device",
            "status target must be a user JID: 111:abc@s.whatsapp.net",
        ),
        (
            "",
            "status-signal-invalid-empty",
            "invalid status target JID: ",
        ),
    ] {
        let err = client
            .send_status_text_with_signal_provider(
                &connection,
                [target],
                "invalid store-backed story",
                MessageRelayOptions::new().with_message_id(message_id),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            wa_core::CoreError::Payload(message) if message == expected_error
        ));
    }

    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_with_signal_provider_stops_before_provider_mutation_when_recipients_unusable()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();

    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let no_devices_send = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "store-backed empty audience",
        MessageRelayOptions::new().with_message_id("status-signal-empty-devices-1"),
    );
    tokio::pin!(no_devices_send);

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
        &mut no_devices_send,
    )
    .await;

    let no_devices_err = no_devices_send.await.unwrap_err();
    assert!(matches!(
        no_devices_err,
        wa_core::CoreError::Protocol(message)
            if message == "status send requires at least one recipient device"
    ));
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();

    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let session_failure_send = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "store-backed missing session",
        MessageRelayOptions::new().with_message_id("status-signal-session-fail-1"),
    );
    tokio::pin!(session_failure_send);

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
                                    BinaryNode::new("device").with_attr("id", "7"),
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut session_failure_send,
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
        &mut session_failure_send,
    )
    .await;

    let session_err = session_failure_send.await.unwrap_err();
    assert!(
        session_err
            .to_string()
            .contains("E2E session query failed (401): session denied")
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_discovers_devices_and_writes_status_broadcast() {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "story hello",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-1"),
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
    assert_eq!(relay.message_id, "status-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "status-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "text");
    assert!(sent.attrs.contains_key("phash"));
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("status message should contain child nodes");
    };
    assert_eq!(content.len(), 1);
    assert_eq!(content[0].tag, "participants");
    let Some(wa_binary::BinaryNodeContent::Nodes(participants)) = &content[0].content else {
        panic!("status message should contain participant nodes");
    };
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0].tag, "to");
    assert_eq!(participants[0].attrs["jid"], "111@s.whatsapp.net");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        plaintext
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("story hello")
    );
    assert!(plaintext.device_sent_message.is_none());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_caches_status_broadcast_for_retry_resend() {
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
            jid: "111:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "retryable story",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
    assert_eq!(relay.message_id, "status-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
    assert_eq!(
        plaintext.extended_text_message.unwrap().text.as_deref(),
        Some("retryable story")
    );
    assert!(plaintext.device_sent_message.is_none());

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "111:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    let resent_plaintext =
        wa_proto::proto::Message::decode(test_node_bytes(resent_enc).unwrap()).unwrap();
    assert_eq!(
        resent_plaintext
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("retryable story")
    );
    assert!(resent_plaintext.device_sent_message.is_none());
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["111:1@s.whatsapp.net", "111:1@s.whatsapp.net"]
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
        vec!["status-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_caches_status_broadcast_for_all_device_retry_resend() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in [
        "111@s.whatsapp.net",
        "111:1@s.whatsapp.net",
        "999:8@s.whatsapp.net",
    ] {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "all-device retryable story",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-all-retry-1"),
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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "status-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&sent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("all-device retryable story")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("all-device retryable story")
            );
        }
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("all-device retryable story")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("all-device retryable story")
            );
        }
    }
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net",
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
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
        vec!["status-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_with_signal_provider_replays_cached_status_retry() {
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
    let remote_one_time_pre_key_id = 121;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "store-backed retryable story",
        MessageRelayOptions::new().with_message_id("status-signal-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
                vec![("111:1@s.whatsapp.net".to_owned(), None)]
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
    assert_eq!(relay.message_id, "status-signal-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let first_enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    assert_eq!(first_enc.attrs["type"], "pkmsg");
    let first_ciphertext = test_node_bytes(first_enc).unwrap();
    let first_message = wa_core::decode_signal_pre_key_whisper_message(&first_ciphertext).unwrap();
    assert_eq!(first_message.pre_key_id, Some(remote_one_time_pre_key_id));
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
        first_decoded.extended_text_message.unwrap().text.as_deref(),
        Some("store-backed retryable story")
    );
    assert!(first_decoded.device_sent_message.is_none());

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
                registration_id: Some(remote_credentials.registration_id),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends_with_signal_provider(&connection, &prepared)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    assert_eq!(resent_enc.attrs["type"], "msg");
    let resent_ciphertext = test_node_bytes(resent_enc).unwrap();
    let resent_decrypted = wa_core::decrypt_signal_provider_session_record_message(
        &first_decrypted.record,
        &resent_ciphertext,
        &remote_material.identity.public_key,
    )
    .unwrap();
    assert_eq!(resent_decrypted.message.counter, 1);
    let resent_unpadded = wa_core::unpad_random_max16(&resent_decrypted.plaintext).unwrap();
    let resent_decoded = wa_proto::proto::Message::decode(resent_unpadded).unwrap();
    assert_eq!(
        resent_decoded
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("store-backed retryable story")
    );
    assert!(resent_decoded.device_sent_message.is_none());
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
        vec!["status-signal-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_with_signal_provider_replays_cached_status_all_device_retry() {
    fn all_device_status_usync_response(node: BinaryNode) -> BinaryNode {
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
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "0"),
                                BinaryNode::new("device")
                                    .with_attr("id", "1")
                                    .with_attr("key-index", "1"),
                            ]),
                        ])]),
                    BinaryNode::new("user")
                        .with_attr("jid", "999@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "7"),
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
            ])])
    }

    fn assert_status_retry_payload(decoded: wa_proto::proto::Message, expected_device_sent: bool) {
        if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("store-backed all-device retryable story")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("store-backed all-device retryable story")
            );
        }
    }

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
    let remote_one_time_pre_key_id = 122;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "store-backed all-device retryable story",
        MessageRelayOptions::new().with_message_id("status-signal-all-retry-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        all_device_status_usync_response,
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
                    ("111:1@s.whatsapp.net".to_owned(), None),
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
    assert_eq!(relay.message_id, "status-signal-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut first_records = BTreeMap::new();
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
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
        assert_status_retry_payload(decoded, expected_device_sent);
        first_records.insert(jid.to_owned(), decrypted.record);
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
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
        all_device_status_usync_response,
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let first_record = first_records.get(jid).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        assert_status_retry_payload(decoded, expected_device_sent);
    }
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
        vec!["status-signal-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_fails_when_device_lookup_has_no_recipients() {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "empty audience",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-empty-devices-1"),
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
            if message == "status send requires at least one recipient device"
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
async fn send_status_text_stops_when_session_assertion_fails() {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "session missing story",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-session-fail-1"),
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
async fn send_status_text_stops_when_participant_encryption_fails() {
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
    let encryptor = FailingAfterEncryptor::new(2, "status participant encrypt failed");
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net", "222@s.whatsapp.net"],
        "partial story",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-encrypt-fail"),
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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
            .contains("status participant encrypt failed")
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
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-encrypt-fail".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(prepared.missing_message_ids, vec!["status-encrypt-fail"]);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_stops_when_relay_send_fails_without_retry_cache() {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net", "222@s.whatsapp.net"],
        "status relay send failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-send-fail"),
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
                                    BinaryNode::new("device").with_attr("id", "7"),
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
        vec!["111@s.whatsapp.net", "222@s.whatsapp.net"]
    );
    for call in &calls {
        let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
        assert_eq!(
            plaintext
                .extended_text_message
                .as_ref()
                .and_then(|message| message.text.as_deref()),
            Some("status relay send failure")
        );
        assert!(plaintext.device_sent_message.is_none());
    }
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-send-fail".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("999:7@s.whatsapp.net".to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(prepared.missing_message_ids, vec!["status-send-fail"]);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_with_signal_codec_stops_after_linked_device_encrypt_without_retry_cache()
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
    let remote_one_time_pre_key_id = 103;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let codec = client.signal_message_codec().unwrap();
    let encryptor = ClosingAfterEncryptor::new(codec, connection.clone(), 2);
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "status signal linked relay failure",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-signal-send-fail-linked"),
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
    assert_eq!(
        audience_plaintext
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("status signal linked relay failure")
    );
    let own_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let device_sent = own_plaintext.device_sent_message.unwrap();
    assert_eq!(
        device_sent.destination_jid.as_deref(),
        Some(wa_core::STATUS_BROADCAST_JID)
    );
    assert_eq!(
        device_sent
            .message
            .unwrap()
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("status signal linked relay failure")
    );
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
                message_ids: vec!["status-signal-send-fail-linked".to_owned()],
                from_jid: Some("111@s.whatsapp.net".to_owned()),
                to_jid: None,
                participant: None,
                recipient: Some("999:7@s.whatsapp.net".to_owned()),
                chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
        vec!["status-signal-send-fail-linked"]
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_poll_attaches_reporting_token_for_secret_message() {
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
    let send_fut = client.send_status_poll(
        &connection,
        ["111@s.whatsapp.net"],
        PollContent::new("Story poll?", ["Yes", "No"], 1, Bytes::from(vec![8u8; 32])),
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-reporting-1"),
    );
    tokio::pin!(send_fut);

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
                                ])],
                            )]),
                    ]),
                ])])
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "status-reporting-1");
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "poll");
    assert!(sent.attrs.contains_key("phash"));
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("status poll message should contain child nodes");
    };
    assert_eq!(content[0].tag, "participants");
    let reporting = content
        .iter()
        .find(|node| node.tag == "reporting")
        .expect("status poll should carry reporting token");
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

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_poll_retry_replays_cached_poll_without_reporting_sidecar() {
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
            jid: "111:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_status_poll(
        &connection,
        ["111@s.whatsapp.net"],
        PollContent::new(
            "Retry story poll?",
            ["Retry yes", "Retry no"],
            1,
            Bytes::from(vec![9u8; 32]),
        ),
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-poll-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
    assert_eq!(relay.message_id, "status-poll-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-poll-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "poll");
    assert!(sent.attrs.contains_key("phash"));
    assert!(!test_children(&sent, "reporting").is_empty());
    let enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
    assert!(plaintext.device_sent_message.is_none());
    let poll = plaintext.poll_creation_message_v3.unwrap();
    assert_eq!(poll.name.as_deref(), Some("Retry story poll?"));
    assert_eq!(poll.options.len(), 2);
    assert!(
        plaintext
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-poll-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "111:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-poll-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-poll-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "poll");
    assert!(resent.attrs.contains_key("phash"));
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    let resent_plaintext =
        wa_proto::proto::Message::decode(test_node_bytes(resent_enc).unwrap()).unwrap();
    assert!(resent_plaintext.device_sent_message.is_none());
    let resent_poll = resent_plaintext.poll_creation_message_v3.unwrap();
    assert_eq!(resent_poll.name.as_deref(), Some("Retry story poll?"));
    assert_eq!(resent_poll.options.len(), 2);
    assert!(
        resent_plaintext
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
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
        vec!["status-poll-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_poll_all_device_retry_replays_cached_poll_without_reporting_sidecar() {
    fn assert_poll_retry_payload(decoded: wa_proto::proto::Message, expected_device_sent: bool) {
        let decoded = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let poll = decoded.poll_creation_message_v3.unwrap();
        assert_eq!(poll.name.as_deref(), Some("All-device retry story poll?"));
        assert_eq!(poll.options.len(), 2);
        assert!(
            decoded
                .message_context_info
                .as_ref()
                .and_then(|context| context.message_secret.as_ref())
                .is_some()
        );
    }

    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in [
        "111@s.whatsapp.net",
        "111:1@s.whatsapp.net",
        "999:8@s.whatsapp.net",
    ] {
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
    let send_fut = client.send_status_poll(
        &connection,
        ["111@s.whatsapp.net"],
        PollContent::new(
            "All-device retry story poll?",
            ["All yes", "All no"],
            1,
            Bytes::from(vec![11u8; 32]),
        ),
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-poll-all-retry-1"),
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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "status-poll-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-poll-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "poll");
    assert!(!test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&sent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        assert_poll_retry_payload(decoded, expected_device_sent);
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-poll-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-poll-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-poll-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "poll");
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        assert_poll_retry_payload(decoded, expected_device_sent);
    }
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
        vec!["status-poll-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_poll_with_signal_provider_replays_cached_poll_without_reporting_sidecar() {
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
    let remote_one_time_pre_key_id = 125;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_poll_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        PollContent::new(
            "Store-backed retry story poll?",
            ["Store retry yes", "Store retry no"],
            1,
            Bytes::from(vec![10u8; 32]),
        ),
        MessageRelayOptions::new().with_message_id("status-signal-poll-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
                vec![("111:1@s.whatsapp.net".to_owned(), None)]
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
    assert_eq!(relay.message_id, "status-signal-poll-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-poll-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "poll");
    assert!(sent.attrs.contains_key("phash"));
    assert!(!test_children(&sent, "reporting").is_empty());
    let first_enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    assert_eq!(first_enc.attrs["type"], "pkmsg");
    let first_ciphertext = test_node_bytes(first_enc).unwrap();
    let first_message = wa_core::decode_signal_pre_key_whisper_message(&first_ciphertext).unwrap();
    assert_eq!(first_message.pre_key_id, Some(remote_one_time_pre_key_id));
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
    assert!(first_decoded.device_sent_message.is_none());
    let first_poll = first_decoded.poll_creation_message_v3.unwrap();
    assert_eq!(
        first_poll.name.as_deref(),
        Some("Store-backed retry story poll?")
    );
    assert_eq!(first_poll.options.len(), 2);
    assert!(
        first_decoded
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-poll-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
                registration_id: Some(remote_credentials.registration_id),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "111:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends_with_signal_provider(&connection, &prepared)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-poll-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-poll-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "poll");
    assert!(resent.attrs.contains_key("phash"));
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    assert_eq!(resent_enc.attrs["type"], "msg");
    let resent_ciphertext = test_node_bytes(resent_enc).unwrap();
    let resent_decrypted = wa_core::decrypt_signal_provider_session_record_message(
        &first_decrypted.record,
        &resent_ciphertext,
        &remote_material.identity.public_key,
    )
    .unwrap();
    assert_eq!(resent_decrypted.message.counter, 1);
    let resent_unpadded = wa_core::unpad_random_max16(&resent_decrypted.plaintext).unwrap();
    let resent_decoded = wa_proto::proto::Message::decode(resent_unpadded).unwrap();
    assert!(resent_decoded.device_sent_message.is_none());
    let resent_poll = resent_decoded.poll_creation_message_v3.unwrap();
    assert_eq!(
        resent_poll.name.as_deref(),
        Some("Store-backed retry story poll?")
    );
    assert_eq!(resent_poll.options.len(), 2);
    assert!(
        resent_decoded
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
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
        vec!["status-signal-poll-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_poll_with_signal_provider_replays_cached_all_device_poll_without_reporting_sidecar()
 {
    fn all_device_status_usync_response(node: BinaryNode) -> BinaryNode {
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
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "0"),
                                BinaryNode::new("device")
                                    .with_attr("id", "1")
                                    .with_attr("key-index", "1"),
                            ]),
                        ])]),
                    BinaryNode::new("user")
                        .with_attr("jid", "999@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "7"),
                                BinaryNode::new("device")
                                    .with_attr("id", "8")
                                    .with_attr("key-index", "8"),
                            ]),
                        ])]),
                ]),
            ])])
    }

    fn assert_signal_poll_retry_payload(
        decoded: wa_proto::proto::Message,
        expected_device_sent: bool,
    ) {
        let decoded = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let poll = decoded.poll_creation_message_v3.unwrap();
        assert_eq!(
            poll.name.as_deref(),
            Some("Store-backed all-device retry story poll?")
        );
        assert_eq!(poll.options.len(), 2);
        assert!(
            decoded
                .message_context_info
                .as_ref()
                .and_then(|context| context.message_secret.as_ref())
                .is_some()
        );
    }

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
    let remote_one_time_pre_key_id = 126;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_poll_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        PollContent::new(
            "Store-backed all-device retry story poll?",
            ["Store all yes", "Store all no"],
            1,
            Bytes::from(vec![12u8; 32]),
        ),
        MessageRelayOptions::new().with_message_id("status-signal-poll-all-retry-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        all_device_status_usync_response,
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
                    ("111:1@s.whatsapp.net".to_owned(), None),
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
    assert_eq!(relay.message_id, "status-signal-poll-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-poll-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "poll");
    assert!(!test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut first_records = BTreeMap::new();
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
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
        assert_signal_poll_retry_payload(decoded, expected_device_sent);
        first_records.insert(jid.to_owned(), decrypted.record);
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-poll-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
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
        all_device_status_usync_response,
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-poll-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-poll-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "poll");
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let first_record = first_records.get(jid).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        assert_signal_poll_retry_payload(decoded, expected_device_sent);
    }
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
        vec!["status-signal-poll-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_event_retry_replays_cached_event_without_reporting_sidecar() {
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
            jid: "111:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let send_fut = client.send_status_event(
        &connection,
        ["111@s.whatsapp.net"],
        EventContent::new(
            "Retry story event",
            1_700_000_223,
            Bytes::from(vec![15u8; 32]),
        )
        .with_join_link("https://call.example.invalid/status-event-retry"),
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-event-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
    assert_eq!(relay.message_id, "status-event-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-event-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "event");
    assert!(sent.attrs.contains_key("phash"));
    assert!(!test_children(&sent, "reporting").is_empty());
    let enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
    assert!(plaintext.device_sent_message.is_none());
    let event = plaintext.event_message.unwrap();
    assert_eq!(event.name.as_deref(), Some("Retry story event"));
    assert_eq!(
        event.join_link.as_deref(),
        Some("https://call.example.invalid/status-event-retry")
    );
    assert!(
        plaintext
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-event-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "111:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-event-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-event-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "event");
    assert!(resent.attrs.contains_key("phash"));
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    let resent_plaintext =
        wa_proto::proto::Message::decode(test_node_bytes(resent_enc).unwrap()).unwrap();
    assert!(resent_plaintext.device_sent_message.is_none());
    let resent_event = resent_plaintext.event_message.unwrap();
    assert_eq!(resent_event.name.as_deref(), Some("Retry story event"));
    assert_eq!(
        resent_event.join_link.as_deref(),
        Some("https://call.example.invalid/status-event-retry")
    );
    assert!(
        resent_plaintext
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
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
        vec!["status-event-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_event_with_signal_provider_replays_cached_event_without_reporting_sidecar() {
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
    let remote_one_time_pre_key_id = 128;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_event_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        EventContent::new(
            "Store-backed retry story event",
            1_700_000_224,
            Bytes::from(vec![16u8; 32]),
        )
        .with_join_link("https://call.example.invalid/store-status-event-retry"),
        MessageRelayOptions::new().with_message_id("status-signal-event-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
                vec![("111:1@s.whatsapp.net".to_owned(), None)]
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
    assert_eq!(relay.message_id, "status-signal-event-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-event-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "event");
    assert!(sent.attrs.contains_key("phash"));
    assert!(!test_children(&sent, "reporting").is_empty());
    let first_enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    assert_eq!(first_enc.attrs["type"], "pkmsg");
    let first_ciphertext = test_node_bytes(first_enc).unwrap();
    let first_message = wa_core::decode_signal_pre_key_whisper_message(&first_ciphertext).unwrap();
    assert_eq!(first_message.pre_key_id, Some(remote_one_time_pre_key_id));
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
    assert!(first_decoded.device_sent_message.is_none());
    let first_event = first_decoded.event_message.unwrap();
    assert_eq!(
        first_event.name.as_deref(),
        Some("Store-backed retry story event")
    );
    assert_eq!(
        first_event.join_link.as_deref(),
        Some("https://call.example.invalid/store-status-event-retry")
    );
    assert!(
        first_decoded
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-event-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
                registration_id: Some(remote_credentials.registration_id),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "111:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends_with_signal_provider(&connection, &prepared)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-event-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-event-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "event");
    assert!(resent.attrs.contains_key("phash"));
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    assert_eq!(resent_enc.attrs["type"], "msg");
    let resent_ciphertext = test_node_bytes(resent_enc).unwrap();
    let resent_decrypted = wa_core::decrypt_signal_provider_session_record_message(
        &first_decrypted.record,
        &resent_ciphertext,
        &remote_material.identity.public_key,
    )
    .unwrap();
    assert_eq!(resent_decrypted.message.counter, 1);
    let resent_unpadded = wa_core::unpad_random_max16(&resent_decrypted.plaintext).unwrap();
    let resent_decoded = wa_proto::proto::Message::decode(resent_unpadded).unwrap();
    assert!(resent_decoded.device_sent_message.is_none());
    let resent_event = resent_decoded.event_message.unwrap();
    assert_eq!(
        resent_event.name.as_deref(),
        Some("Store-backed retry story event")
    );
    assert_eq!(
        resent_event.join_link.as_deref(),
        Some("https://call.example.invalid/store-status-event-retry")
    );
    assert!(
        resent_decoded
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
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
        vec!["status-signal-event-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_event_all_device_retry_replays_cached_event_without_reporting_sidecar() {
    fn assert_event_retry_payload(decoded: wa_proto::proto::Message, expected_device_sent: bool) {
        let decoded = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let event = decoded.event_message.unwrap();
        assert_eq!(event.name.as_deref(), Some("All-device retry story event"));
        assert_eq!(
            event.join_link.as_deref(),
            Some("https://call.example.invalid/status-all-event")
        );
        assert_eq!(event.start_time, Some(1_700_000_221));
        assert!(
            decoded
                .message_context_info
                .as_ref()
                .and_then(|context| context.message_secret.as_ref())
                .is_some()
        );
    }

    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in [
        "111@s.whatsapp.net",
        "111:1@s.whatsapp.net",
        "999:8@s.whatsapp.net",
    ] {
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
    let send_fut = client.send_status_message(
        &connection,
        ["111@s.whatsapp.net"],
        MessageContent::event(
            EventContent::new(
                "All-device retry story event",
                1_700_000_221,
                Bytes::from(vec![13u8; 32]),
            )
            .with_join_link("https://call.example.invalid/status-all-event"),
        ),
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-event-all-retry-1"),
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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "status-event-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-event-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "event");
    assert!(sent.attrs.contains_key("phash"));
    assert!(!test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&sent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        assert_event_retry_payload(decoded, expected_device_sent);
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-event-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-event-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-event-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "event");
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        assert_event_retry_payload(decoded, expected_device_sent);
    }
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
        vec!["status-event-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_event_with_signal_provider_replays_cached_all_device_event_without_reporting_sidecar()
 {
    fn all_device_status_usync_response(node: BinaryNode) -> BinaryNode {
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
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "0"),
                                BinaryNode::new("device")
                                    .with_attr("id", "1")
                                    .with_attr("key-index", "1"),
                            ]),
                        ])]),
                    BinaryNode::new("user")
                        .with_attr("jid", "999@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "7"),
                                BinaryNode::new("device")
                                    .with_attr("id", "8")
                                    .with_attr("key-index", "8"),
                            ]),
                        ])]),
                ]),
            ])])
    }

    fn assert_signal_event_retry_payload(
        decoded: wa_proto::proto::Message,
        expected_device_sent: bool,
    ) {
        let decoded = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            *device_sent.message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded
        };
        let event = decoded.event_message.unwrap();
        assert_eq!(
            event.name.as_deref(),
            Some("Store-backed all-device retry story event")
        );
        assert_eq!(
            event.join_link.as_deref(),
            Some("https://call.example.invalid/store-status-all-event")
        );
        assert_eq!(event.start_time, Some(1_700_000_222));
        assert!(
            decoded
                .message_context_info
                .as_ref()
                .and_then(|context| context.message_secret.as_ref())
                .is_some()
        );
    }

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
    let remote_one_time_pre_key_id = 127;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_message_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        MessageContent::event(
            EventContent::new(
                "Store-backed all-device retry story event",
                1_700_000_222,
                Bytes::from(vec![14u8; 32]),
            )
            .with_join_link("https://call.example.invalid/store-status-all-event"),
        ),
        MessageRelayOptions::new().with_message_id("status-signal-event-all-retry-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        all_device_status_usync_response,
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
                    ("111:1@s.whatsapp.net".to_owned(), None),
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
    assert_eq!(relay.message_id, "status-signal-event-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-event-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "event");
    assert!(!test_children(&sent, "reporting").is_empty());
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut first_records = BTreeMap::new();
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
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
        assert_signal_event_retry_payload(decoded, expected_device_sent);
        first_records.insert(jid.to_owned(), decrypted.record);
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-event-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
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
        all_device_status_usync_response,
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-event-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-event-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "event");
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let first_record = first_records.get(jid).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        assert_signal_event_retry_payload(decoded, expected_device_sent);
    }
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
        vec!["status-signal-event-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_image_relays_media_status_broadcast() {
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
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![1u8; 32]),
        Bytes::from(vec![2u8; 32]),
        Bytes::from(vec![3u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/status-image")
    .with_direct_path("/v/t62.7118-24/status-image")
    .with_media_key_timestamp(1_700_000_000);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("story photo".to_owned());
    let send_fut = client.send_status_image(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-media-1"),
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
    assert_eq!(relay.message_id, "status-media-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "status-media-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("status media message should contain child nodes");
    };
    assert_eq!(content.len(), 1);
    assert_eq!(content[0].tag, "participants");
    let Some(wa_binary::BinaryNodeContent::Nodes(participants)) = &content[0].content else {
        panic!("status media message should contain participant nodes");
    };
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0].tag, "to");
    assert_eq!(participants[0].attrs["jid"], "111@s.whatsapp.net");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let image = plaintext.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("story photo"));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-image")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_video_relays_media_status_broadcast() {
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
    let video_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![22u8; 32]),
        Bytes::from(vec![23u8; 32]),
        Bytes::from(vec![24u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/status-video")
    .with_direct_path("/v/t62.7118-24/status-video")
    .with_media_key_timestamp(1_700_000_020);
    let mut video = wa_core::VideoContent::new(video_media, "video/mp4");
    video.caption = Some("story clip".to_owned());
    video.seconds = Some(7);
    video.height = Some(1_280);
    video.width = Some(720);
    let send_fut = client.send_status_video(
        &connection,
        ["111@s.whatsapp.net"],
        video,
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-video-1"),
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
    assert_eq!(relay.message_id, "status-video-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "status-video-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net"]
    );

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let video = plaintext.video_message.unwrap();
    assert_eq!(video.mimetype.as_deref(), Some("video/mp4"));
    assert_eq!(video.caption.as_deref(), Some("story clip"));
    assert_eq!(video.seconds, Some(7));
    assert_eq!(video.height, Some(1_280));
    assert_eq!(video.width, Some(720));
    assert_eq!(
        video.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-video")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_document_relays_media_status_broadcast() {
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
    let document_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![25u8; 32]),
        Bytes::from(vec![26u8; 32]),
        Bytes::from(vec![27u8; 32]),
        4_096,
    )
    .with_url("https://media.example.invalid/status-document")
    .with_direct_path("/v/t62.7118-24/status-document")
    .with_media_key_timestamp(1_700_000_021);
    let mut document = wa_core::DocumentContent::new(document_media, "application/pdf");
    document.title = Some("Status Brief".to_owned());
    document.file_name = Some("status-brief.pdf".to_owned());
    document.caption = Some("story document".to_owned());
    document.page_count = Some(3);
    let send_fut = client.send_status_document(
        &connection,
        ["111@s.whatsapp.net"],
        document,
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-document-1"),
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
    assert_eq!(relay.message_id, "status-document-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "status-document-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net"]
    );

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let document = plaintext.document_message.unwrap();
    assert_eq!(document.mimetype.as_deref(), Some("application/pdf"));
    assert_eq!(document.title.as_deref(), Some("Status Brief"));
    assert_eq!(document.file_name.as_deref(), Some("status-brief.pdf"));
    assert_eq!(document.caption.as_deref(), Some("story document"));
    assert_eq!(document.page_count, Some(3));
    assert_eq!(
        document.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-document")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_audio_relays_media_status_broadcast() {
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
    let audio_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![28u8; 32]),
        Bytes::from(vec![29u8; 32]),
        Bytes::from(vec![30u8; 32]),
        1_536,
    )
    .with_url("https://media.example.invalid/status-audio")
    .with_direct_path("/v/t62.7118-24/status-audio")
    .with_media_key_timestamp(1_700_000_022);
    let mut audio = wa_core::AudioContent::new(audio_media, "audio/ogg; codecs=opus");
    audio.seconds = Some(11);
    audio.ptt = true;
    audio.waveform = Some(Bytes::from_static(&[3, 1, 4, 1, 5]));
    audio.background_argb = Some(0xff11_2233);
    let send_fut = client.send_status_audio(
        &connection,
        ["111@s.whatsapp.net"],
        audio,
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-audio-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        single_recipient_status_usync_response,
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "status-audio-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "status-audio-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net"]
    );

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let audio = plaintext.audio_message.unwrap();
    assert_eq!(audio.mimetype.as_deref(), Some("audio/ogg; codecs=opus"));
    assert_eq!(audio.seconds, Some(11));
    assert_eq!(audio.ptt, Some(true));
    assert_eq!(audio.waveform.as_deref(), Some([3, 1, 4, 1, 5].as_slice()));
    assert_eq!(audio.background_argb, Some(0xff11_2233));
    assert_eq!(
        audio.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-audio")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_sticker_relays_media_status_broadcast() {
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
    let sticker_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![31u8; 32]),
        Bytes::from(vec![32u8; 32]),
        Bytes::from(vec![33u8; 32]),
        768,
    )
    .with_url("https://media.example.invalid/status-sticker")
    .with_direct_path("/v/t62.7118-24/status-sticker")
    .with_media_key_timestamp(1_700_000_023);
    let mut sticker = wa_core::StickerContent::new(sticker_media, "image/webp");
    sticker.height = Some(512);
    sticker.width = Some(512);
    sticker.png_thumbnail = Some(Bytes::from_static(&[137, 80, 78, 71]));
    sticker.is_animated = true;
    let send_fut = client.send_status_sticker(
        &connection,
        ["111@s.whatsapp.net"],
        sticker,
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-sticker-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        single_recipient_status_usync_response,
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "status-sticker-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "status-sticker-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net"]
    );

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    let sticker = plaintext.sticker_message.unwrap();
    assert_eq!(sticker.mimetype.as_deref(), Some("image/webp"));
    assert_eq!(sticker.height, Some(512));
    assert_eq!(sticker.width, Some(512));
    assert_eq!(sticker.is_animated, Some(true));
    assert_eq!(
        sticker.png_thumbnail.as_deref(),
        Some([137, 80, 78, 71].as_slice())
    );
    assert_eq!(
        sticker.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-sticker")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_image_caches_media_status_broadcast_for_retry_resend() {
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
            jid: "111:1@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![10u8; 32]),
        Bytes::from(vec![11u8; 32]),
        Bytes::from(vec![12u8; 32]),
        4_096,
    )
    .with_url("https://media.example.invalid/status-retry-image")
    .with_direct_path("/v/t62.7118-24/status-retry-image")
    .with_media_key_timestamp(1_700_000_010);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("retryable story photo".to_owned());
    let send_fut = client.send_status_image(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-media-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
    assert_eq!(relay.message_id, "status-media-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-media-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111:1@s.whatsapp.net"]
    );
    let enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    let plaintext = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
    let image = plaintext.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("retryable story photo"));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-retry-image")
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-media-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "111:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-media-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-media-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "media");
    assert!(resent.attrs.contains_key("phash"));
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    let resent_plaintext =
        wa_proto::proto::Message::decode(test_node_bytes(resent_enc).unwrap()).unwrap();
    let resent_image = resent_plaintext.image_message.unwrap();
    assert_eq!(resent_image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(
        resent_image.caption.as_deref(),
        Some("retryable story photo")
    );
    assert_eq!(
        resent_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-retry-image")
    );
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["111:1@s.whatsapp.net", "111:1@s.whatsapp.net"]
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
        vec!["status-media-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_image_caches_media_status_broadcast_for_all_device_retry_resend() {
    fn assert_media_status_payload(decoded: wa_proto::proto::Message, expected_device_sent: bool) {
        let image = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            device_sent.message.unwrap().image_message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.image_message.unwrap()
        };
        assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(
            image.caption.as_deref(),
            Some("all-device retryable story photo")
        );
        assert_eq!(
            image.direct_path.as_deref(),
            Some("/v/t62.7118-24/status-all-retry-image")
        );
    }

    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    for jid in [
        "111@s.whatsapp.net",
        "111:1@s.whatsapp.net",
        "999:8@s.whatsapp.net",
    ] {
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
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![16u8; 32]),
        Bytes::from(vec![17u8; 32]),
        Bytes::from(vec![18u8; 32]),
        16_384,
    )
    .with_url("https://media.example.invalid/status-all-retry-image")
    .with_direct_path("/v/t62.7118-24/status-all-retry-image")
    .with_media_key_timestamp(1_700_000_012);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("all-device retryable story photo".to_owned());
    let send_fut = client.send_status_image(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-media-all-retry-1"),
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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "status-media-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-media-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&sent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        assert_media_status_payload(decoded, expected_device_sent);
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-media-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
    assert_eq!(plan.resend_target, wa_core::RetryResendTarget::AllDevices);
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

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
                                    BinaryNode::new("device")
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-media-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-media-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "media");
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        let decoded = wa_proto::proto::Message::decode(test_node_bytes(enc).unwrap()).unwrap();
        assert_media_status_payload(decoded, expected_device_sent);
    }
    assert_eq!(
        encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net",
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
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
        vec!["status-media-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_deduplicates_discovered_audience_devices() {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "dedup story",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-dedup-1"),
    );
    tokio::pin!(send_fut);

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
                            .with_attr("jid", "111@s.whatsapp.net")
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
    assert_eq!(relay.message_id, "status-dedup-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("status message should contain child nodes");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(participants)) = &content[0].content else {
        panic!("status message should contain participant nodes");
    };
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0].attrs["jid"], "111@s.whatsapp.net");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_normalizes_c_us_targets_and_device_results() {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@c.us", "111@s.whatsapp.net"],
        "canonical story",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-canonical-1"),
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
    assert_eq!(relay.message_id, "status-canonical-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("status message should contain child nodes");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(participants)) = &content[0].content else {
        panic!("status message should contain participant nodes");
    };
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0].attrs["jid"], "111@s.whatsapp.net");

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "111@s.whatsapp.net");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_deduplicates_own_pn_lid_linked_device_aliases() {
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
    let send_fut = client.send_status_text(
        &connection,
        ["111@s.whatsapp.net"],
        "own alias story",
        &encryptor,
        MessageRelayOptions::new().with_message_id("status-own-alias-dedup-1"),
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
        .expect("status send should complete without a session query for the LID alias")
        .unwrap();
    assert_eq!(relay.message_id, "status-own-alias-dedup-1");
    assert_eq!(relay.recipient_count, 2);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
        panic!("status message should contain child nodes");
    };
    let Some(wa_binary::BinaryNodeContent::Nodes(participants)) = &content[0].content else {
        panic!("status message should contain participant nodes");
    };
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    let audience_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert!(audience_plaintext.device_sent_message.is_none());
    let own_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    let device_sent = own_plaintext.device_sent_message.unwrap();
    assert_eq!(
        device_sent.destination_jid.as_deref(),
        Some(wa_core::STATUS_BROADCAST_JID)
    );
    assert_eq!(
        device_sent
            .message
            .unwrap()
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("own alias story")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_with_signal_provider_encrypts_status_participant() {
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
    let remote_one_time_pre_key_id = 91;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "store-backed story",
        MessageRelayOptions::new().with_message_id("status-signal-1"),
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
    assert_eq!(relay.message_id, "status-signal-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let enc = test_participant_enc_node(&sent, "111@s.whatsapp.net");
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
    assert_eq!(
        decoded
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("store-backed story")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_image_with_signal_provider_encrypts_media_status_participant() {
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
    let remote_one_time_pre_key_id = 112;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![1u8; 32]),
        Bytes::from(vec![2u8; 32]),
        Bytes::from(vec![3u8; 32]),
        1_024,
    )
    .with_url("https://media.example.invalid/status-signal-image")
    .with_direct_path("/v/t62.7118-24/status-signal-image")
    .with_media_key_timestamp(1_700_000_000);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed status photo".to_owned());
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_image_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        MessageRelayOptions::new().with_message_id("status-signal-media-1"),
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
    assert_eq!(relay.message_id, "status-signal-media-1");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net"]
    );

    let enc = test_participant_enc_node(&sent, "111@s.whatsapp.net");
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
    let image = decoded.image_message.unwrap();
    assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(image.caption.as_deref(), Some("store-backed status photo"));
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-signal-image")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_image_with_signal_provider_replays_cached_media_status_retry() {
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
    let remote_one_time_pre_key_id = 123;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![13u8; 32]),
        Bytes::from(vec![14u8; 32]),
        Bytes::from(vec![15u8; 32]),
        8_192,
    )
    .with_url("https://media.example.invalid/status-signal-retry-image")
    .with_direct_path("/v/t62.7118-24/status-signal-retry-image")
    .with_media_key_timestamp(1_700_000_011);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed retryable status photo".to_owned());
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_image_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        MessageRelayOptions::new().with_message_id("status-signal-media-retry-1"),
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
                                        .with_attr("id", "1")
                                        .with_attr("key-index", "1"),
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
                vec![("111:1@s.whatsapp.net".to_owned(), None)]
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
    assert_eq!(relay.message_id, "status-signal-media-retry-1");
    assert_eq!(relay.recipient_count, 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-media-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111:1@s.whatsapp.net"]
    );
    let first_enc = test_participant_enc_node(&sent, "111:1@s.whatsapp.net");
    assert_eq!(first_enc.attrs["type"], "pkmsg");
    let first_ciphertext = test_node_bytes(first_enc).unwrap();
    let first_message = wa_core::decode_signal_pre_key_whisper_message(&first_ciphertext).unwrap();
    assert_eq!(first_message.pre_key_id, Some(remote_one_time_pre_key_id));
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
    assert!(first_decoded.device_sent_message.is_none());
    let first_image = first_decoded.image_message.unwrap();
    assert_eq!(first_image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(
        first_image.caption.as_deref(),
        Some("store-backed retryable status photo")
    );
    assert_eq!(
        first_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-signal-retry-image")
    );

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-media-retry-1".to_owned()],
        from_jid: Some("111:1@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
                registration_id: Some(remote_credentials.registration_id),
                base_key: None,
                signal_address: None,
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(
        plan.resend_target,
        wa_core::RetryResendTarget::Participant {
            jid: "111:1@s.whatsapp.net".to_owned(),
            count: 1,
        }
    );
    let prepared = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let relays = client
        .execute_retry_resends_with_signal_provider(&connection, &prepared)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-media-retry-1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-media-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "media");
    let resent_enc = test_participant_enc_node(&resent, "111:1@s.whatsapp.net");
    assert_eq!(resent_enc.attrs["type"], "msg");
    let resent_ciphertext = test_node_bytes(resent_enc).unwrap();
    let resent_decrypted = wa_core::decrypt_signal_provider_session_record_message(
        &first_decrypted.record,
        &resent_ciphertext,
        &remote_material.identity.public_key,
    )
    .unwrap();
    assert_eq!(resent_decrypted.message.counter, 1);
    let resent_unpadded = wa_core::unpad_random_max16(&resent_decrypted.plaintext).unwrap();
    let resent_decoded = wa_proto::proto::Message::decode(resent_unpadded).unwrap();
    assert!(resent_decoded.device_sent_message.is_none());
    let resent_image = resent_decoded.image_message.unwrap();
    assert_eq!(resent_image.mimetype.as_deref(), Some("image/jpeg"));
    assert_eq!(
        resent_image.caption.as_deref(),
        Some("store-backed retryable status photo")
    );
    assert_eq!(
        resent_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-signal-retry-image")
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
        vec!["status-signal-media-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_image_with_signal_provider_replays_cached_media_status_all_device_retry() {
    fn all_device_status_usync_response(node: BinaryNode) -> BinaryNode {
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
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "0"),
                                BinaryNode::new("device")
                                    .with_attr("id", "1")
                                    .with_attr("key-index", "1"),
                            ]),
                        ])]),
                    BinaryNode::new("user")
                        .with_attr("jid", "999@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "7"),
                                BinaryNode::new("device")
                                    .with_attr("id", "8")
                                    .with_attr("key-index", "8"),
                            ]),
                        ])]),
                ]),
            ])])
    }

    fn assert_signal_media_status_payload(
        decoded: wa_proto::proto::Message,
        expected_device_sent: bool,
    ) {
        let image = if expected_device_sent {
            let device_sent = decoded.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            device_sent.message.unwrap().image_message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.image_message.unwrap()
        };
        assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(
            image.caption.as_deref(),
            Some("store-backed all-device retryable status photo")
        );
        assert_eq!(
            image.direct_path.as_deref(),
            Some("/v/t62.7118-24/status-signal-all-retry-image")
        );
    }

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
    let remote_one_time_pre_key_id = 124;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![19u8; 32]),
        Bytes::from(vec![20u8; 32]),
        Bytes::from(vec![21u8; 32]),
        32_768,
    )
    .with_url("https://media.example.invalid/status-signal-all-retry-image")
    .with_direct_path("/v/t62.7118-24/status-signal-all-retry-image")
    .with_media_key_timestamp(1_700_000_013);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed all-device retryable status photo".to_owned());
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_image_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        MessageRelayOptions::new().with_message_id("status-signal-media-all-retry-1"),
    );
    tokio::pin!(send_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        all_device_status_usync_response,
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
                    ("111:1@s.whatsapp.net".to_owned(), None),
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
    assert_eq!(relay.message_id, "status-signal-media-all-retry-1");
    assert_eq!(relay.recipient_count, 3);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "status-signal-media-all-retry-1");
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );

    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let mut first_records = BTreeMap::new();
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
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
        assert_signal_media_status_payload(decoded, expected_device_sent);
        first_records.insert(jid.to_owned(), decrypted.record);
        assert!(
            client
                .signal_provider_state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .is_some()
        );
    }

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["status-signal-media-all-retry-1".to_owned()],
        from_jid: Some("111@s.whatsapp.net".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
        chat_jid: Some(wa_core::STATUS_BROADCAST_JID.to_owned()),
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
    assert_eq!(plan.remote_jid, wa_core::STATUS_BROADCAST_JID);
    assert_eq!(plan.participant_jid, "111@s.whatsapp.net");
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
        all_device_status_usync_response,
        &mut retry_fut,
    )
    .await;

    let relays = retry_fut.await.unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "status-signal-media-all-retry-1");
    assert_eq!(relays[0].recipient_count, 3);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "status-signal-media-all-retry-1");
    assert_eq!(resent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(resent.attrs["type"], "media");
    let resent_participants = test_children(test_child(&resent, "participants"), "to");
    assert_eq!(
        resent_participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec![
            "111@s.whatsapp.net",
            "111:1@s.whatsapp.net",
            "999:8@s.whatsapp.net"
        ]
    );
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
        ("111:1@s.whatsapp.net", false),
        ("999:8@s.whatsapp.net", true),
    ] {
        let enc = test_participant_enc_node(&resent, jid);
        assert_eq!(enc.attrs["type"], "msg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let first_record = first_records.get(jid).unwrap();
        let decrypted = wa_core::decrypt_signal_provider_session_record_message(
            first_record,
            &ciphertext,
            &remote_material.identity.public_key,
        )
        .unwrap();
        assert_eq!(decrypted.message.counter, 1);
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        assert_signal_media_status_payload(decoded, expected_device_sent);
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
        vec!["status-signal-media-all-retry-1"]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_image_with_signal_provider_encrypts_media_status_and_own_linked_device() {
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
    let remote_one_time_pre_key_id = 113;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![4u8; 32]),
        Bytes::from(vec![5u8; 32]),
        Bytes::from(vec![6u8; 32]),
        2_048,
    )
    .with_url("https://media.example.invalid/status-signal-linked-image")
    .with_direct_path("/v/t62.7118-24/status-signal-linked-image")
    .with_media_key_timestamp(1_700_000_001);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed linked status photo".to_owned());
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_image_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        MessageRelayOptions::new().with_message_id("status-signal-media-linked-1"),
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
    assert_eq!(relay.message_id, "status-signal-media-linked-1");
    assert_eq!(relay.recipient_count, 2);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
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
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
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
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            device_sent.message.unwrap().image_message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.image_message.unwrap()
        };
        assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(
            image.caption.as_deref(),
            Some("store-backed linked status photo")
        );
        assert_eq!(
            image.direct_path.as_deref(),
            Some("/v/t62.7118-24/status-signal-linked-image")
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
async fn send_status_image_signal_deduplicates_own_pn_lid_linked_device_aliases() {
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
    let remote_one_time_pre_key_id = 115;
    let image_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![16u8; 32]),
        Bytes::from(vec![17u8; 32]),
        Bytes::from(vec![18u8; 32]),
        5_120,
    )
    .with_url("https://media.example.invalid/status-signal-own-alias-image")
    .with_direct_path("/v/t62.7118-24/status-signal-own-alias-image")
    .with_media_key_timestamp(1_700_000_004);
    let mut image = wa_core::ImageContent::new(image_media, "image/jpeg");
    image.caption = Some("store-backed own alias status photo".to_owned());
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_image_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        image,
        MessageRelayOptions::new().with_message_id("status-signal-media-own-alias-dedup-1"),
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
    assert_eq!(relay.message_id, "status-signal-media-own-alias-dedup-1");
    assert_eq!(relay.recipient_count, 2);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "media");
    assert!(sent.attrs.contains_key("phash"));
    let participants = test_children(test_child(&sent, "participants"), "to");
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
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
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
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            device_sent.message.unwrap().image_message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.image_message.unwrap()
        };
        assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(
            image.caption.as_deref(),
            Some("store-backed own alias status photo")
        );
        assert_eq!(
            image.direct_path.as_deref(),
            Some("/v/t62.7118-24/status-signal-own-alias-image")
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
async fn send_status_image_signal_reuses_established_sessions_for_own_linked_device() {
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
    let remote_one_time_pre_key_id = 114;
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let first_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![7u8; 32]),
        Bytes::from(vec![8u8; 32]),
        Bytes::from(vec![9u8; 32]),
        3_072,
    )
    .with_url("https://media.example.invalid/status-established-first-image")
    .with_direct_path("/v/t62.7118-24/status-established-first-image")
    .with_media_key_timestamp(1_700_000_002);
    let mut first_image = wa_core::ImageContent::new(first_media, "image/jpeg");
    first_image.caption = Some("first linked status photo".to_owned());
    let first_send = client.send_status_image_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        first_image,
        MessageRelayOptions::new().with_message_id("status-signal-media-established-1"),
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
    assert_eq!(first_relay.message_id, "status-signal-media-established-1");
    assert_eq!(first_relay.recipient_count, 2);
    let first_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_node, first_relay.node);
    assert_eq!(first_node.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(first_node.attrs["type"], "media");
    let first_participants = test_children(test_child(&first_node, "participants"), "to");
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

    let first_audience_ciphertext =
        test_node_bytes(test_participant_enc_node(&first_node, "111@s.whatsapp.net")).unwrap();
    let first_audience_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_audience_ciphertext,
    )
    .unwrap();
    let first_audience_unpadded =
        wa_core::unpad_random_max16(&first_audience_decrypted.plaintext).unwrap();
    let first_audience_decoded = wa_proto::proto::Message::decode(first_audience_unpadded).unwrap();
    let first_audience_image = first_audience_decoded.image_message.unwrap();
    assert_eq!(
        first_audience_image.caption.as_deref(),
        Some("first linked status photo")
    );
    assert_eq!(
        first_audience_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-established-first-image")
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
        Some(wa_core::STATUS_BROADCAST_JID)
    );
    let first_own_image = first_device_sent.message.unwrap().image_message.unwrap();
    assert_eq!(
        first_own_image.caption.as_deref(),
        Some("first linked status photo")
    );
    assert_eq!(
        first_own_image.direct_path.as_deref(),
        Some("/v/t62.7118-24/status-established-first-image")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("ownlid:8@lid")
            .await
            .unwrap()
            .is_none()
    );

    let second_media = wa_core::UploadedMedia::new(
        Bytes::from(vec![10u8; 32]),
        Bytes::from(vec![11u8; 32]),
        Bytes::from(vec![12u8; 32]),
        4_096,
    )
    .with_url("https://media.example.invalid/status-established-second-image")
    .with_direct_path("/v/t62.7118-24/status-established-second-image")
    .with_media_key_timestamp(1_700_000_003);
    let mut second_image = wa_core::ImageContent::new(second_media, "image/jpeg");
    second_image.caption = Some("second linked status photo".to_owned());
    let second_send = client.send_status_image_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        second_image,
        MessageRelayOptions::new().with_message_id("status-signal-media-established-2"),
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
        &mut second_send,
    )
    .await;

    let second_relay = tokio::time::timeout(Duration::from_secs(1), &mut second_send)
        .await
        .expect(
            "second linked media status should reuse both provider sessions without key-bundle query",
        )
        .unwrap();
    assert_eq!(second_relay.message_id, "status-signal-media-established-2");
    assert_eq!(second_relay.recipient_count, 2);
    let second_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_node, second_relay.node);
    assert_eq!(second_node.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(second_node.attrs["type"], "media");
    assert!(second_node.attrs.contains_key("phash"));
    let participants = test_children(test_child(&second_node, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );

    for (jid, first_record, expected_device_sent) in [
        (
            "111@s.whatsapp.net",
            &first_audience_decrypted.record,
            false,
        ),
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
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            device_sent.message.unwrap().image_message.unwrap()
        } else {
            assert!(decoded.device_sent_message.is_none());
            decoded.image_message.unwrap()
        };
        assert_eq!(image.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(image.caption.as_deref(), Some("second linked status photo"));
        assert_eq!(
            image.direct_path.as_deref(),
            Some("/v/t62.7118-24/status-established-second-image")
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
async fn send_status_signal_normalizes_legacy_c_us_targets_and_device_results() {
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
    let remote_one_time_pre_key_id = 110;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_text_with_signal_provider(
        &connection,
        ["111@c.us", "111@s.whatsapp.net"],
        "store-backed canonical story",
        MessageRelayOptions::new().with_message_id("status-signal-cus-normalized"),
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
    assert_eq!(relay.message_id, "status-signal-cus-normalized");
    assert_eq!(relay.recipient_count, 1);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "text");
    let participants = test_children(test_child(&sent, "participants"), "to");
    assert_eq!(
        participants
            .iter()
            .map(|node| node.attrs["jid"].as_str())
            .collect::<Vec<_>>(),
        vec!["111@s.whatsapp.net"]
    );

    let enc = test_participant_enc_node(&sent, "111@s.whatsapp.net");
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
        Some("store-backed canonical story")
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_session_record("111@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_text_with_signal_provider_encrypts_audience_and_own_linked_device() {
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
    let remote_one_time_pre_key_id = 99;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "store-backed linked story",
        MessageRelayOptions::new().with_message_id("status-signal-linked-1"),
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
    assert_eq!(relay.message_id, "status-signal-linked-1");
    assert_eq!(relay.recipient_count, 2);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "text");
    let participants = test_children(test_child(&sent, "participants"), "to");
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
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
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
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("store-backed linked story")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("store-backed linked story")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_signal_deduplicates_own_pn_lid_linked_device_aliases() {
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
    let remote_one_time_pre_key_id = 108;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let send_fut = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "store-backed own alias story",
        MessageRelayOptions::new().with_message_id("status-signal-own-alias-dedup-1"),
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
    assert_eq!(relay.message_id, "status-signal-own-alias-dedup-1");
    assert_eq!(relay.recipient_count, 2);

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, relay.node);
    assert_eq!(sent.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    assert_eq!(sent.attrs["type"], "text");
    let participants = test_children(test_child(&sent, "participants"), "to");
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
    for (jid, expected_device_sent) in [
        ("111@s.whatsapp.net", false),
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
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("store-backed own alias story")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("store-backed own alias story")
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_status_signal_reuses_established_sessions_for_own_linked_device() {
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
    let remote_one_time_pre_key_id = 100;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let first_send = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "first linked status",
        MessageRelayOptions::new().with_message_id("status-signal-linked-established-1"),
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
    assert_eq!(first_relay.message_id, "status-signal-linked-established-1");
    assert_eq!(first_relay.recipient_count, 2);
    let first_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_node.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    let remote_material = test_signal_local_key_material(&remote_credentials);
    let remote_pre_key =
        test_signal_local_pre_key(remote_one_time_pre_key_id, &remote_one_time_pre_key);
    let first_audience_ciphertext =
        test_node_bytes(test_participant_enc_node(&first_node, "111@s.whatsapp.net")).unwrap();
    let first_audience_decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
        &remote_material,
        Some(&remote_pre_key),
        &first_audience_ciphertext,
    )
    .unwrap();
    let first_audience_unpadded =
        wa_core::unpad_random_max16(&first_audience_decrypted.plaintext).unwrap();
    let first_audience_decoded = wa_proto::proto::Message::decode(first_audience_unpadded).unwrap();
    assert_eq!(
        first_audience_decoded
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("first linked status")
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
        Some(wa_core::STATUS_BROADCAST_JID)
    );
    assert_eq!(
        first_device_sent
            .message
            .unwrap()
            .extended_text_message
            .unwrap()
            .text
            .as_deref(),
        Some("first linked status")
    );

    let second_send = client.send_status_text_with_signal_provider(
        &connection,
        ["111@s.whatsapp.net"],
        "second linked status",
        MessageRelayOptions::new().with_message_id("status-signal-linked-established-2"),
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
        .expect("second linked status should reuse both provider sessions without key-bundle query")
        .unwrap();
    assert_eq!(
        second_relay.message_id,
        "status-signal-linked-established-2"
    );
    assert_eq!(second_relay.recipient_count, 2);
    let second_node = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_node, second_relay.node);
    assert_eq!(second_node.attrs["to"], wa_core::STATUS_BROADCAST_JID);
    for (jid, first_record, expected_device_sent) in [
        (
            "111@s.whatsapp.net",
            &first_audience_decrypted.record,
            false,
        ),
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
                Some(wa_core::STATUS_BROADCAST_JID)
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("second linked status")
            );
        } else {
            assert!(decoded.device_sent_message.is_none());
            assert_eq!(
                decoded.extended_text_message.unwrap().text.as_deref(),
                Some("second linked status")
            );
        }
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
async fn send_text_schedules_post_send_tc_token_issuance() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
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
        MessageRelayOptions::new().with_message_id("msg-tc-issue"),
    );
    tokio::pin!(send_fut);

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
        &mut send_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            session_response_for_query(&node)
        },
        &mut send_fut,
    )
    .await;

    let relay = send_fut.await.unwrap();
    assert_eq!(relay.message_id, "msg-tc-issue");

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.tag, "message");
    assert_eq!(sent.attrs["id"], "msg-tc-issue");

    let privacy = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &privacy.content else {
        panic!("privacy query should have child nodes");
    };
    let tokens = iq_children
        .iter()
        .find(|child| child.tag == "tokens")
        .unwrap();
    let Some(wa_binary::BinaryNodeContent::Nodes(token_children)) = &tokens.content else {
        panic!("tokens node should have token children");
    };
    assert_eq!(token_children.len(), 1);
    assert_eq!(token_children[0].attrs["jid"], "123@s.whatsapp.net");
    assert_eq!(token_children[0].attrs["type"], "trusted_contact");
    let issue_timestamp = token_children[0].attrs["t"].parse::<u64>().unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", privacy.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "ignored@s.whatsapp.net")
                            .with_attr("t", (issue_timestamp + 1).to_string())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"auto-peer-token")),
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
            .and_then(|record| record.sender_timestamp_seconds)
            == Some(issue_timestamp)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loaded = loaded.unwrap();
    assert_eq!(loaded.token, Bytes::from_static(b"auto-peer-token"));
    assert_eq!(loaded.timestamp_seconds, Some(issue_timestamp + 1));
    assert_eq!(loaded.sender_timestamp_seconds, Some(issue_timestamp));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn post_send_tc_token_issuance_coalesces_duplicate_in_flight_targets() {
    let store = wa_store::MemoryAuthStore::new();
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
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let first_send = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "first",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-tc-coalesce-1"),
    );
    tokio::pin!(first_send);

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
        &mut first_send,
    )
    .await;

    let first_relay = first_send.await.unwrap();
    assert_eq!(first_relay.message_id, "msg-tc-coalesce-1");
    let first_message = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_message.attrs["id"], "msg-tc-coalesce-1");

    let privacy_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("first send should spawn a tc-token issue query")
        .expect("connection sink should stay open");
    let privacy = decode_inbound_binary_node(&privacy_frame).unwrap().node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    let token = test_child(test_child(&privacy, "tokens"), "token");
    assert_eq!(token.attrs["jid"], "123@s.whatsapp.net");
    assert_eq!(token.attrs["type"], "trusted_contact");
    let issue_timestamp = token.attrs["t"].parse::<u64>().unwrap();

    let second_send = client.send_text(
        &connection,
        "123@s.whatsapp.net",
        "second",
        &encryptor,
        MessageRelayOptions::new().with_message_id("msg-tc-coalesce-2"),
    );
    tokio::pin!(second_send);

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
        &mut second_send,
    )
    .await;

    let second_relay = second_send.await.unwrap();
    assert_eq!(second_relay.message_id, "msg-tc-coalesce-2");
    let second_message = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_message.attrs["id"], "msg-tc-coalesce-2");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sink_rx.recv())
            .await
            .is_err(),
        "duplicate in-flight tc-token issue should not emit a second privacy query"
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
                            .with_attr("t", (issue_timestamp + 1).to_string())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"coalesced-peer-token")),
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
            .is_some_and(|record| record.token == Bytes::from_static(b"coalesced-peer-token"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loaded = loaded.unwrap();
    assert_eq!(loaded.token, Bytes::from_static(b"coalesced-peer-token"));
    assert_eq!(loaded.timestamp_seconds, Some(issue_timestamp + 1));
    assert_eq!(loaded.sender_timestamp_seconds, Some(issue_timestamp));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn failed_spawned_tc_token_issuance_clears_in_flight_target() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let plan = TcTokenIssuePlan {
        storage_jid: "123@s.whatsapp.net".to_owned(),
        issue_jid: "123@s.whatsapp.net".to_owned(),
        timestamp_seconds: 1_700_000_000,
    };

    assert!(
        client
            .spawn_tc_token_issue_after_send(&connection, plan.clone())
            .unwrap()
    );
    assert!(
        !client
            .spawn_tc_token_issue_after_send(&connection, plan.clone())
            .unwrap()
    );

    let failed_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("spawned tctoken issue should send a privacy IQ")
        .expect("connection sink should stay open");
    let failed_query = decode_inbound_binary_node(&failed_frame).unwrap().node;
    assert_eq!(failed_query.attrs["xmlns"], "privacy");
    let failed_token = test_child(test_child(&failed_query, "tokens"), "token");
    assert_eq!(failed_token.attrs["jid"], "123@s.whatsapp.net");
    assert_eq!(failed_token.attrs["t"], "1700000000");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&error_result_for(&failed_query, "500", "privacy down")).unwrap(),
        ))
        .await
        .unwrap();

    let mut cleared = false;
    for _ in 0..20 {
        if client
            .try_begin_tc_token_issuance("123@s.whatsapp.net")
            .unwrap()
        {
            client.finish_tc_token_issuance("123@s.whatsapp.net");
            cleared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        cleared,
        "failed spawned tctoken issue should clear in-flight state"
    );
    assert!(
        wa_core::load_tc_token(&store, "123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    let retry_plan = TcTokenIssuePlan {
        timestamp_seconds: 1_700_000_010,
        ..plan
    };
    assert!(
        client
            .spawn_tc_token_issue_after_send(&connection, retry_plan)
            .unwrap()
    );
    let retry_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("retry tctoken issue should send a new privacy IQ")
        .expect("connection sink should stay open");
    let retry_query = decode_inbound_binary_node(&retry_frame).unwrap().node;
    assert_eq!(retry_query.attrs["xmlns"], "privacy");
    let retry_token = test_child(test_child(&retry_query, "tokens"), "token");
    assert_eq!(retry_token.attrs["jid"], "123@s.whatsapp.net");
    assert_eq!(retry_token.attrs["t"], "1700000010");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", retry_query.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "ignored@s.whatsapp.net")
                            .with_attr("t", "1700000011")
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"retry-after-failed-token")),
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
            .is_some_and(|record| record.token == Bytes::from_static(b"retry-after-failed-token"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loaded = loaded.unwrap();
    assert_eq!(
        loaded.token,
        Bytes::from_static(b"retry-after-failed-token")
    );
    assert_eq!(loaded.timestamp_seconds, Some(1_700_000_011));
    assert_eq!(loaded.sender_timestamp_seconds, Some(1_700_000_010));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn issue_tc_token_queries_privacy_and_marks_sender_timestamp() {
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
            lid: "abc@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let issue_fut =
        client.issue_tc_token_with_options(&connection, "123@s.whatsapp.net", true, 1_700_000_000);
    tokio::pin!(issue_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "privacy");
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(node.attrs["to"], wa_core::SERVER_JID);
            let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &node.content else {
                panic!("privacy query should have child nodes");
            };
            let tokens = iq_children
                .iter()
                .find(|child| child.tag == "tokens")
                .unwrap();
            let Some(wa_binary::BinaryNodeContent::Nodes(token_children)) = &tokens.content else {
                panic!("tokens node should have token children");
            };
            assert_eq!(token_children.len(), 1);
            assert_eq!(token_children[0].attrs["jid"], "abc@lid");
            assert_eq!(token_children[0].attrs["t"], "1700000000");
            assert_eq!(token_children[0].attrs["type"], "trusted_contact");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                    BinaryNode::new("token")
                        .with_attr("jid", "ignored@s.whatsapp.net")
                        .with_attr("t", "1700000001")
                        .with_attr("type", "trusted_contact")
                        .with_content(Bytes::from_static(b"peer-token")),
                ])])
        },
        &mut issue_fut,
    )
    .await;

    let outcome = issue_fut.await.unwrap().unwrap();
    assert_eq!(outcome.storage_jid, "abc@lid");
    assert_eq!(outcome.issue_jid, "abc@lid");
    assert_eq!(outcome.timestamp_seconds, 1_700_000_000);
    assert_eq!(outcome.stored_tokens.len(), 1);
    assert_eq!(
        outcome.sender_record.token,
        Bytes::from_static(b"peer-token")
    );
    assert_eq!(
        outcome.sender_record.sender_timestamp_seconds,
        Some(1_700_000_000)
    );
    let loaded = wa_core::load_tc_token(&store, "abc@lid")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.token, Bytes::from_static(b"peer-token"));
    assert_eq!(loaded.timestamp_seconds, Some(1_700_000_001));
    assert_eq!(loaded.sender_timestamp_seconds, Some(1_700_000_000));
    let node = wa_core::load_tc_token_node_for_send(&store, "abc@lid", 1_700_000_002)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(node.tag, "tctoken");
    assert_eq!(
        node.content,
        Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
            b"peer-token"
        )))
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_privacy_token_notification_prefers_sender_lid() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "privacy-sender-lid-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "privacy_token")
        .with_attr("sender_lid", "abc:7@lid")
        .with_content(vec![BinaryNode::new("tokens").with_content(vec![
            BinaryNode::new("token")
                .with_attr("t", "1700000001")
                .with_attr("type", "trusted_contact")
                .with_content(Bytes::from_static(b"sender-lid-token")),
        ])]);

    let outcome = client
        .handle_privacy_token_notification(&notification)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.storage_jid, "abc@lid");
    assert_eq!(outcome.sender_lid.as_deref(), Some("abc@lid"));
    assert_eq!(outcome.stored_tokens.len(), 1);
    assert_eq!(
        wa_core::load_tc_token(&store, "abc@lid")
            .await
            .unwrap()
            .unwrap()
            .token,
        Bytes::from_static(b"sender-lid-token")
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn handle_privacy_token_notification_skips_mapped_self_sender() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "own@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "privacy-mapped-self-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "privacy_token")
        .with_content(vec![BinaryNode::new("tokens").with_content(vec![
            BinaryNode::new("token")
                .with_attr("t", "1700000001")
                .with_attr("type", "trusted_contact")
                .with_content(Bytes::from_static(b"self-token")),
        ])]);

    assert!(
        client
            .handle_privacy_token_notification(&notification)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        wa_core::load_tc_token(&store, "own@lid")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        wa_core::load_tc_token(&store, "123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_stores_privacy_token_notification() {
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
            lid: "abc@lid".to_owned(),
        }])
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "privacy-token-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "privacy_token")
        .with_content(vec![BinaryNode::new("tokens").with_content(vec![
            BinaryNode::new("token")
                .with_attr("t", "1700000001")
                .with_attr("type", "trusted_contact")
                .with_content(Bytes::from_static(b"mapped-token")),
        ])]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &notification, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();
    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "privacy-token-1");
    assert_eq!(ack.attrs["class"], "notification");
    let loaded = wa_core::load_tc_token(&store, "abc@lid")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.token, Bytes::from_static(b"mapped-token"));
    assert_eq!(loaded.timestamp_seconds, Some(1_700_000_001));
    assert_eq!(loaded.sender_timestamp_seconds, None);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_ack_463_schedules_tc_token_recovery() {
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
            lid: "abc@lid".to_owned(),
        }])
        .await
        .unwrap();
    let config = ClientConfig {
        lid_trusted_token_issue_to_lid: true,
        ..ClientConfig::default()
    };
    let client = Client::builder(store.clone())
        .config(config)
        .connect()
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let ack = BinaryNode::new("ack")
        .with_attr("id", "msg-463")
        .with_attr("class", "message")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("error", wa_core::ACK_ERROR_ACCOUNT_RESTRICTED.to_string());
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &ack, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();
    assert_eq!(result.action, wa_core::InboundNodeAction::Ack);
    assert_eq!(result.event_count, 1);
    assert!(result.response.is_none());
    assert!(result.error.is_none());

    let privacy_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let privacy = decode_inbound_binary_node(&privacy_frame).unwrap().node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    assert_eq!(privacy.attrs["type"], "set");
    let tokens = test_child(&privacy, "tokens");
    let token_children = test_children(tokens, "token");
    assert_eq!(token_children.len(), 1);
    assert_eq!(token_children[0].attrs["jid"], "abc@lid");
    assert_eq!(token_children[0].attrs["type"], "trusted_contact");
    let issue_timestamp = token_children[0].attrs["t"].parse::<u64>().unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", privacy.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "ignored@s.whatsapp.net")
                            .with_attr("t", (issue_timestamp + 1).to_string())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"ack-463-token")),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let mut loaded = None;
    for _ in 0..20 {
        loaded = wa_core::load_tc_token(&store, "abc@lid").await.unwrap();
        if loaded
            .as_ref()
            .is_some_and(|record| record.token == Bytes::from_static(b"ack-463-token"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loaded = loaded.unwrap();
    assert_eq!(loaded.token, Bytes::from_static(b"ack-463-token"));
    assert_eq!(loaded.timestamp_seconds, Some(issue_timestamp + 1));
    assert_eq!(loaded.sender_timestamp_seconds, Some(issue_timestamp));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn ack_463_tc_token_recovery_coalesces_with_existing_in_flight_issue() {
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
            lid: "abc@lid".to_owned(),
        }])
        .await
        .unwrap();
    let config = ClientConfig {
        lid_trusted_token_issue_to_lid: true,
        ..ClientConfig::default()
    };
    let client = Client::builder(store.clone())
        .config(config)
        .connect()
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let plan = TcTokenIssuePlan {
        storage_jid: "abc@lid".to_owned(),
        issue_jid: "abc@lid".to_owned(),
        timestamp_seconds: 1_700_000_000,
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
    let token = test_child(test_child(&privacy, "tokens"), "token");
    assert_eq!(token.attrs["jid"], "abc@lid");
    assert_eq!(token.attrs["t"], "1700000000");

    let ack = BinaryNode::new("ack")
        .with_attr("id", "msg-463-coalesced")
        .with_attr("class", "message")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("error", wa_core::ACK_ERROR_ACCOUNT_RESTRICTED.to_string());
    let outcome = client
        .handle_ack_error_tc_token_recovery(&connection, &ack)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.ack_id, "msg-463-coalesced");
    assert_eq!(outcome.remote_jid, "123@s.whatsapp.net");
    assert_eq!(outcome.storage_jid, "abc@lid");
    assert_eq!(outcome.issue_jid, "abc@lid");
    assert!(!outcome.scheduled);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sink_rx.recv())
            .await
            .is_err(),
        "ACK 463 recovery should not emit a duplicate privacy IQ while in flight"
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
                            .with_attr("t", "1700000001")
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"ack-coalesced-token")),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let mut loaded = None;
    for _ in 0..20 {
        loaded = wa_core::load_tc_token(&store, "abc@lid").await.unwrap();
        if loaded
            .as_ref()
            .is_some_and(|record| record.token == Bytes::from_static(b"ack-coalesced-token"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loaded = loaded.unwrap();
    assert_eq!(loaded.token, Bytes::from_static(b"ack-coalesced-token"));
    assert_eq!(loaded.timestamp_seconds, Some(1_700_000_001));
    assert_eq!(loaded.sender_timestamp_seconds, Some(1_700_000_000));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn ack_463_tc_token_recovery_skips_mapped_self_targets_without_query() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "own@lid".to_owned(),
        }])
        .await
        .unwrap();
    let config = ClientConfig {
        lid_trusted_token_issue_to_lid: true,
        ..ClientConfig::default()
    };
    let client = Client::builder(store)
        .config(config)
        .connect()
        .await
        .unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mapped_self_ack = BinaryNode::new("ack")
        .with_attr("id", "msg-463-mapped-self")
        .with_attr("class", "message")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("error", wa_core::ACK_ERROR_ACCOUNT_RESTRICTED.to_string());

    assert!(
        client
            .handle_ack_error_tc_token_recovery(&connection, &mapped_self_ack)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sink_rx.recv())
            .await
            .is_err(),
        "mapped self ACK 463 should not emit a privacy-token recovery query"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn offline_wrapper_child_ack_463_schedules_tc_token_recovery() {
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
            lid: "abc@lid".to_owned(),
        }])
        .await
        .unwrap();
    let config = ClientConfig {
        lid_trusted_token_issue_to_lid: true,
        ..ClientConfig::default()
    };
    let client = Client::builder(store.clone())
        .config(config)
        .connect()
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let offline = BinaryNode::new("offline").with_content(vec![
        BinaryNode::new("ack")
            .with_attr("id", "offline-msg-463")
            .with_attr("class", "message")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("error", wa_core::ACK_ERROR_ACCOUNT_RESTRICTED.to_string()),
    ]);

    client
        .handle_incoming_node_side_effects(&connection, &offline)
        .await
        .unwrap();

    let privacy_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let privacy = decode_inbound_binary_node(&privacy_frame).unwrap().node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    let token = test_child(test_child(&privacy, "tokens"), "token");
    assert_eq!(token.attrs["jid"], "abc@lid");
    let issue_timestamp = token.attrs["t"].parse::<u64>().unwrap();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", privacy.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("t", (issue_timestamp + 1).to_string())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"offline-ack-463-token")),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let mut loaded = None;
    for _ in 0..20 {
        loaded = wa_core::load_tc_token(&store, "abc@lid").await.unwrap();
        if loaded
            .as_ref()
            .is_some_and(|record| record.token == Bytes::from_static(b"offline-ack-463-token"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        loaded.unwrap().token,
        Bytes::from_static(b"offline-ack-463-token")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn issue_tc_token_skips_self_targets_without_query() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();

    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.issue_tc_token_with_options(
                &connection,
                "999:7@s.whatsapp.net",
                false,
                1_700_000_000,
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.issue_tc_token_with_options(&connection, "own@lid", false, 1_700_000_000),
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn tc_token_paths_skip_mapped_self_lid_targets() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "999@s.whatsapp.net".to_owned(),
            lid: "own@lid".to_owned(),
        }])
        .await
        .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("own@lid", Bytes::from_static(b"mapped-self-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp())
            .with_sender_timestamp_seconds(1_700_000_000),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();

    let options = client
        .message_relay_options_with_tc_token("own@lid", MessageRelayOptions::new())
        .await
        .unwrap();
    assert!(!options.has_additional_node("tctoken"));

    let message = wa_core::build_text_message("mapped self").unwrap();
    assert!(
        client
            .tc_token_issue_after_send_plan("own@lid", &message, &MessageRelayOptions::new())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .tc_token_reissue_after_identity_change_plan("own@lid", 1_700_000_060)
            .await
            .unwrap()
            .is_none()
    );

    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.issue_tc_token_with_options(&connection, "own@lid", false, 1_700_000_000,),
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn prune_expired_tc_tokens_facade_removes_stale_records() {
    let store = wa_store::MemoryAuthStore::new();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("111@s.whatsapp.net", Bytes::from_static(b"valid"))
            .unwrap()
            .with_timestamp_seconds(now),
    )
    .await
    .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("222@s.whatsapp.net", Bytes::from_static(b"expired"))
            .unwrap()
            .with_timestamp_seconds(1),
    )
    .await
    .unwrap();

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let outcome = client
        .prune_expired_tc_tokens_with_batch_size(1)
        .await
        .unwrap();
    assert_eq!(outcome.scanned, 2);
    assert_eq!(outcome.retained, 1);
    assert_eq!(outcome.deleted, 1);
    assert!(
        wa_core::load_tc_token(&store, "111@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        wa_core::load_tc_token(&store, "222@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn tc_token_prune_maintenance_runs_on_open_and_throttles() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("111@s.whatsapp.net", Bytes::from_static(b"expired"))
            .unwrap()
            .with_timestamp_seconds(1),
    )
    .await
    .unwrap();

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut maintenance = client
        .spawn_tc_token_prune_on_connection_open(Duration::from_secs(60), 1)
        .unwrap();
    let (first_connection, _sink_rx, _stream_tx) =
        mock_connection_with_events(client.events.clone());
    for _ in 0..20 {
        if wa_core::load_tc_token(&store, "111@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        wa_core::load_tc_token(&store, "111@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
    );

    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("222@s.whatsapp.net", Bytes::from_static(b"expired"))
            .unwrap()
            .with_timestamp_seconds(1),
    )
    .await
    .unwrap();
    let (second_connection, _sink_rx, _stream_tx) =
        mock_connection_with_events(client.events.clone());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        wa_core::load_tc_token(&store, "222@s.whatsapp.net")
            .await
            .unwrap()
            .is_some()
    );

    first_connection.close().await.unwrap();
    second_connection.close().await.unwrap();
    maintenance.abort();

    let invalid_interval = match client.spawn_tc_token_prune_on_connection_open(Duration::ZERO, 1) {
        Ok(_) => panic!("zero prune interval should be rejected"),
        Err(err) => err,
    };
    assert!(
        invalid_interval
            .to_string()
            .contains("tctoken prune interval must be non-zero")
    );
    let invalid_batch =
        match client.spawn_tc_token_prune_on_connection_open(Duration::from_secs(1), 0) {
            Ok(_) => panic!("zero prune batch should be rejected"),
            Err(err) => err,
        };
    assert!(
        invalid_batch
            .to_string()
            .contains("tctoken prune batch size must be non-zero")
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn high_level_relay_options_add_reporting_token_for_secret_messages() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let message = wa_core::build_poll_message(wa_core::PollContent::new(
        "Lunch?",
        ["Rice", "Noodles"],
        1,
        Bytes::from(vec![9u8; 32]),
    ))
    .unwrap();

    let options = client
        .message_relay_options_with_sender(MessageRelayOptions::new().with_message_id("msg-1"))
        .unwrap();
    let options =
        Client::<wa_store::MemoryAuthStore>::message_relay_options_with_generated_id(options)
            .unwrap();
    let options = Client::<wa_store::MemoryAuthStore>::message_relay_options_with_reporting(
        "123@s.whatsapp.net",
        &message,
        options,
    )
    .unwrap();

    let reporting = options
        .additional_nodes
        .iter()
        .find(|node| node.tag == "reporting")
        .expect("reporting node should be attached");
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
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[test]
fn reporting_options_preserve_explicit_reporting_and_skip_peer_category() {
    let message = wa_core::build_poll_message(wa_core::PollContent::new(
        "Lunch?",
        ["Rice", "Noodles"],
        1,
        Bytes::from(vec![9u8; 32]),
    ))
    .unwrap();
    let caller_reporting = BinaryNode::new("reporting").with_content(vec![
        BinaryNode::new("reporting_token")
            .with_attr("v", "caller")
            .with_content(Bytes::from_static(b"caller-token")),
    ]);
    let caller_options = MessageRelayOptions::new()
        .with_message_id("msg-caller-reporting")
        .with_node(caller_reporting.clone())
        .with_node(BinaryNode::new("meta").with_attr("appdata", "default"));

    let caller_options = Client::<wa_store::MemoryAuthStore>::message_relay_options_with_reporting(
        "123@s.whatsapp.net",
        &message,
        caller_options,
    )
    .unwrap();

    assert_eq!(
        caller_options
            .additional_nodes
            .iter()
            .filter(|node| node.tag == "reporting")
            .count(),
        1
    );
    assert_eq!(caller_options.additional_nodes[0], caller_reporting);
    assert!(caller_options.has_additional_node("meta"));

    let peer_options = MessageRelayOptions::new()
        .with_message_id("msg-peer-reporting")
        .with_attribute("category", "peer")
        .with_node(BinaryNode::new("meta").with_attr("appdata", "default"));
    let peer_options = Client::<wa_store::MemoryAuthStore>::message_relay_options_with_reporting(
        "123@s.whatsapp.net",
        &message,
        peer_options,
    )
    .unwrap();

    assert_eq!(peer_options.additional_attributes["category"], "peer");
    assert!(peer_options.has_additional_node("meta"));
    assert!(!peer_options.has_additional_node("reporting"));
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn relay_options_attach_tc_token_for_legacy_cus_target() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"legacy-target-token"),
        )
        .unwrap()
        .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();

    let options = client
        .message_relay_options_with_tc_token("123@c.us", MessageRelayOptions::new())
        .await
        .unwrap();
    let token_node = options
        .additional_nodes
        .iter()
        .find(|node| node.tag == "tctoken")
        .expect("tctoken should be attached for normalized PN target");
    assert_eq!(
        test_node_bytes(token_node),
        Some(Bytes::from_static(b"legacy-target-token"))
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn relay_options_preserve_explicit_tc_token_and_skip_peer_category() {
    let store = wa_store::MemoryAuthStore::new();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"stored-target-token"),
        )
        .unwrap()
        .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let caller_token = BinaryNode::new("tctoken").with_content(Bytes::from_static(b"caller"));
    let caller_options = MessageRelayOptions::new()
        .with_node(caller_token.clone())
        .with_node(BinaryNode::new("meta").with_attr("appdata", "default"));

    let caller_options = client
        .message_relay_options_with_tc_token("123@s.whatsapp.net", caller_options)
        .await
        .unwrap();

    assert_eq!(
        caller_options
            .additional_nodes
            .iter()
            .filter(|node| node.tag == "tctoken")
            .count(),
        1
    );
    assert_eq!(caller_options.additional_nodes[0], caller_token);
    assert!(caller_options.has_additional_node("meta"));

    let peer_options = MessageRelayOptions::new()
        .with_attribute("category", "peer")
        .with_node(BinaryNode::new("meta").with_attr("appdata", "default"));
    let peer_options = client
        .message_relay_options_with_tc_token("123@s.whatsapp.net", peer_options)
        .await
        .unwrap();

    assert_eq!(peer_options.additional_attributes["category"], "peer");
    assert!(peer_options.has_additional_node("meta"));
    assert!(!peer_options.has_additional_node("tctoken"));
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn post_send_tc_token_plan_skips_peer_category_and_protocol_messages() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let message = wa_core::build_text_message("eligible").unwrap();

    let eligible = client
        .tc_token_issue_after_send_plan("123@s.whatsapp.net", &message, &MessageRelayOptions::new())
        .await
        .unwrap();
    assert!(eligible.is_some());

    let peer_options = MessageRelayOptions::new().with_attribute("category", "peer");
    let peer = client
        .tc_token_issue_after_send_plan("123@s.whatsapp.net", &message, &peer_options)
        .await
        .unwrap();
    assert!(peer.is_none());

    let delete = wa_core::build_delete_message(wa_core::DeleteContent {
        key: MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(true),
            id: Some("delete-me".to_owned()),
            participant: None,
        },
    })
    .unwrap();
    let protocol = client
        .tc_token_issue_after_send_plan("123@s.whatsapp.net", &delete, &MessageRelayOptions::new())
        .await
        .unwrap();
    assert!(protocol.is_none());
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn post_send_tc_token_plan_respects_sender_timestamp_bucket() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let message = wa_core::build_text_message("freshness").unwrap();

    let initial = client
        .tc_token_issue_after_send_plan("123@s.whatsapp.net", &message, &MessageRelayOptions::new())
        .await
        .unwrap()
        .expect("missing sender marker should schedule post-send token issue");
    assert_eq!(initial.storage_jid, "123@s.whatsapp.net");
    assert_eq!(initial.issue_jid, "123@s.whatsapp.net");

    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::sender_marker("123@s.whatsapp.net", now).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        client
            .tc_token_issue_after_send_plan(
                "123@s.whatsapp.net",
                &message,
                &MessageRelayOptions::new(),
            )
            .await
            .unwrap()
            .is_none()
    );

    let stale_sender_timestamp = now.saturating_sub(wa_core::TC_TOKEN_BUCKET_DURATION_SECONDS);
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::sender_marker("123@s.whatsapp.net", stale_sender_timestamp)
            .unwrap(),
    )
    .await
    .unwrap();
    let stale = client
        .tc_token_issue_after_send_plan("123@s.whatsapp.net", &message, &MessageRelayOptions::new())
        .await
        .unwrap()
        .expect("stale sender marker should schedule post-send token issue");
    assert_eq!(stale.storage_jid, "123@s.whatsapp.net");
    assert_eq!(stale.issue_jid, "123@s.whatsapp.net");
    assert!(stale.timestamp_seconds >= now);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn identity_change_tc_token_reissue_plan_requires_recent_sender_marker() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let now = current_unix_timestamp();

    assert!(
        client
            .tc_token_reissue_after_identity_change_plan("123@s.whatsapp.net", now)
            .await
            .unwrap()
            .is_none()
    );

    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"stored-without-marker"),
        )
        .unwrap()
        .with_timestamp_seconds(now),
    )
    .await
    .unwrap();
    assert!(
        client
            .tc_token_reissue_after_identity_change_plan("123@s.whatsapp.net", now)
            .await
            .unwrap()
            .is_none()
    );

    let expired_sender_timestamp =
        now.saturating_sub(wa_core::TC_TOKEN_BUCKET_DURATION_SECONDS * 8);
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"expired"))
            .unwrap()
            .with_timestamp_seconds(expired_sender_timestamp)
            .with_sender_timestamp_seconds(expired_sender_timestamp),
    )
    .await
    .unwrap();
    assert!(
        client
            .tc_token_reissue_after_identity_change_plan("123@s.whatsapp.net", now)
            .await
            .unwrap()
            .is_none()
    );

    let recent_sender_timestamp = now.saturating_sub(60);
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"recent"))
            .unwrap()
            .with_timestamp_seconds(recent_sender_timestamp)
            .with_sender_timestamp_seconds(recent_sender_timestamp),
    )
    .await
    .unwrap();
    let plan = client
        .tc_token_reissue_after_identity_change_plan("123@s.whatsapp.net", now)
        .await
        .unwrap()
        .expect("recent sender marker should schedule identity-change reissue");
    assert_eq!(plan.storage_jid, "123@s.whatsapp.net");
    assert_eq!(plan.issue_jid, "123@s.whatsapp.net");
    assert_eq!(plan.timestamp_seconds, recent_sender_timestamp);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn relay_options_and_issue_plan_skip_self_tc_token_targets() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let now = current_unix_timestamp();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("999@s.whatsapp.net", Bytes::from_static(b"self-pn-token"))
            .unwrap()
            .with_timestamp_seconds(now),
    )
    .await
    .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("own@lid", Bytes::from_static(b"self-lid-token"))
            .unwrap()
            .with_timestamp_seconds(now),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();

    let pn_options = client
        .message_relay_options_with_tc_token("999:7@s.whatsapp.net", MessageRelayOptions::new())
        .await
        .unwrap();
    assert!(!pn_options.has_additional_node("tctoken"));
    let lid_options = client
        .message_relay_options_with_tc_token("own@lid", MessageRelayOptions::new())
        .await
        .unwrap();
    assert!(!lid_options.has_additional_node("tctoken"));

    let message = wa_core::build_text_message("self send").unwrap();
    assert!(
        client
            .tc_token_issue_after_send_plan(
                "999:7@s.whatsapp.net",
                &message,
                &MessageRelayOptions::new(),
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .tc_token_issue_after_send_plan("own@lid", &message, &MessageRelayOptions::new(),)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_replays_cached_message_to_requesting_device() {
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
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let message = wa_proto::proto::Message {
        conversation: Some("cached".to_owned()),
        ..wa_proto::proto::Message::default()
    };

    client
        .relay_proto_message_to_devices(
            &connection,
            "123@s.whatsapp.net",
            message.clone(),
            &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
            &encryptor,
            MessageRelayOptions::new().with_message_id("m1"),
        )
        .await
        .unwrap();
    let first = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first.attrs["id"], "m1");

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["m1".to_owned()],
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
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
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

    let relays = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap();

    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "m1");
    assert_eq!(relays[0].recipient_count, 1);
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "m1");
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["123:1@s.whatsapp.net", "123:1@s.whatsapp.net"]
    );
    for call in calls {
        let decoded = wa_proto::proto::Message::decode(call.1).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("cached"));
    }
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 1);
    let prepared_after_success = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_success.jobs.is_empty());
    assert_eq!(prepared_after_success.missing_message_ids, vec!["m1"]);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn plan_retry_resend_normalizes_legacy_c_us_requester_and_chat_before_replay() {
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
            "123@s.whatsapp.net",
            "retry-c-us-plan",
            wa_proto::proto::Message {
                conversation: Some("canonical retry".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();

    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-c-us-plan".to_owned()],
        from_jid: Some("123:1@c.us".to_owned()),
        to_jid: None,
        participant: None,
        recipient: Some("123@c.us".to_owned()),
        chat_jid: Some("123@c.us".to_owned()),
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
    assert_eq!(plan.participant_jid, "123:1@s.whatsapp.net");
    assert_eq!(plan.remote_jid, "123@s.whatsapp.net");
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
    assert_eq!(prepared.jobs[0].requester_jid, "123:1@s.whatsapp.net");

    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let relays = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "retry-c-us-plan");
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "retry-c-us-plan");
    let call_jids = {
        let calls = encryptor.calls.lock().unwrap();
        calls.iter().map(|call| call.0.clone()).collect::<Vec<_>>()
    };
    assert_eq!(call_jids, vec!["123:1@s.whatsapp.net"]);
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_participant_stops_when_session_assertion_fails() {
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
    let prepared = wa_core::RetryResendPreparation {
        jobs: vec![wa_core::RetryResendJob {
            remote_jid: "123@s.whatsapp.net".to_owned(),
            requester_jid: "123:1@s.whatsapp.net".to_owned(),
            message_id: "retry-participant-session-fail".to_owned(),
            message: wa_proto::proto::Message {
                conversation: Some("cached participant retry missing session".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            target: wa_core::RetryResendTarget::Participant {
                jid: "123:1@s.whatsapp.net".to_owned(),
                count: 1,
            },
        }],
        missing_message_ids: Vec::new(),
        session_action: wa_core::RetrySessionAction::None,
        should_clear_group_sender_key: false,
    };
    let retry_fut = client.execute_retry_resends(&connection, &prepared, &encryptor);
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(encryptor.calls.lock().unwrap().is_empty());
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
async fn execute_retry_resends_participant_keeps_cached_message_when_relay_fails() {
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
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let message = wa_proto::proto::Message {
        conversation: Some("cached retry relay failure".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-participant-relay-fails",
            message,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-participant-relay-fails".to_owned()],
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
    assert!(prepared.is_complete());
    assert_eq!(prepared.jobs.len(), 1);

    let err = client
        .execute_retry_resends(
            &connection,
            &prepared,
            &FailingEncryptor::new("retry participant encrypt failed"),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("retry participant encrypt failed"));
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 0);
    assert_eq!(stats.failed_retries, 0);

    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_failure.is_complete());
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert!(prepared_after_failure.missing_message_ids.is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_finalizes_first_participant_replay_when_second_replay_encrypt_fails()
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
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-participant-first-sent",
            wa_proto::proto::Message {
                conversation: Some("first participant retry succeeds".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-participant-second-fails",
            wa_proto::proto::Message {
                conversation: Some("second participant retry fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "retry-participant-first-sent".to_owned(),
            "retry-participant-second-fails".to_owned(),
        ],
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
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
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
    assert_eq!(prepared.jobs.len(), 2);

    let failing_encryptor =
        FailingAfterEncryptor::new(2, "retry participant second replay late encrypt failed");
    let err = client
        .execute_retry_resends(&connection, &prepared, &failing_encryptor)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("retry participant second replay late encrypt failed")
    );
    let calls = failing_encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["123:1@s.whatsapp.net", "123:1@s.whatsapp.net"]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first participant retry succeeds")
    );
    let second_replay_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    assert_eq!(
        second_replay_plaintext.conversation.as_deref(),
        Some("second participant retry fails")
    );
    let first_replay_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("participant retry should send first cached replay")
        .expect("connection sink should stay open");
    let first_replay_node = decode_inbound_binary_node(&first_replay_frame)
        .unwrap()
        .node;
    assert_eq!(
        first_replay_node.attrs["id"],
        "retry-participant-first-sent"
    );
    assert_eq!(first_replay_node.attrs["to"], "123@s.whatsapp.net");
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
        vec!["retry-participant-first-sent"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "retry-participant-second-fails"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_finalizes_first_participant_replay_when_second_session_assertion_fails()
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
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-participant-first-before-session-fail",
            wa_proto::proto::Message {
                conversation: Some("first participant before session failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-participant-session-fail-second",
            wa_proto::proto::Message {
                conversation: Some("second participant session assertion fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "retry-participant-first-before-session-fail".to_owned(),
            "retry-participant-session-fail-second".to_owned(),
        ],
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
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
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
    assert_eq!(prepared.jobs.len(), 2);

    let encryptor = DeletingSessionsAfterEncryptor::new(
        client.signal_repository(),
        1,
        ["123:1@s.whatsapp.net"],
    );
    let retry_fut = client.execute_retry_resends(&connection, &prepared, &encryptor);
    tokio::pin!(retry_fut);

    let first_replay_frame = tokio::select! {
        result = &mut retry_fut => panic!("participant retry completed before first replay stanza: {result:?}"),
        sent = sink_rx.recv() => sent.expect("connection sink should stay open"),
    };
    let first_replay_node = decode_inbound_binary_node(&first_replay_frame)
        .unwrap()
        .node;
    assert_eq!(
        first_replay_node.attrs["id"],
        "retry-participant-first-before-session-fail"
    );
    assert_eq!(first_replay_node.attrs["to"], "123@s.whatsapp.net");

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123:1@s.whatsapp.net".to_owned(), None)]
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
        vec!["123:1@s.whatsapp.net"]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first participant before session failure")
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
        vec!["retry-participant-first-before-session-fail"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "retry-participant-session-fail-second"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_finalizes_first_participant_replay_when_second_relay_send_fails() {
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
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-participant-first-before-send-fail",
            wa_proto::proto::Message {
                conversation: Some("first participant before send failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-participant-send-fail-second",
            wa_proto::proto::Message {
                conversation: Some("second participant relay send fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "retry-participant-first-before-send-fail".to_owned(),
            "retry-participant-send-fail-second".to_owned(),
        ],
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
            wa_core::RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(0x0102_0304),
                base_key: None,
                signal_address: None,
            },
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
    assert_eq!(prepared.jobs.len(), 2);

    let encryptor = ClosingConnectionAtEncryptor::new(connection.clone(), 2);
    let err = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap_err();
    assert!(matches!(err, wa_core::CoreError::ConnectionClosed));
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["123:1@s.whatsapp.net", "123:1@s.whatsapp.net"]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first participant before send failure")
    );
    let second_replay_plaintext = wa_proto::proto::Message::decode(calls[1].1.clone()).unwrap();
    assert_eq!(
        second_replay_plaintext.conversation.as_deref(),
        Some("second participant relay send fails")
    );
    let first_replay_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("participant retry should send first cached replay")
        .expect("connection sink should keep first replay frame");
    let first_replay_node = decode_inbound_binary_node(&first_replay_frame)
        .unwrap()
        .node;
    assert_eq!(
        first_replay_node.attrs["id"],
        "retry-participant-first-before-send-fail"
    );
    assert_eq!(first_replay_node.attrs["to"], "123@s.whatsapp.net");
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
        vec!["retry-participant-first-before-send-fail"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "retry-participant-send-fail-second"
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn retry_resend_skips_reporting_and_tc_token_sidecars() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"retry-target-token"),
        )
        .unwrap()
        .with_timestamp_seconds(current_unix_timestamp()),
    )
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
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let encryptor = RelayEncryptor::default();
    let message = wa_core::build_poll_message(PollContent::new(
        "Retry poll?",
        ["Yes", "No"],
        1,
        Bytes::from(vec![6u8; 32]),
    ))
    .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-secret-1",
            message,
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-secret-1".to_owned()],
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

    let relays = client
        .execute_retry_resends(&connection, &prepared, &encryptor)
        .await
        .unwrap();

    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].message_id, "retry-secret-1");
    let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(resent.attrs["id"], "retry-secret-1");
    assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
    assert!(test_children(&resent, "reporting").is_empty());
    assert!(test_children(&resent, "tctoken").is_empty());
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "123:1@s.whatsapp.net");
    let decoded = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        decoded
            .poll_creation_message_v3
            .as_ref()
            .unwrap()
            .name
            .as_deref(),
        Some("Retry poll?")
    );
    assert!(
        decoded
            .message_context_info
            .as_ref()
            .and_then(|context| context.message_secret.as_ref())
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_all_devices_fails_when_device_lookup_has_no_recipients() {
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
    let prepared = wa_core::RetryResendPreparation {
        jobs: vec![wa_core::RetryResendJob {
            remote_jid: "123@s.whatsapp.net".to_owned(),
            requester_jid: "123@s.whatsapp.net".to_owned(),
            message_id: "retry-empty-devices".to_owned(),
            message: wa_proto::proto::Message {
                conversation: Some("cached retry empty devices".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            target: wa_core::RetryResendTarget::AllDevices,
        }],
        missing_message_ids: Vec::new(),
        session_action: wa_core::RetrySessionAction::None,
        should_clear_group_sender_key: false,
    };
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
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(matches!(
        err,
        wa_core::CoreError::Protocol(message)
            if message == "retry resend requires at least one recipient device"
    ));
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(encryptor.calls.lock().unwrap().is_empty());
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
async fn execute_retry_resends_all_devices_stops_when_session_assertion_fails() {
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
    let prepared = wa_core::RetryResendPreparation {
        jobs: vec![wa_core::RetryResendJob {
            remote_jid: "123@s.whatsapp.net".to_owned(),
            requester_jid: "123@s.whatsapp.net".to_owned(),
            message_id: "retry-session-fail".to_owned(),
            message: wa_proto::proto::Message {
                conversation: Some("cached retry missing session".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            target: wa_core::RetryResendTarget::AllDevices,
        }],
        missing_message_ids: Vec::new(),
        session_action: wa_core::RetrySessionAction::None,
        should_clear_group_sender_key: false,
    };
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
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
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

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123:1@s.whatsapp.net".to_owned(), None)]
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
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(encryptor.calls.lock().unwrap().is_empty());
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
async fn execute_retry_resends_all_devices_keeps_cached_message_when_relay_fails() {
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
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-all-relay-fails",
            wa_proto::proto::Message {
                conversation: Some("cached all-devices retry relay failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-all-relay-fails".to_owned()],
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
    assert_eq!(prepared.jobs.len(), 1);

    let failing_encryptor = FailingEncryptor::new("retry all-devices encrypt failed");
    let retry_fut = client.execute_retry_resends(&connection, &prepared, &failing_encryptor);
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
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
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

    let err = retry_fut.await.unwrap_err();
    assert!(err.to_string().contains("retry all-devices encrypt failed"));
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 0);
    assert_eq!(stats.failed_retries, 0);

    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_failure.is_complete());
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert!(prepared_after_failure.missing_message_ids.is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_all_devices_keeps_cached_message_when_later_participant_encrypt_fails()
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
            "retry-all-late-relay-fails",
            wa_proto::proto::Message {
                conversation: Some("cached all-devices retry late relay failure".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec!["retry-all-late-relay-fails".to_owned()],
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
    assert_eq!(prepared.jobs.len(), 1);

    let failing_encryptor = FailingAfterEncryptor::new(2, "retry all-devices late encrypt failed");
    let retry_fut = client.execute_retry_resends(&connection, &prepared, &failing_encryptor);
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
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(
                                vec![BinaryNode::new("device-list").with_content(vec![
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

    let err = retry_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("retry all-devices late encrypt failed")
    );
    assert_eq!(
        failing_encryptor
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.0.as_str())
            .collect::<Vec<_>>(),
        vec!["123:1@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let stats = client.message_retry_statistics().unwrap();
    assert_eq!(stats.successful_retries, 0);
    assert_eq!(stats.failed_retries, 0);

    let prepared_after_failure = client
        .prepare_retry_resends(&plan, current_unix_timestamp_ms())
        .unwrap();
    assert!(prepared_after_failure.is_complete());
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert!(prepared_after_failure.missing_message_ids.is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_finalizes_first_all_device_replay_when_second_replay_encrypt_fails()
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
            "retry-all-first-sent",
            wa_proto::proto::Message {
                conversation: Some("first all-device retry succeeds".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-all-second-fails",
            wa_proto::proto::Message {
                conversation: Some("second all-device retry fails".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "retry-all-first-sent".to_owned(),
            "retry-all-second-fails".to_owned(),
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

    let failing_encryptor =
        FailingAfterEncryptor::new(4, "retry all-devices second replay late encrypt failed");
    let retry_fut = client.execute_retry_resends(&connection, &prepared, &failing_encryptor);
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
    assert_eq!(first_replay_node.attrs["id"], "retry-all-first-sent");
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
    assert!(
        err.to_string()
            .contains("retry all-devices second replay late encrypt failed")
    );
    let calls = failing_encryptor.calls.lock().unwrap().clone();
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
        Some("first all-device retry succeeds")
    );
    let second_replay_plaintext = wa_proto::proto::Message::decode(calls[2].1.clone()).unwrap();
    assert_eq!(
        second_replay_plaintext.conversation.as_deref(),
        Some("second all-device retry fails")
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
        vec!["retry-all-first-sent"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "retry-all-second-fails"
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn execute_retry_resends_finalizes_first_all_device_replay_when_second_device_lookup_is_empty()
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
            "retry-all-first-before-empty",
            wa_proto::proto::Message {
                conversation: Some("first all-device before empty lookup".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    client
        .cache_recent_message_for_retry(
            "123@s.whatsapp.net",
            "retry-all-empty-second",
            wa_proto::proto::Message {
                conversation: Some("second all-device has no recipients".to_owned()),
                ..wa_proto::proto::Message::default()
            },
            current_unix_timestamp_ms(),
        )
        .unwrap();
    let receipt = wa_core::RetryReceipt {
        message_ids: vec![
            "retry-all-first-before-empty".to_owned(),
            "retry-all-empty-second".to_owned(),
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

    let encryptor = RelayEncryptor::default();
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
        "retry-all-first-before-empty"
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
        &mut retry_fut,
    )
    .await;

    let err = retry_fut.await.unwrap_err();
    assert!(matches!(
        err,
        wa_core::CoreError::Protocol(message)
            if message == "retry resend requires at least one recipient device"
    ));
    let calls = encryptor.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        vec!["123:1@s.whatsapp.net", "999:8@s.whatsapp.net"]
    );
    let first_replay_plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
    assert_eq!(
        first_replay_plaintext.conversation.as_deref(),
        Some("first all-device before empty lookup")
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
        vec!["retry-all-first-before-empty"]
    );
    assert_eq!(prepared_after_failure.jobs.len(), 1);
    assert_eq!(
        prepared_after_failure.jobs[0].message_id,
        "retry-all-empty-second"
    );
    connection.close().await.unwrap();
}
