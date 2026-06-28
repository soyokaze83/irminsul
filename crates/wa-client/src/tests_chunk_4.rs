// Auto-partitioned test chunk 4 of 8 (feature `wat4`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat4 to stay within the VM RAM budget.
// Included into `mod chunk_4` in lib.rs; allow-attrs live on that module decl.
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
async fn process_incoming_node_emits_group_membership_request_message_stub() {
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
        .with_attr("id", "group-membership-request-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000350")
        .with_content(vec![
            BinaryNode::new("membership_approval_requests").with_content(vec![
                BinaryNode::new("membership_approval_request")
                    .with_attr("jid", "222@s.whatsapp.net")
                    .with_attr("lidJid", "222@lid")
                    .with_attr("phoneNumber", "222@s.whatsapp.net")
                    .with_attr("participantUsername", "two")
                    .with_attr("requestMethod", "invite_link")
                    .with_attr("t", "1699999999"),
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
    assert_eq!(ack.attrs["id"], "group-membership-request-stub-live");
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
        "group-membership-request-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000350");
    assert_eq!(group.fields["join_requests"], "222@s.whatsapp.net");
    assert_eq!(group.fields["join_requests_count"], "1");
    assert_eq!(
        group.fields["join_requests_lids"],
        "222@s.whatsapp.net=222@lid"
    );
    assert_eq!(
        group.fields["join_requests_phone_numbers"],
        "222@s.whatsapp.net=222@s.whatsapp.net"
    );
    assert_eq!(
        group.fields["join_requests_usernames"],
        "222@s.whatsapp.net=two"
    );
    assert_eq!(
        group.fields["join_requests_requested_at"],
        "222@s.whatsapp.net=1699999999"
    );
    assert_eq!(
        group.fields["join_requests_methods"],
        "222@s.whatsapp.net=invite_link"
    );

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-membership-request-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_350));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupMembershipJoinApprovalRequest as i32)
            .to_string()
    );
    assert_eq!(
        stub.fields["stub_type"],
        "group_membership_join_approval_request"
    );
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 3);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["lid"], "222@lid");
    assert_eq!(participant["pn"], "222@s.whatsapp.net");
    assert_eq!(participant["username"], "two");
    assert_eq!(parameters[1], "requested");
    assert_eq!(parameters[2], "invite_link");
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
async fn process_incoming_node_emits_group_membership_created_message_stub() {
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
        .with_attr("id", "group-membership-created-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "one")
        .with_attr("t", "1700000360")
        .with_content(vec![
            BinaryNode::new("created_membership_requests")
                .with_attr("requestMethod", "non_admin_add")
                .with_attr("t", "1700000700"),
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
    assert_eq!(ack.attrs["id"], "group-membership-created-stub-live");
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
        "group-membership-created-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "one");
    assert_eq!(group.fields["timestamp"], "1700000360");
    assert_eq!(group.fields["join_requests_created"], "111@lid");
    assert_eq!(group.fields["join_requests_created_count"], "1");
    assert_eq!(
        group.fields["join_requests_created_phone_numbers"],
        "111@lid=111@s.whatsapp.net"
    );
    assert_eq!(
        group.fields["join_requests_created_usernames"],
        "111@lid=one"
    );
    assert_eq!(
        group.fields["join_requests_created_methods"],
        "111@lid=non_admin_add"
    );
    assert_eq!(
        group.fields["join_requests_created_requested_at"],
        "111@lid=1700000700"
    );
    assert_eq!(
        group.fields["join_requests_created_outcomes"],
        "111@lid=created"
    );

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-membership-created-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_360));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupMembershipJoinApprovalRequestNonAdminAdd
            as i32)
            .to_string()
    );
    assert_eq!(
        stub.fields["stub_type"],
        "group_membership_join_approval_request_non_admin_add"
    );
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 3);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["lid"], "111@lid");
    assert_eq!(participant["pn"], "111@s.whatsapp.net");
    assert_eq!(participant["username"], "one");
    assert_eq!(parameters[1], "created");
    assert_eq!(parameters[2], "non_admin_add");
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
async fn process_offline_node_emits_group_membership_revoked_append_stub() {
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
        .with_attr("id", "offline-group-membership-revoked-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "222@lid")
        .with_attr("participant_pn", "222@s.whatsapp.net")
        .with_attr("participant_username", "two")
        .with_attr("t", "1700000370")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("revoked_membership_requests")
                .with_attr("method", "admin_review")
                .with_attr("t", "1700000800")
                .with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "222@lid")
                        .with_attr("phone_number", "222@s.whatsapp.net")
                        .with_attr("error", "409"),
                    BinaryNode::new("participant")
                        .with_attr("jid", "333@lid")
                        .with_attr("phone_number", "333@s.whatsapp.net")
                        .with_attr("status", "200")
                        .with_attr("username", "three"),
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
    assert_eq!(ack.attrs["id"], "offline-group-membership-revoked-stub");
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
        "offline-group-membership-revoked-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "222@lid");
    assert_eq!(group.fields["actor_pn"], "222@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "two");
    assert_eq!(group.fields["timestamp"], "1700000370");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["join_requests_revoked"], "222@lid,333@lid");
    assert_eq!(group.fields["join_requests_revoked_count"], "2");
    assert_eq!(
        group.fields["join_requests_revoked_phone_numbers"],
        "222@lid=222@s.whatsapp.net,333@lid=333@s.whatsapp.net"
    );
    assert_eq!(group.fields["join_requests_revoked_errors"], "222@lid=409");
    assert_eq!(
        group.fields["join_requests_revoked_statuses"],
        "333@lid=200"
    );
    assert_eq!(
        group.fields["join_requests_revoked_usernames"],
        "333@lid=three"
    );
    assert_eq!(
        group.fields["join_requests_revoked_methods"],
        "222@lid=admin_review,333@lid=admin_review"
    );
    assert_eq!(
        group.fields["join_requests_revoked_requested_at"],
        "222@lid=1700000800,333@lid=1700000800"
    );
    assert_eq!(
        group.fields["join_requests_revoked_outcomes"],
        "222@lid=revoked,333@lid=rejected"
    );

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-membership-revoked-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("222@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_370));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupMembershipJoinApprovalRequestNonAdminAdd
            as i32)
            .to_string()
    );
    assert_eq!(
        stub.fields["stub_type"],
        "group_membership_join_approval_request_non_admin_add"
    );
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 2);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["lid"], "222@lid");
    assert_eq!(participant["pn"], "222@s.whatsapp.net");
    assert!(participant.get("username").is_none());
    assert_eq!(parameters[1], "revoked");
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
async fn process_incoming_node_emits_group_membership_action_update() {
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
        .with_attr("id", "group-membership-action-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000380")
        .with_content(vec![
            BinaryNode::new("membership_requests_action").with_content(vec![
                BinaryNode::new("approve").with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "222@s.whatsapp.net")
                        .with_attr("status", "200"),
                ]),
                BinaryNode::new("reject").with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "333@s.whatsapp.net")
                        .with_attr("error", "403"),
                ]),
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
    assert_eq!(ack.attrs["id"], "group-membership-action-live");
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
        "group-membership-action-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000380");
    assert_eq!(group.fields["join_requests_approve"], "222@s.whatsapp.net");
    assert_eq!(group.fields["join_requests_approve_count"], "1");
    assert_eq!(
        group.fields["join_requests_approve_statuses"],
        "222@s.whatsapp.net=200"
    );
    assert_eq!(group.fields["join_requests_reject"], "333@s.whatsapp.net");
    assert_eq!(group.fields["join_requests_reject_count"], "1");
    assert_eq!(
        group.fields["join_requests_reject_errors"],
        "333@s.whatsapp.net=403"
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, *group);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_emits_group_community_linkage_update() {
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
        .with_attr("id", "offline-group-community-linkage")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000390")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("parent")
                .with_attr("default_membership_approval_mode", "request_required"),
            BinaryNode::new("default_sub_group"),
            BinaryNode::new("linked_parent").with_attr("jid", "999@g.us"),
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
    assert_eq!(ack.attrs["id"], "offline-group-community-linkage");
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
        "offline-group-community-linkage"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000390");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["is_community"], "true");
    assert_eq!(
        group.fields["default_membership_approval_mode"],
        "request_required"
    );
    assert_eq!(group.fields["is_community_announce"], "true");
    assert_eq!(group.fields["linked_parent"], "999@g.us");
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, *group);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_emits_group_participant_invite_message_stub() {
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
        .with_attr("id", "group-participant-invite-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@lid")
        .with_attr("participant_pn", "111@s.whatsapp.net")
        .with_attr("participant_username", "actor-one")
        .with_attr("t", "1700000360")
        .with_content(vec![
            BinaryNode::new("invite")
                .with_attr("code", "new-code")
                .with_attr("expiration", "1700000660")
                .with_attr("admin", "111@lid")
                .with_attr("adminPn", "111@s.whatsapp.net")
                .with_attr("adminUsername", "one")
                .with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "444@lid")
                        .with_attr("phoneNumber", "444@s.whatsapp.net")
                        .with_attr("participantUsername", "four"),
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
    assert_eq!(ack.attrs["id"], "group-participant-invite-stub-live");
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
        "group-participant-invite-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@lid");
    assert_eq!(group.fields["actor_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "actor-one");
    assert_eq!(group.fields["timestamp"], "1700000360");
    assert_eq!(group.fields["invite_updated"], "true");
    assert_eq!(group.fields["invite_code"], "new-code");
    assert_eq!(group.fields["invite_expiration"], "1700000660");
    assert_eq!(group.fields["invite_admin"], "111@lid");
    assert_eq!(group.fields["invite_admin_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["invite_admin_username"], "one");
    assert_eq!(group.fields["participants_invite"], "444@lid");
    assert_eq!(group.fields["participants_invite_count"], "1");
    assert_eq!(
        group.fields["participants_invite_phone_numbers"],
        "444@lid=444@s.whatsapp.net"
    );
    assert_eq!(
        group.fields["participants_invite_usernames"],
        "444@lid=four"
    );

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-participant-invite-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_360));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantInvite as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_invite");
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 1);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["id"], "444@lid");
    assert_eq!(participant["phoneNumber"], "444@s.whatsapp.net");
    assert_eq!(participant["username"], "four");
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
async fn process_incoming_node_emits_group_participant_accept_fallback_message_stub() {
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
        .with_attr("id", "group-participant-accept-fallback-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "333@lid")
        .with_attr("participantPn", "333@s.whatsapp.net")
        .with_attr("participantUsername", "three")
        .with_attr("t", "1700000370")
        .with_content(vec![
            BinaryNode::new("accept")
                .with_attr("code", "fallback-code")
                .with_attr("admin", "111@s.whatsapp.net")
                .with_attr("author_pn", "111@s.whatsapp.net")
                .with_attr("author_username", "one"),
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
    assert_eq!(
        ack.attrs["id"],
        "group-participant-accept-fallback-stub-live"
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
        "group-participant-accept-fallback-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "333@lid");
    assert_eq!(group.fields["actor_pn"], "333@s.whatsapp.net");
    assert_eq!(group.fields["actor_username"], "three");
    assert_eq!(group.fields["timestamp"], "1700000370");
    assert_eq!(group.fields["invite_accepted"], "true");
    assert_eq!(group.fields["invite_code"], "fallback-code");
    assert_eq!(group.fields["invite_admin"], "111@s.whatsapp.net");
    assert_eq!(group.fields["invite_admin_pn"], "111@s.whatsapp.net");
    assert_eq!(group.fields["invite_admin_username"], "one");
    assert_eq!(group.fields["participants_accept"], "333@lid");
    assert_eq!(group.fields["participants_accept_count"], "1");
    assert_eq!(
        group.fields["participants_accept_phone_numbers"],
        "333@lid=333@s.whatsapp.net"
    );
    assert_eq!(
        group.fields["participants_accept_usernames"],
        "333@lid=three"
    );

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-participant-accept-fallback-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("333@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_370));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantAccept as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_accept");
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 1);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["id"], "333@lid");
    assert_eq!(participant["phoneNumber"], "333@s.whatsapp.net");
    assert_eq!(participant["username"], "three");
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
async fn process_offline_node_emits_group_invite_revoke_append_stub() {
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
        .with_attr("id", "offline-group-invite-revoke-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000380")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("revoke")
                .with_attr("code", "old-code")
                .with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "222@s.whatsapp.net")
                        .with_attr("status", "200"),
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
    assert_eq!(ack.attrs["id"], "offline-group-invite-revoke-stub");
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
        "offline-group-invite-revoke-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000380");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["invite_revoked"], "true");
    assert_eq!(group.fields["invite_code"], "old-code");
    assert_eq!(group.fields["participants_revoke"], "222@s.whatsapp.net");
    assert_eq!(group.fields["participants_revoke_count"], "1");
    assert_eq!(
        group.fields["participants_revoke_statuses"],
        "222@s.whatsapp.net=200"
    );

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-invite-revoke-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_380));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeInviteLink as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_change_invite_link");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["old-code"]"#);
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
async fn process_incoming_node_emits_group_participant_add_message_stub() {
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
        .with_attr("id", "group-participant-add-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000240")
        .with_content(vec![BinaryNode::new("add").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
        ])]);
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
    assert_eq!(ack.attrs["id"], "group-participant-add-stub-live");
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
        "group-participant-add-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000240");
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
    assert_eq!(stub.key.id, "group-participant-add-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_240));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_emits_group_participant_remove_message_stub() {
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
        .with_attr("id", "group-participant-remove-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000260")
        .with_content(vec![BinaryNode::new("remove").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
        ])]);
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
    assert_eq!(ack.attrs["id"], "group-participant-remove-stub-live");
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
        "group-participant-remove-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000260");
    assert_eq!(group.fields["participants_remove"], "222@lid");
    assert_eq!(
        group.fields["participants_remove_phone_numbers"],
        "222@lid=222@s.whatsapp.net"
    );
    assert_eq!(group.fields["participants_remove_usernames"], "222@lid=two");
    assert_eq!(group.fields["participants_remove_roles"], "222@lid=admin");
    assert!(!group.fields.contains_key("participants_remove_is_leave"));
    assert!(!group.fields.contains_key("participants_leave"));

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-participant-remove-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_260));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantRemove as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_remove");
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
async fn process_offline_node_emits_group_participant_add_append_stub() {
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
        .with_attr("id", "offline-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000250")
        .with_attr("offline", "1")
        .with_content(vec![BinaryNode::new("add").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
        ])]);
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
    assert_eq!(ack.attrs["id"], "offline-group-participant-add-stub");
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
        "offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000250");
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
    assert_eq!(stub.key.id, "offline-group-participant-add-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_250));
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
async fn process_offline_node_emits_group_participant_leave_append_stub() {
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
        .with_attr("id", "offline-group-participant-leave-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "222@lid")
        .with_attr("t", "1700000270")
        .with_attr("offline", "1")
        .with_content(vec![BinaryNode::new("remove").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
        ])]);
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
    assert_eq!(ack.attrs["id"], "offline-group-participant-leave-stub");
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
        "offline-group-participant-leave-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "222@lid");
    assert_eq!(group.fields["timestamp"], "1700000270");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["participants_remove"], "222@lid");
    assert_eq!(group.fields["participants_remove_is_leave"], "true");
    assert_eq!(
        group.fields["participants_remove_phone_numbers"],
        "222@lid=222@s.whatsapp.net"
    );
    assert_eq!(group.fields["participants_remove_usernames"], "222@lid=two");
    assert_eq!(group.fields["participants_remove_roles"], "222@lid=admin");
    assert_eq!(group.fields["participants_leave"], "222@lid");
    assert_eq!(group.fields["participants_leave_count"], "1");
    assert_eq!(
        group.fields["participants_leave_phone_numbers"],
        "222@lid=222@s.whatsapp.net"
    );
    assert_eq!(group.fields["participants_leave_usernames"], "222@lid=two");
    assert_eq!(group.fields["participants_leave_roles"], "222@lid=admin");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-participant-leave-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("222@lid"));
    assert_eq!(stub.timestamp, Some(1_700_000_270));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantLeave as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_leave");
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
async fn process_incoming_node_emits_group_participant_promote_message_stub() {
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
        .with_attr("id", "group-participant-promote-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000280")
        .with_content(vec![BinaryNode::new("promote").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("lidJid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
        ])]);
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
    assert_eq!(ack.attrs["id"], "group-participant-promote-stub-live");
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
        "group-participant-promote-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000280");
    assert_eq!(group.fields["participants_promote"], "222@lid");
    assert_eq!(group.fields["participants_promote_lids"], "222@lid=222@lid");
    assert_eq!(
        group.fields["participants_promote_phone_numbers"],
        "222@lid=222@s.whatsapp.net"
    );
    assert_eq!(
        group.fields["participants_promote_usernames"],
        "222@lid=two"
    );
    assert_eq!(group.fields["participants_promote_roles"], "222@lid=admin");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "group-participant-promote-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_280));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantPromote as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_promote");
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
async fn process_incoming_node_emits_group_participant_demote_message_stub() {
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
        .with_attr("id", "group-participant-demote-stub-live")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000285")
        .with_content(vec![BinaryNode::new("demote").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("lidJid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two"),
        ])]);
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
    assert_eq!(ack.attrs["id"], "group-participant-demote-stub-live");
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
        "group-participant-demote-stub-live"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000285");
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
    assert_eq!(stub.key.id, "group-participant-demote-stub-live");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_285));
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_emits_group_participant_change_number_append_stub() {
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
        .with_attr("id", "offline-group-participant-change-number-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000290")
        .with_attr("offline", "1")
        .with_content(vec![BinaryNode::new("modify").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@s.whatsapp.net")
                .with_attr("lidJid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two"),
        ])]);
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
    assert_eq!(
        ack.attrs["id"],
        "offline-group-participant-change-number-stub"
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
        "offline-group-participant-change-number-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000290");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["participants_modify"], "222@s.whatsapp.net");
    assert_eq!(
        group.fields["participants_modify_lids"],
        "222@s.whatsapp.net=222@lid"
    );
    assert_eq!(
        group.fields["participants_modify_phone_numbers"],
        "222@s.whatsapp.net=222@s.whatsapp.net"
    );
    assert_eq!(
        group.fields["participants_modify_usernames"],
        "222@s.whatsapp.net=two"
    );

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-participant-change-number-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_290));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantChangeNumber as i32)
            .to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_change_number");
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 1);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["id"], "222@s.whatsapp.net");
    assert_eq!(participant["lid"], "222@lid");
    assert_eq!(participant["phoneNumber"], "222@s.whatsapp.net");
    assert_eq!(participant["username"], "two");

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
async fn process_offline_node_emits_group_notification_message_stub() {
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
        .with_attr("id", "offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000160")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
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
    assert_eq!(ack.attrs["id"], "offline-group-ephemeral-stub");
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
        "offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000160");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "offline-group-ephemeral-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_160));
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
async fn process_incoming_node_enriches_call_timeout_from_persisted_offer() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let offer = BinaryNode::new("call")
        .with_attr("id", "call-offer-stanza")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", "1700000100")
        .with_content(vec![
            BinaryNode::new("offer")
                .with_attr("call-id", "call-live-1")
                .with_attr("call-creator", "123@s.whatsapp.net")
                .with_attr("caller_pn", "123@s.whatsapp.net")
                .with_content(vec![BinaryNode::new("video")]),
        ]);

    let result = client
        .process_incoming_node(&connection, &offer, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Call);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "call-offer-stanza");
    assert_eq!(ack.attrs["class"], "call");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    let offer_batch = recv_batch_event(&mut events).await;
    assert!(offer_batch.messages_upsert.is_empty());
    assert_eq!(offer_batch.calls_update.len(), 1);
    let offer_call = &offer_batch.calls_update[0];
    assert_eq!(offer_call.id, "call-offer-stanza");
    assert_eq!(offer_call.from, "123@s.whatsapp.net");
    assert_eq!(offer_call.event_type, "offer");
    assert_eq!(offer_call.call_id.as_deref(), Some("call-live-1"));
    assert_eq!(offer_call.timestamp, Some(1_700_000_100));
    assert_eq!(offer_call.fields["is_video"], "true");
    assert_eq!(offer_call.fields["is_group"], "false");
    assert_eq!(offer_call.fields["caller_pn"], "123@s.whatsapp.net");
    assert_eq!(offer_call.fields["call_from"], "123@s.whatsapp.net");
    let cache_key = call_offer_cache_key(offer_call).unwrap();
    let cached_offer = store
        .get(KeyNamespace::CallEvent, &cache_key)
        .await
        .unwrap()
        .unwrap();
    let cached_offer = wa_core::decode_stored_call_event(&cached_offer).unwrap();
    assert_eq!(cached_offer, *offer_call);

    let timeout = BinaryNode::new("call")
        .with_attr("id", "call-timeout-stanza")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", "1700000105")
        .with_content(vec![
            BinaryNode::new("timeout").with_attr("call-id", "call-live-1"),
        ]);
    let result = client
        .process_incoming_node(&connection, &timeout, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Call);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "call-timeout-stanza");
    assert_eq!(ack.attrs["class"], "call");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert!(!ack.attrs.contains_key("from"));

    let timeout_batch = recv_batch_event(&mut events).await;
    assert_eq!(timeout_batch.calls_update.len(), 1);
    let timeout_call = &timeout_batch.calls_update[0];
    assert_eq!(timeout_call.id, "call-timeout-stanza");
    assert_eq!(timeout_call.event_type, "timeout");
    assert_eq!(timeout_call.call_id.as_deref(), Some("call-live-1"));
    assert_eq!(timeout_call.timestamp, Some(1_700_000_105));
    assert_eq!(timeout_call.fields["is_video"], "true");
    assert_eq!(timeout_call.fields["is_group"], "false");
    assert_eq!(timeout_call.fields["caller_pn"], "123@s.whatsapp.net");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let missed = &message_batch.messages_upsert[0];
    assert_eq!(missed.key.remote_jid, "123@s.whatsapp.net");
    assert_eq!(missed.key.id, "call-live-1");
    assert_eq!(missed.timestamp, Some(1_700_000_105));
    assert_eq!(missed.fields["source"], "call_event");
    assert_eq!(missed.fields["call_status"], "timeout");
    assert_eq!(missed.fields["is_video"], "true");
    assert_eq!(missed.fields["is_group"], "false");
    assert_eq!(missed.fields["caller_pn"], "123@s.whatsapp.net");
    assert_eq!(
        missed.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::CallMissedVideo as i32).to_string()
    );
    assert_eq!(missed.fields["stub_type"], "call_missed_video");
    assert!(missed.payload.is_none());

    let stored_timeout = store
        .get(
            KeyNamespace::CallEvent,
            &wa_core::call_event_store_key(timeout_call),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_timeout = wa_core::decode_stored_call_event(&stored_timeout).unwrap();
    assert_eq!(stored_timeout, *timeout_call);
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
            .get(KeyNamespace::CallEvent, &cache_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_emits_group_call_offer_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let offer = BinaryNode::new("call")
        .with_attr("id", "group-call-offer-stanza")
        .with_attr("from", "456@g.us")
        .with_attr("t", "1700000110")
        .with_content(vec![
            BinaryNode::new("offer")
                .with_attr("call-id", "group-call-live-1")
                .with_attr("from", "123@s.whatsapp.net")
                .with_attr("caller_pn", "123@s.whatsapp.net")
                .with_attr("type", "group")
                .with_attr("group-jid", "456@g.us")
                .with_content(vec![BinaryNode::new("video")]),
        ]);

    let result = client
        .process_incoming_node(&connection, &offer, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Call);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "group-call-offer-stanza");
    assert_eq!(ack.attrs["class"], "call");
    assert_eq!(ack.attrs["to"], "456@g.us");
    assert!(!ack.attrs.contains_key("from"));

    let offer_batch = recv_batch_event(&mut events).await;
    assert_eq!(offer_batch.calls_update.len(), 1);
    assert!(offer_batch.messages_upsert.is_empty());
    let offer_call = &offer_batch.calls_update[0];
    assert_eq!(offer_call.id, "group-call-offer-stanza");
    assert_eq!(offer_call.from, "456@g.us");
    assert_eq!(offer_call.event_type, "offer");
    assert_eq!(offer_call.call_id.as_deref(), Some("group-call-live-1"));
    assert_eq!(offer_call.timestamp, Some(1_700_000_110));
    assert_eq!(offer_call.fields["is_video"], "true");
    assert_eq!(offer_call.fields["is_group"], "true");
    assert_eq!(offer_call.fields["caller_pn"], "123@s.whatsapp.net");
    assert_eq!(offer_call.fields["call_from"], "123@s.whatsapp.net");
    assert_eq!(offer_call.fields["group_jid"], "456@g.us");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let call_message = &message_batch.messages_upsert[0];
    assert_eq!(call_message.key.remote_jid, "456@g.us");
    assert_eq!(call_message.key.id, "group-call-live-1");
    assert_eq!(call_message.timestamp, Some(1_700_000_110));
    assert_eq!(call_message.fields["kind"], "notify");
    assert_eq!(call_message.fields["source"], "call_event");
    assert_eq!(call_message.fields["call_status"], "offer");
    assert_eq!(call_message.fields["payload_kind"], "call");
    assert_eq!(call_message.fields["is_video"], "true");
    assert_eq!(call_message.fields["is_group"], "true");
    assert_eq!(call_message.fields["caller_pn"], "123@s.whatsapp.net");
    assert_eq!(call_message.fields["call_from"], "123@s.whatsapp.net");
    assert_eq!(call_message.fields["group_jid"], "456@g.us");
    let decoded = wa_proto::proto::Message::decode(call_message.payload.clone().unwrap()).unwrap();
    assert_eq!(
        decoded.call.unwrap().call_key.as_deref(),
        Some(b"group-call-live-1".as_slice())
    );

    let stored_call = store
        .get(
            KeyNamespace::CallEvent,
            &wa_core::call_event_store_key(offer_call),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_call = wa_core::decode_stored_call_event(&stored_call).unwrap();
    assert_eq!(stored_call, *offer_call);
    let cache_key = call_offer_cache_key(offer_call).unwrap();
    let cached_offer = store
        .get(KeyNamespace::CallEvent, &cache_key)
        .await
        .unwrap()
        .unwrap();
    let cached_offer = wa_core::decode_stored_call_event(&cached_offer).unwrap();
    assert_eq!(cached_offer, *offer_call);
    let stored_message = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&call_message.key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message, *call_message);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_offline_node_prefers_group_call_timeout_stub_over_offer_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let offer = BinaryNode::new("call")
        .with_attr("id", "offline-group-call-offer-stanza")
        .with_attr("from", "456@g.us")
        .with_attr("t", "1700000120")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("offer")
                .with_attr("call-id", "offline-group-call-live-1")
                .with_attr("from", "123@s.whatsapp.net")
                .with_attr("caller_pn", "123@s.whatsapp.net")
                .with_attr("type", "group")
                .with_attr("group-jid", "456@g.us")
                .with_content(vec![BinaryNode::new("video")]),
        ]);
    let timeout = BinaryNode::new("call")
        .with_attr("id", "offline-group-call-timeout-stanza")
        .with_attr("from", "456@g.us")
        .with_attr("t", "1700000125")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("timeout").with_attr("call-id", "offline-group-call-live-1"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![offer, timeout]);

    let result = client
        .process_offline_node(&connection, &offline, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.child_count, 2);
    assert_eq!(result.event_count(), 2);
    assert_eq!(result.response_count(), 2);
    for child in &result.results {
        assert_eq!(child.action, wa_core::InboundNodeAction::Call);
        assert!(child.error.is_none());
    }
    for expected_id in [
        "offline-group-call-offer-stanza",
        "offline-group-call-timeout-stanza",
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
        Some("offline-group-call-live-1")
    );
    assert_eq!(offer_call.fields["is_video"], "true");
    assert_eq!(offer_call.fields["is_group"], "true");
    assert_eq!(offer_call.fields["offline"], "true");
    assert_eq!(
        timeout_call.call_id.as_deref(),
        Some("offline-group-call-live-1")
    );
    assert_eq!(timeout_call.timestamp, Some(1_700_000_125));
    assert_eq!(timeout_call.fields["is_video"], "true");
    assert_eq!(timeout_call.fields["is_group"], "true");
    assert_eq!(timeout_call.fields["caller_pn"], "123@s.whatsapp.net");
    assert_eq!(timeout_call.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let missed = &message_batch.messages_upsert[0];
    assert_eq!(missed.key.remote_jid, "456@g.us");
    assert_eq!(missed.key.id, "offline-group-call-live-1");
    assert_eq!(missed.timestamp, Some(1_700_000_125));
    assert_eq!(missed.fields["kind"], "append");
    assert_eq!(missed.fields["source"], "call_event");
    assert_eq!(missed.fields["call_status"], "timeout");
    assert_eq!(missed.fields["is_video"], "true");
    assert_eq!(missed.fields["is_group"], "true");
    assert_eq!(missed.fields["caller_pn"], "123@s.whatsapp.net");
    assert_eq!(missed.fields["offline"], "true");
    assert_eq!(
        missed.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::CallMissedGroupVideo as i32).to_string()
    );
    assert_eq!(missed.fields["stub_type"], "call_missed_group_video");
    assert!(missed.payload.is_none());

    for call in [offer_call, timeout_call] {
        let stored = store
            .get(
                KeyNamespace::CallEvent,
                &wa_core::call_event_store_key(call),
            )
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_call_event(&stored).unwrap();
        assert_eq!(stored, *call);
    }
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_deletes_sessions_for_device_remove_notification() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let repository = client.signal_repository();
    repository
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123:7@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    assert!(
        repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "devices-remove-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "devices")
        .with_content(vec![BinaryNode::new("remove").with_content(vec![
            BinaryNode::new("device").with_attr("jid", "123:7@s.whatsapp.net"),
        ])]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &notification, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "devices-remove-1");
    assert_eq!(ack.attrs["class"], "notification");
    assert!(
        !repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap()
            .exists
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_resyncs_app_state_for_server_sync_notification() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    client
        .save_app_state_sync_key_data(&key_id, &key_data)
        .await
        .unwrap();
    let previous = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
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

    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "server-sync-1")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "server_sync")
        .with_content(vec![
            BinaryNode::new("collection").with_attr("name", "regular"),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let process_fut =
        client.process_incoming_node(&connection, &notification, &IncomingDecryptor, &mut buffer);
    tokio::pin!(process_fut);
    let sent_frame = tokio::select! {
        result = &mut process_fut => panic!("server-sync processing completed before ack: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "server-sync-1");
    assert_eq!(ack.attrs["class"], "notification");

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
        &mut process_fut,
    )
    .await;

    let result = process_fut.await.unwrap();
    assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());

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
    assert_eq!(stored.version(), expected_version);
    assert_eq!(stored.hash(), &expected_hash);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_media_retry_recovers_server_sync_snapshot() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
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
        "https://mmg.whatsapp.net/app-state/snapshot",
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "server-sync-snapshot-1")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "server_sync")
        .with_content(vec![
            BinaryNode::new("collection").with_attr("name", "regular"),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let process_fut = client.process_incoming_node_with_media_retry(
        &connection,
        &notification,
        &IncomingDecryptor,
        &mut buffer,
        &transfer,
    );
    tokio::pin!(process_fut);
    let sent_frame = tokio::select! {
        result = &mut process_fut => panic!("server-sync snapshot processing completed before ack: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "server-sync-snapshot-1");
    assert_eq!(ack.attrs["class"], "notification");

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
                        .with_attr("version", "0")
                        .with_content(vec![
                            BinaryNode::new("snapshot").with_content(snapshot_ref_bytes),
                        ]),
                ])])
        },
        &mut process_fut,
    )
    .await;

    let result = process_fut.await.unwrap();
    assert_eq!(
        result.inbound.action,
        wa_core::InboundNodeAction::Notification
    );
    assert_eq!(result.inbound.event_count, 2);
    assert!(result.inbound.error.is_none());
    assert!(result.media_retry.is_empty());
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
    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_handles_malformed_ack_without_failing() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, _sink_rx, _stream_tx) = mock_connection();
    let incoming = BinaryNode::new("ack")
        .with_attr("id", "bad-ack")
        .with_attr("class", "message")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("error", "nan");
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Ack);
    assert_eq!(result.event_count, 0);
    assert!(result.response.is_none());
    assert!(result.error.is_some());
    assert!(buffer.is_empty());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_preserves_receipt_list_item_participants() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let list = BinaryNode::new("list").with_content(vec![
        BinaryNode::new("item")
            .with_attr("id", "m2")
            .with_attr("participant", "222@s.whatsapp.net")
            .with_attr("t", "21"),
        BinaryNode::new("item").with_attr("id", "m3"),
    ]);
    let incoming = BinaryNode::new("receipt")
        .with_attr("id", "m1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("type", "read")
        .with_attr("t", "20")
        .with_content(vec![list]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Receipt);
    assert_eq!(result.event_count, 3);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "m1");
    assert_eq!(ack.attrs["class"], "receipt");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert_eq!(ack.attrs["participant"], "111@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.receipts_update.len(), 3);
    assert_eq!(
        batch.receipts_update[0].key.participant.as_deref(),
        Some("111@s.whatsapp.net")
    );
    assert_eq!(
        batch.receipts_update[1].key.participant.as_deref(),
        Some("222@s.whatsapp.net")
    );
    assert_eq!(
        batch.receipts_update[1].participant.as_deref(),
        Some("222@s.whatsapp.net")
    );
    assert_eq!(batch.receipts_update[1].timestamp, Some(21));
    assert_eq!(
        batch.receipts_update[2].key.participant.as_deref(),
        Some("111@s.whatsapp.net")
    );

    let stored_key = wa_core::receipt_event_store_key(&batch.receipts_update[1]);
    let stored = store
        .get(KeyNamespace::ReceiptEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_receipt_event(&stored).unwrap();
    assert_eq!(stored, batch.receipts_update[1]);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_maps_reaction_message_to_reaction_update() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("target-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let reaction = wa_proto::proto::Message {
        reaction_message: Some(wa_proto::proto::message::ReactionMessage {
            key: Some(target_key),
            text: Some("+".to_owned()),
            sender_timestamp_ms: Some(1_700_000_005_123),
            ..Default::default()
        }),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "reaction-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "reaction")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(reaction.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "reaction-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], "789@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "reaction-1");
    assert_eq!(batch.messages_upsert[0].fields["payload_kind"], "plaintext");
    assert_eq!(batch.reactions_update.len(), 1);
    let reaction = &batch.reactions_update[0];
    assert_eq!(reaction.key.remote_jid, "123@g.us");
    assert_eq!(reaction.key.id, "target-1");
    assert_eq!(
        reaction.key.participant.as_deref(),
        Some("456@s.whatsapp.net")
    );
    assert_eq!(reaction.from_jid, "789@s.whatsapp.net");
    assert_eq!(reaction.text.as_deref(), Some("+"));
    assert_eq!(reaction.timestamp, Some(1_700_000_005_123));

    let stored_key = wa_core::reaction_event_store_key(reaction);
    let stored = store
        .get(KeyNamespace::ReactionEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_reaction_event(&stored).unwrap();
    assert_eq!(stored, *reaction);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_maps_poll_update_to_message_update() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("poll-creation-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let poll_update = wa_proto::proto::Message {
        poll_update_message: Some(wa_proto::proto::message::PollUpdateMessage {
            poll_creation_message_key: Some(target_key),
            vote: Some(wa_proto::proto::message::PollEncValue {
                enc_payload: Some(Bytes::from_static(b"encrypted-vote")),
                enc_iv: Some(Bytes::from_static(b"vote-iv")),
            }),
            metadata: Some(Default::default()),
            sender_timestamp_ms: Some(1_700_000_007_123),
        }),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "poll-update-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "poll")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(poll_update.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "poll-update-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], "789@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "poll-update-1");
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.timestamp, Some(1_700_000_007_123));
    assert_eq!(update.fields["source"], "poll_update_message");
    assert_eq!(update.fields["poll_update"], "true");
    assert_eq!(update.fields["voter_jid"], "789@s.whatsapp.net");
    assert_eq!(update.fields["vote_encrypted"], "true");
    assert_eq!(update.fields["metadata_present"], "true");
    assert_eq!(update.fields["encrypted_vote_payload_bytes"], "14");
    assert_eq!(update.fields["encrypted_vote_iv_bytes"], "7");

    let stored_update_key = wa_core::message_event_store_key(&update.key);
    let stored_update = store
        .get(KeyNamespace::MessageUpdate, &stored_update_key)
        .await
        .unwrap()
        .unwrap();
    let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
    assert_eq!(stored_update, *update);
    let stored_upsert_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    assert!(
        store
            .get(KeyNamespace::MessageEvent, &stored_upsert_key)
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_decrypts_poll_update_from_stored_creation_secret() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let poll_secret = Bytes::from(vec![7u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("poll-creation-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let creation_message = wa_core::build_poll_message(wa_core::PollContent::new(
        "Deploy?",
        ["Ship", "Hold"],
        1,
        poll_secret.clone(),
    ))
    .unwrap();
    let creation_event = MessageEvent::new(target_event_key.clone())
        .with_payload(wa_core::encode_message(&creation_message).unwrap())
        .with_field("kind", "group")
        .with_field("author", "456@s.whatsapp.net")
        .with_field("sender", "123@g.us")
        .with_field("from_me", "false");
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
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let poll_update_content = wa_core::build_encrypted_poll_update_content_with_iv(
        wa_core::PollVoteContent::from_option_names(
            target_key.clone(),
            ["Ship"],
            poll_secret,
            "456@s.whatsapp.net",
            "789@s.whatsapp.net",
        )
        .unwrap(),
        Bytes::from_static(b"poll-vote-iv"),
    )
    .unwrap()
    .with_sender_timestamp_ms(1_700_000_007_123);
    let poll_update = wa_core::build_poll_update_message(poll_update_content).unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "poll-update-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "poll")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(poll_update.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "poll-update-1");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.fields["vote_decrypted"], "true");
    assert_eq!(update.fields["selected_options_count"], "1");
    assert_eq!(
        update.fields["poll_secret_creator_jid"],
        "456@s.whatsapp.net"
    );
    assert_eq!(update.fields["selected_option_hashes_hex"].len(), 64);

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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_decrypts_poll_update_from_stored_creation_secret()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "signal-poll-update")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];

    let poll_secret = Bytes::from(vec![35u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("poll-creation-signal-in-1".to_owned()),
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
    .with_sender_timestamp_ms(1_700_000_010_123);
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
    let plaintext = pad_random_max16_for_test(Bytes::from(poll_update.encode_to_vec()), 6);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-poll-update-in-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "poll")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes.clone()),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-poll-update-in-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "signal-poll-update-in-1");
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert!(decoded.poll_update_message.is_some());
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.timestamp, Some(1_700_000_010_123));
    assert_eq!(update.fields["source"], "poll_update_message");
    assert_eq!(update.fields["poll_update"], "true");
    assert_eq!(update.fields["voter_jid"], "123@s.whatsapp.net");
    assert_eq!(
        update.fields["poll_secret_creator_jid"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(update.fields["vote_decrypted"], "true");
    assert_eq!(update.fields["selected_options_count"], "1");
    assert_eq!(update.fields["selected_option_hashes_hex"].len(), 64);

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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn late_poll_creation_merges_and_decrypts_pending_poll_update() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let poll_secret = Bytes::from(vec![7u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("poll-creation-late-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let poll_update_content = wa_core::build_encrypted_poll_update_content_with_iv(
        wa_core::PollVoteContent::from_option_names(
            target_key.clone(),
            ["Ship"],
            poll_secret.clone(),
            "456@s.whatsapp.net",
            "789@s.whatsapp.net",
        )
        .unwrap(),
        Bytes::from_static(b"poll-vote-iv"),
    )
    .unwrap()
    .with_sender_timestamp_ms(1_700_000_007_123);
    let poll_update = wa_core::build_poll_update_message(poll_update_content).unwrap();
    let poll_update = wa_core::ProtoMessage {
        view_once_message: Some(Box::new(wa_proto::proto::message::FutureProofMessage {
            message: Some(Box::new(poll_update)),
        })),
        ..wa_core::ProtoMessage::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "poll-update-late-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "poll")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(poll_update.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "poll-update-late-1");
    let target_store_key = wa_core::message_event_store_key(&target_event_key);
    let pending = store
        .get(KeyNamespace::MessageUpdate, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let pending = wa_core::decode_stored_message_update(&pending).unwrap();
    assert_eq!(pending.fields["vote_encrypted"], "true");
    assert!(!pending.fields.contains_key("vote_decrypted"));

    let creation_message = wa_core::build_poll_message(wa_core::PollContent::new(
        "Deploy?",
        ["Ship", "Hold"],
        1,
        poll_secret,
    ))
    .unwrap();
    let creation_event = MessageEvent::new(target_event_key.clone())
        .with_payload(wa_core::encode_message(&creation_message).unwrap())
        .with_field("kind", "group")
        .with_field("author", "456@s.whatsapp.net")
        .with_field("sender", "123@g.us")
        .with_field("from_me", "false");
    persist_receive_events(
        &store,
        &[Event::Batch(Box::new(wa_core::EventBatch {
            messages_upsert: vec![creation_event],
            ..wa_core::EventBatch::default()
        }))],
    )
    .await
    .unwrap();

    let stored_target = store
        .get(KeyNamespace::MessageEvent, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let stored_target = wa_core::decode_stored_message_event(&stored_target).unwrap();
    assert_eq!(stored_target.fields["vote_decrypted"], "true");
    assert_eq!(stored_target.fields["selected_options_count"], "1");
    assert_eq!(stored_target.fields["poll_update"], "true");
    assert!(
        store
            .get(KeyNamespace::MessageUpdate, &target_store_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn late_poll_creation_merges_signal_provider_pending_poll_update() {
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
        "signal-late-poll-update",
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

    let poll_secret = Bytes::from(vec![37u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("poll-creation-signal-late-1".to_owned()),
        participant: None,
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let poll_update_content = wa_core::build_encrypted_poll_update_content_with_iv(
        wa_core::PollVoteContent::from_option_names(
            target_key.clone(),
            ["Approve"],
            poll_secret.clone(),
            "999:7@s.whatsapp.net",
            "123@s.whatsapp.net",
        )
        .unwrap(),
        Bytes::from_static(b"poll-vote-iv"),
    )
    .unwrap()
    .with_sender_timestamp_ms(1_700_000_012_123);
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
    let plaintext = pad_random_max16_for_test(Bytes::from(poll_update.encode_to_vec()), 8);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-poll-update-late-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "poll")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "signal-poll-update-late-1");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
    let target_store_key = wa_core::message_event_store_key(&target_event_key);
    let pending = store
        .get(KeyNamespace::MessageUpdate, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let pending = wa_core::decode_stored_message_update(&pending).unwrap();
    assert_eq!(pending.fields["vote_encrypted"], "true");
    assert_eq!(pending.fields["voter_jid"], "123@s.whatsapp.net");
    assert!(!pending.fields.contains_key("vote_decrypted"));
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

    let creation_message = wa_core::build_poll_message(wa_core::PollContent::new(
        "Launch?",
        ["Approve", "Hold"],
        1,
        poll_secret,
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

    let stored_target = store
        .get(KeyNamespace::MessageEvent, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let stored_target = wa_core::decode_stored_message_event(&stored_target).unwrap();
    assert_eq!(stored_target.fields["vote_decrypted"], "true");
    assert_eq!(stored_target.fields["selected_options_count"], "1");
    assert_eq!(stored_target.fields["poll_update"], "true");
    assert_eq!(
        stored_target.fields["poll_secret_creator_jid"],
        "999:7@s.whatsapp.net"
    );
    assert!(
        store
            .get(KeyNamespace::MessageUpdate, &target_store_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn late_event_creation_merges_and_decrypts_pending_event_response() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let event_secret = Bytes::from(vec![8u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("event-creation-late-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let event_response_content = wa_core::build_encrypted_event_response_content_with_iv(
        wa_core::EventResponsePayload::new(
            target_key.clone(),
            wa_core::EventResponseKind::Maybe,
            event_secret.clone(),
            "456@s.whatsapp.net",
            "789@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_009_123)
        .with_extra_guest_count(4),
        Bytes::from_static(b"event-rsvpiv"),
    )
    .unwrap();
    let event_response = wa_core::build_event_response_message(event_response_content).unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "event-response-late-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(event_response.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "event-response-late-1");
    let target_store_key = wa_core::message_event_store_key(&target_event_key);
    let pending = store
        .get(KeyNamespace::MessageUpdate, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let pending = wa_core::decode_stored_message_update(&pending).unwrap();
    assert_eq!(pending.fields["response_encrypted"], "true");
    assert!(!pending.fields.contains_key("response_decrypted"));

    let creation_message = wa_core::build_event_message(wa_core::EventContent::new(
        "Standup",
        1_700_000_000,
        event_secret,
    ))
    .unwrap();
    let creation_event = MessageEvent::new(target_event_key.clone())
        .with_payload(wa_core::encode_message(&creation_message).unwrap())
        .with_field("kind", "group")
        .with_field("author", "456@s.whatsapp.net")
        .with_field("sender", "123@g.us")
        .with_field("from_me", "false");
    persist_receive_events(
        &store,
        &[Event::Batch(Box::new(wa_core::EventBatch {
            messages_upsert: vec![creation_event],
            ..wa_core::EventBatch::default()
        }))],
    )
    .await
    .unwrap();

    let stored_target = store
        .get(KeyNamespace::MessageEvent, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let stored_target = wa_core::decode_stored_message_event(&stored_target).unwrap();
    assert_eq!(stored_target.fields["response_decrypted"], "true");
    assert_eq!(stored_target.fields["response"], "maybe");
    assert_eq!(
        stored_target.fields["response_timestamp_ms"],
        "1700000009123"
    );
    assert_eq!(stored_target.fields["extra_guest_count"], "4");
    assert_eq!(stored_target.fields["event_response"], "true");
    assert_eq!(
        stored_target.fields["event_secret_creator_jid"],
        "456@s.whatsapp.net"
    );
    assert!(
        store
            .get(KeyNamespace::MessageUpdate, &target_store_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn late_event_creation_merges_signal_provider_pending_event_response() {
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
        "signal-late-event-response",
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

    let event_secret = Bytes::from(vec![38u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("event-creation-signal-late-1".to_owned()),
        participant: None,
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let event_response_content = wa_core::build_encrypted_event_response_content_with_iv(
        wa_core::EventResponsePayload::new(
            target_key.clone(),
            wa_core::EventResponseKind::Going,
            event_secret.clone(),
            "999:7@s.whatsapp.net",
            "123@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_013_123)
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
    let plaintext = pad_random_max16_for_test(Bytes::from(event_response.encode_to_vec()), 9);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-event-response-late-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes.clone()),
        ]);
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "signal-event-response-late-1");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
    let target_store_key = wa_core::message_event_store_key(&target_event_key);
    let pending = store
        .get(KeyNamespace::MessageUpdate, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let pending = wa_core::decode_stored_message_update(&pending).unwrap();
    assert_eq!(pending.fields["response_encrypted"], "true");
    assert_eq!(pending.fields["responder_jid"], "123@s.whatsapp.net");
    assert!(!pending.fields.contains_key("response_decrypted"));
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

    let creation_message = wa_core::build_event_message(wa_core::EventContent::new(
        "Launch review",
        1_700_000_000,
        event_secret,
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

    let stored_target = store
        .get(KeyNamespace::MessageEvent, &target_store_key)
        .await
        .unwrap()
        .unwrap();
    let stored_target = wa_core::decode_stored_message_event(&stored_target).unwrap();
    assert_eq!(stored_target.fields["response_decrypted"], "true");
    assert_eq!(stored_target.fields["response"], "going");
    assert_eq!(
        stored_target.fields["response_timestamp_ms"],
        "1700000013123"
    );
    assert_eq!(stored_target.fields["extra_guest_count"], "1");
    assert_eq!(stored_target.fields["event_response"], "true");
    assert_eq!(
        stored_target.fields["event_secret_creator_jid"],
        "999:7@s.whatsapp.net"
    );
    assert!(
        store
            .get(KeyNamespace::MessageUpdate, &target_store_key)
            .await
            .unwrap()
            .is_none()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_maps_event_response_to_message_update() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("event-creation-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let event_response = wa_proto::proto::Message {
        enc_event_response_message: Some(wa_proto::proto::message::EncEventResponseMessage {
            event_creation_message_key: Some(target_key),
            enc_payload: Some(Bytes::from_static(b"encrypted-rsvp")),
            enc_iv: Some(Bytes::from_static(b"rsvp-iv")),
        }),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "event-response-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(event_response.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "event-response-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], "789@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "event-response-1");
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.fields["source"], "enc_event_response_message");
    assert_eq!(update.fields["event_response"], "true");
    assert_eq!(update.fields["responder_jid"], "789@s.whatsapp.net");
    assert_eq!(update.fields["response_encrypted"], "true");
    assert_eq!(
        update.fields["encrypted_event_response_payload_bytes"],
        "14"
    );
    assert_eq!(update.fields["encrypted_event_response_iv_bytes"], "7");

    let stored_update_key = wa_core::message_event_store_key(&update.key);
    let stored_update = store
        .get(KeyNamespace::MessageUpdate, &stored_update_key)
        .await
        .unwrap()
        .unwrap();
    let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
    assert_eq!(stored_update, *update);
    let stored_upsert_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    assert!(
        store
            .get(KeyNamespace::MessageEvent, &stored_upsert_key)
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_decrypts_event_response_from_stored_creation_secret() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let event_secret = Bytes::from(vec![8u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("event-creation-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let target_event_key = wa_core::message_event_key_from_proto_key(&target_key).unwrap();
    let creation_message = wa_core::build_event_message(wa_core::EventContent::new(
        "Standup",
        1_700_000_000,
        event_secret.clone(),
    ))
    .unwrap();
    let creation_event = MessageEvent::new(target_event_key.clone())
        .with_payload(wa_core::encode_message(&creation_message).unwrap())
        .with_field("kind", "group")
        .with_field("author", "456@s.whatsapp.net")
        .with_field("sender", "123@g.us")
        .with_field("from_me", "false");
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
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let event_response_content = wa_core::build_encrypted_event_response_content_with_iv(
        wa_core::EventResponsePayload::new(
            target_key.clone(),
            wa_core::EventResponseKind::Going,
            event_secret,
            "456@s.whatsapp.net",
            "789@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_009_123)
        .with_extra_guest_count(3),
        Bytes::from_static(b"event-rsvpiv"),
    )
    .unwrap();
    let event_response = wa_core::build_event_response_message(event_response_content).unwrap();
    let incoming = BinaryNode::new("message")
        .with_attr("id", "event-response-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(event_response.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.attrs["id"], "event-response-1");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_update.len(), 1);
    let update = &batch.messages_update[0];
    assert_eq!(update.key, target_event_key);
    assert_eq!(update.fields["response_decrypted"], "true");
    assert_eq!(update.fields["response"], "going");
    assert_eq!(update.fields["response_timestamp_ms"], "1700000009123");
    assert_eq!(update.fields["extra_guest_count"], "3");
    assert_eq!(
        update.fields["event_secret_creator_jid"],
        "456@s.whatsapp.net"
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
    assert_eq!(stored_target.fields["extra_guest_count"], "3");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_decrypts_event_response_from_stored_creation_secret()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload =
        wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 1, "signal-event-response")
            .await
            .unwrap();
    let receiver_credentials = upload.credentials;
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let receiver_pre_key_id = upload.pre_key_ids[0];

    let event_secret = Bytes::from(vec![36u8; 32]);
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(true),
        id: Some("event-creation-signal-in-1".to_owned()),
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
        .with_timestamp_ms(1_700_000_011_123)
        .with_extra_guest_count(2),
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
    let plaintext = pad_random_max16_for_test(Bytes::from(event_response.encode_to_vec()), 7);
    let encrypted = wa_core::encrypt_signal_outbound_pre_key_session_message(
        &sender_material,
        &sender_base_key,
        &receiver_session,
        &XEdDsaNoiseCertificateVerifier,
        &plaintext,
    )
    .unwrap();

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-event-response-in-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "event")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(encrypted.message_bytes.clone()),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-event-response-in-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-event-response-in-1"
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
    assert_eq!(
        update.fields["event_secret_creator_jid"],
        "999:7@s.whatsapp.net"
    );
    assert_eq!(update.fields["response_decrypted"], "true");
    assert_eq!(update.fields["response"], "maybe");
    assert_eq!(update.fields["response_timestamp_ms"], "1700000011123");
    assert_eq!(update.fields["extra_guest_count"], "2");

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
    assert_eq!(stored_target.fields["extra_guest_count"], "2");
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
async fn process_incoming_node_maps_revoke_protocol_to_message_delete() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let target_key = wa_core::MessageEventKey::new(
        "123@g.us",
        "target-1",
        Some("456@s.whatsapp.net".to_owned()),
    );
    persist_receive_events(
        &store,
        &[Event::Batch(Box::new(wa_core::EventBatch {
            messages_upsert: vec![
                wa_core::MessageEvent::new(target_key.clone()).with_field("body", "old"),
            ],
            ..wa_core::EventBatch::default()
        }))],
    )
    .await
    .unwrap();
    assert!(
        store
            .get(
                KeyNamespace::MessageEvent,
                &wa_core::message_event_store_key(&target_key)
            )
            .await
            .unwrap()
            .is_some()
    );

    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let revoke = wa_proto::proto::Message {
        protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
            key: Some(wa_proto::proto::MessageKey {
                remote_jid: Some("123@g.us".to_owned()),
                from_me: Some(true),
                id: Some("target-1".to_owned()),
                participant: Some("456@s.whatsapp.net".to_owned()),
            }),
            r#type: Some(wa_proto::proto::message::protocol_message::Type::Revoke as i32),
            ..Default::default()
        })),
        ..wa_proto::proto::Message::default()
    };
    let incoming = BinaryNode::new("message")
        .with_attr("id", "protocol-delete-1")
        .with_attr("from", "123@g.us")
        .with_attr("participant", "789@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(revoke.encode_to_vec())),
        ]);
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 2);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "protocol-delete-1");
    assert_eq!(ack.attrs["class"], "message");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "protocol-delete-1");
    assert_eq!(batch.messages_delete, vec![target_key.clone()]);
    assert!(
        store
            .get(
                KeyNamespace::MessageEvent,
                &wa_core::message_event_store_key(&target_key)
            )
            .await
            .unwrap()
            .is_none()
    );
    let protocol_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
    assert!(
        store
            .get(KeyNamespace::MessageEvent, &protocol_key)
            .await
            .unwrap()
            .is_some()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_decrypts_pre_key_message_and_replies() {
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
        conversation: Some("encrypted hello".to_owned()),
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
        .with_attr("id", "signal-in-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-in-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(batch.messages_upsert[0].key.id, "signal-in-1");
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(decoded.conversation.as_deref(), Some("encrypted hello"));
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

    let replay_pre_key = BinaryNode::new("message")
        .with_attr("id", "signal-in-1-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let replay_pre_key_result = client
        .process_incoming_node_with_signal_provider(&connection, &replay_pre_key, &mut buffer)
        .await
        .unwrap();
    assert_eq!(
        replay_pre_key_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(replay_pre_key_result.event_count, 0);
    assert!(
        replay_pre_key_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 0"))
    );
    let replay_pre_key_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_pre_key_nack.tag, "ack");
    assert_eq!(replay_pre_key_nack.attrs["id"], "signal-in-1-replay");
    assert_eq!(replay_pre_key_nack.attrs["class"], "message");
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
            .load_session_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap(),
        record_after_first_bytes
    );

    let second_text = wa_proto::proto::Message {
        conversation: Some("encrypted second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 5);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    store
        .delete_signal_key(KeyNamespace::SignalProviderSession, "123.0")
        .await
        .unwrap();
    let missing_session_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-missing-session")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let missing_session_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &missing_session_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        missing_session_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(missing_session_result.event_count, 0);
    assert!(
        missing_session_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("missing Signal provider session"))
    );
    let missing_session_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(missing_session_nack.tag, "ack");
    assert_eq!(
        missing_session_nack.attrs["id"],
        "signal-in-2-missing-session"
    );
    assert_eq!(missing_session_nack.attrs["class"], "message");
    assert_eq!(
        missing_session_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
            &record_after_first_bytes,
        )
        .await
        .unwrap();
    store
        .delete_signal_key(KeyNamespace::SignalProviderIdentity, "123.0")
        .await
        .unwrap();
    let missing_identity_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-missing-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let missing_identity_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &missing_identity_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        missing_identity_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(missing_identity_result.event_count, 0);
    assert!(
        missing_identity_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("no provider identity"))
    );
    let missing_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(missing_identity_nack.tag, "ack");
    assert_eq!(
        missing_identity_nack.attrs["id"],
        "signal-in-2-missing-identity"
    );
    assert_eq!(missing_identity_nack.attrs["class"], "message");
    assert_eq!(
        missing_identity_nack.attrs["error"],
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
        record_after_first_bytes
    );
    assert!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap()
            .is_none()
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
    let malformed_identity_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-malformed-identity")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let malformed_identity_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &malformed_identity_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        malformed_identity_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(malformed_identity_result.event_count, 0);
    assert!(
        malformed_identity_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("invalid signal public key length: 5"))
    );
    let malformed_identity_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(malformed_identity_nack.tag, "ack");
    assert_eq!(
        malformed_identity_nack.attrs["id"],
        "signal-in-2-malformed-identity"
    );
    assert_eq!(malformed_identity_nack.attrs["class"], "message");
    assert_eq!(
        malformed_identity_nack.attrs["error"],
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
        record_after_first_bytes
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(malformed_identity)
    );

    let wrong_identity =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&generate_key_pair().public));
    assert_ne!(wrong_identity, sender_material.identity.public_key);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            "123.0",
            &wrong_identity,
        )
        .await
        .unwrap();
    let identity_mismatch_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-identity-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let identity_mismatch_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &identity_mismatch_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        identity_mismatch_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(identity_mismatch_result.event_count, 0);
    assert!(
        identity_mismatch_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("provider identity mismatch"))
    );
    let identity_mismatch_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(identity_mismatch_nack.tag, "ack");
    assert_eq!(
        identity_mismatch_nack.attrs["id"],
        "signal-in-2-identity-mismatch"
    );
    assert_eq!(identity_mismatch_nack.attrs["class"], "message");
    assert_eq!(
        identity_mismatch_nack.attrs["error"],
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
        record_after_first_bytes
    );
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_identity_record("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some(wrong_identity)
    );
    store
        .set_signal_key(
            KeyNamespace::SignalProviderIdentity,
            "123.0",
            &sender_material.identity.public_key,
        )
        .await
        .unwrap();
    let valid_session_record =
        wa_core::decode_signal_provider_session_record(&record_after_first_bytes).unwrap();
    let local_public =
        prefixed_signal_public_key(&valid_session_record.local_ratchet_key_pair.public);
    let local_public_offset = record_after_first_bytes
        .windows(local_public.len())
        .position(|window| window == local_public)
        .expect("encoded session contains local ratchet public key");
    let mut invalid_session = record_after_first_bytes.to_vec();
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
    let invalid_session_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-invalid-session")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let invalid_session_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &invalid_session_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        invalid_session_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(invalid_session_result.event_count, 0);
    assert!(
        invalid_session_result
            .error
            .as_deref()
            .is_some_and(|error| {
                error.contains(
                    "Signal provider session local ratchet public key does not match private key",
                )
            })
    );
    let invalid_session_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_session_nack.tag, "ack");
    assert_eq!(
        invalid_session_nack.attrs["id"],
        "signal-in-2-invalid-session"
    );
    assert_eq!(invalid_session_nack.attrs["class"], "message");
    assert_eq!(
        invalid_session_nack.attrs["error"],
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
        invalid_session
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
    let unpaired_receiving_chain_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-unpaired-receiving-chain")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let unpaired_receiving_chain_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &unpaired_receiving_chain_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        unpaired_receiving_chain_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(unpaired_receiving_chain_result.event_count, 0);
    assert!(
        unpaired_receiving_chain_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains(
                "Signal provider session receiving chain and remote ratchet key must be stored together"
            ))
    );
    let unpaired_receiving_chain_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(unpaired_receiving_chain_nack.tag, "ack");
    assert_eq!(
        unpaired_receiving_chain_nack.attrs["id"],
        "signal-in-2-unpaired-receiving-chain"
    );
    assert_eq!(unpaired_receiving_chain_nack.attrs["class"], "message");
    assert_eq!(
        unpaired_receiving_chain_nack.attrs["error"],
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
    let uninitialized_sending_chain_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-uninitialized-send-chain")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let uninitialized_sending_chain_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &uninitialized_sending_chain_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        uninitialized_sending_chain_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(uninitialized_sending_chain_result.event_count, 0);
    assert!(
        uninitialized_sending_chain_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("decryption failed"))
    );
    let uninitialized_sending_chain_nack =
        decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
    assert_eq!(uninitialized_sending_chain_nack.tag, "ack");
    assert_eq!(
        uninitialized_sending_chain_nack.attrs["id"],
        "signal-in-2-uninitialized-send-chain"
    );
    assert_eq!(uninitialized_sending_chain_nack.attrs["class"], "message");
    assert_eq!(
        uninitialized_sending_chain_nack.attrs["error"],
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
    let remote_without_receiving_chain_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-remote-without-receiving-chain")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let remote_without_receiving_chain_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &remote_without_receiving_chain_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        remote_without_receiving_chain_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(remote_without_receiving_chain_result.event_count, 0);
    assert!(
        remote_without_receiving_chain_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains(
                "Signal provider session receiving chain and remote ratchet key must be stored together"
            ))
    );
    let remote_without_receiving_chain_nack =
        decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
    assert_eq!(remote_without_receiving_chain_nack.tag, "ack");
    assert_eq!(
        remote_without_receiving_chain_nack.attrs["id"],
        "signal-in-2-remote-without-receiving-chain"
    );
    assert_eq!(
        remote_without_receiving_chain_nack.attrs["class"],
        "message"
    );
    assert_eq!(
        remote_without_receiving_chain_nack.attrs["error"],
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
    let skipped_without_remote_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-skipped-without-remote")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let skipped_without_remote_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &skipped_without_remote_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        skipped_without_remote_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(skipped_without_remote_result.event_count, 0);
    assert!(
        skipped_without_remote_result
            .error
            .as_deref()
            .is_some_and(|error| error
                .contains("Signal provider skipped message keys require remote ratchet key"))
    );
    let skipped_without_remote_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(skipped_without_remote_nack.tag, "ack");
    assert_eq!(
        skipped_without_remote_nack.attrs["id"],
        "signal-in-2-skipped-without-remote"
    );
    assert_eq!(skipped_without_remote_nack.attrs["class"], "message");
    assert_eq!(
        skipped_without_remote_nack.attrs["error"],
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

    let malformed_session = Bytes::from_static(b"not-a-provider-session");
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &malformed_session,
        )
        .await
        .unwrap();
    let malformed_session_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-in-2-malformed-session")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let malformed_session_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &malformed_session_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        malformed_session_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(malformed_session_result.event_count, 0);
    assert!(
        malformed_session_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unsupported Signal provider session version"))
    );
    let malformed_session_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(malformed_session_nack.tag, "ack");
    assert_eq!(
        malformed_session_nack.attrs["id"],
        "signal-in-2-malformed-session"
    );
    assert_eq!(malformed_session_nack.attrs["class"], "message");
    assert_eq!(
        malformed_session_nack.attrs["error"],
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
        malformed_session
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
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-in-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);

    let second_result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming_second, &mut buffer)
        .await
        .unwrap();

    assert_eq!(second_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(second_result.event_count, 1);
    assert!(second_result.error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-in-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");

    let Event::Batch(second_batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.remote_jid,
        "123@s.whatsapp.net"
    );
    assert_eq!(second_batch.messages_upsert[0].key.id, "signal-in-2");
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("encrypted second")
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

    let send_fut = client.send_text_with_signal_provider(
        &connection,
        "123@s.whatsapp.net",
        "provider reply",
        MessageRelayOptions::new().with_message_id("signal-reply-1"),
    );
    tokio::pin!(send_fut);
    tokio::time::timeout(
        Duration::from_secs(1),
        respond_to_next_query(
            &mut sink_rx,
            &_stream_tx,
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
        ),
    )
    .await
    .expect("reply send should issue a device query");

    let reply_relay = tokio::time::timeout(Duration::from_secs(1), send_fut)
        .await
        .expect("reply send should complete")
        .unwrap();
    assert_eq!(reply_relay.message_id, "signal-reply-1");
    let sent_reply_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("reply relay should be emitted")
        .unwrap();
    let sent_reply = decode_inbound_binary_node(&sent_reply_frame).unwrap().node;
    assert_eq!(sent_reply, reply_relay.node);
    assert_eq!(sent_reply.tag, "message");
    assert_eq!(sent_reply.attrs["id"], "signal-reply-1");
    let enc = test_participant_enc_node(&sent_reply, "123@s.whatsapp.net");
    assert_eq!(enc.attrs["type"], "msg");
    let reply_ciphertext = test_node_bytes(enc).unwrap();
    let decrypted_reply = wa_core::decrypt_signal_provider_session_record_message(
        &second.record,
        &reply_ciphertext,
        &sender_identity,
    )
    .unwrap();
    let unpadded_reply = wa_core::unpad_random_max16(&decrypted_reply.plaintext).unwrap();
    let reply = wa_proto::proto::Message::decode(unpadded_reply).unwrap();
    assert_eq!(
        reply
            .extended_text_message
            .as_ref()
            .unwrap()
            .text
            .as_deref(),
        Some("provider reply")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_canonicalizes_legacy_direct_signal_sender() {
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
    let first_text = wa_proto::proto::Message {
        conversation: Some("legacy encrypted hello".to_owned()),
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
    let incoming_first = BinaryNode::new("message")
        .with_attr("id", "signal-legacy-direct-in-1")
        .with_attr("from", legacy_sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let first_result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming_first, &mut buffer)
        .await
        .unwrap();

    assert_eq!(first_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(first_result.event_count, 1);
    assert!(first_result.error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-legacy-direct-in-1");
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
        "signal-legacy-direct-in-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("legacy encrypted hello")
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
        Some(sender_material.identity.public_key.clone())
    );

    let second_text = wa_proto::proto::Message {
        conversation: Some("legacy encrypted second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 5);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-legacy-direct-in-2")
        .with_attr("from", legacy_sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);

    let second_result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming_second, &mut buffer)
        .await
        .unwrap();

    assert_eq!(second_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(second_result.event_count, 1);
    assert!(second_result.error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-legacy-direct-in-2");
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
        "signal-legacy-direct-in-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("legacy encrypted second")
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

    let reply = client
        .signal_message_codec()
        .unwrap()
        .encrypt_message(canonical_sender_jid, Bytes::from_static(b"legacy reply"))
        .await
        .unwrap();
    assert_eq!(
        reply.ciphertext_type,
        wa_core::MessageCiphertextType::Message
    );
    let decrypted_reply = wa_core::decrypt_signal_provider_session_record_message(
        &first.record,
        &reply.ciphertext,
        &sender_identity,
    )
    .unwrap();
    let reply_plaintext = wa_core::unpad_random_max16(&decrypted_reply.plaintext).unwrap();
    assert_eq!(reply_plaintext, Bytes::from_static(b"legacy reply"));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_accepts_signed_pre_key_only_message() {
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
                conversation: Some("signed-pre-key only".to_owned()),
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
        &plaintext,
    )
    .unwrap();
    assert!(!first.used_one_time_pre_key);
    assert_eq!(first.message.pre_key_id, None);
    let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-signed-only-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-signed-only-1");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");

    let Event::Batch(batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "signal-signed-only-1");
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(decoded.conversation.as_deref(), Some("signed-pre-key only"));
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
        Some(sender_material.identity.public_key)
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
        .with_attr("id", "signal-signed-only-1-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first_message_bytes.clone()),
        ]);
    let replay_pre_key_result = client
        .process_incoming_node_with_signal_provider(&connection, &replay_pre_key, &mut buffer)
        .await
        .unwrap();
    assert_eq!(
        replay_pre_key_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(replay_pre_key_result.event_count, 0);
    assert!(
        replay_pre_key_result
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
        "signal-signed-only-1-replay"
    );
    assert_eq!(replay_pre_key_nack.attrs["class"], "message");
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

    let second_text = wa_proto::proto::Message {
        conversation: Some("signed-pre-key second".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let second_plaintext = pad_random_max16_for_test(Bytes::from(second_text.encode_to_vec()), 5);
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &second_plaintext,
        &sender_identity,
    )
    .unwrap();
    let incoming_second = BinaryNode::new("message")
        .with_attr("id", "signal-signed-only-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);

    let second_result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming_second, &mut buffer)
        .await
        .unwrap();

    assert_eq!(second_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(second_result.event_count, 1);
    assert!(second_result.error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-signed-only-2");
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
        "signal-signed-only-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("signed-pre-key second")
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
async fn process_incoming_node_with_signal_provider_preserves_state_after_failed_pre_key_decrypt() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials.clone())
        .await
        .unwrap();
    let upload = wa_core::prepare_pre_key_upload(&store, &receiver_credentials, 2, "pre-key")
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
                conversation: Some("pre-key after failures".to_owned()),
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
        &plaintext,
    )
    .unwrap();

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

    let incoming_node = |id: &'static str, ciphertext: Bytes| {
        BinaryNode::new("message")
            .with_attr("id", id)
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "pkmsg")
                    .with_content(ciphertext),
            ])
    };
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    store
        .delete_signal_key(KeyNamespace::Credentials, "schema-version")
        .await
        .unwrap();
    let missing_material_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-pre-key-missing-material",
                first.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        missing_material_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(missing_material_result.event_count, 0);
    assert!(
        missing_material_result.error.as_deref().is_some_and(
            |error| error.contains("missing local Signal key material for pre-key decrypt")
        )
    );
    let missing_material_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(missing_material_nack.tag, "ack");
    assert_eq!(
        missing_material_nack.attrs["id"],
        "signal-pre-key-missing-material"
    );
    assert_eq!(missing_material_nack.attrs["class"], "message");
    assert_eq!(missing_material_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(missing_material_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        missing_material_nack.attrs["error"],
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

    let wrong_pre_key_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-pre-key-wrong-material", wrong_pre_key_message),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        wrong_pre_key_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(wrong_pre_key_result.event_count, 0);
    assert!(
        wrong_pre_key_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error: decryption failed"))
    );
    let wrong_pre_key_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(wrong_pre_key_nack.tag, "ack");
    assert_eq!(
        wrong_pre_key_nack.attrs["id"],
        "signal-pre-key-wrong-material"
    );
    assert_eq!(wrong_pre_key_nack.attrs["class"], "message");
    assert_eq!(wrong_pre_key_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(wrong_pre_key_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        wrong_pre_key_nack.attrs["error"],
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

    let tampered_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-pre-key-tampered", tampered),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(tampered_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(tampered_result.event_count, 0);
    assert!(
        tampered_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error: decryption failed"))
    );
    let tampered_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_nack.tag, "ack");
    assert_eq!(tampered_nack.attrs["id"], "signal-pre-key-tampered");
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

    let signed_pre_key_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-pre-key-signed-id-mismatch",
                mismatched_signed_pre_key,
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        signed_pre_key_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(signed_pre_key_result.event_count, 0);
    assert!(
        signed_pre_key_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains(&expected_signed_pre_key_error))
    );
    let signed_pre_key_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(signed_pre_key_nack.tag, "ack");
    assert_eq!(
        signed_pre_key_nack.attrs["id"],
        "signal-pre-key-signed-id-mismatch"
    );
    assert_eq!(signed_pre_key_nack.attrs["class"], "message");
    assert_eq!(signed_pre_key_nack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(signed_pre_key_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(
        signed_pre_key_nack.attrs["error"],
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

    let valid_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-pre-key-after-failures", first.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(valid_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(valid_result.event_count, 1);
    assert!(valid_result.error.is_none());
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(valid_ack.attrs["id"], "signal-pre-key-after-failures");
    assert_eq!(valid_ack.attrs["class"], "message");
    assert_eq!(valid_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(valid_ack.attrs["from"], "999:7@s.whatsapp.net");
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(
        batch.messages_upsert[0].key.id,
        "signal-pre-key-after-failures"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("pre-key after failures")
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
async fn process_incoming_node_with_signal_provider_rejects_invalid_sender_key_record_without_mutation()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
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
                conversation: Some("group sender-key hello".to_owned()),
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
            "Signal sender-key signing public key does not match private key",
        ),
        (
            "duplicate-state",
            raw_client_sender_key_record(vec![
                raw_client_sender_key_state(key_id, 0, 0x11, signing_public_key.clone(), None, &[]),
                raw_client_sender_key_state(key_id, 1, 0x12, signing_public_key.clone(), None, &[]),
            ]),
            "duplicate Signal sender-key state",
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
            "duplicate Signal sender-key skipped message iteration",
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
            "Signal sender-key skipped iteration must be below chain iteration",
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
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    for (suffix, invalid_receiver_record, expected_error) in invalid_records {
        client
            .signal_provider_state_store()
            .store_sender_key_record(&record_key, &invalid_receiver_record)
            .await
            .unwrap();
        let invalid_id = format!("signal-group-invalid-sender-key-{suffix}");
        let invalid_result = client
            .process_incoming_node_with_signal_provider(
                &connection,
                &incoming_node(&invalid_id, encrypted.message_bytes.clone()),
                &mut buffer,
            )
            .await
            .unwrap();
        assert_eq!(invalid_result.action, wa_core::InboundNodeAction::Message);
        assert_eq!(invalid_result.event_count, 0);
        assert!(
            invalid_result
                .error
                .as_deref()
                .is_some_and(|error| error.contains(expected_error)),
            "{suffix} expected {expected_error:?}, got {:?}",
            invalid_result.error
        );
        let invalid_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(invalid_nack.tag, "ack");
        assert_eq!(invalid_nack.attrs["id"], invalid_id);
        assert_eq!(invalid_nack.attrs["class"], "message");
        assert_eq!(invalid_nack.attrs["to"], group_jid);
        assert_eq!(invalid_nack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(invalid_nack.attrs["participant"], sender_jid);
        assert_eq!(
            invalid_nack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
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
    let valid_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-group-valid-sender-key",
                encrypted.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(valid_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(valid_result.event_count, 1);
    assert!(valid_result.error.is_none());
    let valid_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(valid_ack.tag, "ack");
    assert_eq!(valid_ack.attrs["id"], "signal-group-valid-sender-key");
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
        "signal-group-valid-sender-key"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("group sender-key hello")
    );
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

    let mut invalid_signature = encrypted.message_bytes.to_vec();
    *invalid_signature
        .last_mut()
        .expect("sender-key signature bytes are present") ^= 1;
    let far_future_message = wa_core::sign_signal_sender_key_message(
        key_id,
        25_002,
        Bytes::from_static(b"far-future-group-ciphertext"),
        signing_key.private.expose(),
    )
    .unwrap();
    let far_future_message =
        wa_core::encode_signal_sender_key_message(&far_future_message).unwrap();
    let runtime_failures = vec![
        (
            "replay",
            encrypted.message_bytes.clone(),
            "duplicate Signal sender-key message iteration: 0",
        ),
        (
            "far-future",
            far_future_message,
            "Signal sender-key message is too far in the future",
        ),
        (
            "invalid-signature",
            Bytes::from(invalid_signature),
            "invalid Signal sender-key message signature",
        ),
    ];
    for (suffix, ciphertext, expected_error) in runtime_failures {
        let failure_id = format!("signal-group-sender-key-{suffix}");
        let failure_result = client
            .process_incoming_node_with_signal_provider(
                &connection,
                &incoming_node(&failure_id, ciphertext),
                &mut buffer,
            )
            .await
            .unwrap();
        assert_eq!(failure_result.action, wa_core::InboundNodeAction::Message);
        assert_eq!(failure_result.event_count, 0);
        assert!(
            failure_result
                .error
                .as_deref()
                .is_some_and(|error| error.contains(expected_error)),
            "{suffix} expected {expected_error:?}, got {:?}",
            failure_result.error
        );
        let failure_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(failure_nack.tag, "ack");
        assert_eq!(failure_nack.attrs["id"], failure_id);
        assert_eq!(failure_nack.attrs["class"], "message");
        assert_eq!(failure_nack.attrs["to"], group_jid);
        assert_eq!(failure_nack.attrs["from"], "999:7@s.whatsapp.net");
        assert_eq!(failure_nack.attrs["participant"], sender_jid);
        assert_eq!(
            failure_nack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(
            client
                .signal_provider_state_store()
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            updated_record
        );
    }
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_decrypts_out_of_order_sender_key_messages() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
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
        &text_plaintext("group sender-key first", 4),
    )
    .unwrap();
    assert_eq!(first.message.iteration, 0);
    let second = wa_core::encrypt_signal_sender_key_record_message(
        &first.record,
        &text_plaintext("group sender-key second", 5),
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
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let second_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-group-ooo-2", second.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(second_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(second_result.event_count, 1);
    assert!(second_result.error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&second_ack, "signal-group-ooo-2");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(second_batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        second_batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("group sender-key second")
    );
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

    let second_replay_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-group-ooo-2-replay", second.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        second_replay_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(second_replay_result.event_count, 0);
    assert!(second_replay_result.error.as_deref().is_some_and(|error| {
        error.contains("duplicate Signal sender-key message iteration: 1")
    }));
    let second_replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&second_replay_nack, "signal-group-ooo-2-replay");
    assert_eq!(
        second_replay_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
    let invalid_first_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-group-ooo-1-invalid-signature",
                Bytes::from(invalid_first_signature),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        invalid_first_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(invalid_first_result.event_count, 0);
    assert!(
        invalid_first_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("invalid Signal sender-key message signature")),
        "unexpected sender-key invalid-signature error: {:?}",
        invalid_first_result.error
    );
    let invalid_first_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&invalid_first_nack, "signal-group-ooo-1-invalid-signature");
    assert_eq!(
        invalid_first_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
    let failed_first_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-group-ooo-1-failed", failed_first),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        failed_first_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(failed_first_result.event_count, 0);
    assert!(
        failed_first_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error") && error.contains("decrypt")),
        "unexpected sender-key failed decrypt error: {:?}",
        failed_first_result.error
    );
    let failed_first_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&failed_first_nack, "signal-group-ooo-1-failed");
    assert_eq!(
        failed_first_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        client
            .signal_provider_state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_second
    );

    let first_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-group-ooo-1", first.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(first_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(first_result.event_count, 1);
    assert!(first_result.error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&first_ack, "signal-group-ooo-1");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(first_batch.messages_upsert[0].key.remote_jid, group_jid);
    assert_eq!(
        first_batch.messages_upsert[0].key.participant.as_deref(),
        Some(sender_jid)
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("group sender-key first")
    );
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

    let replay_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-group-ooo-1-replay", first.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(replay_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(replay_result.event_count, 0);
    assert!(replay_result.error.as_deref().is_some_and(|error| {
        error.contains("duplicate Signal sender-key message iteration: 0")
    }));
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_message_ack(&replay_nack, "signal-group-ooo-1-replay");
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
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap(),
        record_after_first
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_recovers_sender_key_record_from_distribution() {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
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
        &text_plaintext("group distribution first", 4),
    )
    .unwrap();
    let second = wa_core::encrypt_signal_sender_key_record_message(
        &first.record,
        &text_plaintext("group distribution second", 5),
    )
    .unwrap();
    let third = wa_core::encrypt_signal_sender_key_record_message(
        &second.record,
        &text_plaintext("group distribution third", 6),
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
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    for (id, encrypted, expected_text, expected_iteration, expected_skipped) in [
        (
            "signal-group-distribution-missing",
            first.message_bytes.clone(),
            "group distribution first",
            1,
            Vec::<u32>::new(),
        ),
        (
            "signal-group-distribution-deleted",
            second.message_bytes.clone(),
            "group distribution second",
            2,
            vec![0],
        ),
        (
            "signal-group-distribution-corrupt",
            third.message_bytes.clone(),
            "group distribution third",
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
        let result = client
            .process_incoming_node_with_signal_provider(
                &connection,
                &incoming_node(id, encrypted.clone()),
                &mut buffer,
            )
            .await
            .unwrap();
        assert_eq!(result.action, wa_core::InboundNodeAction::Message);
        assert_eq!(result.event_count, 1);
        assert!(result.error.is_none());
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
        let invalid_signature_result = client
            .process_incoming_node_with_signal_provider(
                &connection,
                &incoming_node(&invalid_signature_id, Bytes::from(invalid_signature)),
                &mut buffer,
            )
            .await
            .unwrap();
        assert_eq!(
            invalid_signature_result.action,
            wa_core::InboundNodeAction::Message
        );
        assert_eq!(invalid_signature_result.event_count, 0);
        assert!(
            invalid_signature_result
                .error
                .as_deref()
                .is_some_and(|error| error.contains("invalid Signal sender-key message signature")),
            "{id} expected invalid sender-key signature, got {:?}",
            invalid_signature_result.error
        );
        let invalid_signature_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&invalid_signature_nack, &invalid_signature_id);
        assert_eq!(
            invalid_signature_nack.attrs["error"],
            wa_core::NACK_PARSING_ERROR.to_string()
        );
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
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
        let replay_result = client
            .process_incoming_node_with_signal_provider(
                &connection,
                &incoming_node(&replay_id, encrypted),
                &mut buffer,
            )
            .await
            .unwrap();
        assert_eq!(replay_result.action, wa_core::InboundNodeAction::Message);
        assert_eq!(replay_result.event_count, 0);
        let expected_replay_error = format!(
            "duplicate Signal sender-key message iteration: {}",
            expected_iteration - 1
        );
        assert!(
            replay_result
                .error
                .as_deref()
                .is_some_and(|error| error.contains(&expected_replay_error)),
            "{id} expected {expected_replay_error:?}, got {:?}",
            replay_result.error
        );
        let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_message_ack(&replay_nack, &replay_id);
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
                .load_sender_key_record(&record_key)
                .await
                .unwrap()
                .unwrap(),
            stored_record
        );
    }
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_recovers_stale_sender_key_record_from_distribution()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
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
                conversation: Some("group stale distribution recovered".to_owned()),
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
        .with_attr("id", "signal-group-stale-distribution-recovery")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(encrypted.message_bytes.clone()),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-group-stale-distribution-recovery");
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
        "signal-group-stale-distribution-recovery"
    );
    let payload = batch.messages_upsert[0].payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("group stale distribution recovered")
    );
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
    let invalid_signature_incoming = BinaryNode::new("message")
        .with_attr(
            "id",
            "signal-group-stale-distribution-recovery-invalid-signature",
        )
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(Bytes::from(invalid_signature)),
        ]);
    let invalid_signature_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &invalid_signature_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        invalid_signature_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(invalid_signature_result.event_count, 0);
    assert!(
        invalid_signature_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("invalid Signal sender-key message signature")),
        "unexpected stale distribution invalid-signature error: {:?}",
        invalid_signature_result.error
    );
    let invalid_signature_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_signature_nack.tag, "ack");
    assert_eq!(
        invalid_signature_nack.attrs["id"],
        "signal-group-stale-distribution-recovery-invalid-signature"
    );
    assert_eq!(invalid_signature_nack.attrs["class"], "message");
    assert_eq!(invalid_signature_nack.attrs["to"], group_jid);
    assert_eq!(invalid_signature_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(invalid_signature_nack.attrs["participant"], sender_jid);
    assert_eq!(
        invalid_signature_nack.attrs["error"],
        wa_core::NACK_PARSING_ERROR.to_string()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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

    let replay_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-group-stale-distribution-recovery-replay")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "skmsg")
                .with_content(encrypted.message_bytes),
        ]);
    let replay_result = client
        .process_incoming_node_with_signal_provider(&connection, &replay_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(replay_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(replay_result.event_count, 0);
    assert!(
        replay_result.error.as_deref().is_some_and(|error| {
            error.contains("duplicate Signal sender-key message iteration: 0")
        }),
        "unexpected stale distribution replay error: {:?}",
        replay_result.error
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(
        replay_nack.attrs["id"],
        "signal-group-stale-distribution-recovery-replay"
    );
    assert_eq!(replay_nack.attrs["class"], "message");
    assert_eq!(replay_nack.attrs["to"], group_jid);
    assert_eq!(replay_nack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(replay_nack.attrs["participant"], sender_jid);
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_canonicalizes_legacy_sender_key_distribution_message()
 {
    let store = wa_store::MemoryAuthStore::new();
    let mut receiver_credentials = wa_core::create_initial_credentials().unwrap();
    receiver_credentials.registered = true;
    receiver_credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, receiver_credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
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
        conversation: Some("group sender-key distribution".to_owned()),
        sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(distribution_bytes.clone()),
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
        .with_attr("id", "signal-group-distribution-message")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(message.encode_to_vec())),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 1);
    assert!(result.error.is_none());
    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "signal-group-distribution-message");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], group_jid);
    assert_eq!(ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(ack.attrs["participant"], canonical_sender_jid);
    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    let event = &batch.messages_upsert[0];
    assert_eq!(event.key.remote_jid, group_jid);
    assert_eq!(event.key.participant.as_deref(), Some(sender_jid));
    assert_eq!(event.key.id, "signal-group-distribution-message");
    assert_eq!(event.fields["payload_kind"], "plaintext");
    assert_eq!(event.fields["sender_key_distribution_count"], "2");
    let payload = event.payload.clone().unwrap();
    let decoded = wa_proto::proto::Message::decode(payload).unwrap();
    assert_eq!(
        decoded.conversation.as_deref(),
        Some("group sender-key distribution")
    );
    assert!(decoded.sender_key_distribution_message.is_some());
    assert!(
        decoded
            .fast_ratchet_key_sender_key_distribution_message
            .is_some()
    );
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
    let stored_record_bytes = client
        .signal_provider_state_store()
        .load_sender_key_record(&record_key)
        .await
        .unwrap()
        .unwrap();
    let stored_record = wa_core::decode_signal_sender_key_record(&stored_record_bytes).unwrap();
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
        conversation: Some("group sender-key distribution advance".to_owned()),
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
        .with_attr("id", "signal-group-distribution-message-advance")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext")
                .with_content(Bytes::from(advanced_message.encode_to_vec())),
        ]);
    let advanced_result = client
        .process_incoming_node_with_signal_provider(&connection, &advanced_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(advanced_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(advanced_result.event_count, 1);
    assert!(advanced_result.error.is_none());
    let advanced_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(advanced_ack.tag, "ack");
    assert_eq!(
        advanced_ack.attrs["id"],
        "signal-group-distribution-message-advance"
    );
    assert_eq!(advanced_ack.attrs["class"], "message");
    assert_eq!(advanced_ack.attrs["to"], group_jid);
    assert_eq!(advanced_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(advanced_ack.attrs["participant"], canonical_sender_jid);
    let advanced_batch = recv_batch_event(&mut events).await;
    assert_eq!(advanced_batch.messages_upsert.len(), 1);
    assert_eq!(
        advanced_batch.messages_upsert[0].key.id,
        "signal-group-distribution-message-advance"
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
        conversation: Some("group sender-key distribution invalid".to_owned()),
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
        .with_attr("id", "signal-group-distribution-message-invalid")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![BinaryNode::new("plaintext").with_content(
            Bytes::from(invalid_distribution_message.encode_to_vec()),
        )]);
    let invalid_distribution_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &invalid_distribution_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        invalid_distribution_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(invalid_distribution_result.event_count, 0);
    assert!(
        invalid_distribution_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal sender-key distribution message")),
        "unexpected invalid sender-key distribution error: {:?}",
        invalid_distribution_result.error
    );
    let invalid_distribution_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_distribution_nack.tag, "ack");
    assert_eq!(
        invalid_distribution_nack.attrs["id"],
        "signal-group-distribution-message-invalid"
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
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
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
        conversation: Some("group sender-key distribution stale".to_owned()),
        fast_ratchet_key_sender_key_distribution_message: Some(
            wa_proto::proto::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(fast_distribution_bytes),
            },
        ),
        ..wa_proto::proto::Message::default()
    };
    let stale_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-group-distribution-message-stale")
        .with_attr("from", group_jid)
        .with_attr("participant", sender_jid)
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("plaintext").with_content(Bytes::from(stale_message.encode_to_vec())),
        ]);
    let stale_result = client
        .process_incoming_node_with_signal_provider(&connection, &stale_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(stale_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(stale_result.event_count, 1);
    assert!(stale_result.error.is_none());
    let stale_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(stale_ack.tag, "ack");
    assert_eq!(
        stale_ack.attrs["id"],
        "signal-group-distribution-message-stale"
    );
    assert_eq!(stale_ack.attrs["class"], "message");
    assert_eq!(stale_ack.attrs["to"], group_jid);
    assert_eq!(stale_ack.attrs["from"], "999:7@s.whatsapp.net");
    assert_eq!(stale_ack.attrs["participant"], canonical_sender_jid);
    let stale_batch = recv_batch_event(&mut events).await;
    assert_eq!(stale_batch.messages_upsert.len(), 1);
    assert_eq!(
        stale_batch.messages_upsert[0].key.id,
        "signal-group-distribution-message-stale"
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_rejects_missing_one_time_pre_key() {
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
    let plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("missing pre-key".to_owned()),
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
        .with_attr("id", "signal-missing-pre-key")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 0);
    assert!(
        result
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
    assert_eq!(nack.attrs["id"], "signal-missing-pre-key");
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
async fn process_incoming_signal_provider_accepts_same_base_pre_key_wrapper() {
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
                conversation: Some("same-base first".to_owned()),
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
        .with_attr("id", "signal-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_result = client
        .process_incoming_node_with_signal_provider(&connection, &first_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(first_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(first_result.event_count, 1);
    assert!(first_result.error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-same-base-1");
    assert_eq!(first_ack.attrs["class"], "message");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("same-base first")
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
                conversation: Some("same-base wrapped second".to_owned()),
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
        .with_attr("id", "signal-same-base-2-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    let changed_identity_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &changed_identity_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        changed_identity_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(changed_identity_result.event_count, 0);
    assert!(
        changed_identity_result
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
        "signal-same-base-2-identity-change"
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
        .with_attr("id", "signal-same-base-2-signed-pre-key-mismatch")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    let signed_pre_key_mismatch_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &signed_pre_key_mismatch_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        signed_pre_key_mismatch_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(signed_pre_key_mismatch_result.event_count, 0);
    assert!(
        signed_pre_key_mismatch_result
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
        "signal-same-base-2-signed-pre-key-mismatch"
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
        .with_attr("id", "signal-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    let second_result = client
        .process_incoming_node_with_signal_provider(&connection, &second_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(second_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(second_result.event_count, 1);
    assert!(second_result.error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-same-base-2");
    assert_eq!(second_ack.attrs["class"], "message");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(second_batch.messages_upsert[0].key.id, "signal-same-base-2");
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("same-base wrapped second")
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

    let replay_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    let replay_result = client
        .process_incoming_node_with_signal_provider(&connection, &replay_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(replay_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(replay_result.event_count, 0);
    assert!(
        replay_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 1"))
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(replay_nack.attrs["id"], "signal-same-base-2-replay");
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
                conversation: Some("same-base third".to_owned()),
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
        .with_attr("id", "signal-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    let third_result = client
        .process_incoming_node_with_signal_provider(&connection, &third_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(third_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(third_result.event_count, 1);
    assert!(third_result.error.is_none());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(third_ack.attrs["id"], "signal-same-base-3");
    assert_eq!(third_ack.attrs["class"], "message");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(third_batch.messages_upsert[0].key.id, "signal-same-base-3");
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("same-base third")
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
async fn process_incoming_node_with_signal_provider_rejects_pre_key_identity_change() {
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
                conversation: Some("identity change".to_owned()),
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
        &plaintext,
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

    let incoming = BinaryNode::new("message")
        .with_attr("id", "signal-identity-change")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let result = client
        .process_incoming_node_with_signal_provider(&connection, &incoming, &mut buffer)
        .await
        .unwrap();

    assert_eq!(result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(result.event_count, 0);
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal provider identity changed for 123.0"))
    );
    let nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(nack.tag, "ack");
    assert_eq!(nack.attrs["id"], "signal-identity-change");
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
async fn process_incoming_node_with_signal_provider_decrypts_out_of_order_session_messages() {
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
    let first_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("out-of-order first".to_owned()),
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
    let second_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("out-of-order second".to_owned()),
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
    let third_plaintext = pad_random_max16_for_test(
        Bytes::from(
            wa_proto::proto::Message {
                conversation: Some("out-of-order third".to_owned()),
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

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let first_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-ooo-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_result = client
        .process_incoming_node_with_signal_provider(&connection, &first_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(first_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(first_result.event_count, 1);
    assert!(first_result.error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.attrs["id"], "signal-ooo-1");
    let Event::Batch(first_batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("out-of-order first")
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
    let tampered_third_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-ooo-3-tampered")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(tampered_third),
        ]);
    let tampered_third_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &tampered_third_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        tampered_third_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(tampered_third_result.event_count, 0);
    assert!(
        tampered_third_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error") && error.contains("decrypt"))
    );
    let tampered_third_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_third_nack.tag, "ack");
    assert_eq!(tampered_third_nack.attrs["id"], "signal-ooo-3-tampered");
    assert_eq!(tampered_third_nack.attrs["class"], "message");
    assert_eq!(
        tampered_third_nack.attrs["error"],
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
        record_after_first_bytes
    );

    let third_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-ooo-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes.clone()),
        ]);
    let third_result = client
        .process_incoming_node_with_signal_provider(&connection, &third_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(third_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(third_result.event_count, 1);
    assert!(third_result.error.is_none());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.attrs["id"], "signal-ooo-3");
    let Event::Batch(third_batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("out-of-order third")
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
    let invalid_skipped_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-ooo-2-invalid-skipped")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let invalid_skipped_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &invalid_skipped_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        invalid_skipped_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(invalid_skipped_result.event_count, 0);
    assert!(
        invalid_skipped_result
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("duplicate or old Signal message counter: 1") })
    );
    let invalid_skipped_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(invalid_skipped_nack.tag, "ack");
    assert_eq!(
        invalid_skipped_nack.attrs["id"],
        "signal-ooo-2-invalid-skipped"
    );
    assert_eq!(invalid_skipped_nack.attrs["class"], "message");
    assert_eq!(
        invalid_skipped_nack.attrs["error"],
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
    let tampered_second_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-ooo-2-tampered")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(tampered_second),
        ]);
    let tampered_second_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &tampered_second_incoming,
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        tampered_second_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(tampered_second_result.event_count, 0);
    assert!(
        tampered_second_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error") && error.contains("decrypt"))
    );
    let tampered_second_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_second_nack.tag, "ack");
    assert_eq!(tampered_second_nack.attrs["id"], "signal-ooo-2-tampered");
    assert_eq!(tampered_second_nack.attrs["class"], "message");
    assert_eq!(
        tampered_second_nack.attrs["error"],
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
        record_after_third_bytes
    );

    let second_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-ooo-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let second_result = client
        .process_incoming_node_with_signal_provider(&connection, &second_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(second_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(second_result.event_count, 1);
    assert!(second_result.error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.attrs["id"], "signal-ooo-2");
    let Event::Batch(second_batch) = events.recv().await.unwrap() else {
        panic!("expected typed event batch");
    };
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("out-of-order second")
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
        record_after_second
            .receiving_chain
            .as_ref()
            .unwrap()
            .counter,
        3
    );
    assert!(record_after_second.message_keys.is_empty());

    let replay_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-ooo-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(second.message_bytes.clone()),
        ]);
    let replay_result = client
        .process_incoming_node_with_signal_provider(&connection, &replay_incoming, &mut buffer)
        .await
        .unwrap();
    assert_eq!(replay_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(replay_result.event_count, 0);
    assert!(
        replay_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 1"))
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(replay_nack.attrs["id"], "signal-ooo-2-replay");
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
        record_after_second_bytes
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_prunes_old_skipped_message_keys() {
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
        &text_plaintext("skipped prune first", 4),
    )
    .unwrap();
    let skipped_key_cap = 2_000usize;
    // 0-based Signal counters: `first` is counter 0, so the chain emits 1, 2, ... next.
    let pruned_counter = 1u32;
    let retained_counter = 2u32;
    let target_counter = u32::try_from(skipped_key_cap).unwrap() + 2;
    let mut sender_record = first.record.clone();
    let mut pruned_message_bytes = None;
    let mut retained_message_bytes = None;
    let mut target_message_bytes = None;
    for counter in 1..=target_counter {
        let plaintext = match counter {
            value if value == pruned_counter => text_plaintext("skipped prune second", 5),
            value if value == retained_counter => text_plaintext("skipped prune third", 6),
            value if value == target_counter => text_plaintext("skipped prune target", 7),
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

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });

    let first_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-prune-1", "pkmsg", first.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(first_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(first_result.event_count, 1);
    assert!(first_result.error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.attrs["id"], "signal-prune-1");
    let first_batch = recv_batch_event(&mut events).await;
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("skipped prune first")
    );

    let target_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-prune-target", "msg", target_message_bytes),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(target_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(target_result.event_count, 1);
    assert!(target_result.error.is_none());
    let target_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(target_ack.attrs["id"], "signal-prune-target");
    let target_batch = recv_batch_event(&mut events).await;
    let target_payload = target_batch.messages_upsert[0].payload.clone().unwrap();
    let target_decoded = wa_proto::proto::Message::decode(target_payload).unwrap();
    assert_eq!(
        target_decoded.conversation.as_deref(),
        Some("skipped prune target")
    );
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

    let retained_ratchet = record_after_target.message_keys[0].ratchet_key.clone();
    let retained_ratchet_offsets = record_after_target_bytes
        .windows(retained_ratchet.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == retained_ratchet).then_some(offset))
        .collect::<Vec<_>>();
    assert!(
        retained_ratchet_offsets.len() >= 3,
        "encoded session should contain active ratchet plus at least two skipped keys"
    );
    let active_future_counter_offset = retained_ratchet_offsets[1] + retained_ratchet.len();
    let active_future_counter_range =
        active_future_counter_offset..active_future_counter_offset + 4;
    let mut active_future_skipped_session = record_after_target_bytes.to_vec();
    active_future_skipped_session[active_future_counter_range]
        .copy_from_slice(&(target_counter + 1).to_be_bytes());
    let active_future_skipped_session = Bytes::from(active_future_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &active_future_skipped_session,
        )
        .await
        .unwrap();
    let active_future_skipped_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-prune-active-skipped",
                "msg",
                retained_message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        active_future_skipped_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(active_future_skipped_result.event_count, 0);
    assert!(
        active_future_skipped_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains(
                "Signal provider skipped message counter must be below active receiving counter"
            ))
    );
    let active_future_skipped_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(active_future_skipped_nack.tag, "ack");
    assert_eq!(
        active_future_skipped_nack.attrs["id"],
        "signal-prune-active-skipped"
    );
    assert_eq!(active_future_skipped_nack.attrs["class"], "message");
    assert_eq!(
        active_future_skipped_nack.attrs["error"],
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
        active_future_skipped_session
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
            &record_after_target_bytes,
        )
        .await
        .unwrap();

    let duplicate_counter_offset = retained_ratchet_offsets[2] + retained_ratchet.len();
    let mut duplicate_skipped_session = record_after_target_bytes.to_vec();
    duplicate_skipped_session[duplicate_counter_offset..duplicate_counter_offset + 4]
        .copy_from_slice(&retained_counter.to_be_bytes());
    let duplicate_skipped_session = Bytes::from(duplicate_skipped_session);
    store
        .set_signal_key(
            KeyNamespace::SignalProviderSession,
            "123.0",
            &duplicate_skipped_session,
        )
        .await
        .unwrap();
    let duplicate_skipped_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-prune-duplicate-skipped",
                "msg",
                retained_message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        duplicate_skipped_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(duplicate_skipped_result.event_count, 0);
    assert!(
        duplicate_skipped_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate Signal provider skipped message key"))
    );
    let duplicate_skipped_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(duplicate_skipped_nack.tag, "ack");
    assert_eq!(
        duplicate_skipped_nack.attrs["id"],
        "signal-prune-duplicate-skipped"
    );
    assert_eq!(duplicate_skipped_nack.attrs["class"], "message");
    assert_eq!(
        duplicate_skipped_nack.attrs["error"],
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
            &record_after_target_bytes,
        )
        .await
        .unwrap();

    let pruned_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-prune-2", "msg", pruned_message_bytes),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(pruned_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(pruned_result.event_count, 0);
    assert!(
        pruned_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 1"))
    );
    let pruned_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(pruned_nack.tag, "ack");
    assert_eq!(pruned_nack.attrs["id"], "signal-prune-2");
    assert_eq!(pruned_nack.attrs["class"], "message");
    assert_eq!(
        pruned_nack.attrs["error"],
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
        record_after_target_bytes
    );

    let retained_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-prune-3", "msg", retained_message_bytes),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(retained_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(retained_result.event_count, 1);
    assert!(retained_result.error.is_none());
    let retained_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(retained_ack.attrs["id"], "signal-prune-3");
    let retained_batch = recv_batch_event(&mut events).await;
    let retained_payload = retained_batch.messages_upsert[0].payload.clone().unwrap();
    let retained_decoded = wa_proto::proto::Message::decode(retained_payload).unwrap();
    assert_eq!(
        retained_decoded.conversation.as_deref(),
        Some("skipped prune third")
    );
    let record_after_retained = client
        .signal_provider_state_store()
        .load_session_record("123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let record_after_retained =
        wa_core::decode_signal_provider_session_record(&record_after_retained).unwrap();
    assert_eq!(
        record_after_retained.message_keys.len(),
        skipped_key_cap - 1
    );
    assert_eq!(
        record_after_retained.message_keys.first().unwrap().counter,
        retained_counter + 1
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_signal_provider_accepts_new_remote_ratchet() {
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
        &text_plaintext("ratchet first", 4),
    )
    .unwrap();
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("ratchet old third", 6),
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
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-1", "pkmsg", first.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(first_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(first_result.event_count, 1);
    assert!(first_result.error.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.attrs["id"], "signal-ratchet-1");
    let first_batch = recv_batch_event(&mut events).await;
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(first_decoded.conversation.as_deref(), Some("ratchet first"));

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
        &text_plaintext("ratchet fourth", 7),
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
        &text_plaintext("ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();
    let sixth = wa_core::encrypt_signal_provider_session_record_message(
        &fifth.record,
        &text_plaintext("ratchet sixth", 9),
        &sender_identity,
    )
    .unwrap();
    let seventh = wa_core::encrypt_signal_provider_session_record_message(
        &sixth.record,
        &text_plaintext("ratchet seventh", 10),
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
    let tampered_fourth_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-4-tampered", "msg", tampered_fourth),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        tampered_fourth_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(tampered_fourth_result.event_count, 0);
    assert!(
        tampered_fourth_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error") && error.contains("decrypt"))
    );
    let tampered_fourth_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_fourth_nack.tag, "ack");
    assert_eq!(
        tampered_fourth_nack.attrs["id"],
        "signal-ratchet-4-tampered"
    );
    assert_eq!(tampered_fourth_nack.attrs["class"], "message");
    assert_eq!(
        tampered_fourth_nack.attrs["error"],
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
        record_after_reply_bytes
    );

    let fourth_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-4", "msg", fourth.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(fourth_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(fourth_result.event_count, 1);
    assert!(fourth_result.error.is_none());
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.attrs["id"], "signal-ratchet-4");
    let fourth_batch = recv_batch_event(&mut events).await;
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("ratchet fourth")
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

    let replay_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-ratchet-4-replay",
                "msg",
                fourth.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(replay_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(replay_result.event_count, 0);
    assert!(
        replay_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate or old Signal message counter: 0"))
    );
    let replay_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(replay_nack.tag, "ack");
    assert_eq!(replay_nack.attrs["id"], "signal-ratchet-4-replay");
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
    let tampered_old_third_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-old-3-tampered", "msg", tampered_old_third),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        tampered_old_third_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(tampered_old_third_result.event_count, 0);
    assert!(
        tampered_old_third_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("crypto error") && error.contains("decrypt"))
    );
    let tampered_old_third_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(tampered_old_third_nack.tag, "ack");
    assert_eq!(
        tampered_old_third_nack.attrs["id"],
        "signal-ratchet-old-3-tampered"
    );
    assert_eq!(tampered_old_third_nack.attrs["class"], "message");
    assert_eq!(
        tampered_old_third_nack.attrs["error"],
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
        record_after_fourth_bytes
    );

    let old_third_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-ratchet-old-3",
                "msg",
                old_third.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(old_third_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(old_third_result.event_count, 1);
    assert!(old_third_result.error.is_none());
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.attrs["id"], "signal-ratchet-old-3");
    let old_third_batch = recv_batch_event(&mut events).await;
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("ratchet old third")
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
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-ratchet-old-3-replay",
                "msg",
                old_third.message_bytes.clone(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        old_third_replay_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(old_third_replay_result.event_count, 0);
    assert!(
        old_third_replay_result
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
        "signal-ratchet-old-3-replay"
    );
    assert_eq!(old_third_replay_nack.attrs["class"], "message");
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
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-2", "msg", second.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(second_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(second_result.event_count, 1);
    assert!(second_result.error.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.attrs["id"], "signal-ratchet-2");
    let second_batch = recv_batch_event(&mut events).await;
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("ratchet second")
    );
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
        Some(fourth.message.ephemeral_key.clone())
    );
    assert!(record_after_second.message_keys.is_empty());

    let fifth_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-5", "msg", fifth.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(fifth_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(fifth_result.event_count, 1);
    assert!(fifth_result.error.is_none());
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.attrs["id"], "signal-ratchet-5");
    let fifth_batch = recv_batch_event(&mut events).await;
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(fifth_decoded.conversation.as_deref(), Some("ratchet fifth"));
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
        Some(fourth.message.ephemeral_key)
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
        ciphertext: Bytes::from_static(b"stale-previous-counter"),
    };
    let stale_previous_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-ratchet-stale-previous",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &stale_previous,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        stale_previous_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(stale_previous_result.event_count, 0);
    assert!(
        stale_previous_result
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("decryption failed") })
    );
    let stale_previous_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(stale_previous_nack.tag, "ack");
    assert_eq!(
        stale_previous_nack.attrs["id"],
        "signal-ratchet-stale-previous"
    );
    assert_eq!(stale_previous_nack.attrs["class"], "message");
    assert_eq!(
        stale_previous_nack.attrs["error"],
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
        record_after_fifth_bytes
    );

    let sixth_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-6", "msg", sixth.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(sixth_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(sixth_result.event_count, 1);
    assert!(sixth_result.error.is_none());
    let sixth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sixth_ack.attrs["id"], "signal-ratchet-6");
    let sixth_batch = recv_batch_event(&mut events).await;
    let sixth_payload = sixth_batch.messages_upsert[0].payload.clone().unwrap();
    let sixth_decoded = wa_proto::proto::Message::decode(sixth_payload).unwrap();
    assert_eq!(sixth_decoded.conversation.as_deref(), Some("ratchet sixth"));
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
        ciphertext: Bytes::from_static(b"far-future-previous-counter"),
    };
    let far_future_previous_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-ratchet-far-future-previous",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &far_future_previous,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        far_future_previous_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(far_future_previous_result.event_count, 0);
    assert!(
        far_future_previous_result.error.as_deref().is_some_and(
            |error| error.contains("Signal previous chain is too far in the future: 25001")
        )
    );
    let far_future_previous_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(far_future_previous_nack.tag, "ack");
    assert_eq!(
        far_future_previous_nack.attrs["id"],
        "signal-ratchet-far-future-previous"
    );
    assert_eq!(far_future_previous_nack.attrs["class"], "message");
    assert_eq!(
        far_future_previous_nack.attrs["error"],
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
        record_after_sixth_bytes
    );

    let far_future_current = wa_core::SignalWhisperMessage {
        ephemeral_key: sixth.message.ephemeral_key.clone(),
        counter: far_future_counter,
        previous_counter: 3,
        ciphertext: Bytes::from_static(b"far-future-current-counter"),
    };
    let far_future_current_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-ratchet-far-future-current",
                "msg",
                wa_core::encode_signal_whisper_message(
                    &far_future_current,
                    &[0u8; 32],
                    &sender_identity,
                    &receiver_identity,
                )
                .unwrap(),
            ),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(
        far_future_current_result.action,
        wa_core::InboundNodeAction::Message
    );
    assert_eq!(far_future_current_result.event_count, 0);
    assert!(
        far_future_current_result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("Signal message is too far in the future: 25001"))
    );
    let far_future_current_nack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(far_future_current_nack.tag, "ack");
    assert_eq!(
        far_future_current_nack.attrs["id"],
        "signal-ratchet-far-future-current"
    );
    assert_eq!(far_future_current_nack.attrs["class"], "message");
    assert_eq!(
        far_future_current_nack.attrs["error"],
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
        record_after_sixth_bytes
    );

    let seventh_result = client
        .process_incoming_node_with_signal_provider(
            &connection,
            &incoming_node("signal-ratchet-7", "msg", seventh.message_bytes.clone()),
            &mut buffer,
        )
        .await
        .unwrap();
    assert_eq!(seventh_result.action, wa_core::InboundNodeAction::Message);
    assert_eq!(seventh_result.event_count, 1);
    assert!(seventh_result.error.is_none());
    let seventh_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(seventh_ack.attrs["id"], "signal-ratchet-7");
    let seventh_batch = recv_batch_event(&mut events).await;
    let seventh_payload = seventh_batch.messages_upsert[0].payload.clone().unwrap();
    let seventh_decoded = wa_proto::proto::Message::decode(seventh_payload).unwrap();
    assert_eq!(
        seventh_decoded.conversation.as_deref(),
        Some("ratchet seventh")
    );
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
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn process_incoming_node_with_placeholder_resend_requests_unavailable_stub() {
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
    let incoming = BinaryNode::new("message")
        .with_attr("id", "missing-live")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let encryptor = RelayEncryptor::default();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let process_fut = client.process_incoming_node_with_placeholder_resend(
        &connection,
        &incoming,
        &IncomingDecryptor,
        &encryptor,
        &mut buffer,
    );
    tokio::pin!(process_fut);

    let ack_frame = tokio::select! {
        result = &mut process_fut => panic!("processing completed before ACK: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "missing-live");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

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
            session_response_for_query(&node)
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
    assert!(
        client
            .placeholder_resend_tracker()
            .contains("missing-live", current_unix_timestamp_ms())
            .unwrap()
    );

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "missing-live");
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
async fn process_incoming_node_with_placeholder_resend_with_signal_provider_requests_stub() {
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
        .with_attr("id", "missing-live-signal")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("t", current_unix_timestamp().to_string())
        .with_content(vec![
            BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
        ]);
    let expected_key =
        wa_core::build_message_key("123@s.whatsapp.net", false, "missing-live-signal", None)
            .unwrap();
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
    assert_eq!(ack.attrs["id"], "missing-live-signal");
    assert_eq!(ack.attrs["class"], "message");
    assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

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
            .contains("missing-live-signal", current_unix_timestamp_ms())
            .unwrap()
    );

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 1);
    assert_eq!(batch.messages_upsert[0].key.id, "missing-live-signal");
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
async fn process_incoming_node_with_placeholder_resend_signal_provider_accepts_same_base_pre_key_wrapper()
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
        "placeholder-direct-same-base",
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
                conversation: Some("placeholder direct same-base first".to_owned()),
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

    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
        max_pending_items: 8,
    });
    let first_incoming = BinaryNode::new("message")
        .with_attr("id", "signal-placeholder-direct-same-base-1")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(first.message_bytes.clone()),
        ]);
    let first_result = client
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
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
    assert!(first_result.placeholder_resend.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(
        first_ack.attrs["id"],
        "signal-placeholder-direct-same-base-1"
    );
    assert_eq!(first_ack.attrs["class"], "message");

    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-placeholder-direct-same-base-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("placeholder direct same-base first")
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
                conversation: Some("placeholder direct same-base wrapped second".to_owned()),
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
            "signal-placeholder-direct-same-base-2-identity-change",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(changed_identity_wrapped_second),
        ]);
    let changed_identity_result = client
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
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
    assert!(changed_identity_result.placeholder_resend.is_none());
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
        "signal-placeholder-direct-same-base-2-identity-change"
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
            "signal-placeholder-direct-same-base-2-signed-pre-key-mismatch",
        )
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(mismatched_signed_pre_key_wrapped_second),
        ]);
    let signed_pre_key_mismatch_result = client
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
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
    assert!(signed_pre_key_mismatch_result.placeholder_resend.is_none());
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
        "signal-placeholder-direct-same-base-2-signed-pre-key-mismatch"
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
        .with_attr("id", "signal-placeholder-direct-same-base-2")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second.clone()),
        ]);
    let second_result = client
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
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
    assert!(second_result.placeholder_resend.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(
        second_ack.attrs["id"],
        "signal-placeholder-direct-same-base-2"
    );
    assert_eq!(second_ack.attrs["class"], "message");

    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-placeholder-direct-same-base-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("placeholder direct same-base wrapped second")
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
        .with_attr("id", "signal-placeholder-direct-same-base-2-replay")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "pkmsg")
                .with_content(wrapped_second),
        ]);
    let replay_result = client
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
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
    assert!(replay_result.placeholder_resend.is_none());
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
        "signal-placeholder-direct-same-base-2-replay"
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
                conversation: Some("placeholder direct same-base third".to_owned()),
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
        .with_attr("id", "signal-placeholder-direct-same-base-3")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "text")
        .with_content(vec![
            BinaryNode::new("enc")
                .with_attr("type", "msg")
                .with_content(third.message_bytes),
        ]);
    let third_result = client
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
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
    assert!(third_result.placeholder_resend.is_none());
    let third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(third_ack.tag, "ack");
    assert_eq!(
        third_ack.attrs["id"],
        "signal-placeholder-direct-same-base-3"
    );
    assert_eq!(third_ack.attrs["class"], "message");

    let third_batch = recv_batch_event(&mut events).await;
    assert_eq!(third_batch.messages_upsert.len(), 1);
    assert_eq!(
        third_batch.messages_upsert[0].key.id,
        "signal-placeholder-direct-same-base-3"
    );
    let third_payload = third_batch.messages_upsert[0].payload.clone().unwrap();
    let third_decoded = wa_proto::proto::Message::decode(third_payload).unwrap();
    assert_eq!(
        third_decoded.conversation.as_deref(),
        Some("placeholder direct same-base third")
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
async fn process_incoming_node_with_placeholder_resend_signal_provider_accepts_new_remote_ratchet()
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
        "placeholder-direct-new-ratchet",
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
        &text_plaintext("placeholder ratchet first", 4),
    )
    .unwrap();
    assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
    let second = wa_core::encrypt_signal_provider_session_record_message(
        &first.record,
        &text_plaintext("placeholder ratchet second", 5),
        &sender_identity,
    )
    .unwrap();
    let old_third = wa_core::encrypt_signal_provider_session_record_message(
        &second.record,
        &text_plaintext("placeholder ratchet old third", 6),
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
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-placeholder-ratchet-1",
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
    assert!(first_result.placeholder_resend.is_none());
    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "signal-placeholder-ratchet-1");
    assert_eq!(first_ack.attrs["class"], "message");
    assert_eq!(first_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(first_ack.attrs["from"], "999:7@s.whatsapp.net");
    let first_batch = recv_batch_event(&mut events).await;
    assert_eq!(first_batch.messages_upsert.len(), 1);
    assert_eq!(
        first_batch.messages_upsert[0].key.id,
        "signal-placeholder-ratchet-1"
    );
    let first_payload = first_batch.messages_upsert[0].payload.clone().unwrap();
    let first_decoded = wa_proto::proto::Message::decode(first_payload).unwrap();
    assert_eq!(
        first_decoded.conversation.as_deref(),
        Some("placeholder ratchet first")
    );

    let reply = client
        .signal_provider_state_store()
        .encrypt_existing_session_record_message(
            "123@s.whatsapp.net",
            Bytes::from_static(b"receiver placeholder ratchet reply"),
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
        &text_plaintext("placeholder ratchet fourth", 7),
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
        &text_plaintext("placeholder ratchet fifth", 8),
        &sender_identity,
    )
    .unwrap();

    let fourth_result = client
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-placeholder-ratchet-4",
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
    assert!(fourth_result.placeholder_resend.is_none());
    let fourth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fourth_ack.tag, "ack");
    assert_eq!(fourth_ack.attrs["id"], "signal-placeholder-ratchet-4");
    assert_eq!(fourth_ack.attrs["class"], "message");
    assert_eq!(fourth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fourth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fourth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fourth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fourth_batch.messages_upsert[0].key.id,
        "signal-placeholder-ratchet-4"
    );
    let fourth_payload = fourth_batch.messages_upsert[0].payload.clone().unwrap();
    let fourth_decoded = wa_proto::proto::Message::decode(fourth_payload).unwrap();
    assert_eq!(
        fourth_decoded.conversation.as_deref(),
        Some("placeholder ratchet fourth")
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
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-placeholder-ratchet-old-3",
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
    assert!(old_third_result.placeholder_resend.is_none());
    let old_third_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(old_third_ack.tag, "ack");
    assert_eq!(
        old_third_ack.attrs["id"],
        "signal-placeholder-ratchet-old-3"
    );
    assert_eq!(old_third_ack.attrs["class"], "message");
    assert_eq!(old_third_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(old_third_ack.attrs["from"], "999:7@s.whatsapp.net");
    let old_third_batch = recv_batch_event(&mut events).await;
    assert_eq!(old_third_batch.messages_upsert.len(), 1);
    assert_eq!(
        old_third_batch.messages_upsert[0].key.id,
        "signal-placeholder-ratchet-old-3"
    );
    let old_third_payload = old_third_batch.messages_upsert[0].payload.clone().unwrap();
    let old_third_decoded = wa_proto::proto::Message::decode(old_third_payload).unwrap();
    assert_eq!(
        old_third_decoded.conversation.as_deref(),
        Some("placeholder ratchet old third")
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
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
            &connection,
            &incoming_node(
                "signal-placeholder-ratchet-old-3-replay",
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
    assert!(old_third_replay_result.placeholder_resend.is_none());
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
        "signal-placeholder-ratchet-old-3-replay"
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
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
            &connection,
            &incoming_node("signal-placeholder-ratchet-2", "msg", second.message_bytes),
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
    assert!(second_result.placeholder_resend.is_none());
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "signal-placeholder-ratchet-2");
    assert_eq!(second_ack.attrs["class"], "message");
    assert_eq!(second_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(second_ack.attrs["from"], "999:7@s.whatsapp.net");
    let second_batch = recv_batch_event(&mut events).await;
    assert_eq!(second_batch.messages_upsert.len(), 1);
    assert_eq!(
        second_batch.messages_upsert[0].key.id,
        "signal-placeholder-ratchet-2"
    );
    let second_payload = second_batch.messages_upsert[0].payload.clone().unwrap();
    let second_decoded = wa_proto::proto::Message::decode(second_payload).unwrap();
    assert_eq!(
        second_decoded.conversation.as_deref(),
        Some("placeholder ratchet second")
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
        .process_incoming_node_with_placeholder_resend_with_signal_provider(
            &connection,
            &incoming_node("signal-placeholder-ratchet-5", "msg", fifth.message_bytes),
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
    assert!(fifth_result.placeholder_resend.is_none());
    let fifth_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(fifth_ack.tag, "ack");
    assert_eq!(fifth_ack.attrs["id"], "signal-placeholder-ratchet-5");
    assert_eq!(fifth_ack.attrs["class"], "message");
    assert_eq!(fifth_ack.attrs["to"], "123@s.whatsapp.net");
    assert_eq!(fifth_ack.attrs["from"], "999:7@s.whatsapp.net");
    let fifth_batch = recv_batch_event(&mut events).await;
    assert_eq!(fifth_batch.messages_upsert.len(), 1);
    assert_eq!(
        fifth_batch.messages_upsert[0].key.id,
        "signal-placeholder-ratchet-5"
    );
    let fifth_payload = fifth_batch.messages_upsert[0].payload.clone().unwrap();
    let fifth_decoded = wa_proto::proto::Message::decode(fifth_payload).unwrap();
    assert_eq!(
        fifth_decoded.conversation.as_deref(),
        Some("placeholder ratchet fifth")
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
