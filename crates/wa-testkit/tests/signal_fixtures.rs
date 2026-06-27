use std::path::PathBuf;

use bytes::{BufMut, Bytes, BytesMut};
use prost::Message as ProstMessage;
use wa_core::signal::SignalProviderStoredMessageKey;
use wa_core::{
    SignalLocalIdentity, SignalLocalKeyMaterial, SignalLocalPreKey, SignalLocalSignedPreKey,
    SignalMessageChainKey, SignalMessageKeyMaterial, SignalPreKey, SignalPreKeyWhisperMessage,
    SignalProviderSessionRecord, SignalRootKey, SignalSenderChainKey, SignalSenderKeyMessage,
    SignalSenderKeyRecord, SignalSenderKeyState, SignalSenderMessageKeyMaterial,
    SignalSenderStoredMessageKey, SignalSession, SignalSignedPreKey, SignalWhisperMessage,
    build_signal_sender_key_distribution_message, decode_signal_pre_key_whisper_message,
    decode_signal_provider_session_record, decode_signal_sender_key_distribution_message,
    decode_signal_sender_key_message, decode_signal_sender_key_record,
    decode_signal_whisper_message, decrypt_signal_inbound_pre_key_session_message,
    decrypt_signal_message_body, decrypt_signal_provider_session_record_message,
    decrypt_signal_sender_key_record_message, decrypt_signal_sender_message_body,
    derive_signal_inbound_pre_key_root_chain_keys, derive_signal_message_key_seed,
    derive_signal_outbound_pre_key_root_chain_keys, encode_signal_pre_key_whisper_message,
    encode_signal_provider_session_record, encode_signal_sender_key_distribution_message,
    encode_signal_sender_key_message, encode_signal_sender_key_record,
    encode_signal_whisper_message, encrypt_signal_message_body,
    encrypt_signal_outbound_pre_key_session_message,
    encrypt_signal_outbound_pre_key_session_message_with_sending_ratchet,
    encrypt_signal_provider_session_record_message, encrypt_signal_sender_key_record_message,
    encrypt_signal_sender_message_body, process_signal_sender_key_distribution_record,
    ratchet_signal_message_chain, ratchet_signal_root_key, ratchet_signal_sender_chain,
    should_replace_cached_signal_sender_key_distribution, sign_signal_sender_key_message,
    verify_signal_sender_key_message_bytes,
};
use wa_crypto::{
    KeyPair, SecretBytes, XEdDsaNoiseCertificateVerifier, hmac_sha256, prefixed_signal_public_key,
};
use wa_proto::proto::{
    PreKeySignalMessage, SenderKeyRecordStructure, SenderKeyStateStructure,
    sender_key_state_structure,
};
use wa_testkit::{
    SignalFixture, SignalFixtureManifest, SignalProviderSessionInvalidRecordFixture,
    SignalProviderSessionInvalidSkippedKeyFixture, SignalSenderKeyRecordInvalidSigningKeyFixture,
    SignalSenderKeyRecordInvalidStateFixture, decode_fixture_hex,
};

const TEST_PROVIDER_SESSION_VERSION: u8 = 1;
const TEST_PROVIDER_SESSION_RECORD_KIND: u8 = 2;

// Fixed identities / mac key used to frame the standalone Whisper and
// PreKeyWhisper round-trip fixtures (which do not carry identity material).
// The libsignal 1:1 WhisperMessage MAC covers senderId(33) || receiverId(33) ||
// version || protobuf; round-trips only need consistent values here.
const WHISPER_TEST_MAC_KEY: [u8; 32] = [0x5au8; 32];

fn whisper_test_sender() -> Bytes {
    Bytes::copy_from_slice(&prefixed_signal_public_key(&[0x21u8; 32]))
}

fn whisper_test_receiver() -> Bytes {
    Bytes::copy_from_slice(&prefixed_signal_public_key(&[0x31u8; 32]))
}

// Frame a standalone WhisperMessage with the fixed test identities/mac key.
fn frame_test_whisper(message: &SignalWhisperMessage) -> Bytes {
    encode_signal_whisper_message(
        message,
        &WHISPER_TEST_MAC_KEY,
        &whisper_test_sender(),
        &whisper_test_receiver(),
    )
    .unwrap()
}

// Decode a standalone framed WhisperMessage with the fixed test identities/mac key.
fn unframe_test_whisper(bytes: &[u8]) -> wa_core::CoreResult<SignalWhisperMessage> {
    decode_signal_whisper_message(
        bytes,
        &WHISPER_TEST_MAC_KEY,
        &whisper_test_sender(),
        &whisper_test_receiver(),
    )
}

// Frame a standalone PreKeyWhisperMessage with the fixed test identities/mac key
// (the outer carries no MAC; only the inner WhisperMessage does).
fn frame_test_pre_key_whisper(message: &SignalPreKeyWhisperMessage) -> wa_core::CoreResult<Bytes> {
    encode_signal_pre_key_whisper_message(
        message,
        &WHISPER_TEST_MAC_KEY,
        &whisper_test_sender(),
        &whisper_test_receiver(),
    )
}

// Extract the already-framed inner WhisperMessage bytes (0x33 || protobuf || MAC8)
// from a framed PreKeyWhisperMessage (0x33 || PreKeySignalMessage protobuf). Used to
// replay the exact inner message against an established session.
fn pre_key_inner_framed_bytes(framed_pre_key: &[u8]) -> Bytes {
    let proto = PreKeySignalMessage::decode(&framed_pre_key[1..])
        .expect("pre-key message protobuf decodes after version byte");
    proto.message.expect("pre-key message has inner message")
}

// Recompute the first outbound message key (and thus the inner WhisperMessage MAC
// key) of a pre-key session, so tests can re-frame / decode the inner
// WhisperMessage with the SAME key libsignal framing used when it was produced.
// The inner MAC covers senderId(alice/local) || receiverId(bob/remote) || version
// || protobuf; for the outbound direction sender = alice (local) identity and
// receiver = bob (remote) identity.
fn pre_key_inner_mac_key(
    alice_material: &SignalLocalKeyMaterial,
    alice_base: &KeyPair,
    sending_ratchet: &KeyPair,
    bob_session: &SignalSession,
) -> SecretBytes {
    let bootstrap =
        derive_signal_outbound_pre_key_root_chain_keys(alice_material, alice_base, bob_session)
            .expect("pre-key fixture derives outbound root chain");
    // The initiator's first sending chain is a DH ratchet against bob's signed
    // pre-key with a fresh sending-ratchet key pair (libsignal
    // `calculateSendingRatchet`), NOT the X3DH chain key directly.
    let sending_step = ratchet_signal_root_key(
        &bootstrap.root_key,
        sending_ratchet.private.expose(),
        &bob_session.signed_pre_key.public_key,
    )
    .expect("pre-key fixture derives outbound sending chain");
    ratchet_signal_message_chain(&sending_step.chain_key)
        .expect("pre-key fixture ratchets first message key")
        .message_keys
        .mac_key
}

// The libsignal WhisperMessage version byte (message version 3, ciphertext version
// 3 => 0x33). The inner WhisperMessage MAC covers
//   senderId(33) || receiverId(33) || version_byte || protobuf
// and the trailing MAC is HMAC-SHA256(macKey, that)[..8].
const WHISPER_MESSAGE_VERSION_BYTE: u8 = 0x33;
const WHISPER_MESSAGE_MAC_LEN: usize = 8;

// Take a framed inner WhisperMessage (0x33 || protobuf || MAC8) and produce a new
// framed WhisperMessage with an unknown protobuf field appended INSIDE the protobuf
// (before the MAC), re-MAC-ed with the same per-message key/identities. This is the
// libsignal-correct way to exercise unknown-field tolerance: unknown fields live in
// the protobuf the MAC covers, not after the trailer.
fn inner_whisper_with_unknown_field(
    framed_inner: &[u8],
    mac_key: &[u8],
    sender_id_pub: &[u8],
    receiver_id_pub: &[u8],
) -> Bytes {
    let protobuf = &framed_inner[1..framed_inner.len() - WHISPER_MESSAGE_MAC_LEN];
    let mut serialized = Vec::with_capacity(1 + protobuf.len() + 2 + WHISPER_MESSAGE_MAC_LEN);
    serialized.push(WHISPER_MESSAGE_VERSION_BYTE);
    serialized.extend_from_slice(protobuf);
    // Unknown protobuf field: field number 15, varint wire type, value 0x63.
    serialized.extend_from_slice(&[0x78, 0x63]);
    let mut mac_input =
        Vec::with_capacity(sender_id_pub.len() + receiver_id_pub.len() + serialized.len());
    mac_input.extend_from_slice(sender_id_pub);
    mac_input.extend_from_slice(receiver_id_pub);
    mac_input.extend_from_slice(&serialized);
    let mac = hmac_sha256(&mac_input, mac_key).expect("inner whisper unknown-field MAC");
    serialized.extend_from_slice(&mac[..WHISPER_MESSAGE_MAC_LEN]);
    Bytes::from(serialized)
}

#[test]
fn signal_fixtures_match_public_signal_primitives() {
    let manifest_path = workspace_fixture_path("signal/manifest.json");
    let manifest = SignalFixtureManifest::load(&manifest_path).unwrap();

    assert_eq!(manifest.schema, "wa-signal-fixture-v1");
    assert!(
        !manifest.vectors.is_empty(),
        "fixture manifest should contain at least one Signal vector"
    );

    let mut missing_expected = Vec::new();
    for vector in manifest.vectors {
        match vector {
            SignalFixture::MessageBody(vector) => {
                let keys = SignalMessageKeyMaterial {
                    cipher_key: secret_hex(&vector.cipher_key_hex),
                    mac_key: secret_hex(&vector.mac_key_hex),
                    iv: fixed_16_hex(&vector.iv_hex),
                };
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let ciphertext = encrypt_signal_message_body(&plaintext, &keys).unwrap();
                assert_eq!(
                    decrypt_signal_message_body(&ciphertext, &keys).unwrap(),
                    plaintext,
                    "{}",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.ciphertext_hex", vector.name),
                    &ciphertext,
                    &vector.ciphertext_hex,
                );
            }
            SignalFixture::MessageChain(vector) => {
                let chain_key = bytes_hex(&vector.chain_key_hex);
                let step = ratchet_signal_message_chain(&SignalMessageChainKey {
                    key: SecretBytes::from(chain_key.to_vec()),
                    counter: vector.counter,
                })
                .unwrap();
                assert_eq!(
                    step.message_counter, vector.message_counter,
                    "{} message counter",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_key_seed_hex", vector.name),
                    derive_signal_message_key_seed(&chain_key).unwrap().expose(),
                    &vector.message_key_seed_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.cipher_key_hex", vector.name),
                    step.message_keys.cipher_key.expose(),
                    &vector.cipher_key_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.mac_key_hex", vector.name),
                    step.message_keys.mac_key.expose(),
                    &vector.mac_key_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.iv_hex", vector.name),
                    &step.message_keys.iv,
                    &vector.iv_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.next_chain_key_hex", vector.name),
                    step.next_chain_key.key.expose(),
                    &vector.next_chain_key_hex,
                );
            }
            SignalFixture::PreKeyRootChain(vector) => {
                let fixture = pre_key_fixture_keys(PreKeyFixtureKeyParams {
                    alice_registration_id: 1001,
                    bob_registration_id: 2002,
                    bob_signed_pre_key_id: 202,
                    bob_one_time_pre_key_id: 203,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                    bob_one_time_pre_key_private_hex: &vector.bob_one_time_pre_key_private_hex,
                });

                let outbound = derive_signal_outbound_pre_key_root_chain_keys(
                    &fixture.alice_material,
                    &fixture.alice_base,
                    &fixture.bob_session,
                )
                .unwrap();
                let inbound = derive_signal_inbound_pre_key_root_chain_keys(
                    &fixture.bob_material,
                    Some(&fixture.bob_one_time),
                    &fixture.alice_material.identity.public_key,
                    &prefixed_public_key(&fixture.alice_base),
                )
                .unwrap();

                assert!(outbound.used_one_time_pre_key, "{}", vector.name);
                assert!(inbound.used_one_time_pre_key, "{}", vector.name);
                assert_eq!(outbound.root_key, inbound.root_key, "{}", vector.name);
                assert_eq!(outbound.chain_key, inbound.chain_key, "{}", vector.name);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.root_key_hex", vector.name),
                    outbound.root_key.key.expose(),
                    &vector.root_key_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.chain_key_hex", vector.name),
                    outbound.chain_key.key.expose(),
                    &vector.chain_key_hex,
                );
            }
            SignalFixture::PreKeySessionMessage(vector) => {
                let fixture = pre_key_fixture_keys(PreKeyFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    bob_one_time_pre_key_id: vector.bob_one_time_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                    bob_one_time_pre_key_private_hex: &vector.bob_one_time_pre_key_private_hex,
                });
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let accept_all_signatures = |_: &[u8], _: &[u8], _: &[u8]| true;
                let alice_sending_ratchet =
                    key_pair_from_private_hex(&vector.alice_sending_ratchet_private_hex);
                let encrypted =
                    encrypt_signal_outbound_pre_key_session_message_with_sending_ratchet(
                        &fixture.alice_material,
                        &fixture.alice_base,
                        &alice_sending_ratchet,
                        &fixture.bob_session,
                        &accept_all_signatures,
                        &plaintext,
                    )
                    .unwrap();
                match (
                    vector.tampered_message_hex.as_ref(),
                    vector.expected_tamper_error.as_ref(),
                ) {
                    (Some(tampered_message_hex), Some(expected_tamper_error)) => {
                        // Corrupt the inner WhisperMessage MAC trailer. Under the
                        // libsignal framing the MAC lives inside the outer protobuf's
                        // `message` field (not at the end of the outer message, which
                        // is the signed_pre_key_id varint), so flip the last byte of
                        // the framed inner WhisperMessage and rewrap the outer.
                        let inner_framed = pre_key_inner_framed_bytes(&encrypted.message_bytes);
                        let mut tampered_inner = inner_framed.to_vec();
                        *tampered_inner.last_mut().unwrap() ^= 1;
                        let tampered_outer = PreKeySignalMessage {
                            registration_id: Some(encrypted.message.registration_id),
                            pre_key_id: encrypted.message.pre_key_id,
                            signed_pre_key_id: Some(encrypted.message.signed_pre_key_id),
                            base_key: Some(encrypted.message.base_key.clone()),
                            identity_key: Some(encrypted.message.identity_key.clone()),
                            message: Some(Bytes::from(tampered_inner)),
                        };
                        let mut tampered_message = vec![encrypted.message_bytes[0]];
                        tampered_message.extend_from_slice(&tampered_outer.encode_to_vec());
                        let tamper_err = decrypt_signal_inbound_pre_key_session_message(
                            &fixture.bob_material,
                            Some(&fixture.bob_one_time),
                            &tampered_message,
                        )
                        .unwrap_err()
                        .to_string();
                        assert_eq!(
                            tamper_err, *expected_tamper_error,
                            "{} expected exact pre-key tamper error",
                            vector.name,
                        );
                        assert_hex(
                            &mut missing_expected,
                            &format!("{}.tampered_message_hex", vector.name),
                            &tampered_message,
                            tampered_message_hex,
                        );
                    }
                    (None, None) => {}
                    _ => panic!(
                        "{} pre-key tamper fixture fields must be both present or both absent",
                        vector.name
                    ),
                }
                let decrypted = decrypt_signal_inbound_pre_key_session_message(
                    &fixture.bob_material,
                    Some(&fixture.bob_one_time),
                    &encrypted.message_bytes,
                )
                .unwrap();
                assert_eq!(decrypted.plaintext, plaintext, "{}", vector.name);
                assert!(encrypted.used_one_time_pre_key, "{}", vector.name);
                assert!(decrypted.used_one_time_pre_key, "{}", vector.name);
                // The exact framed inner WhisperMessage alice sent; replaying it
                // against bob's now-established session is a duplicate-counter reject.
                let inner_replay = pre_key_inner_framed_bytes(&encrypted.message_bytes);
                let inner_mac_key = pre_key_inner_mac_key(
                    &fixture.alice_material,
                    &fixture.alice_base,
                    &alice_sending_ratchet,
                    &fixture.bob_session,
                );
                let alice_identity = fixture.alice_material.identity.public_key.clone();
                let bob_identity = fixture.bob_material.identity.public_key.clone();
                if let Some(expected_outer_unknown_message_hex) =
                    vector.message_outer_unknown_field_hex.as_ref()
                {
                    // The outer PreKeyWhisperMessage carries no MAC, so appending an
                    // unknown protobuf field is ignored on decode and decryption still
                    // succeeds (the inner MAC is intact).
                    let mut outer_unknown_message = encrypted.message_bytes.to_vec();
                    outer_unknown_message.extend_from_slice(&[0x78, 0x63]);
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.message_outer_unknown_field_hex", vector.name),
                        &outer_unknown_message,
                        expected_outer_unknown_message_hex,
                    );
                    let decrypted_outer_unknown = decrypt_signal_inbound_pre_key_session_message(
                        &fixture.bob_material,
                        Some(&fixture.bob_one_time),
                        &outer_unknown_message,
                    )
                    .unwrap();
                    assert_eq!(
                        decrypted_outer_unknown.plaintext, plaintext,
                        "{} pre-key session outer unknown plaintext",
                        vector.name
                    );
                    assert_eq!(
                        decrypted_outer_unknown.record, decrypted.record,
                        "{} pre-key session outer unknown record",
                        vector.name
                    );
                    assert!(decrypted_outer_unknown.used_one_time_pre_key);
                }
                if let Some(expected_inner_unknown_message_hex) =
                    vector.message_inner_unknown_field_hex.as_ref()
                {
                    // Append an unknown protobuf field INSIDE the inner WhisperMessage
                    // protobuf, re-MAC the inner with the same per-message key, and rewrap.
                    let inner_unknown = inner_whisper_with_unknown_field(
                        &inner_replay,
                        inner_mac_key.expose(),
                        &alice_identity,
                        &bob_identity,
                    );
                    let inner_unknown_message = PreKeySignalMessage {
                        registration_id: Some(encrypted.message.registration_id),
                        pre_key_id: encrypted.message.pre_key_id,
                        signed_pre_key_id: Some(encrypted.message.signed_pre_key_id),
                        base_key: Some(encrypted.message.base_key.clone()),
                        identity_key: Some(encrypted.message.identity_key.clone()),
                        message: Some(inner_unknown),
                    };
                    let mut inner_unknown_message_bytes = vec![inner_replay[0]];
                    inner_unknown_message_bytes
                        .extend_from_slice(&inner_unknown_message.encode_to_vec());
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.message_inner_unknown_field_hex", vector.name),
                        &inner_unknown_message_bytes,
                        expected_inner_unknown_message_hex,
                    );
                    let decrypted_inner_unknown = decrypt_signal_inbound_pre_key_session_message(
                        &fixture.bob_material,
                        Some(&fixture.bob_one_time),
                        &inner_unknown_message_bytes,
                    )
                    .unwrap();
                    assert_eq!(
                        decrypted_inner_unknown.plaintext, plaintext,
                        "{} pre-key session inner unknown plaintext",
                        vector.name
                    );
                    assert_eq!(
                        decrypted_inner_unknown.record, decrypted.record,
                        "{} pre-key session inner unknown record",
                        vector.name
                    );
                    assert!(decrypted_inner_unknown.used_one_time_pre_key);
                }
                let replay_err = decrypt_signal_provider_session_record_message(
                    &decrypted.record,
                    &inner_replay,
                    &fixture.bob_material.identity.public_key,
                )
                .unwrap_err();
                assert_eq!(
                    replay_err.to_string(),
                    vector.expected_replay_error,
                    "{} pre-key inner replay",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_hex", vector.name),
                    &encrypted.message_bytes,
                    &vector.message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_hex", vector.name),
                    &encrypted.record,
                    &vector.sender_record_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_hex,
                );
            }
            SignalFixture::PreKeySessionInvalidSignedPreKey(vector) => {
                let fixture = pre_key_fixture_keys(PreKeyFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    bob_one_time_pre_key_id: vector.bob_one_time_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                    bob_one_time_pre_key_private_hex: &vector.bob_one_time_pre_key_private_hex,
                });
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let mut bob_session = fixture.bob_session;
                if let Some(invalid_identity_key_hex) = &vector.invalid_identity_key_hex {
                    bob_session.identity_key = bytes_hex(invalid_identity_key_hex);
                }
                if let Some(invalid_signed_pre_key_public_key_hex) =
                    &vector.invalid_signed_pre_key_public_key_hex
                {
                    bob_session.signed_pre_key.public_key =
                        bytes_hex(invalid_signed_pre_key_public_key_hex);
                }
                bob_session.signed_pre_key.signature = bytes_hex(&vector.invalid_signature_hex);
                let err = encrypt_signal_outbound_pre_key_session_message(
                    &fixture.alice_material,
                    &fixture.alice_base,
                    &bob_session,
                    &XEdDsaNoiseCertificateVerifier,
                    &plaintext,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeySessionInvalidPreKey(vector) => {
                let fixture = pre_key_fixture_keys(PreKeyFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    bob_one_time_pre_key_id: vector.bob_one_time_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                    bob_one_time_pre_key_private_hex: &vector.bob_one_time_pre_key_private_hex,
                });
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let mut bob_session = fixture.bob_session;
                let pre_key = bob_session
                    .pre_key
                    .as_mut()
                    .expect("invalid pre-key fixture requires a one-time pre-key");
                pre_key.public_key = bytes_hex(&vector.invalid_one_time_pre_key_public_key_hex);
                let accept_all_signatures = |_: &[u8], _: &[u8], _: &[u8]| true;
                let err = encrypt_signal_outbound_pre_key_session_message(
                    &fixture.alice_material,
                    &fixture.alice_base,
                    &bob_session,
                    &accept_all_signatures,
                    &plaintext,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeySessionPreKeyIdMismatch(vector) => {
                let fixture = pre_key_fixture_keys(PreKeyFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    bob_one_time_pre_key_id: vector.bob_one_time_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                    bob_one_time_pre_key_private_hex: &vector.bob_one_time_pre_key_private_hex,
                });
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let accept_all_signatures = |_: &[u8], _: &[u8], _: &[u8]| true;
                let alice_sending_ratchet =
                    key_pair_from_private_hex(&vector.alice_sending_ratchet_private_hex);
                let encrypted =
                    encrypt_signal_outbound_pre_key_session_message_with_sending_ratchet(
                        &fixture.alice_material,
                        &fixture.alice_base,
                        &alice_sending_ratchet,
                        &fixture.bob_session,
                        &accept_all_signatures,
                        &plaintext,
                    )
                    .unwrap();
                let mut mismatched =
                    decode_signal_pre_key_whisper_message(&encrypted.message_bytes).unwrap();
                mismatched.pre_key_id = Some(vector.mismatched_one_time_pre_key_id);
                let inner_mac_key = pre_key_inner_mac_key(
                    &fixture.alice_material,
                    &fixture.alice_base,
                    &alice_sending_ratchet,
                    &fixture.bob_session,
                );
                let mismatched_message = encode_signal_pre_key_whisper_message(
                    &mismatched,
                    inner_mac_key.expose(),
                    &fixture.alice_material.identity.public_key,
                    &fixture.bob_material.identity.public_key,
                )
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.mismatched_message_hex", vector.name),
                    &mismatched_message,
                    &vector.mismatched_message_hex,
                );
                let err = decrypt_signal_inbound_pre_key_session_message(
                    &fixture.bob_material,
                    Some(&fixture.bob_one_time),
                    &mismatched_message,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeySessionPreKeyStateMismatch(vector) => {
                let fixture = pre_key_fixture_keys(PreKeyFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    bob_one_time_pre_key_id: vector.bob_one_time_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                    bob_one_time_pre_key_private_hex: &vector.bob_one_time_pre_key_private_hex,
                });
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let accept_all_signatures = |_: &[u8], _: &[u8], _: &[u8]| true;
                let alice_sending_ratchet =
                    key_pair_from_private_hex(&vector.alice_sending_ratchet_private_hex);
                let encrypted =
                    encrypt_signal_outbound_pre_key_session_message_with_sending_ratchet(
                        &fixture.alice_material,
                        &fixture.alice_base,
                        &alice_sending_ratchet,
                        &fixture.bob_session,
                        &accept_all_signatures,
                        &plaintext,
                    )
                    .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_hex", vector.name),
                    &encrypted.message_bytes,
                    &vector.message_hex,
                );
                let err = decrypt_signal_inbound_pre_key_session_message(
                    &fixture.bob_material,
                    None,
                    &encrypted.message_bytes,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeySessionUnexpectedPreKeyStateMismatch(vector) => {
                let fixture = pre_key_fixture_keys_no_one_time(PreKeyNoOneTimeFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                });
                let unexpected_one_time =
                    key_pair_from_private_hex(&vector.unexpected_one_time_pre_key_private_hex);
                let unexpected_one_time = SignalLocalPreKey {
                    key_id: vector.unexpected_one_time_pre_key_id,
                    public_key: prefixed_public_key(&unexpected_one_time),
                    key_pair: unexpected_one_time,
                };
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let accept_all_signatures = |_: &[u8], _: &[u8], _: &[u8]| true;
                let alice_sending_ratchet =
                    key_pair_from_private_hex(&vector.alice_sending_ratchet_private_hex);
                let encrypted =
                    encrypt_signal_outbound_pre_key_session_message_with_sending_ratchet(
                        &fixture.alice_material,
                        &fixture.alice_base,
                        &alice_sending_ratchet,
                        &fixture.bob_session,
                        &accept_all_signatures,
                        &plaintext,
                    )
                    .unwrap();
                assert_eq!(encrypted.message.pre_key_id, None, "{}", vector.name);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_hex", vector.name),
                    &encrypted.message_bytes,
                    &vector.message_hex,
                );
                let err = decrypt_signal_inbound_pre_key_session_message(
                    &fixture.bob_material,
                    Some(&unexpected_one_time),
                    &encrypted.message_bytes,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeySessionSignedPreKeyIdMismatch(vector) => {
                let fixture = pre_key_fixture_keys(PreKeyFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    bob_one_time_pre_key_id: vector.bob_one_time_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                    bob_one_time_pre_key_private_hex: &vector.bob_one_time_pre_key_private_hex,
                });
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let accept_all_signatures = |_: &[u8], _: &[u8], _: &[u8]| true;
                let alice_sending_ratchet =
                    key_pair_from_private_hex(&vector.alice_sending_ratchet_private_hex);
                let encrypted =
                    encrypt_signal_outbound_pre_key_session_message_with_sending_ratchet(
                        &fixture.alice_material,
                        &fixture.alice_base,
                        &alice_sending_ratchet,
                        &fixture.bob_session,
                        &accept_all_signatures,
                        &plaintext,
                    )
                    .unwrap();
                let mut mismatched =
                    decode_signal_pre_key_whisper_message(&encrypted.message_bytes).unwrap();
                mismatched.signed_pre_key_id = vector.mismatched_signed_pre_key_id;
                let inner_mac_key = pre_key_inner_mac_key(
                    &fixture.alice_material,
                    &fixture.alice_base,
                    &alice_sending_ratchet,
                    &fixture.bob_session,
                );
                let mismatched_message = encode_signal_pre_key_whisper_message(
                    &mismatched,
                    inner_mac_key.expose(),
                    &fixture.alice_material.identity.public_key,
                    &fixture.bob_material.identity.public_key,
                )
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.mismatched_message_hex", vector.name),
                    &mismatched_message,
                    &vector.mismatched_message_hex,
                );
                let err = decrypt_signal_inbound_pre_key_session_message(
                    &fixture.bob_material,
                    Some(&fixture.bob_one_time),
                    &mismatched_message,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeySessionMessageNoOneTime(vector) => {
                let fixture = pre_key_fixture_keys_no_one_time(PreKeyNoOneTimeFixtureKeyParams {
                    alice_registration_id: vector.alice_registration_id,
                    bob_registration_id: vector.bob_registration_id,
                    bob_signed_pre_key_id: vector.bob_signed_pre_key_id,
                    alice_identity_private_hex: &vector.alice_identity_private_hex,
                    alice_base_private_hex: &vector.alice_base_private_hex,
                    bob_identity_private_hex: &vector.bob_identity_private_hex,
                    bob_signed_pre_key_private_hex: &vector.bob_signed_pre_key_private_hex,
                });
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let accept_all_signatures = |_: &[u8], _: &[u8], _: &[u8]| true;
                let alice_sending_ratchet =
                    key_pair_from_private_hex(&vector.alice_sending_ratchet_private_hex);
                let encrypted =
                    encrypt_signal_outbound_pre_key_session_message_with_sending_ratchet(
                        &fixture.alice_material,
                        &fixture.alice_base,
                        &alice_sending_ratchet,
                        &fixture.bob_session,
                        &accept_all_signatures,
                        &plaintext,
                    )
                    .unwrap();
                match (
                    vector.tampered_message_hex.as_ref(),
                    vector.expected_tamper_error.as_ref(),
                ) {
                    (Some(tampered_message_hex), Some(expected_tamper_error)) => {
                        let mut tampered =
                            decode_signal_pre_key_whisper_message(&encrypted.message_bytes)
                                .unwrap();
                        let mut tampered_ciphertext = tampered.message.ciphertext.to_vec();
                        *tampered_ciphertext.last_mut().unwrap() ^= 1;
                        tampered.message.ciphertext = Bytes::from(tampered_ciphertext);
                        let inner_mac_key = pre_key_inner_mac_key(
                            &fixture.alice_material,
                            &fixture.alice_base,
                            &alice_sending_ratchet,
                            &fixture.bob_session,
                        );
                        let tampered_message = encode_signal_pre_key_whisper_message(
                            &tampered,
                            inner_mac_key.expose(),
                            &fixture.alice_material.identity.public_key,
                            &fixture.bob_material.identity.public_key,
                        )
                        .unwrap();
                        let tamper_err = decrypt_signal_inbound_pre_key_session_message(
                            &fixture.bob_material,
                            None,
                            &tampered_message,
                        )
                        .unwrap_err()
                        .to_string();
                        assert_eq!(
                            tamper_err, *expected_tamper_error,
                            "{} expected exact no-one-time pre-key tamper error",
                            vector.name,
                        );
                        assert_hex(
                            &mut missing_expected,
                            &format!("{}.tampered_message_hex", vector.name),
                            &tampered_message,
                            tampered_message_hex,
                        );
                    }
                    (None, None) => {}
                    _ => panic!(
                        "{} no-one-time pre-key tamper fixture fields must be both present or both absent",
                        vector.name
                    ),
                }
                let decrypted = decrypt_signal_inbound_pre_key_session_message(
                    &fixture.bob_material,
                    None,
                    &encrypted.message_bytes,
                )
                .unwrap();
                assert_eq!(decrypted.plaintext, plaintext, "{}", vector.name);
                assert!(!encrypted.used_one_time_pre_key, "{}", vector.name);
                assert!(!decrypted.used_one_time_pre_key, "{}", vector.name);
                assert_eq!(encrypted.message.pre_key_id, None, "{}", vector.name);
                let inner_mac_key = pre_key_inner_mac_key(
                    &fixture.alice_material,
                    &fixture.alice_base,
                    &alice_sending_ratchet,
                    &fixture.bob_session,
                );
                let alice_identity = fixture.alice_material.identity.public_key.clone();
                let bob_identity = fixture.bob_material.identity.public_key.clone();
                let inner_replay = pre_key_inner_framed_bytes(&encrypted.message_bytes);
                if let Some(expected_outer_unknown_message_hex) =
                    vector.message_outer_unknown_field_hex.as_ref()
                {
                    let mut outer_unknown_message = encrypted.message_bytes.to_vec();
                    outer_unknown_message.extend_from_slice(&[0x78, 0x63]);
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.message_outer_unknown_field_hex", vector.name),
                        &outer_unknown_message,
                        expected_outer_unknown_message_hex,
                    );
                    let decoded_outer_unknown =
                        decode_signal_pre_key_whisper_message(&outer_unknown_message)
                            .expect("signed-pre-key-only outer unknown field should decode");
                    assert_eq!(
                        encode_signal_pre_key_whisper_message(
                            &decoded_outer_unknown,
                            inner_mac_key.expose(),
                            &alice_identity,
                            &bob_identity,
                        )
                        .unwrap(),
                        encrypted.message_bytes,
                        "{} signed-pre-key-only outer unknown field should canonicalize",
                        vector.name
                    );
                    let decrypted_outer_unknown = decrypt_signal_inbound_pre_key_session_message(
                        &fixture.bob_material,
                        None,
                        &outer_unknown_message,
                    )
                    .unwrap();
                    assert_eq!(
                        decrypted_outer_unknown.plaintext, plaintext,
                        "{} signed-pre-key-only outer unknown plaintext",
                        vector.name
                    );
                    assert_eq!(
                        decrypted_outer_unknown.record, decrypted.record,
                        "{} signed-pre-key-only outer unknown record",
                        vector.name
                    );
                    assert!(!decrypted_outer_unknown.used_one_time_pre_key);
                }
                if let Some(expected_inner_unknown_message_hex) =
                    vector.message_inner_unknown_field_hex.as_ref()
                {
                    // Append an unknown protobuf field INSIDE the inner WhisperMessage
                    // protobuf, re-MAC the inner with the same per-message key, and rewrap.
                    let inner_unknown = inner_whisper_with_unknown_field(
                        &inner_replay,
                        inner_mac_key.expose(),
                        &alice_identity,
                        &bob_identity,
                    );
                    let inner_unknown_message = PreKeySignalMessage {
                        registration_id: Some(encrypted.message.registration_id),
                        pre_key_id: None,
                        signed_pre_key_id: Some(encrypted.message.signed_pre_key_id),
                        base_key: Some(encrypted.message.base_key.clone()),
                        identity_key: Some(encrypted.message.identity_key.clone()),
                        message: Some(inner_unknown),
                    };
                    let mut inner_unknown_message_bytes = vec![inner_replay[0]];
                    inner_unknown_message_bytes
                        .extend_from_slice(&inner_unknown_message.encode_to_vec());
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.message_inner_unknown_field_hex", vector.name),
                        &inner_unknown_message_bytes,
                        expected_inner_unknown_message_hex,
                    );
                    let decrypted_inner_unknown = decrypt_signal_inbound_pre_key_session_message(
                        &fixture.bob_material,
                        None,
                        &inner_unknown_message_bytes,
                    )
                    .unwrap();
                    assert_eq!(
                        decrypted_inner_unknown.plaintext, plaintext,
                        "{} signed-pre-key-only inner unknown plaintext",
                        vector.name
                    );
                    assert_eq!(
                        decrypted_inner_unknown.record, decrypted.record,
                        "{} signed-pre-key-only inner unknown record",
                        vector.name
                    );
                    assert!(!decrypted_inner_unknown.used_one_time_pre_key);
                }
                let replay_err = decrypt_signal_provider_session_record_message(
                    &decrypted.record,
                    &inner_replay,
                    &bob_identity,
                )
                .unwrap_err();
                assert_eq!(
                    replay_err.to_string(),
                    vector.expected_replay_error,
                    "{} signed-pre-key-only inner replay",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_hex", vector.name),
                    &encrypted.message_bytes,
                    &vector.message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_hex", vector.name),
                    &encrypted.record,
                    &vector.sender_record_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_hex,
                );
            }
            SignalFixture::PreKeyWhisperMessage(vector) => {
                let message = SignalPreKeyWhisperMessage {
                    registration_id: vector.registration_id,
                    pre_key_id: vector.pre_key_id,
                    signed_pre_key_id: vector.signed_pre_key_id,
                    base_key: bytes_hex(&vector.base_key_hex),
                    identity_key: bytes_hex(&vector.identity_key_hex),
                    message: SignalWhisperMessage {
                        ephemeral_key: bytes_hex(&vector.ephemeral_key_hex),
                        counter: vector.counter,
                        previous_counter: vector.previous_counter,
                        ciphertext: bytes_hex(&vector.ciphertext_hex),
                    },
                };
                let encoded = frame_test_pre_key_whisper(&message).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
                assert_eq!(
                    decode_signal_pre_key_whisper_message(&bytes_hex(&vector.encoded_hex)).unwrap(),
                    message,
                    "{}",
                    vector.name
                );
            }
            SignalFixture::PreKeyWhisperMessageMissingInnerPreviousCounter(vector) => {
                // Build an inner WhisperMessage protobuf that OMITS the previous_counter
                // field (field 3); on decode it must default to 0. The inner is framed
                // with the libsignal MAC (0x33 || protobuf || MAC8) over the fixed test
                // identities, then wrapped in the outer PreKeyWhisperMessage.
                let ratchet = bytes_hex(&vector.ephemeral_key_hex);
                let ciphertext = bytes_hex(&vector.ciphertext_hex);
                let mut inner_proto = Vec::new();
                inner_proto.push(0x0a); // field 1 (ratchetKey), len-delimited
                inner_proto.push(ratchet.len() as u8);
                inner_proto.extend_from_slice(&ratchet);
                inner_proto.push(0x10); // field 2 (counter), varint
                inner_proto.push(vector.counter as u8);
                // field 3 (previousCounter) intentionally omitted
                inner_proto.push(0x22); // field 4 (ciphertext), len-delimited
                inner_proto.push(ciphertext.len() as u8);
                inner_proto.extend_from_slice(&ciphertext);
                let mut inner_serialized = vec![WHISPER_MESSAGE_VERSION_BYTE];
                inner_serialized.extend_from_slice(&inner_proto);
                let mut mac_input = Vec::new();
                mac_input.extend_from_slice(&whisper_test_sender());
                mac_input.extend_from_slice(&whisper_test_receiver());
                mac_input.extend_from_slice(&inner_serialized);
                let mac = hmac_sha256(&mac_input, &WHISPER_TEST_MAC_KEY).unwrap();
                inner_serialized.extend_from_slice(&mac[..WHISPER_MESSAGE_MAC_LEN]);
                let outer = PreKeySignalMessage {
                    registration_id: Some(vector.registration_id),
                    pre_key_id: vector.pre_key_id,
                    signed_pre_key_id: Some(vector.signed_pre_key_id),
                    base_key: Some(bytes_hex(&vector.base_key_hex)),
                    identity_key: Some(bytes_hex(&vector.identity_key_hex)),
                    message: Some(Bytes::from(inner_serialized)),
                };
                let mut encoded = vec![WHISPER_MESSAGE_VERSION_BYTE];
                encoded.extend_from_slice(&outer.encode_to_vec());
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
                let decoded =
                    decode_signal_pre_key_whisper_message(&encoded).unwrap_or_else(|err| {
                        panic!(
                            "{} should decode without inner previous counter: {err}",
                            vector.name
                        )
                    });
                assert_eq!(
                    decoded.registration_id, vector.registration_id,
                    "{}",
                    vector.name
                );
                assert_eq!(decoded.pre_key_id, vector.pre_key_id, "{}", vector.name);
                assert_eq!(
                    decoded.signed_pre_key_id, vector.signed_pre_key_id,
                    "{}",
                    vector.name
                );
                assert_eq!(decoded.base_key, bytes_hex(&vector.base_key_hex));
                assert_eq!(decoded.identity_key, bytes_hex(&vector.identity_key_hex));
                assert_eq!(
                    decoded.message.ephemeral_key,
                    bytes_hex(&vector.ephemeral_key_hex)
                );
                assert_eq!(decoded.message.counter, vector.counter, "{}", vector.name);
                assert_eq!(decoded.message.previous_counter, 0, "{}", vector.name);
                assert_eq!(
                    decoded.message.ciphertext,
                    bytes_hex(&vector.ciphertext_hex)
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.canonical_encoded_hex", vector.name),
                    &frame_test_pre_key_whisper(&decoded).unwrap(),
                    &vector.canonical_encoded_hex,
                );
            }
            SignalFixture::PreKeyWhisperMessageUnknownField(vector) => {
                // Rebuild the canonical pre-key message from the fixture fields, then
                // inject an unknown protobuf field (outer or inner depending on the
                // vector). Under the libsignal framing the inner WhisperMessage carries
                // a MAC over its protobuf, so an inner unknown field must live inside
                // that protobuf and be re-MAC-ed; an outer unknown field is appended to
                // the (MAC-less) outer protobuf. Both must decode and canonicalize to
                // the same unknown-field-free message.
                let canonical_message = SignalPreKeyWhisperMessage {
                    registration_id: vector.registration_id,
                    pre_key_id: vector.pre_key_id,
                    signed_pre_key_id: vector.signed_pre_key_id,
                    base_key: bytes_hex(&vector.base_key_hex),
                    identity_key: bytes_hex(&vector.identity_key_hex),
                    message: SignalWhisperMessage {
                        ephemeral_key: bytes_hex(&vector.ephemeral_key_hex),
                        counter: vector.counter,
                        previous_counter: vector.previous_counter,
                        ciphertext: bytes_hex(&vector.ciphertext_hex),
                    },
                };
                let canonical = frame_test_pre_key_whisper(&canonical_message).unwrap();
                let inner_framed = pre_key_inner_framed_bytes(&canonical);
                let encoded = if vector.name.contains("inner_unknown") {
                    let inner_unknown = inner_whisper_with_unknown_field(
                        &inner_framed,
                        &WHISPER_TEST_MAC_KEY,
                        &whisper_test_sender(),
                        &whisper_test_receiver(),
                    );
                    let outer = PreKeySignalMessage {
                        registration_id: Some(canonical_message.registration_id),
                        pre_key_id: canonical_message.pre_key_id,
                        signed_pre_key_id: Some(canonical_message.signed_pre_key_id),
                        base_key: Some(canonical_message.base_key.clone()),
                        identity_key: Some(canonical_message.identity_key.clone()),
                        message: Some(inner_unknown),
                    };
                    let mut bytes = vec![canonical[0]];
                    bytes.extend_from_slice(&outer.encode_to_vec());
                    bytes
                } else {
                    let mut bytes = canonical.to_vec();
                    // Unknown outer protobuf field: field 15, varint wire type, value 0x63.
                    bytes.extend_from_slice(&[0x78, 0x63]);
                    bytes
                };
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
                let decoded =
                    decode_signal_pre_key_whisper_message(&encoded).unwrap_or_else(|err| {
                        panic!("{} should decode with unknown fields: {err}", vector.name)
                    });
                assert_eq!(
                    decoded.registration_id, vector.registration_id,
                    "{}",
                    vector.name
                );
                assert_eq!(decoded.pre_key_id, vector.pre_key_id, "{}", vector.name);
                assert_eq!(
                    decoded.signed_pre_key_id, vector.signed_pre_key_id,
                    "{}",
                    vector.name
                );
                assert_eq!(decoded.base_key, bytes_hex(&vector.base_key_hex));
                assert_eq!(decoded.identity_key, bytes_hex(&vector.identity_key_hex));
                assert_eq!(
                    decoded.message.ephemeral_key,
                    bytes_hex(&vector.ephemeral_key_hex)
                );
                assert_eq!(decoded.message.counter, vector.counter, "{}", vector.name);
                assert_eq!(
                    decoded.message.previous_counter, vector.previous_counter,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    decoded.message.ciphertext,
                    bytes_hex(&vector.ciphertext_hex)
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.canonical_encoded_hex", vector.name),
                    &frame_test_pre_key_whisper(&decoded).unwrap(),
                    &vector.canonical_encoded_hex,
                );
            }
            SignalFixture::PreKeyWhisperInvalidBaseKey(vector) => {
                let message = SignalPreKeyWhisperMessage {
                    registration_id: vector.registration_id,
                    pre_key_id: vector.pre_key_id,
                    signed_pre_key_id: vector.signed_pre_key_id,
                    base_key: bytes_hex(&vector.base_key_hex),
                    identity_key: bytes_hex(&vector.identity_key_hex),
                    message: SignalWhisperMessage {
                        ephemeral_key: bytes_hex(&vector.ephemeral_key_hex),
                        counter: vector.counter,
                        previous_counter: vector.previous_counter,
                        ciphertext: bytes_hex(&vector.ciphertext_hex),
                    },
                };
                let err = frame_test_pre_key_whisper(&message).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeyWhisperInvalidIdentityKey(vector) => {
                let message = SignalPreKeyWhisperMessage {
                    registration_id: vector.registration_id,
                    pre_key_id: vector.pre_key_id,
                    signed_pre_key_id: vector.signed_pre_key_id,
                    base_key: bytes_hex(&vector.base_key_hex),
                    identity_key: bytes_hex(&vector.identity_key_hex),
                    message: SignalWhisperMessage {
                        ephemeral_key: bytes_hex(&vector.ephemeral_key_hex),
                        counter: vector.counter,
                        previous_counter: vector.previous_counter,
                        ciphertext: bytes_hex(&vector.ciphertext_hex),
                    },
                };
                let err = frame_test_pre_key_whisper(&message).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::PreKeyWhisperInvalidWire(vector) => {
                let encoded = bytes_hex(&vector.encoded_hex);
                let err = decode_signal_pre_key_whisper_message(&encoded).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::ProviderSessionRecord(vector) => {
                let local_ratchet = key_pair_from_private_hex(&vector.local_ratchet_private_hex);
                let record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.receiving_chain_key_hex),
                        counter: vector.receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.remote_ratchet_key_hex)),
                    local_ratchet_key_pair: local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: vec![SignalProviderStoredMessageKey {
                        ratchet_key: bytes_hex(&vector.skipped_ratchet_key_hex),
                        counter: vector.skipped_counter,
                        message_keys: SignalMessageKeyMaterial {
                            cipher_key: secret_hex(&vector.skipped_cipher_key_hex),
                            mac_key: secret_hex(&vector.skipped_mac_key_hex),
                            iv: fixed_16_hex(&vector.skipped_iv_hex),
                        },
                    }],
                    inbound_base_key: None,
                };
                let encoded = encode_signal_provider_session_record(&record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
            }
            SignalFixture::ProviderSessionBidirectional(vector) => {
                let alice_local_ratchet =
                    key_pair_from_private_hex(&vector.alice_local_ratchet_private_hex);
                let bob_local_ratchet =
                    key_pair_from_private_hex(&vector.bob_local_ratchet_private_hex);
                let alice_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.bob_registration_id,
                    remote_identity_key: bytes_hex(&vector.bob_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.alice_sending_chain_key_hex),
                        counter: vector.alice_sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.bob_sending_chain_key_hex),
                        counter: vector.bob_sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&bob_local_ratchet)),
                    local_ratchet_key_pair: alice_local_ratchet.clone(),
                    previous_counter: vector.alice_previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let bob_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.alice_registration_id,
                    remote_identity_key: bytes_hex(&vector.alice_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.bob_sending_chain_key_hex),
                        counter: vector.bob_sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.alice_sending_chain_key_hex),
                        counter: vector.alice_sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&alice_local_ratchet)),
                    local_ratchet_key_pair: bob_local_ratchet,
                    previous_counter: vector.bob_previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let alice_identity = bytes_hex(&vector.alice_identity_key_hex);
                let bob_identity = bytes_hex(&vector.bob_identity_key_hex);
                let alice_record = encode_signal_provider_session_record(&alice_record).unwrap();
                let bob_record = encode_signal_provider_session_record(&bob_record).unwrap();
                let alice_message = encrypt_signal_provider_session_record_message(
                    &alice_record,
                    &bytes_hex(&vector.alice_plaintext_hex),
                    &alice_identity,
                )
                .unwrap();
                let bob_receive = decrypt_signal_provider_session_record_message(
                    &bob_record,
                    &alice_message.message_bytes,
                    &bob_identity,
                )
                .unwrap();
                assert_eq!(
                    bob_receive.plaintext,
                    bytes_hex(&vector.alice_plaintext_hex),
                    "{} alice message",
                    vector.name
                );
                let bob_after_receive =
                    decode_signal_provider_session_record(&bob_receive.record).unwrap();
                assert_eq!(
                    bob_after_receive.receiving_chain.as_ref().unwrap().counter,
                    vector.alice_sending_counter + 1,
                    "{} bob receive counter",
                    vector.name
                );
                let bob_message = encrypt_signal_provider_session_record_message(
                    &bob_receive.record,
                    &bytes_hex(&vector.bob_plaintext_hex),
                    &bob_identity,
                )
                .unwrap();
                let bob_after_reply =
                    decode_signal_provider_session_record(&bob_message.record).unwrap();
                assert_eq!(
                    bob_after_reply.sending_chain.counter,
                    vector.bob_sending_counter + 1,
                    "{} bob send counter",
                    vector.name
                );
                let alice_receive = decrypt_signal_provider_session_record_message(
                    &alice_message.record,
                    &bob_message.message_bytes,
                    &alice_identity,
                )
                .unwrap();
                assert_eq!(
                    alice_receive.plaintext,
                    bytes_hex(&vector.bob_plaintext_hex),
                    "{} bob message",
                    vector.name
                );
                let alice_after_reply =
                    decode_signal_provider_session_record(&alice_receive.record).unwrap();
                assert_eq!(
                    alice_after_reply.receiving_chain.as_ref().unwrap().counter,
                    vector.bob_sending_counter + 1,
                    "{} alice receive counter",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.alice_message_hex", vector.name),
                    &alice_message.message_bytes,
                    &vector.alice_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.bob_message_hex", vector.name),
                    &bob_message.message_bytes,
                    &vector.bob_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.alice_record_after_send_hex", vector.name),
                    &alice_message.record,
                    &vector.alice_record_after_send_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.bob_record_after_receive_hex", vector.name),
                    &bob_receive.record,
                    &vector.bob_record_after_receive_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.bob_record_after_reply_hex", vector.name),
                    &bob_message.record,
                    &vector.bob_record_after_reply_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.alice_record_after_reply_hex", vector.name),
                    &alice_receive.record,
                    &vector.alice_record_after_reply_hex,
                );
            }
            SignalFixture::ProviderSessionMessage(vector) => {
                let sender_local_ratchet =
                    key_pair_from_private_hex(&vector.sender_local_ratchet_private_hex);
                let receiver_local_ratchet =
                    key_pair_from_private_hex(&vector.receiver_local_ratchet_private_hex);
                // Both records share the same remote identity (single 1:1 peer), so
                // the local identity passed to encrypt/decrypt equals it and the inner
                // WhisperMessage MAC covers remote_identity || remote_identity.
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let sender_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sender_receiving_chain_key_hex),
                        counter: vector.sender_receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.sender_remote_ratchet_key_hex)),
                    local_ratchet_key_pair: sender_local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let sender_record = encode_signal_provider_session_record(&sender_record).unwrap();
                let encrypted = encrypt_signal_provider_session_record_message(
                    &sender_record,
                    &bytes_hex(&vector.plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let receiver_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&sender_local_ratchet)),
                    local_ratchet_key_pair: receiver_local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let receiver_record =
                    encode_signal_provider_session_record(&receiver_record).unwrap();
                let decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &encrypted.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    decrypted.plaintext,
                    bytes_hex(&vector.plaintext_hex),
                    "{}",
                    vector.name
                );
                if let Some(expected_unknown_message_hex) =
                    vector.message_with_unknown_field_hex.as_ref()
                {
                    let message_mac_key = ratchet_signal_message_chain(&SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    })
                    .unwrap()
                    .message_keys
                    .mac_key;
                    // Append the unknown field INSIDE the WhisperMessage protobuf and
                    // re-MAC with the same per-message key/identities (the MAC covers the
                    // protobuf, so the unknown field must precede the MAC trailer).
                    let unknown_message = inner_whisper_with_unknown_field(
                        &encrypted.message_bytes,
                        message_mac_key.expose(),
                        &local_identity,
                        &local_identity,
                    );
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.message_with_unknown_field_hex", vector.name),
                        &unknown_message,
                        expected_unknown_message_hex,
                    );
                    let decoded_unknown = decode_signal_whisper_message(
                        &unknown_message,
                        message_mac_key.expose(),
                        &local_identity,
                        &local_identity,
                    )
                    .expect("provider-session whisper with unknown field should decode");
                    assert_eq!(
                        encode_signal_whisper_message(
                            &decoded_unknown,
                            message_mac_key.expose(),
                            &local_identity,
                            &local_identity,
                        )
                        .unwrap(),
                        encrypted.message_bytes,
                        "{} provider-session whisper unknown field should canonicalize",
                        vector.name
                    );
                    let decrypted_unknown = decrypt_signal_provider_session_record_message(
                        &receiver_record,
                        &unknown_message,
                        &local_identity,
                    )
                    .unwrap();
                    assert_eq!(
                        decrypted_unknown.plaintext,
                        bytes_hex(&vector.plaintext_hex),
                        "{} provider-session unknown-field whisper plaintext",
                        vector.name
                    );
                    assert_eq!(
                        decrypted_unknown.record, decrypted.record,
                        "{} provider-session unknown-field whisper record",
                        vector.name
                    );
                }
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_hex", vector.name),
                    &encrypted.message_bytes,
                    &vector.message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_hex", vector.name),
                    &encrypted.record,
                    &vector.sender_record_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_hex,
                );
            }
            SignalFixture::ProviderSessionReplayReject(vector) => {
                let sender_local_ratchet =
                    key_pair_from_private_hex(&vector.sender_local_ratchet_private_hex);
                let receiver_local_ratchet =
                    key_pair_from_private_hex(&vector.receiver_local_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let sender_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: None,
                    remote_ratchet_key: None,
                    local_ratchet_key_pair: sender_local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let sender_record = encode_signal_provider_session_record(&sender_record).unwrap();
                let first = encrypt_signal_provider_session_record_message(
                    &sender_record,
                    &bytes_hex(&vector.first_plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let second = encrypt_signal_provider_session_record_message(
                    &first.record,
                    &bytes_hex(&vector.second_plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let receiver_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&sender_local_ratchet)),
                    local_ratchet_key_pair: receiver_local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let receiver_record =
                    encode_signal_provider_session_record(&receiver_record).unwrap();
                let first_decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &first.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    first_decrypted.plaintext,
                    bytes_hex(&vector.first_plaintext_hex),
                    "{} first message",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &first_decrypted.record,
                    &vector.receiver_record_before_reject_hex,
                );
                let replay_err = decrypt_signal_provider_session_record_message(
                    &first_decrypted.record,
                    &first.message_bytes,
                    &local_identity,
                )
                .unwrap_err();
                assert_eq!(
                    replay_err.to_string(),
                    vector.expected_replay_error,
                    "{} consumed current-chain replay",
                    vector.name
                );
                let second_decrypted = decrypt_signal_provider_session_record_message(
                    &first_decrypted.record,
                    &second.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    second_decrypted.plaintext,
                    bytes_hex(&vector.second_plaintext_hex),
                    "{} second message",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.first_message_hex", vector.name),
                    &first.message_bytes,
                    &vector.first_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.second_message_hex", vector.name),
                    &second.message_bytes,
                    &vector.second_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_after_first_hex", vector.name),
                    &first.record,
                    &vector.sender_record_after_first_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_after_second_hex", vector.name),
                    &second.record,
                    &vector.sender_record_after_second_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_first_hex", vector.name),
                    &first_decrypted.record,
                    &vector.receiver_record_after_first_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_second_hex", vector.name),
                    &second_decrypted.record,
                    &vector.receiver_record_after_second_hex,
                );
            }
            SignalFixture::ProviderSessionNewRatchetReplay(vector) => {
                let local_ratchet = key_pair_from_private_hex(&vector.local_ratchet_private_hex);
                let new_remote_ratchet =
                    key_pair_from_private_hex(&vector.new_remote_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.receiving_chain_key_hex),
                        counter: vector.receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.old_remote_ratchet_key_hex)),
                    local_ratchet_key_pair: local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let root_step = ratchet_signal_root_key(
                    &record.root_key,
                    record.local_ratchet_key_pair.private.expose(),
                    &prefixed_public_key(&new_remote_ratchet),
                )
                .unwrap();
                let first_step = ratchet_signal_message_chain(&root_step.chain_key).unwrap();
                let first_plaintext = bytes_hex(&vector.first_plaintext_hex);
                let first_message = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                    counter: first_step.message_counter,
                    previous_counter: vector.message_previous_counter,
                    ciphertext: encrypt_signal_message_body(
                        &first_plaintext,
                        &first_step.message_keys,
                    )
                    .unwrap(),
                };
                let first_message_bytes = encode_signal_whisper_message(
                    &first_message,
                    first_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let next_step = ratchet_signal_message_chain(&first_step.next_chain_key).unwrap();
                let next_plaintext = bytes_hex(&vector.next_plaintext_hex);
                let next_message = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                    counter: next_step.message_counter,
                    previous_counter: vector.message_previous_counter,
                    ciphertext: encrypt_signal_message_body(
                        &next_plaintext,
                        &next_step.message_keys,
                    )
                    .unwrap(),
                };
                let next_message_bytes = encode_signal_whisper_message(
                    &next_message,
                    next_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let record = encode_signal_provider_session_record(&record).unwrap();
                let first_decrypted = decrypt_signal_provider_session_record_message(
                    &record,
                    &first_message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    first_decrypted.plaintext, first_plaintext,
                    "{} first new-ratchet message",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &first_decrypted.record,
                    &vector.receiver_record_before_reject_hex,
                );
                let replay_err = decrypt_signal_provider_session_record_message(
                    &first_decrypted.record,
                    &first_message_bytes,
                    &local_identity,
                )
                .unwrap_err();
                assert_eq!(
                    replay_err.to_string(),
                    vector.expected_replay_error,
                    "{} expected exact new-ratchet replay error",
                    vector.name,
                );
                let next_decrypted = decrypt_signal_provider_session_record_message(
                    &first_decrypted.record,
                    &next_message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    next_decrypted.plaintext, next_plaintext,
                    "{} next new-ratchet message",
                    vector.name
                );
                let after_next =
                    decode_signal_provider_session_record(&next_decrypted.record).unwrap();
                assert_eq!(
                    after_next.remote_ratchet_key,
                    Some(prefixed_public_key(&new_remote_ratchet)),
                    "{} remote ratchet after next new-ratchet message",
                    vector.name
                );
                assert_eq!(
                    after_next.receiving_chain.as_ref().unwrap().counter,
                    next_step.message_counter + 1,
                    "{} receiving counter after next new-ratchet message",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.first_message_hex", vector.name),
                    &first_message_bytes,
                    &vector.first_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.next_message_hex", vector.name),
                    &next_message_bytes,
                    &vector.next_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_first_hex", vector.name),
                    &first_decrypted.record,
                    &vector.receiver_record_after_first_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_next_hex", vector.name),
                    &next_decrypted.record,
                    &vector.receiver_record_after_next_hex,
                );
            }
            SignalFixture::ProviderSessionNewRatchetTamperReject(vector) => {
                let local_ratchet = key_pair_from_private_hex(&vector.local_ratchet_private_hex);
                let new_remote_ratchet =
                    key_pair_from_private_hex(&vector.new_remote_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.receiving_chain_key_hex),
                        counter: vector.receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.old_remote_ratchet_key_hex)),
                    local_ratchet_key_pair: local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let root_step = ratchet_signal_root_key(
                    &record.root_key,
                    record.local_ratchet_key_pair.private.expose(),
                    &prefixed_public_key(&new_remote_ratchet),
                )
                .unwrap();
                let message_step = ratchet_signal_message_chain(&root_step.chain_key).unwrap();
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let valid_message = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                    counter: message_step.message_counter,
                    previous_counter: vector.message_previous_counter,
                    ciphertext: encrypt_signal_message_body(&plaintext, &message_step.message_keys)
                        .unwrap(),
                };
                let valid_message_bytes = encode_signal_whisper_message(
                    &valid_message,
                    message_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let mut tampered_message = valid_message.clone();
                let mut tampered_ciphertext = tampered_message.ciphertext.to_vec();
                *tampered_ciphertext.last_mut().unwrap() ^= 1;
                tampered_message.ciphertext = Bytes::from(tampered_ciphertext);
                let tampered_message_bytes = encode_signal_whisper_message(
                    &tampered_message,
                    message_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let record = encode_signal_provider_session_record(&record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &record,
                    &vector.receiver_record_before_reject_hex,
                );
                let tamper_err = decrypt_signal_provider_session_record_message(
                    &record,
                    &tampered_message_bytes,
                    &local_identity,
                )
                .unwrap_err();
                assert_eq!(
                    tamper_err.to_string(),
                    vector.expected_error,
                    "{} expected exact new-ratchet tamper error",
                    vector.name,
                );
                let decrypted = decrypt_signal_provider_session_record_message(
                    &record,
                    &valid_message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    decrypted.plaintext, plaintext,
                    "{} valid new-ratchet message after tamper rejection",
                    vector.name
                );
                let after_valid = decode_signal_provider_session_record(&decrypted.record).unwrap();
                assert_eq!(
                    after_valid.remote_ratchet_key,
                    Some(prefixed_public_key(&new_remote_ratchet)),
                    "{} remote ratchet after valid new-ratchet message",
                    vector.name
                );
                assert_eq!(
                    after_valid.receiving_chain.as_ref().unwrap().counter,
                    message_step.message_counter + 1,
                    "{} receiving counter after valid new-ratchet message",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.tampered_message_hex", vector.name),
                    &tampered_message_bytes,
                    &vector.tampered_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.valid_message_hex", vector.name),
                    &valid_message_bytes,
                    &vector.valid_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_valid_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_after_valid_hex,
                );
            }
            SignalFixture::ProviderSessionTamperReject(vector) => {
                let sender_local_ratchet =
                    key_pair_from_private_hex(&vector.sender_local_ratchet_private_hex);
                let receiver_local_ratchet =
                    key_pair_from_private_hex(&vector.receiver_local_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let sender_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: None,
                    remote_ratchet_key: None,
                    local_ratchet_key_pair: sender_local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let sender_record = encode_signal_provider_session_record(&sender_record).unwrap();
                let valid = encrypt_signal_provider_session_record_message(
                    &sender_record,
                    &bytes_hex(&vector.plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let receiver_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&sender_local_ratchet)),
                    local_ratchet_key_pair: receiver_local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let receiver_record =
                    encode_signal_provider_session_record(&receiver_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &receiver_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let mut tampered_message = valid.message_bytes.to_vec();
                *tampered_message.last_mut().unwrap() ^= 1;
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.tampered_message_hex", vector.name),
                    &tampered_message,
                    &vector.tampered_message_hex,
                );
                let tamper_err = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &tampered_message,
                    &local_identity,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    tamper_err, "crypto error: decryption failed",
                    "{} expected exact tamper rejection",
                    vector.name
                );
                let decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &valid.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    decrypted.plaintext,
                    bytes_hex(&vector.plaintext_hex),
                    "{} valid message after tamper rejection",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.valid_message_hex", vector.name),
                    &valid.message_bytes,
                    &vector.valid_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_after_valid_hex", vector.name),
                    &valid.record,
                    &vector.sender_record_after_valid_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_valid_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_after_valid_hex,
                );
            }
            SignalFixture::ProviderSessionFutureTamperReject(vector) => {
                let remote_ratchet = key_pair_from_private_hex(&vector.remote_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let remote_ratchet_key = prefixed_public_key(&remote_ratchet);
                let initial_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.receiving_chain_key_hex),
                        counter: vector.receiving_counter,
                    }),
                    remote_ratchet_key: Some(remote_ratchet_key.clone()),
                    local_ratchet_key_pair: key_pair_from_private_hex(
                        &vector.local_ratchet_private_hex,
                    ),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let initial_record =
                    encode_signal_provider_session_record(&initial_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &initial_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let mut chain = SignalMessageChainKey {
                    key: secret_hex(&vector.receiving_chain_key_hex),
                    counter: vector.receiving_counter,
                };
                let skipped_step = ratchet_signal_message_chain(&chain).unwrap();
                chain = skipped_step.next_chain_key.clone();
                let target_step = ratchet_signal_message_chain(&chain).unwrap();
                let next_step = ratchet_signal_message_chain(&target_step.next_chain_key).unwrap();
                assert_eq!(
                    skipped_step.message_counter, vector.receiving_counter,
                    "{} skipped counter",
                    vector.name
                );
                assert_eq!(
                    target_step.message_counter,
                    vector.receiving_counter + 1,
                    "{} target counter",
                    vector.name
                );
                assert_eq!(
                    next_step.message_counter,
                    vector.receiving_counter + 2,
                    "{} next counter",
                    vector.name
                );

                let skipped_message = encode_signal_whisper_message(
                    &SignalWhisperMessage {
                        ephemeral_key: remote_ratchet_key.clone(),
                        counter: skipped_step.message_counter,
                        previous_counter: vector.previous_counter,
                        ciphertext: encrypt_signal_message_body(
                            &bytes_hex(&vector.skipped_plaintext_hex),
                            &skipped_step.message_keys,
                        )
                        .unwrap(),
                    },
                    skipped_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let target_message = encode_signal_whisper_message(
                    &SignalWhisperMessage {
                        ephemeral_key: remote_ratchet_key.clone(),
                        counter: target_step.message_counter,
                        previous_counter: vector.previous_counter,
                        ciphertext: encrypt_signal_message_body(
                            &bytes_hex(&vector.target_plaintext_hex),
                            &target_step.message_keys,
                        )
                        .unwrap(),
                    },
                    target_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let next_message = encode_signal_whisper_message(
                    &SignalWhisperMessage {
                        ephemeral_key: remote_ratchet_key,
                        counter: next_step.message_counter,
                        previous_counter: vector.previous_counter,
                        ciphertext: encrypt_signal_message_body(
                            &bytes_hex(&vector.next_plaintext_hex),
                            &next_step.message_keys,
                        )
                        .unwrap(),
                    },
                    next_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let mut tampered_message = target_message.to_vec();
                *tampered_message.last_mut().unwrap() ^= 1;
                let tamper_err = decrypt_signal_provider_session_record_message(
                    &initial_record,
                    &tampered_message,
                    &local_identity,
                )
                .unwrap_err();
                assert_eq!(
                    tamper_err.to_string(),
                    vector.expected_error,
                    "{} expected exact future-chain tamper error",
                    vector.name
                );

                let target_decrypted = decrypt_signal_provider_session_record_message(
                    &initial_record,
                    &target_message,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    target_decrypted.plaintext,
                    bytes_hex(&vector.target_plaintext_hex),
                    "{} target message after tamper rejection",
                    vector.name
                );
                let after_target =
                    decode_signal_provider_session_record(&target_decrypted.record).unwrap();
                assert_eq!(
                    after_target.receiving_chain.as_ref().unwrap().counter,
                    target_step.message_counter + 1,
                    "{} receiving counter after target",
                    vector.name
                );
                assert_eq!(
                    after_target.message_keys.len(),
                    1,
                    "{} skipped keys",
                    vector.name
                );
                assert_eq!(
                    after_target.message_keys[0].counter, skipped_step.message_counter,
                    "{} skipped counter retained",
                    vector.name
                );

                let skipped_decrypted = decrypt_signal_provider_session_record_message(
                    &target_decrypted.record,
                    &skipped_message,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    skipped_decrypted.plaintext,
                    bytes_hex(&vector.skipped_plaintext_hex),
                    "{} skipped message",
                    vector.name
                );
                let after_skipped =
                    decode_signal_provider_session_record(&skipped_decrypted.record).unwrap();
                assert!(
                    after_skipped.message_keys.is_empty(),
                    "{} skipped key consumed",
                    vector.name
                );
                assert_eq!(
                    after_skipped.receiving_chain.as_ref().unwrap().counter,
                    target_step.message_counter + 1,
                    "{} receiving counter after skipped",
                    vector.name
                );

                let next_decrypted = decrypt_signal_provider_session_record_message(
                    &skipped_decrypted.record,
                    &next_message,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    next_decrypted.plaintext,
                    bytes_hex(&vector.next_plaintext_hex),
                    "{} next message",
                    vector.name
                );
                assert_eq!(
                    decode_signal_provider_session_record(&next_decrypted.record)
                        .unwrap()
                        .receiving_chain
                        .as_ref()
                        .unwrap()
                        .counter,
                    next_step.message_counter + 1,
                    "{} receiving counter after next",
                    vector.name
                );

                assert_hex(
                    &mut missing_expected,
                    &format!("{}.tampered_message_hex", vector.name),
                    &tampered_message,
                    &vector.tampered_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.skipped_message_hex", vector.name),
                    &skipped_message,
                    &vector.skipped_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.target_message_hex", vector.name),
                    &target_message,
                    &vector.target_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.next_message_hex", vector.name),
                    &next_message,
                    &vector.next_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_target_hex", vector.name),
                    &target_decrypted.record,
                    &vector.receiver_record_after_target_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_skipped_hex", vector.name),
                    &skipped_decrypted.record,
                    &vector.receiver_record_after_skipped_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_next_hex", vector.name),
                    &next_decrypted.record,
                    &vector.receiver_record_after_next_hex,
                );
            }
            SignalFixture::ProviderSessionFarFutureCounter(vector) => {
                let sender_local_ratchet =
                    key_pair_from_private_hex(&vector.sender_local_ratchet_private_hex);
                let receiver_local_ratchet =
                    key_pair_from_private_hex(&vector.receiver_local_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let sender_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: None,
                    remote_ratchet_key: None,
                    local_ratchet_key_pair: sender_local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let sender_record = encode_signal_provider_session_record(&sender_record).unwrap();
                let valid = encrypt_signal_provider_session_record_message(
                    &sender_record,
                    &bytes_hex(&vector.valid_plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let receiver_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&sender_local_ratchet)),
                    local_ratchet_key_pair: receiver_local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let receiver_record =
                    encode_signal_provider_session_record(&receiver_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &receiver_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let far_future = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&sender_local_ratchet),
                    counter: vector.far_future_counter,
                    previous_counter: vector.previous_counter,
                    ciphertext: bytes_hex(&vector.far_future_ciphertext_hex),
                };
                // Rejected on the far-future counter check before the MAC is verified,
                // so the exact MAC key is irrelevant; identities stay consistent.
                let far_future_message = encode_signal_whisper_message(
                    &far_future,
                    &[0u8; 32],
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.far_future_message_hex", vector.name),
                    &far_future_message,
                    &vector.far_future_message_hex,
                );
                let err = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &far_future_message,
                    &local_identity,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, "protocol error: Signal message is too far in the future: 25001",
                    "{} expected exact far-future rejection",
                    vector.name
                );
                let decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &valid.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    decrypted.plaintext,
                    bytes_hex(&vector.valid_plaintext_hex),
                    "{} valid message after rejection",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.valid_message_hex", vector.name),
                    &valid.message_bytes,
                    &vector.valid_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_after_valid_hex", vector.name),
                    &valid.record,
                    &vector.sender_record_after_valid_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_valid_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_after_valid_hex,
                );
            }
            SignalFixture::ProviderSessionFarFuturePreviousCounter(vector) => {
                let sender_local_ratchet =
                    key_pair_from_private_hex(&vector.sender_local_ratchet_private_hex);
                let receiver_local_ratchet =
                    key_pair_from_private_hex(&vector.receiver_local_ratchet_private_hex);
                let new_remote_ratchet =
                    key_pair_from_private_hex(&vector.new_remote_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let sender_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: None,
                    remote_ratchet_key: None,
                    local_ratchet_key_pair: sender_local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let sender_record = encode_signal_provider_session_record(&sender_record).unwrap();
                let valid = encrypt_signal_provider_session_record_message(
                    &sender_record,
                    &bytes_hex(&vector.valid_plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let receiver_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&sender_local_ratchet)),
                    local_ratchet_key_pair: receiver_local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let receiver_record =
                    encode_signal_provider_session_record(&receiver_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &receiver_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let far_future = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                    counter: vector.far_future_counter,
                    previous_counter: vector.far_future_previous_counter,
                    ciphertext: bytes_hex(&vector.far_future_ciphertext_hex),
                };
                // Rejected on the far-future counter check before the MAC is verified.
                let far_future_message = encode_signal_whisper_message(
                    &far_future,
                    &[0u8; 32],
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.far_future_message_hex", vector.name),
                    &far_future_message,
                    &vector.far_future_message_hex,
                );
                let err = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &far_future_message,
                    &local_identity,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err, "protocol error: Signal previous chain is too far in the future: 25001",
                    "{} expected exact far-future previous-counter rejection",
                    vector.name
                );
                let decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &valid.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    decrypted.plaintext,
                    bytes_hex(&vector.valid_plaintext_hex),
                    "{} valid message after rejection",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.valid_message_hex", vector.name),
                    &valid.message_bytes,
                    &vector.valid_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_after_valid_hex", vector.name),
                    &valid.record,
                    &vector.sender_record_after_valid_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_valid_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_after_valid_hex,
                );
            }
            SignalFixture::ProviderSessionStalePreviousCounter(vector) => {
                let sender_ratchet = key_pair_from_private_hex(&vector.sender_ratchet_private_hex);
                let receiver_local_ratchet =
                    key_pair_from_private_hex(&vector.receiver_local_ratchet_private_hex);
                let new_remote_ratchet =
                    key_pair_from_private_hex(&vector.new_remote_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let receiving_chain = SignalMessageChainKey {
                    key: secret_hex(&vector.receiving_chain_key_hex),
                    counter: vector.receiving_counter,
                };
                let receiver_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(receiving_chain.clone()),
                    remote_ratchet_key: Some(prefixed_public_key(&sender_ratchet)),
                    local_ratchet_key_pair: receiver_local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let receiver_record =
                    encode_signal_provider_session_record(&receiver_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &receiver_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let stale = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                    counter: vector.stale_counter,
                    previous_counter: vector.stale_previous_counter,
                    ciphertext: bytes_hex(&vector.stale_ciphertext_hex),
                };
                // Rejected on the stale previous-counter check before MAC verification.
                let stale_message = encode_signal_whisper_message(
                    &stale,
                    &[0u8; 32],
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.stale_message_hex", vector.name),
                    &stale_message,
                    &vector.stale_message_hex,
                );
                let err = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &stale_message,
                    &local_identity,
                )
                .unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact stale previous-counter error",
                    vector.name
                );

                let message_step = ratchet_signal_message_chain(&receiving_chain).unwrap();
                let plaintext = bytes_hex(&vector.valid_plaintext_hex);
                let valid = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&sender_ratchet),
                    counter: message_step.message_counter,
                    previous_counter: vector.previous_counter,
                    ciphertext: encrypt_signal_message_body(&plaintext, &message_step.message_keys)
                        .unwrap(),
                };
                let valid_message = encode_signal_whisper_message(
                    &valid,
                    message_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.valid_message_hex", vector.name),
                    &valid_message,
                    &vector.valid_message_hex,
                );
                let decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &valid_message,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    decrypted.plaintext, plaintext,
                    "{} valid message after rejection",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_valid_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_after_valid_hex,
                );
            }
            SignalFixture::ProviderSessionOutOfOrder(vector) => {
                let sender_local_ratchet =
                    key_pair_from_private_hex(&vector.sender_local_ratchet_private_hex);
                let receiver_local_ratchet =
                    key_pair_from_private_hex(&vector.receiver_local_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let sender_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sender_receiving_chain_key_hex),
                        counter: vector.sender_receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.sender_remote_ratchet_key_hex)),
                    local_ratchet_key_pair: sender_local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let sender_record = encode_signal_provider_session_record(&sender_record).unwrap();
                let first = encrypt_signal_provider_session_record_message(
                    &sender_record,
                    &bytes_hex(&vector.first_plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let second = encrypt_signal_provider_session_record_message(
                    &first.record,
                    &bytes_hex(&vector.second_plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let third = encrypt_signal_provider_session_record_message(
                    &second.record,
                    &bytes_hex(&vector.third_plaintext_hex),
                    &local_identity,
                )
                .unwrap();
                let receiver_record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: uninitialized_message_chain(),
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    }),
                    remote_ratchet_key: Some(prefixed_public_key(&sender_local_ratchet)),
                    local_ratchet_key_pair: receiver_local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let receiver_record =
                    encode_signal_provider_session_record(&receiver_record).unwrap();
                let second_decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &second.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    second_decrypted.plaintext,
                    bytes_hex(&vector.second_plaintext_hex),
                    "{} second message",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &second_decrypted.record,
                    &vector.receiver_record_before_reject_hex,
                );
                let after_second =
                    decode_signal_provider_session_record(&second_decrypted.record).unwrap();
                assert_eq!(after_second.message_keys.len(), 1, "{}", vector.name);
                assert_eq!(
                    after_second.message_keys[0].counter, vector.sending_counter,
                    "{} skipped counter",
                    vector.name
                );
                let first_step_mac_key = ratchet_signal_message_chain(&SignalMessageChainKey {
                    key: secret_hex(&vector.sending_chain_key_hex),
                    counter: vector.sending_counter,
                })
                .unwrap()
                .message_keys
                .mac_key;
                let mut tampered_first = decode_signal_whisper_message(
                    &first.message_bytes,
                    first_step_mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let mut tampered_first_ciphertext = tampered_first.ciphertext.to_vec();
                *tampered_first_ciphertext.last_mut().unwrap() ^= 1;
                tampered_first.ciphertext = Bytes::from(tampered_first_ciphertext);
                let tampered_first_message = encode_signal_whisper_message(
                    &tampered_first,
                    first_step_mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let tamper_err = decrypt_signal_provider_session_record_message(
                    &second_decrypted.record,
                    &tampered_first_message,
                    &local_identity,
                )
                .unwrap_err();
                assert_eq!(
                    tamper_err.to_string(),
                    vector.expected_tamper_error,
                    "{} expected exact skipped-message tamper error",
                    vector.name,
                );
                let first_decrypted = decrypt_signal_provider_session_record_message(
                    &second_decrypted.record,
                    &first.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    first_decrypted.plaintext,
                    bytes_hex(&vector.first_plaintext_hex),
                    "{} first message",
                    vector.name
                );
                let after_first =
                    decode_signal_provider_session_record(&first_decrypted.record).unwrap();
                assert!(
                    after_first.message_keys.is_empty(),
                    "{} skipped key consumed",
                    vector.name
                );
                let replay_err = decrypt_signal_provider_session_record_message(
                    &first_decrypted.record,
                    &first.message_bytes,
                    &local_identity,
                )
                .unwrap_err();
                assert_eq!(
                    replay_err.to_string(),
                    vector.expected_replay_error,
                    "{} consumed skipped-key replay",
                    vector.name
                );
                let third_decrypted = decrypt_signal_provider_session_record_message(
                    &first_decrypted.record,
                    &third.message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    third_decrypted.plaintext,
                    bytes_hex(&vector.third_plaintext_hex),
                    "{} third message after skipped-key replay rejection",
                    vector.name
                );
                assert_eq!(
                    decode_signal_provider_session_record(&third_decrypted.record)
                        .unwrap()
                        .receiving_chain
                        .as_ref()
                        .unwrap()
                        .counter,
                    vector.sending_counter + 3,
                    "{} receiving counter after third message",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.first_message_hex", vector.name),
                    &first.message_bytes,
                    &vector.first_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.second_message_hex", vector.name),
                    &second.message_bytes,
                    &vector.second_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.third_message_hex", vector.name),
                    &third.message_bytes,
                    &vector.third_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.tampered_first_message_hex", vector.name),
                    &tampered_first_message,
                    &vector.tampered_first_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_hex", vector.name),
                    &second.record,
                    &vector.sender_record_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_after_third_hex", vector.name),
                    &third.record,
                    &vector.sender_record_after_third_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_second_hex", vector.name),
                    &second_decrypted.record,
                    &vector.receiver_record_after_second_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_first_hex", vector.name),
                    &first_decrypted.record,
                    &vector.receiver_record_after_first_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_third_hex", vector.name),
                    &third_decrypted.record,
                    &vector.receiver_record_after_third_hex,
                );
            }
            SignalFixture::ProviderSessionInvalidSkippedKey(vector) => {
                let record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.receiving_chain_key_hex),
                        counter: vector.receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.remote_ratchet_key_hex)),
                    local_ratchet_key_pair: key_pair_from_private_hex(
                        &vector.local_ratchet_private_hex,
                    ),
                    previous_counter: vector.previous_counter,
                    message_keys: vec![SignalProviderStoredMessageKey {
                        ratchet_key: bytes_hex(&vector.remote_ratchet_key_hex),
                        counter: vector.skipped_counter,
                        message_keys: SignalMessageKeyMaterial {
                            cipher_key: secret_hex(&vector.skipped_cipher_key_hex),
                            mac_key: secret_hex(&vector.skipped_mac_key_hex),
                            iv: fixed_16_hex(&vector.skipped_iv_hex),
                        },
                    }],
                    inbound_base_key: None,
                };
                let err = encode_signal_provider_session_record(&record).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name,
                );
                let raw_record = encode_raw_provider_session_invalid_skipped_key(&vector);
                let err = decode_signal_provider_session_record(&raw_record).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact decode-time error",
                    vector.name,
                );
            }
            SignalFixture::ProviderSessionInvalidRecord(vector) => {
                let mut local_ratchet =
                    key_pair_from_private_hex(&vector.local_ratchet_private_hex);
                if let Some(public_hex) = &vector.local_ratchet_public_hex {
                    local_ratchet.public = fixed_32_hex(public_hex);
                }
                let receiving_chain = if vector.receiving_chain_key_hex.is_some()
                    || vector.receiving_counter.is_some()
                {
                    Some(SignalMessageChainKey {
                        key: secret_hex(
                            vector
                                .receiving_chain_key_hex
                                .as_deref()
                                .expect("receiving chain key fixture field"),
                        ),
                        counter: vector
                            .receiving_counter
                            .expect("receiving counter fixture field"),
                    })
                } else {
                    None
                };
                let message_keys = invalid_provider_session_message_keys(&vector);
                let record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain,
                    remote_ratchet_key: vector.remote_ratchet_key_hex.as_deref().map(bytes_hex),
                    local_ratchet_key_pair: local_ratchet,
                    previous_counter: vector.previous_counter,
                    message_keys,
                    inbound_base_key: None,
                };
                let err = encode_signal_provider_session_record(&record).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name,
                );
                let raw_record = encode_raw_provider_session_invalid_record(&vector);
                let err = decode_signal_provider_session_record(&raw_record).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact decode-time error",
                    vector.name,
                );
            }
            SignalFixture::ProviderSessionInvalidWire(vector) => {
                let encoded = bytes_hex(&vector.encoded_hex);
                let err = decode_signal_provider_session_record(&encoded).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name,
                );
            }
            SignalFixture::ProviderSessionRatchetStep(vector) => {
                let local_ratchet = key_pair_from_private_hex(&vector.local_ratchet_private_hex);
                let new_remote_ratchet =
                    key_pair_from_private_hex(&vector.new_remote_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.receiving_chain_key_hex),
                        counter: vector.receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.old_remote_ratchet_key_hex)),
                    local_ratchet_key_pair: local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let root_step = ratchet_signal_root_key(
                    &record.root_key,
                    local_ratchet.private.expose(),
                    &prefixed_public_key(&new_remote_ratchet),
                )
                .unwrap();
                let message_step = ratchet_signal_message_chain(&root_step.chain_key).unwrap();
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let message = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                    counter: message_step.message_counter,
                    previous_counter: vector.message_previous_counter,
                    ciphertext: encrypt_signal_message_body(&plaintext, &message_step.message_keys)
                        .unwrap(),
                };
                let message_bytes = encode_signal_whisper_message(
                    &message,
                    message_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let record = encode_signal_provider_session_record(&record).unwrap();
                let decrypted = decrypt_signal_provider_session_record_message(
                    &record,
                    &message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(decrypted.plaintext, plaintext, "{}", vector.name);
                let after = decode_signal_provider_session_record(&decrypted.record).unwrap();
                assert_eq!(after.root_key, root_step.root_key, "{} root", vector.name);
                assert_eq!(
                    after.receiving_chain.as_ref().unwrap().counter,
                    message_step.message_counter + 1,
                    "{} receive counter",
                    vector.name
                );
                assert_eq!(
                    after.receiving_chain.as_ref().unwrap().key,
                    message_step.next_chain_key.key,
                    "{} receive chain",
                    vector.name
                );
                assert_eq!(
                    after.remote_ratchet_key,
                    Some(prefixed_public_key(&new_remote_ratchet)),
                    "{} remote ratchet",
                    vector.name
                );
                assert_eq!(
                    after.previous_counter,
                    vector.sending_counter - 1,
                    "{} previous counter",
                    vector.name
                );
                assert_eq!(
                    after.sending_chain,
                    uninitialized_message_chain(),
                    "{} reset send chain",
                    vector.name
                );
                // 0-based, inclusive skip: stashing the previous chain up to and
                // including `message_previous_counter` yields keys for
                // receiving_counter..=message_previous_counter.
                let expected_skipped =
                    vector.message_previous_counter - vector.receiving_counter + 1;
                assert_eq!(
                    after.message_keys.len(),
                    usize::try_from(expected_skipped).unwrap(),
                    "{} skipped keys",
                    vector.name
                );
                for (offset, message_key) in after.message_keys.iter().enumerate() {
                    assert_eq!(
                        message_key.counter,
                        vector.receiving_counter + u32::try_from(offset).unwrap(),
                        "{} skipped counter",
                        vector.name
                    );
                }
                assert!(
                    after.message_keys.iter().all(|key| {
                        key.ratchet_key == bytes_hex(&vector.old_remote_ratchet_key_hex)
                    }),
                    "{} skipped ratchet",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_hex", vector.name),
                    &message_bytes,
                    &vector.message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_hex,
                );
            }
            SignalFixture::ProviderSessionPreviousChainReplay(vector) => {
                let local_ratchet = key_pair_from_private_hex(&vector.local_ratchet_private_hex);
                let new_remote_ratchet =
                    key_pair_from_private_hex(&vector.new_remote_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let record = SignalProviderSessionRecord {
                    remote_registration_id: vector.remote_registration_id,
                    remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                    root_key: SignalRootKey {
                        key: secret_hex(&vector.root_key_hex),
                    },
                    sending_chain: SignalMessageChainKey {
                        key: secret_hex(&vector.sending_chain_key_hex),
                        counter: vector.sending_counter,
                    },
                    receiving_chain: Some(SignalMessageChainKey {
                        key: secret_hex(&vector.receiving_chain_key_hex),
                        counter: vector.receiving_counter,
                    }),
                    remote_ratchet_key: Some(bytes_hex(&vector.old_remote_ratchet_key_hex)),
                    local_ratchet_key_pair: local_ratchet.clone(),
                    previous_counter: vector.previous_counter,
                    message_keys: Vec::new(),
                    inbound_base_key: None,
                };
                let old_step = ratchet_signal_message_chain(&SignalMessageChainKey {
                    key: secret_hex(&vector.receiving_chain_key_hex),
                    counter: vector.receiving_counter,
                })
                .unwrap();
                let old_plaintext = bytes_hex(&vector.old_plaintext_hex);
                let old_message = SignalWhisperMessage {
                    ephemeral_key: bytes_hex(&vector.old_remote_ratchet_key_hex),
                    counter: old_step.message_counter,
                    previous_counter: vector.previous_counter,
                    ciphertext: encrypt_signal_message_body(&old_plaintext, &old_step.message_keys)
                        .unwrap(),
                };
                let old_message_bytes = encode_signal_whisper_message(
                    &old_message,
                    old_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let second_old = match (
                    vector.second_old_plaintext_hex.as_ref(),
                    vector.second_old_message_hex.as_ref(),
                    vector.receiver_record_after_second_old_hex.as_ref(),
                ) {
                    (Some(plaintext_hex), Some(message_hex), Some(record_hex)) => {
                        let second_old_step =
                            ratchet_signal_message_chain(&old_step.next_chain_key).unwrap();
                        let plaintext = bytes_hex(plaintext_hex);
                        let message = SignalWhisperMessage {
                            ephemeral_key: bytes_hex(&vector.old_remote_ratchet_key_hex),
                            counter: second_old_step.message_counter,
                            previous_counter: vector.previous_counter,
                            ciphertext: encrypt_signal_message_body(
                                &plaintext,
                                &second_old_step.message_keys,
                            )
                            .unwrap(),
                        };
                        let message_bytes = encode_signal_whisper_message(
                            &message,
                            second_old_step.message_keys.mac_key.expose(),
                            &local_identity,
                            &local_identity,
                        )
                        .unwrap();
                        Some((
                            plaintext,
                            second_old_step.message_counter,
                            message_bytes,
                            message_hex,
                            record_hex,
                        ))
                    }
                    (None, None, None) => None,
                    _ => panic!(
                        "{} second previous-chain fixture fields must be all present or all absent",
                        vector.name
                    ),
                };

                let root_step = ratchet_signal_root_key(
                    &record.root_key,
                    local_ratchet.private.expose(),
                    &prefixed_public_key(&new_remote_ratchet),
                )
                .unwrap();
                let new_step = ratchet_signal_message_chain(&root_step.chain_key).unwrap();
                let new_plaintext = bytes_hex(&vector.new_plaintext_hex);
                let new_message = SignalWhisperMessage {
                    ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                    counter: new_step.message_counter,
                    previous_counter: vector.message_previous_counter,
                    ciphertext: encrypt_signal_message_body(&new_plaintext, &new_step.message_keys)
                        .unwrap(),
                };
                let new_message_bytes = encode_signal_whisper_message(
                    &new_message,
                    new_step.message_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let next_new = match (
                    vector.next_new_plaintext_hex.as_ref(),
                    vector.next_new_message_hex.as_ref(),
                    vector.receiver_record_after_next_new_hex.as_ref(),
                ) {
                    (Some(plaintext_hex), Some(message_hex), Some(record_hex)) => {
                        let next_new_step =
                            ratchet_signal_message_chain(&new_step.next_chain_key).unwrap();
                        let plaintext = bytes_hex(plaintext_hex);
                        let message = SignalWhisperMessage {
                            ephemeral_key: prefixed_public_key(&new_remote_ratchet),
                            counter: next_new_step.message_counter,
                            previous_counter: vector.message_previous_counter,
                            ciphertext: encrypt_signal_message_body(
                                &plaintext,
                                &next_new_step.message_keys,
                            )
                            .unwrap(),
                        };
                        let message_bytes = encode_signal_whisper_message(
                            &message,
                            next_new_step.message_keys.mac_key.expose(),
                            &local_identity,
                            &local_identity,
                        )
                        .unwrap();
                        Some((
                            plaintext,
                            next_new_step.message_counter,
                            message_bytes,
                            message_hex,
                            record_hex,
                        ))
                    }
                    (None, None, None) => None,
                    _ => panic!(
                        "{} next current-ratchet fixture fields must be all present or all absent",
                        vector.name
                    ),
                };

                let record = encode_signal_provider_session_record(&record).unwrap();
                let new_decrypted = decrypt_signal_provider_session_record_message(
                    &record,
                    &new_message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    new_decrypted.plaintext, new_plaintext,
                    "{} new message",
                    vector.name
                );
                let after_new =
                    decode_signal_provider_session_record(&new_decrypted.record).unwrap();
                // 0-based, inclusive skip: receiving_counter..=message_previous_counter.
                let expected_skipped =
                    vector.message_previous_counter - vector.receiving_counter + 1;
                assert_eq!(
                    after_new.message_keys.len(),
                    usize::try_from(expected_skipped).unwrap(),
                    "{} skipped after new",
                    vector.name
                );
                for (offset, message_key) in after_new.message_keys.iter().enumerate() {
                    assert_eq!(
                        message_key.counter,
                        vector.receiving_counter + u32::try_from(offset).unwrap(),
                        "{} skipped counter after new",
                        vector.name
                    );
                    assert_eq!(
                        message_key.ratchet_key,
                        bytes_hex(&vector.old_remote_ratchet_key_hex),
                        "{} skipped ratchet after new",
                        vector.name
                    );
                }
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_old_reject_hex", vector.name),
                    &new_decrypted.record,
                    &vector.receiver_record_before_old_reject_hex,
                );

                match (
                    vector.tampered_old_message_hex.as_ref(),
                    vector.expected_tamper_error.as_ref(),
                ) {
                    (Some(tampered_old_message_hex), Some(expected_tamper_error)) => {
                        let mut tampered_old = old_message.clone();
                        let mut tampered_ciphertext = tampered_old.ciphertext.to_vec();
                        *tampered_ciphertext.last_mut().unwrap() ^= 1;
                        tampered_old.ciphertext = Bytes::from(tampered_ciphertext);
                        let tampered_old_message_bytes = encode_signal_whisper_message(
                            &tampered_old,
                            old_step.message_keys.mac_key.expose(),
                            &local_identity,
                            &local_identity,
                        )
                        .unwrap();
                        let tamper_err = decrypt_signal_provider_session_record_message(
                            &new_decrypted.record,
                            &tampered_old_message_bytes,
                            &local_identity,
                        )
                        .unwrap_err();
                        assert_eq!(
                            tamper_err.to_string(),
                            *expected_tamper_error,
                            "{} expected exact previous-chain tamper error",
                            vector.name,
                        );
                        assert_hex(
                            &mut missing_expected,
                            &format!("{}.tampered_old_message_hex", vector.name),
                            &tampered_old_message_bytes,
                            tampered_old_message_hex,
                        );
                    }
                    (None, None) => {}
                    _ => panic!(
                        "{} previous-chain tamper fixture fields must be both present or both absent",
                        vector.name
                    ),
                }

                let old_decrypted = decrypt_signal_provider_session_record_message(
                    &new_decrypted.record,
                    &old_message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    old_decrypted.plaintext, old_plaintext,
                    "{} old message",
                    vector.name
                );
                let after_old =
                    decode_signal_provider_session_record(&old_decrypted.record).unwrap();
                assert_eq!(
                    after_old.remote_ratchet_key,
                    Some(prefixed_public_key(&new_remote_ratchet)),
                    "{} remote ratchet after old",
                    vector.name
                );
                assert_eq!(
                    after_old.receiving_chain.as_ref().unwrap().counter,
                    new_step.message_counter + 1,
                    "{} receiving counter after old",
                    vector.name
                );
                assert_eq!(
                    after_old.message_keys.len(),
                    usize::try_from(expected_skipped - 1).unwrap(),
                    "{} skipped after old",
                    vector.name
                );
                assert!(
                    after_old
                        .message_keys
                        .iter()
                        .all(|key| key.counter != old_step.message_counter),
                    "{} old skipped key consumed",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_old_replay_hex", vector.name),
                    &old_decrypted.record,
                    &vector.receiver_record_before_old_replay_hex,
                );
                if let Some(expected_old_replay_error) = vector.expected_old_replay_error.as_ref() {
                    let replay_err = decrypt_signal_provider_session_record_message(
                        &old_decrypted.record,
                        &old_message_bytes,
                        &local_identity,
                    )
                    .unwrap_err()
                    .to_string();
                    assert_eq!(
                        replay_err, *expected_old_replay_error,
                        "{} expected exact consumed previous-chain replay error",
                        vector.name,
                    );
                    assert_eq!(
                        decrypt_signal_provider_session_record_message(
                            &old_decrypted.record,
                            &old_message_bytes,
                            &local_identity,
                        )
                        .unwrap_err()
                        .to_string(),
                        replay_err,
                        "{} consumed previous-chain replay error must be stable",
                        vector.name
                    );
                    assert_eq!(
                        old_decrypted.record,
                        encode_signal_provider_session_record(&after_old).unwrap(),
                        "{} consumed previous-chain replay must not mutate record",
                        vector.name
                    );
                }
                let mut record_after_late_messages = old_decrypted.record.clone();
                if let Some((
                    second_old_plaintext,
                    second_old_counter,
                    second_old_message_bytes,
                    second_old_message_hex,
                    receiver_record_after_second_old_hex,
                )) = second_old
                {
                    let second_old_decrypted = decrypt_signal_provider_session_record_message(
                        &record_after_late_messages,
                        &second_old_message_bytes,
                        &local_identity,
                    )
                    .unwrap();
                    assert_eq!(
                        second_old_decrypted.plaintext, second_old_plaintext,
                        "{} second old message",
                        vector.name
                    );
                    let after_second_old =
                        decode_signal_provider_session_record(&second_old_decrypted.record)
                            .unwrap();
                    assert_eq!(
                        after_second_old.remote_ratchet_key,
                        Some(prefixed_public_key(&new_remote_ratchet)),
                        "{} remote ratchet after second old",
                        vector.name
                    );
                    assert_eq!(
                        after_second_old.receiving_chain.as_ref().unwrap().counter,
                        new_step.message_counter + 1,
                        "{} receiving counter after second old",
                        vector.name
                    );
                    assert_eq!(
                        after_second_old.message_keys.len(),
                        usize::try_from(expected_skipped - 2).unwrap(),
                        "{} skipped after second old",
                        vector.name
                    );
                    assert!(
                        after_second_old
                            .message_keys
                            .iter()
                            .all(|key| key.counter != second_old_counter),
                        "{} second old skipped key consumed",
                        vector.name
                    );
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.second_old_message_hex", vector.name),
                        &second_old_message_bytes,
                        second_old_message_hex,
                    );
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.receiver_record_after_second_old_hex", vector.name),
                        &second_old_decrypted.record,
                        receiver_record_after_second_old_hex,
                    );
                    record_after_late_messages = second_old_decrypted.record;
                }
                if let Some((
                    next_new_plaintext,
                    next_new_counter,
                    next_new_message_bytes,
                    next_new_message_hex,
                    receiver_record_after_next_new_hex,
                )) = next_new
                {
                    let next_new_decrypted = decrypt_signal_provider_session_record_message(
                        &record_after_late_messages,
                        &next_new_message_bytes,
                        &local_identity,
                    )
                    .unwrap();
                    assert_eq!(
                        next_new_decrypted.plaintext, next_new_plaintext,
                        "{} next new message",
                        vector.name
                    );
                    let after_next_new =
                        decode_signal_provider_session_record(&next_new_decrypted.record).unwrap();
                    assert_eq!(
                        after_next_new.receiving_chain.as_ref().unwrap().counter,
                        next_new_counter + 1,
                        "{} receiving counter after next new",
                        vector.name
                    );
                    assert!(after_next_new.message_keys.is_empty());
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.next_new_message_hex", vector.name),
                        &next_new_message_bytes,
                        next_new_message_hex,
                    );
                    assert_hex(
                        &mut missing_expected,
                        &format!("{}.receiver_record_after_next_new_hex", vector.name),
                        &next_new_decrypted.record,
                        receiver_record_after_next_new_hex,
                    );
                }
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.old_message_hex", vector.name),
                    &old_message_bytes,
                    &vector.old_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.new_message_hex", vector.name),
                    &new_message_bytes,
                    &vector.new_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_new_hex", vector.name),
                    &new_decrypted.record,
                    &vector.receiver_record_after_new_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_old_hex", vector.name),
                    &old_decrypted.record,
                    &vector.receiver_record_after_old_hex,
                );
            }
            SignalFixture::ProviderSessionPrunedSkippedKeys(vector) => {
                let sender_ratchet = key_pair_from_private_hex(&vector.sender_ratchet_private_hex);
                let local_identity = bytes_hex(&vector.remote_identity_key_hex);
                let sender_ratchet_key = prefixed_public_key(&sender_ratchet);
                let mut chain = SignalMessageChainKey {
                    key: secret_hex(&vector.receiving_chain_key_hex),
                    counter: vector.receiving_counter,
                };
                let mut first_keys = None;
                let mut second_keys = None;
                let mut target_keys = None;
                // 0-based: ratchet through message counters up to and including the target.
                while chain.counter <= vector.target_counter {
                    let step = ratchet_signal_message_chain(&chain).unwrap();
                    match step.message_counter {
                        1 => first_keys = Some(step.message_keys.clone()),
                        2 => second_keys = Some(step.message_keys.clone()),
                        value if value == vector.target_counter => {
                            target_keys = Some(step.message_keys.clone());
                        }
                        _ => {}
                    }
                    chain = step.next_chain_key;
                }
                let first_keys = first_keys.unwrap();
                let second_keys = second_keys.unwrap();
                let target_keys = target_keys.unwrap();
                let first_message = SignalWhisperMessage {
                    ephemeral_key: sender_ratchet_key.clone(),
                    counter: 1,
                    previous_counter: vector.previous_counter,
                    ciphertext: encrypt_signal_message_body(
                        &bytes_hex(&vector.first_plaintext_hex),
                        &first_keys,
                    )
                    .unwrap(),
                };
                let second_message = SignalWhisperMessage {
                    ephemeral_key: sender_ratchet_key.clone(),
                    counter: 2,
                    previous_counter: vector.previous_counter,
                    ciphertext: encrypt_signal_message_body(
                        &bytes_hex(&vector.second_plaintext_hex),
                        &second_keys,
                    )
                    .unwrap(),
                };
                let target_message = SignalWhisperMessage {
                    ephemeral_key: sender_ratchet_key.clone(),
                    counter: vector.target_counter,
                    previous_counter: vector.previous_counter,
                    ciphertext: encrypt_signal_message_body(
                        &bytes_hex(&vector.target_plaintext_hex),
                        &target_keys,
                    )
                    .unwrap(),
                };
                let first_message_bytes = encode_signal_whisper_message(
                    &first_message,
                    first_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let second_message_bytes = encode_signal_whisper_message(
                    &second_message,
                    second_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let target_message_bytes = encode_signal_whisper_message(
                    &target_message,
                    target_keys.mac_key.expose(),
                    &local_identity,
                    &local_identity,
                )
                .unwrap();
                let receiver_record =
                    encode_signal_provider_session_record(&SignalProviderSessionRecord {
                        remote_registration_id: vector.remote_registration_id,
                        remote_identity_key: bytes_hex(&vector.remote_identity_key_hex),
                        root_key: SignalRootKey {
                            key: secret_hex(&vector.root_key_hex),
                        },
                        sending_chain: uninitialized_message_chain(),
                        receiving_chain: Some(SignalMessageChainKey {
                            key: secret_hex(&vector.receiving_chain_key_hex),
                            counter: vector.receiving_counter,
                        }),
                        remote_ratchet_key: Some(sender_ratchet_key),
                        local_ratchet_key_pair: key_pair_from_private_hex(
                            &vector.receiver_local_ratchet_private_hex,
                        ),
                        previous_counter: vector.previous_counter,
                        message_keys: Vec::new(),
                        inbound_base_key: None,
                    })
                    .unwrap();

                let target_decrypted = decrypt_signal_provider_session_record_message(
                    &receiver_record,
                    &target_message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    target_decrypted.plaintext,
                    bytes_hex(&vector.target_plaintext_hex),
                    "{} target plaintext",
                    vector.name
                );
                let after_target =
                    decode_signal_provider_session_record(&target_decrypted.record).unwrap();
                assert_eq!(
                    after_target.message_keys.len(),
                    vector.expected_retained_skipped_count,
                    "{} retained skipped keys",
                    vector.name
                );
                assert_eq!(
                    after_target.message_keys[0].counter, vector.expected_oldest_retained_counter,
                    "{} oldest retained skipped key",
                    vector.name
                );
                assert_eq!(
                    after_target.message_keys.last().unwrap().counter,
                    vector.expected_newest_retained_counter,
                    "{} newest retained skipped key",
                    vector.name
                );

                let pruned_err = decrypt_signal_provider_session_record_message(
                    &target_decrypted.record,
                    &first_message_bytes,
                    &local_identity,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    pruned_err, vector.pruned_replay_expected_error,
                    "{} expected exact pruned skipped-key replay error",
                    vector.name
                );

                let second_decrypted = decrypt_signal_provider_session_record_message(
                    &target_decrypted.record,
                    &second_message_bytes,
                    &local_identity,
                )
                .unwrap();
                assert_eq!(
                    second_decrypted.plaintext,
                    bytes_hex(&vector.second_plaintext_hex),
                    "{} second plaintext",
                    vector.name
                );
                let after_second =
                    decode_signal_provider_session_record(&second_decrypted.record).unwrap();
                assert_eq!(
                    after_second.message_keys.len(),
                    vector.expected_retained_after_second_count,
                    "{} retained after second",
                    vector.name
                );
                assert_eq!(
                    after_second.message_keys[0].counter,
                    vector.expected_oldest_after_second_counter,
                    "{} oldest after second",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.first_message_hex", vector.name),
                    &first_message_bytes,
                    &vector.first_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.second_message_hex", vector.name),
                    &second_message_bytes,
                    &vector.second_message_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.target_message_hex", vector.name),
                    &target_message_bytes,
                    &vector.target_message_hex,
                );
            }
            SignalFixture::SenderChain(vector) => {
                let step = ratchet_signal_sender_chain(&SignalSenderChainKey {
                    key: secret_hex(&vector.chain_key_hex),
                    iteration: vector.iteration,
                })
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.message_key_seed_hex", vector.name),
                    step.message_key.seed.expose(),
                    &vector.message_key_seed_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.cipher_key_hex", vector.name),
                    step.message_key.cipher_key.expose(),
                    &vector.cipher_key_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.iv_hex", vector.name),
                    &step.message_key.iv,
                    &vector.iv_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.next_chain_key_hex", vector.name),
                    step.next_chain_key.key.expose(),
                    &vector.next_chain_key_hex,
                );
            }
            SignalFixture::SenderMessageBody(vector) => {
                let keys = SignalSenderMessageKeyMaterial {
                    iteration: 0,
                    seed: SecretBytes::from(vec![0u8; 32]),
                    cipher_key: secret_hex(&vector.cipher_key_hex),
                    iv: fixed_16_hex(&vector.iv_hex),
                };
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let ciphertext = encrypt_signal_sender_message_body(&plaintext, &keys).unwrap();
                assert_eq!(
                    decrypt_signal_sender_message_body(&ciphertext, &keys).unwrap(),
                    plaintext,
                    "{}",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.ciphertext_hex", vector.name),
                    &ciphertext,
                    &vector.ciphertext_hex,
                );
            }
            SignalFixture::SenderKeyDistribution(vector) => {
                let distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.iteration,
                    &bytes_hex(&vector.chain_key_hex),
                    &bytes_hex(&vector.signing_public_key_hex),
                )
                .unwrap();
                let encoded = encode_signal_sender_key_distribution_message(&distribution).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
            }
            SignalFixture::SenderKeyDistributionUnknownField(vector) => {
                let decoded =
                    decode_signal_sender_key_distribution_message(&bytes_hex(&vector.encoded_hex))
                        .unwrap_or_else(|err| {
                            panic!("{} should decode with unknown fields: {err}", vector.name)
                        });
                assert_eq!(decoded.key_id, vector.key_id, "{}", vector.name);
                assert_eq!(decoded.iteration, vector.iteration, "{}", vector.name);
                assert_eq!(
                    decoded.chain_key.expose(),
                    &bytes_hex(&vector.chain_key_hex)
                );
                let signing_public_key = bytes_hex(&vector.signing_public_key_hex);
                assert_eq!(decoded.signing_key.as_ref(), signing_public_key.as_ref());
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.canonical_encoded_hex", vector.name),
                    &encode_signal_sender_key_distribution_message(&decoded).unwrap(),
                    &vector.canonical_encoded_hex,
                );
            }
            SignalFixture::SenderKeyDistributionInvalidWire(vector) => {
                let encoded = bytes_hex(&vector.encoded_hex);
                let err = decode_signal_sender_key_distribution_message(&encoded).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::SenderKeyDistributionMerge(vector) => {
                let signing_key = key_pair_from_private_hex(&vector.signing_private_key_hex);
                let signing_public_key = prefixed_public_key(&signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.signing_public_key_hex", vector.name),
                    &signing_public_key,
                    &vector.signing_public_key_hex,
                );
                let existing = SignalSenderKeyRecord {
                    states: vec![
                        SignalSenderKeyState {
                            key_id: vector.key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.existing_chain_key_hex),
                                iteration: vector.existing_chain_iteration,
                            },
                            signing_public_key: signing_public_key.clone(),
                            signing_private_key: Some(secret_hex(&vector.signing_private_key_hex)),
                            message_keys: vec![SignalSenderStoredMessageKey {
                                iteration: vector.skipped_iteration,
                                seed: secret_hex(&vector.skipped_seed_hex),
                            }],
                        },
                        SignalSenderKeyState {
                            key_id: vector.key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.preserved_chain_key_hex),
                                iteration: vector.preserved_chain_iteration,
                            },
                            signing_public_key: bytes_hex(&vector.replaced_signing_public_key_hex),
                            signing_private_key: None,
                            message_keys: Vec::new(),
                        },
                        SignalSenderKeyState {
                            key_id: vector.preserved_key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.preserved_chain_key_hex),
                                iteration: vector.preserved_chain_iteration,
                            },
                            signing_public_key: bytes_hex(&vector.preserved_signing_public_key_hex),
                            signing_private_key: None,
                            message_keys: Vec::new(),
                        },
                    ],
                };
                let existing = encode_signal_sender_key_record(&existing).unwrap();
                let distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.distribution_iteration,
                    &bytes_hex(&vector.distribution_chain_key_hex),
                    &signing_public_key,
                )
                .unwrap();
                let updated =
                    process_signal_sender_key_distribution_record(Some(&existing), &distribution)
                        .unwrap();
                let decoded = decode_signal_sender_key_record(&updated).unwrap();
                assert_eq!(decoded.states.len(), 2, "{}", vector.name);
                assert_eq!(decoded.states[0].key_id, vector.key_id, "{}", vector.name);
                assert_eq!(
                    decoded.states[0].chain_key.iteration, vector.distribution_iteration,
                    "{} updated iteration",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].chain_key.key,
                    secret_hex(&vector.distribution_chain_key_hex),
                    "{} updated chain",
                    vector.name
                );
                assert!(
                    decoded.states[0].signing_private_key.is_some(),
                    "{} private key preserved",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].message_keys.len(),
                    1,
                    "{} skipped key preserved",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].message_keys[0].iteration, vector.skipped_iteration,
                    "{} skipped iteration",
                    vector.name
                );
                assert_eq!(
                    decoded.states[1].key_id, vector.preserved_key_id,
                    "{} unrelated state preserved",
                    vector.name
                );
                assert!(
                    decoded
                        .states
                        .iter()
                        .filter(|state| state.key_id == vector.key_id)
                        .count()
                        == 1,
                    "{} same-key replacement removed",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.updated_record_hex", vector.name),
                    &updated,
                    &vector.updated_record_hex,
                );
            }
            SignalFixture::SenderKeyDistributionReplace(vector) => {
                let replacement_key =
                    key_pair_from_private_hex(&vector.replacement_signing_private_key_hex);
                let replacement_public_key = prefixed_public_key(&replacement_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.replacement_signing_public_key_hex", vector.name),
                    &replacement_public_key,
                    &vector.replacement_signing_public_key_hex,
                );
                let existing = SignalSenderKeyRecord {
                    states: vec![
                        SignalSenderKeyState {
                            key_id: vector.key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.existing_chain_key_hex),
                                iteration: vector.existing_chain_iteration,
                            },
                            signing_public_key: bytes_hex(&vector.existing_signing_public_key_hex),
                            signing_private_key: Some(secret_hex(
                                &vector.existing_signing_private_key_hex,
                            )),
                            message_keys: vec![SignalSenderStoredMessageKey {
                                iteration: vector.skipped_iteration,
                                seed: secret_hex(&vector.skipped_seed_hex),
                            }],
                        },
                        SignalSenderKeyState {
                            key_id: vector.preserved_key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.preserved_chain_key_hex),
                                iteration: vector.preserved_chain_iteration,
                            },
                            signing_public_key: bytes_hex(&vector.preserved_signing_public_key_hex),
                            signing_private_key: None,
                            message_keys: Vec::new(),
                        },
                    ],
                };
                let existing = encode_signal_sender_key_record(&existing).unwrap();
                let replacement_distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.replacement_iteration,
                    &bytes_hex(&vector.replacement_chain_key_hex),
                    &replacement_public_key,
                )
                .unwrap();
                let updated = process_signal_sender_key_distribution_record(
                    Some(&existing),
                    &replacement_distribution,
                )
                .unwrap();
                let decoded = decode_signal_sender_key_record(&updated).unwrap();
                assert_eq!(decoded.states.len(), 2, "{}", vector.name);
                assert_eq!(decoded.states[0].key_id, vector.key_id, "{}", vector.name);
                assert_eq!(
                    decoded.states[0].chain_key.iteration, vector.replacement_iteration,
                    "{} replacement iteration",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].chain_key.key,
                    secret_hex(&vector.replacement_chain_key_hex),
                    "{} replacement chain",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].signing_public_key, replacement_public_key,
                    "{} replacement signing key",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].signing_private_key, None,
                    "{} private key dropped",
                    vector.name
                );
                assert!(
                    decoded.states[0].message_keys.is_empty(),
                    "{} skipped keys dropped",
                    vector.name
                );
                assert_eq!(
                    decoded.states[1].key_id, vector.preserved_key_id,
                    "{} unrelated state preserved",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.updated_record_hex", vector.name),
                    &updated,
                    &vector.updated_record_hex,
                );
            }
            SignalFixture::SenderKeyDistributionStale(vector) => {
                let signing_key = key_pair_from_private_hex(&vector.signing_private_key_hex);
                let signing_public_key = prefixed_public_key(&signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.signing_public_key_hex", vector.name),
                    &signing_public_key,
                    &vector.signing_public_key_hex,
                );
                let existing = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.existing_chain_key_hex),
                            iteration: vector.existing_chain_iteration,
                        },
                        signing_public_key: signing_public_key.clone(),
                        signing_private_key: Some(secret_hex(&vector.signing_private_key_hex)),
                        message_keys: vec![SignalSenderStoredMessageKey {
                            iteration: vector.skipped_iteration,
                            seed: secret_hex(&vector.skipped_seed_hex),
                        }],
                    }],
                };
                let existing = encode_signal_sender_key_record(&existing).unwrap();
                let stale_distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.stale_iteration,
                    &bytes_hex(&vector.stale_chain_key_hex),
                    &signing_public_key,
                )
                .unwrap();
                let updated = process_signal_sender_key_distribution_record(
                    Some(&existing),
                    &stale_distribution,
                )
                .unwrap();
                let decoded = decode_signal_sender_key_record(&updated).unwrap();
                assert_eq!(decoded.states.len(), 1, "{}", vector.name);
                assert_eq!(decoded.states[0].key_id, vector.key_id, "{}", vector.name);
                assert_eq!(
                    decoded.states[0].chain_key.iteration, vector.existing_chain_iteration,
                    "{} stale iteration ignored",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].chain_key.key,
                    secret_hex(&vector.existing_chain_key_hex),
                    "{} stale chain ignored",
                    vector.name
                );
                assert!(
                    decoded.states[0].signing_private_key.is_some(),
                    "{} private key preserved",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].message_keys.len(),
                    1,
                    "{} skipped key preserved",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].message_keys[0].iteration, vector.skipped_iteration,
                    "{} skipped iteration",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.updated_record_hex", vector.name),
                    &updated,
                    &vector.updated_record_hex,
                );
            }
            SignalFixture::SenderKeyDistributionCacheStale(vector) => {
                let signing_key = key_pair_from_private_hex(&vector.signing_private_key_hex);
                let signing_public_key = prefixed_public_key(&signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.signing_public_key_hex", vector.name),
                    &signing_public_key,
                    &vector.signing_public_key_hex,
                );
                let existing_distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.existing_iteration,
                    &bytes_hex(&vector.existing_chain_key_hex),
                    &signing_public_key,
                )
                .unwrap();
                let existing_distribution_bytes =
                    encode_signal_sender_key_distribution_message(&existing_distribution).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.existing_distribution_hex", vector.name),
                    &existing_distribution_bytes,
                    &vector.existing_distribution_hex,
                );
                let incoming_distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.incoming_iteration,
                    &bytes_hex(&vector.incoming_chain_key_hex),
                    &signing_public_key,
                )
                .unwrap();
                let incoming_distribution_bytes =
                    encode_signal_sender_key_distribution_message(&incoming_distribution).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.incoming_distribution_hex", vector.name),
                    &incoming_distribution_bytes,
                    &vector.incoming_distribution_hex,
                );
                let should_replace = should_replace_cached_signal_sender_key_distribution(
                    Some(&existing_distribution_bytes),
                    &incoming_distribution_bytes,
                )
                .unwrap();
                assert!(
                    !should_replace,
                    "{} stale same-signer cache replacement",
                    vector.name
                );
                let should_store_without_existing =
                    should_replace_cached_signal_sender_key_distribution(
                        None,
                        &incoming_distribution_bytes,
                    )
                    .unwrap();
                assert!(
                    should_store_without_existing,
                    "{} incoming distribution stored without existing cache",
                    vector.name
                );
                let cached_distribution = if should_replace {
                    incoming_distribution_bytes
                } else {
                    existing_distribution_bytes
                };
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.expected_cached_distribution_hex", vector.name),
                    &cached_distribution,
                    &vector.expected_cached_distribution_hex,
                );
                let equal_iteration_distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.equal_iteration,
                    &bytes_hex(&vector.equal_iteration_chain_key_hex),
                    &signing_public_key,
                )
                .unwrap();
                let equal_iteration_distribution_bytes =
                    encode_signal_sender_key_distribution_message(&equal_iteration_distribution)
                        .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.equal_iteration_distribution_hex", vector.name),
                    &equal_iteration_distribution_bytes,
                    &vector.equal_iteration_distribution_hex,
                );
                let should_replace_equal_iteration =
                    should_replace_cached_signal_sender_key_distribution(
                        Some(&cached_distribution),
                        &equal_iteration_distribution_bytes,
                    )
                    .unwrap();
                assert!(
                    should_replace_equal_iteration,
                    "{} equal-iteration same-signer cache replacement",
                    vector.name
                );
                let equal_iteration_cached = if should_replace_equal_iteration {
                    equal_iteration_distribution_bytes
                } else {
                    cached_distribution
                };
                assert_hex(
                    &mut missing_expected,
                    &format!(
                        "{}.expected_equal_iteration_cached_distribution_hex",
                        vector.name
                    ),
                    &equal_iteration_cached,
                    &vector.expected_equal_iteration_cached_distribution_hex,
                );
                let replacement_signing_key =
                    key_pair_from_private_hex(&vector.replacement_signing_private_key_hex);
                let replacement_signing_public_key = prefixed_public_key(&replacement_signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.replacement_signing_public_key_hex", vector.name),
                    &replacement_signing_public_key,
                    &vector.replacement_signing_public_key_hex,
                );
                let replacement_distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.replacement_iteration,
                    &bytes_hex(&vector.replacement_chain_key_hex),
                    &replacement_signing_public_key,
                )
                .unwrap();
                let replacement_distribution_bytes =
                    encode_signal_sender_key_distribution_message(&replacement_distribution)
                        .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.replacement_distribution_hex", vector.name),
                    &replacement_distribution_bytes,
                    &vector.replacement_distribution_hex,
                );
                let should_replace_different_signer =
                    should_replace_cached_signal_sender_key_distribution(
                        Some(&equal_iteration_cached),
                        &replacement_distribution_bytes,
                    )
                    .unwrap();
                assert!(
                    should_replace_different_signer,
                    "{} different-signer cache replacement",
                    vector.name
                );
                let replacement_cached = if should_replace_different_signer {
                    replacement_distribution_bytes
                } else {
                    equal_iteration_cached
                };
                assert_hex(
                    &mut missing_expected,
                    &format!(
                        "{}.expected_replacement_cached_distribution_hex",
                        vector.name
                    ),
                    &replacement_cached,
                    &vector.expected_replacement_cached_distribution_hex,
                );
                let malformed_incoming = bytes_hex(&vector.malformed_incoming_distribution_hex);
                let malformed_err = should_replace_cached_signal_sender_key_distribution(
                    Some(&replacement_cached),
                    &malformed_incoming,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    malformed_err, vector.malformed_incoming_error,
                    "{} expected exact malformed incoming error",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!(
                        "{}.expected_cached_after_malformed_distribution_hex",
                        vector.name
                    ),
                    &replacement_cached,
                    &vector.expected_cached_after_malformed_distribution_hex,
                );
                let malformed_existing = bytes_hex(&vector.malformed_existing_distribution_hex);
                let should_replace_malformed_existing =
                    should_replace_cached_signal_sender_key_distribution(
                        Some(&malformed_existing),
                        &replacement_cached,
                    )
                    .unwrap();
                assert!(
                    should_replace_malformed_existing,
                    "{} malformed-existing cache replacement",
                    vector.name
                );
                let cached_after_malformed_existing = if should_replace_malformed_existing {
                    replacement_cached
                } else {
                    malformed_existing
                };
                assert_hex(
                    &mut missing_expected,
                    &format!(
                        "{}.expected_cached_after_malformed_existing_distribution_hex",
                        vector.name
                    ),
                    &cached_after_malformed_existing,
                    &vector.expected_cached_after_malformed_existing_distribution_hex,
                );
            }
            SignalFixture::SenderKeyDistributionStaleChainRetry(vector) => {
                let signing_key = key_pair_from_private_hex(&vector.signing_private_key_hex);
                let signing_public_key = prefixed_public_key(&signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.signing_public_key_hex", vector.name),
                    &signing_public_key,
                    &vector.signing_public_key_hex,
                );
                let stale_record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.stale_chain_key_hex),
                            iteration: vector.stale_iteration,
                        },
                        signing_public_key: signing_public_key.clone(),
                        signing_private_key: None,
                        message_keys: Vec::new(),
                    }],
                };
                let stale_record = encode_signal_sender_key_record(&stale_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.stale_record_hex", vector.name),
                    &stale_record,
                    &vector.stale_record_hex,
                );

                let fresh_distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.fresh_iteration,
                    &bytes_hex(&vector.fresh_chain_key_hex),
                    &signing_public_key,
                )
                .unwrap();
                let fresh_distribution_bytes =
                    encode_signal_sender_key_distribution_message(&fresh_distribution).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.fresh_distribution_hex", vector.name),
                    &fresh_distribution_bytes,
                    &vector.fresh_distribution_hex,
                );
                let candidate_record = process_signal_sender_key_distribution_record(
                    Some(&stale_record),
                    &fresh_distribution,
                )
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.candidate_record_hex", vector.name),
                    &candidate_record,
                    &vector.candidate_record_hex,
                );

                let fresh_message_key = ratchet_signal_sender_chain(&SignalSenderChainKey {
                    key: secret_hex(&vector.fresh_chain_key_hex),
                    iteration: vector.fresh_iteration,
                })
                .unwrap()
                .message_key;
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let fresh_body =
                    encrypt_signal_sender_message_body(&plaintext, &fresh_message_key).unwrap();
                let fresh_message = sign_signal_sender_key_message(
                    vector.key_id,
                    fresh_message_key.iteration,
                    fresh_body,
                    signing_key.private.expose(),
                )
                .unwrap();
                let fresh_message_bytes = encode_signal_sender_key_message(&fresh_message).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.fresh_ciphertext_hex", vector.name),
                    &fresh_message.ciphertext,
                    &vector.fresh_ciphertext_hex,
                );

                let stale_err = decrypt_signal_sender_key_record_message(
                    &stale_record,
                    &fresh_message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .expect_err("same-signer stale sender-key record should fail body decrypt");
                assert_eq!(
                    stale_err.to_string(),
                    vector.stale_decrypt_error,
                    "{} stale decrypt error",
                    vector.name
                );

                let truncated_ciphertext = Bytes::copy_from_slice(
                    &fresh_message.ciphertext[..fresh_message.ciphertext.len() - 1],
                );
                let tampered_message = sign_signal_sender_key_message(
                    vector.key_id,
                    fresh_message_key.iteration,
                    truncated_ciphertext,
                    signing_key.private.expose(),
                )
                .unwrap();
                let tampered_message_bytes =
                    encode_signal_sender_key_message(&tampered_message).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.tampered_ciphertext_hex", vector.name),
                    &tampered_message.ciphertext,
                    &vector.tampered_ciphertext_hex,
                );
                let tampered_err = decrypt_signal_sender_key_record_message(
                    &candidate_record,
                    &tampered_message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .expect_err("same-signer distribution candidate should reject tampered body");
                assert_eq!(
                    tampered_err.to_string(),
                    vector.tampered_decrypt_error,
                    "{} tampered decrypt error",
                    vector.name
                );

                let decrypted = decrypt_signal_sender_key_record_message(
                    &candidate_record,
                    &fresh_message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap();
                assert_eq!(decrypted.plaintext, plaintext, "{} plaintext", vector.name);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.recovered_record_hex", vector.name),
                    &decrypted.record,
                    &vector.recovered_record_hex,
                );
                let recovered = decode_signal_sender_key_record(&decrypted.record).unwrap();
                assert_eq!(recovered.states.len(), 1, "{}", vector.name);
                assert_eq!(recovered.states[0].key_id, vector.key_id, "{}", vector.name);
                assert_eq!(
                    recovered.states[0].chain_key.iteration,
                    vector.fresh_iteration + 1,
                    "{} recovered iteration",
                    vector.name
                );
                assert_eq!(
                    recovered.states[0].signing_public_key, signing_public_key,
                    "{} recovered signing key",
                    vector.name
                );
                assert_eq!(
                    recovered.states[0].signing_private_key, None,
                    "{} recovered private key",
                    vector.name
                );
            }
            SignalFixture::SenderKeyDistributionTruncate(vector) => {
                assert_eq!(
                    vector.existing_key_ids.len(),
                    5,
                    "{} existing state count",
                    vector.name
                );
                let existing_states = vector
                    .existing_key_ids
                    .iter()
                    .enumerate()
                    .map(|(index, key_id)| {
                        let fill = 0x30 + index as u8;
                        SignalSenderKeyState {
                            key_id: *key_id,
                            chain_key: SignalSenderChainKey {
                                key: SecretBytes::from(vec![fill; 32]),
                                iteration: vector.existing_chain_iteration + index as u32,
                            },
                            signing_public_key: repeated_prefixed_public_key(0xa0 + index as u8),
                            signing_private_key: None,
                            message_keys: Vec::new(),
                        }
                    })
                    .collect();
                let existing = encode_signal_sender_key_record(&SignalSenderKeyRecord {
                    states: existing_states,
                })
                .unwrap();
                let distribution_signing_public_key =
                    bytes_hex(&vector.distribution_signing_public_key_hex);
                let distribution = build_signal_sender_key_distribution_message(
                    vector.key_id,
                    vector.distribution_iteration,
                    &bytes_hex(&vector.distribution_chain_key_hex),
                    &distribution_signing_public_key,
                )
                .unwrap();
                let updated =
                    process_signal_sender_key_distribution_record(Some(&existing), &distribution)
                        .unwrap();
                let decoded = decode_signal_sender_key_record(&updated).unwrap();
                let actual_key_ids = decoded
                    .states
                    .iter()
                    .map(|state| state.key_id)
                    .collect::<Vec<_>>();
                assert_eq!(actual_key_ids, vector.expected_key_ids, "{}", vector.name);
                assert!(
                    !actual_key_ids.contains(&vector.dropped_key_id),
                    "{} oldest state dropped",
                    vector.name
                );
                assert_eq!(decoded.states[0].key_id, vector.key_id, "{}", vector.name);
                assert_eq!(
                    decoded.states[0].chain_key.iteration, vector.distribution_iteration,
                    "{} distribution iteration",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].chain_key.key,
                    secret_hex(&vector.distribution_chain_key_hex),
                    "{} distribution chain key",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].signing_public_key, distribution_signing_public_key,
                    "{} distribution signing key",
                    vector.name
                );
                assert_eq!(
                    decoded.states[0].signing_private_key, None,
                    "{} distribution private key",
                    vector.name
                );
                assert!(
                    decoded.states[0].message_keys.is_empty(),
                    "{} distribution skipped keys",
                    vector.name
                );
                for (source_index, state) in decoded.states.iter().skip(1).enumerate() {
                    let fill = 0x30 + source_index as u8;
                    let expected_chain_key = SecretBytes::from(vec![fill; 32]);
                    assert_eq!(
                        state.key_id, vector.existing_key_ids[source_index],
                        "{} preserved key id",
                        vector.name
                    );
                    assert_eq!(
                        state.chain_key.iteration,
                        vector.existing_chain_iteration + source_index as u32,
                        "{} preserved iteration",
                        vector.name
                    );
                    assert_eq!(
                        state.chain_key.key, expected_chain_key,
                        "{} preserved chain key",
                        vector.name
                    );
                    assert_eq!(
                        state.signing_public_key,
                        repeated_prefixed_public_key(0xa0 + source_index as u8),
                        "{} preserved signing key",
                        vector.name
                    );
                }
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.updated_record_hex", vector.name),
                    &updated,
                    &vector.updated_record_hex,
                );
            }
            SignalFixture::SenderKeyRecord(vector) => {
                let record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key: bytes_hex(&vector.signing_public_key_hex),
                        signing_private_key: vector
                            .signing_private_key_hex
                            .as_deref()
                            .map(secret_hex),
                        message_keys: vec![SignalSenderStoredMessageKey {
                            iteration: vector.message_key_iteration,
                            seed: secret_hex(&vector.message_key_seed_hex),
                        }],
                    }],
                };
                let encoded = encode_signal_sender_key_record(&record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
            }
            SignalFixture::SenderKeyRecordUnknownField(vector) => {
                let decoded = decode_signal_sender_key_record(&bytes_hex(&vector.encoded_hex))
                    .unwrap_or_else(|err| {
                        panic!("{} should decode with unknown fields: {err}", vector.name)
                    });
                assert_eq!(decoded.states.len(), 1, "{}", vector.name);
                let state = &decoded.states[0];
                assert_eq!(state.key_id, vector.key_id, "{}", vector.name);
                assert_eq!(
                    state.chain_key.iteration, vector.chain_iteration,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    state.chain_key.key,
                    secret_hex(&vector.chain_key_hex),
                    "{}",
                    vector.name
                );
                assert_eq!(
                    state.signing_public_key,
                    bytes_hex(&vector.signing_public_key_hex),
                    "{}",
                    vector.name
                );
                assert_eq!(
                    state.signing_private_key,
                    vector.signing_private_key_hex.as_deref().map(secret_hex),
                    "{}",
                    vector.name
                );
                assert_eq!(state.message_keys.len(), 1, "{}", vector.name);
                assert_eq!(
                    state.message_keys[0].iteration, vector.message_key_iteration,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    state.message_keys[0].seed,
                    secret_hex(&vector.message_key_seed_hex),
                    "{}",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.canonical_encoded_hex", vector.name),
                    &encode_signal_sender_key_record(&decoded).unwrap(),
                    &vector.canonical_encoded_hex,
                );
            }
            SignalFixture::SenderKeyRecordInvalidSigningKey(vector) => {
                let record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key: bytes_hex(&vector.signing_public_key_hex),
                        signing_private_key: Some(secret_hex(&vector.signing_private_key_hex)),
                        message_keys: vec![SignalSenderStoredMessageKey {
                            iteration: vector.message_key_iteration,
                            seed: secret_hex(&vector.message_key_seed_hex),
                        }],
                    }],
                };
                let err = encode_signal_sender_key_record(&record).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name,
                );
                let raw_record = encode_raw_sender_key_record_invalid_signing_key(&vector);
                let err = decode_signal_sender_key_record(&raw_record).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact decode-time error",
                    vector.name,
                );
            }
            SignalFixture::SenderKeyRecordInvalidState(vector) => {
                let mut message_keys = vec![SignalSenderStoredMessageKey {
                    iteration: vector.message_key_iteration,
                    seed: secret_hex(&vector.message_key_seed_hex),
                }];
                if let Some(iteration) = vector.second_message_key_iteration {
                    message_keys.push(SignalSenderStoredMessageKey {
                        iteration,
                        seed: secret_hex(
                            vector
                                .second_message_key_seed_hex
                                .as_deref()
                                .expect("second sender-key message seed fixture field"),
                        ),
                    });
                }
                let signing_public_key = bytes_hex(&vector.signing_public_key_hex);
                let signing_private_key = vector.signing_private_key_hex.as_deref().map(secret_hex);
                let primary = SignalSenderKeyState {
                    key_id: vector.key_id,
                    chain_key: SignalSenderChainKey {
                        key: secret_hex(&vector.chain_key_hex),
                        iteration: vector.chain_iteration,
                    },
                    signing_public_key: signing_public_key.clone(),
                    signing_private_key,
                    message_keys,
                };
                let mut states = vec![primary];
                if vector.duplicate_state.unwrap_or(false) {
                    states.push(SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration + 1,
                        },
                        signing_public_key,
                        signing_private_key: None,
                        message_keys: Vec::new(),
                    });
                }
                let err =
                    encode_signal_sender_key_record(&SignalSenderKeyRecord { states }).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name,
                );
                let raw_record = encode_raw_sender_key_record_invalid_state(&vector);
                let err = decode_signal_sender_key_record(&raw_record).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact decode-time error",
                    vector.name,
                );
            }
            SignalFixture::SenderKeyRecordInvalidWire(vector) => {
                let encoded = bytes_hex(&vector.encoded_hex);
                let err = decode_signal_sender_key_record(&encoded).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name,
                );
            }
            SignalFixture::SenderKeyRecordMessage(vector) => {
                let signing_key = key_pair_from_private_hex(&vector.signing_private_key_hex);
                let signing_public_key = prefixed_public_key(&signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.signing_public_key_hex", vector.name),
                    &signing_public_key,
                    &vector.signing_public_key_hex,
                );
                let sender_record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key: signing_public_key.clone(),
                        signing_private_key: Some(secret_hex(&vector.signing_private_key_hex)),
                        message_keys: Vec::new(),
                    }],
                };
                let receiver_record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key,
                        signing_private_key: None,
                        message_keys: Vec::new(),
                    }],
                };
                let sender_record = encode_signal_sender_key_record(&sender_record).unwrap();
                let receiver_record = encode_signal_sender_key_record(&receiver_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &receiver_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let plaintext = bytes_hex(&vector.plaintext_hex);
                let encrypted =
                    encrypt_signal_sender_key_record_message(&sender_record, &plaintext).unwrap();
                assert_eq!(encrypted.message.key_id, vector.key_id, "{}", vector.name);
                assert_eq!(
                    encrypted.message.iteration, vector.chain_iteration,
                    "{} iteration",
                    vector.name
                );
                assert_eq!(
                    encrypted.message.signature.len(),
                    64,
                    "{} signature length",
                    vector.name
                );
                let sender_after = decode_signal_sender_key_record(&encrypted.record).unwrap();
                assert_eq!(
                    sender_after.states[0].chain_key.iteration,
                    vector.chain_iteration + 1,
                    "{} sender iteration",
                    vector.name
                );
                let mut tampered = encrypted.message_bytes.to_vec();
                *tampered.last_mut().unwrap() ^= 1;
                let tamper_err = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &tampered,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    tamper_err, "protocol error: invalid Signal sender-key message signature",
                    "{} expected exact signature tamper rejection",
                    vector.name
                );
                let truncated_ciphertext = Bytes::copy_from_slice(
                    &encrypted.message.ciphertext[..encrypted.message.ciphertext.len() - 1],
                );
                let signed_failed_decrypt = sign_signal_sender_key_message(
                    encrypted.message.key_id,
                    encrypted.message.iteration,
                    truncated_ciphertext,
                    signing_key.private.expose(),
                )
                .unwrap();
                let signed_failed_decrypt =
                    encode_signal_sender_key_message(&signed_failed_decrypt).unwrap();
                let failed_decrypt_err = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &signed_failed_decrypt,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    failed_decrypt_err, "crypto error: decryption failed",
                    "{} expected exact valid-signature failed decrypt",
                    vector.name
                );
                let decrypted = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &encrypted.message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap();
                assert_eq!(decrypted.plaintext, plaintext, "{}", vector.name);
                let receiver_after = decode_signal_sender_key_record(&decrypted.record).unwrap();
                assert_eq!(
                    receiver_after.states[0].chain_key.iteration,
                    vector.chain_iteration + 1,
                    "{} receiver iteration",
                    vector.name
                );
                assert!(
                    receiver_after.states[0].message_keys.is_empty(),
                    "{} receiver skipped keys",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.ciphertext_hex", vector.name),
                    &encrypted.message.ciphertext,
                    &vector.ciphertext_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_hex", vector.name),
                    &encrypted.record,
                    &vector.sender_record_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_hex,
                );
            }
            SignalFixture::SenderKeyMessageInvalidWire(vector) => {
                let encoded = bytes_hex(&vector.encoded_hex);
                let err = decode_signal_sender_key_message(&encoded).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::SenderKeyMessageUnknownField(vector) => {
                let decoded = decode_signal_sender_key_message(&bytes_hex(&vector.encoded_hex))
                    .unwrap_or_else(|err| {
                        panic!("{} should decode with unknown fields: {err}", vector.name)
                    });
                assert_eq!(decoded.key_id, vector.key_id, "{}", vector.name);
                assert_eq!(decoded.iteration, vector.iteration, "{}", vector.name);
                assert_eq!(decoded.ciphertext, bytes_hex(&vector.ciphertext_hex));
                assert_eq!(decoded.signature, bytes_hex(&vector.signature_hex));
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.canonical_encoded_hex", vector.name),
                    &encode_signal_sender_key_message(&decoded).unwrap(),
                    &vector.canonical_encoded_hex,
                );
            }
            SignalFixture::SenderKeyMessageInvalidSignature(vector) => {
                let encoded = bytes_hex(&vector.encoded_hex);
                let signing_public_key = bytes_hex(&vector.signing_public_key_hex);
                let err = verify_signal_sender_key_message_bytes(
                    &encoded,
                    &signing_public_key,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
            SignalFixture::SenderKeyRecordFarFuture(vector) => {
                let signing_key = key_pair_from_private_hex(&vector.signing_private_key_hex);
                let signing_public_key = prefixed_public_key(&signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.signing_public_key_hex", vector.name),
                    &signing_public_key,
                    &vector.signing_public_key_hex,
                );
                let sender_record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key: signing_public_key.clone(),
                        signing_private_key: Some(secret_hex(&vector.signing_private_key_hex)),
                        message_keys: Vec::new(),
                    }],
                };
                let receiver_record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key,
                        signing_private_key: None,
                        message_keys: Vec::new(),
                    }],
                };
                let sender_record = encode_signal_sender_key_record(&sender_record).unwrap();
                let receiver_record = encode_signal_sender_key_record(&receiver_record).unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &receiver_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let valid = encrypt_signal_sender_key_record_message(
                    &sender_record,
                    &bytes_hex(&vector.plaintext_hex),
                )
                .unwrap();
                let far_future = sign_signal_sender_key_message(
                    vector.key_id,
                    vector.far_future_iteration,
                    bytes_hex(&vector.far_future_ciphertext_hex),
                    signing_key.private.expose(),
                )
                .unwrap();
                let far_future = encode_signal_sender_key_message(&far_future).unwrap();
                let err = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &far_future,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err,
                    "protocol error: Signal sender-key message is too far in the future: 25001",
                    "{} expected exact sender-key far-future rejection",
                    vector.name
                );
                let decrypted = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &valid.message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap();
                assert_eq!(
                    decrypted.plaintext,
                    bytes_hex(&vector.plaintext_hex),
                    "{} valid message after rejection",
                    vector.name
                );
                assert_eq!(
                    valid.message.iteration, vector.chain_iteration,
                    "{} valid iteration",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.ciphertext_hex", vector.name),
                    &valid.message.ciphertext,
                    &vector.ciphertext_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_hex", vector.name),
                    &valid.record,
                    &vector.sender_record_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_hex", vector.name),
                    &decrypted.record,
                    &vector.receiver_record_hex,
                );
            }
            SignalFixture::SenderKeyRecordMultiStateDecrypt(vector) => {
                let old_signing_key =
                    key_pair_from_private_hex(&vector.old_signing_private_key_hex);
                let old_signing_public_key = prefixed_public_key(&old_signing_key);
                let replacement_signing_key =
                    key_pair_from_private_hex(&vector.replacement_signing_private_key_hex);
                let replacement_signing_public_key = prefixed_public_key(&replacement_signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.old_signing_public_key_hex", vector.name),
                    &old_signing_public_key,
                    &vector.old_signing_public_key_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.replacement_signing_public_key_hex", vector.name),
                    &replacement_signing_public_key,
                    &vector.replacement_signing_public_key_hex,
                );
                let old_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.old_chain_key_hex),
                            iteration: vector.old_chain_iteration,
                        },
                        signing_public_key: old_signing_public_key.clone(),
                        signing_private_key: Some(secret_hex(&vector.old_signing_private_key_hex)),
                        message_keys: Vec::new(),
                    }],
                })
                .unwrap();
                let replacement_sender_record =
                    encode_signal_sender_key_record(&SignalSenderKeyRecord {
                        states: vec![SignalSenderKeyState {
                            key_id: vector.key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.replacement_chain_key_hex),
                                iteration: vector.replacement_chain_iteration,
                            },
                            signing_public_key: replacement_signing_public_key.clone(),
                            signing_private_key: Some(secret_hex(
                                &vector.replacement_signing_private_key_hex,
                            )),
                            message_keys: Vec::new(),
                        }],
                    })
                    .unwrap();
                let receiver_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
                    states: vec![
                        SignalSenderKeyState {
                            key_id: vector.key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.replacement_chain_key_hex),
                                iteration: vector.replacement_chain_iteration,
                            },
                            signing_public_key: replacement_signing_public_key,
                            signing_private_key: None,
                            message_keys: Vec::new(),
                        },
                        SignalSenderKeyState {
                            key_id: vector.key_id,
                            chain_key: SignalSenderChainKey {
                                key: secret_hex(&vector.old_chain_key_hex),
                                iteration: vector.old_chain_iteration,
                            },
                            signing_public_key: old_signing_public_key,
                            signing_private_key: None,
                            message_keys: Vec::new(),
                        },
                    ],
                })
                .unwrap();
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &receiver_record,
                    &vector.receiver_record_before_reject_hex,
                );
                let old_plaintext = bytes_hex(&vector.old_plaintext_hex);
                let replacement_plaintext = bytes_hex(&vector.replacement_plaintext_hex);
                let old_encrypted =
                    encrypt_signal_sender_key_record_message(&old_sender_record, &old_plaintext)
                        .unwrap();
                let replacement_encrypted = encrypt_signal_sender_key_record_message(
                    &replacement_sender_record,
                    &replacement_plaintext,
                )
                .unwrap();

                let mut invalid_signature_message = old_encrypted.message_bytes.to_vec();
                *invalid_signature_message.last_mut().unwrap() ^= 1;
                let invalid_signature_err = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &invalid_signature_message,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err();
                assert_eq!(
                    invalid_signature_err.to_string(),
                    vector.invalid_signature_error,
                    "{}",
                    vector.name
                );
                let failed_decrypt_message = sign_signal_sender_key_message(
                    vector.key_id,
                    vector.old_chain_iteration,
                    Bytes::from_static(b"not-a-valid-cbc-frame"),
                    old_signing_key.private.expose(),
                )
                .unwrap();
                let failed_decrypt_message =
                    encode_signal_sender_key_message(&failed_decrypt_message).unwrap();
                let failed_decrypt_err = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &failed_decrypt_message,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    failed_decrypt_err, vector.failed_decrypt_error,
                    "{} expected exact multi-state sender-key failed-decrypt error",
                    vector.name
                );
                let far_future_message = sign_signal_sender_key_message(
                    vector.key_id,
                    vector.far_future_iteration,
                    Bytes::from_static(b"far-future-ciphertext"),
                    old_signing_key.private.expose(),
                )
                .unwrap();
                let far_future_message =
                    encode_signal_sender_key_message(&far_future_message).unwrap();
                let far_future_err = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &far_future_message,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    far_future_err, vector.far_future_error,
                    "{} expected exact multi-state sender-key far-future error",
                    vector.name
                );

                let old_decrypted = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &old_encrypted.message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap();
                assert_eq!(old_decrypted.plaintext, old_plaintext, "{}", vector.name);
                let after_old = decode_signal_sender_key_record(&old_decrypted.record).unwrap();
                assert_eq!(after_old.states.len(), 2, "{}", vector.name);
                assert_eq!(
                    after_old.states[0].chain_key.iteration, vector.replacement_chain_iteration,
                    "{} replacement state unchanged",
                    vector.name
                );
                assert_eq!(
                    after_old.states[1].chain_key.iteration,
                    vector.old_chain_iteration + 1,
                    "{} old state advanced",
                    vector.name
                );
                let replay_err = decrypt_signal_sender_key_record_message(
                    &old_decrypted.record,
                    &old_encrypted.message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap_err();
                assert_eq!(
                    replay_err.to_string(),
                    vector.replay_error,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    old_decrypted.record,
                    encode_signal_sender_key_record(&after_old).unwrap(),
                    "{} multi-state replay must not mutate sender-key record",
                    vector.name
                );

                let replacement_decrypted = decrypt_signal_sender_key_record_message(
                    &old_decrypted.record,
                    &replacement_encrypted.message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap();
                assert_eq!(
                    replacement_decrypted.plaintext, replacement_plaintext,
                    "{}",
                    vector.name
                );
                let after_replacement =
                    decode_signal_sender_key_record(&replacement_decrypted.record).unwrap();
                assert_eq!(
                    after_replacement.states[0].chain_key.iteration,
                    vector.replacement_chain_iteration + 1,
                    "{} replacement state advanced",
                    vector.name
                );
                assert_eq!(
                    after_replacement.states[1].chain_key.iteration,
                    vector.old_chain_iteration + 1,
                    "{} old state preserved",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.old_ciphertext_hex", vector.name),
                    &old_encrypted.message.ciphertext,
                    &vector.old_ciphertext_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.replacement_ciphertext_hex", vector.name),
                    &replacement_encrypted.message.ciphertext,
                    &vector.replacement_ciphertext_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_old_hex", vector.name),
                    &old_decrypted.record,
                    &vector.receiver_record_after_old_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_replacement_hex", vector.name),
                    &replacement_decrypted.record,
                    &vector.receiver_record_after_replacement_hex,
                );
            }
            SignalFixture::SenderKeyRecordOutOfOrder(vector) => {
                let signing_key = key_pair_from_private_hex(&vector.signing_private_key_hex);
                let signing_public_key = prefixed_public_key(&signing_key);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.signing_public_key_hex", vector.name),
                    &signing_public_key,
                    &vector.signing_public_key_hex,
                );
                let sender_record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key: signing_public_key.clone(),
                        signing_private_key: Some(secret_hex(&vector.signing_private_key_hex)),
                        message_keys: Vec::new(),
                    }],
                };
                let receiver_record = SignalSenderKeyRecord {
                    states: vec![SignalSenderKeyState {
                        key_id: vector.key_id,
                        chain_key: SignalSenderChainKey {
                            key: secret_hex(&vector.chain_key_hex),
                            iteration: vector.chain_iteration,
                        },
                        signing_public_key,
                        signing_private_key: None,
                        message_keys: Vec::new(),
                    }],
                };
                let sender_record = encode_signal_sender_key_record(&sender_record).unwrap();
                let receiver_record = encode_signal_sender_key_record(&receiver_record).unwrap();
                let first = encrypt_signal_sender_key_record_message(
                    &sender_record,
                    &bytes_hex(&vector.first_plaintext_hex),
                )
                .unwrap();
                let second = encrypt_signal_sender_key_record_message(
                    &first.record,
                    &bytes_hex(&vector.second_plaintext_hex),
                )
                .unwrap();
                assert_eq!(
                    first.message.iteration, vector.chain_iteration,
                    "{} first iteration",
                    vector.name
                );
                assert_eq!(
                    second.message.iteration,
                    vector.chain_iteration + 1,
                    "{} second iteration",
                    vector.name
                );
                let sender_after = decode_signal_sender_key_record(&second.record).unwrap();
                assert_eq!(
                    sender_after.states[0].chain_key.iteration,
                    vector.chain_iteration + 2,
                    "{} sender iteration",
                    vector.name
                );
                let second_decrypted = decrypt_signal_sender_key_record_message(
                    &receiver_record,
                    &second.message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap();
                assert_eq!(
                    second_decrypted.plaintext,
                    bytes_hex(&vector.second_plaintext_hex),
                    "{} second plaintext",
                    vector.name
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_before_reject_hex", vector.name),
                    &second_decrypted.record,
                    &vector.receiver_record_before_reject_hex,
                );
                let receiver_after_second =
                    decode_signal_sender_key_record(&second_decrypted.record).unwrap();
                assert_eq!(
                    receiver_after_second.states[0].chain_key.iteration,
                    vector.chain_iteration + 2,
                    "{} receiver second iteration",
                    vector.name
                );
                assert_eq!(
                    receiver_after_second.states[0].message_keys.len(),
                    1,
                    "{} skipped after second",
                    vector.name
                );
                assert_eq!(
                    receiver_after_second.states[0].message_keys[0].iteration,
                    vector.chain_iteration,
                    "{} skipped iteration",
                    vector.name
                );
                match (
                    vector.tampered_first_ciphertext_hex.as_ref(),
                    vector.expected_tamper_error.as_ref(),
                ) {
                    (Some(tampered_first_ciphertext_hex), Some(expected_tamper_error)) => {
                        let tampered_ciphertext = Bytes::copy_from_slice(
                            &first.message.ciphertext[..first.message.ciphertext.len() - 1],
                        );
                        let tampered_first = sign_signal_sender_key_message(
                            first.message.key_id,
                            first.message.iteration,
                            tampered_ciphertext.clone(),
                            signing_key.private.expose(),
                        )
                        .unwrap();
                        let tampered_first_message_bytes =
                            encode_signal_sender_key_message(&tampered_first).unwrap();
                        let tamper_err = decrypt_signal_sender_key_record_message(
                            &second_decrypted.record,
                            &tampered_first_message_bytes,
                            &XEdDsaNoiseCertificateVerifier,
                        )
                        .unwrap_err()
                        .to_string();
                        assert_eq!(
                            tamper_err, *expected_tamper_error,
                            "{} expected exact skipped sender-key tamper error",
                            vector.name
                        );
                        assert_hex(
                            &mut missing_expected,
                            &format!("{}.tampered_first_ciphertext_hex", vector.name),
                            &tampered_ciphertext,
                            tampered_first_ciphertext_hex,
                        );
                    }
                    (None, None) => {}
                    _ => panic!(
                        "{} sender-key skipped-message tamper fixture fields must be both present or both absent",
                        vector.name
                    ),
                }
                match (
                    vector.invalid_signature_first_message_hex.as_ref(),
                    vector.expected_invalid_signature_error.as_ref(),
                    vector.receiver_record_after_invalid_signature_hex.as_ref(),
                ) {
                    (
                        Some(invalid_signature_first_message_hex),
                        Some(expected_invalid_signature_error),
                        Some(receiver_record_after_invalid_signature_hex),
                    ) => {
                        let invalid_signature =
                            encode_signal_sender_key_message(&SignalSenderKeyMessage {
                                signature: Bytes::from(vec![0u8; 64]),
                                ..first.message.clone()
                            })
                            .unwrap();
                        let invalid_signature_err = decrypt_signal_sender_key_record_message(
                            &second_decrypted.record,
                            &invalid_signature,
                            &XEdDsaNoiseCertificateVerifier,
                        )
                        .unwrap_err()
                        .to_string();
                        assert_eq!(
                            invalid_signature_err, *expected_invalid_signature_error,
                            "{} expected exact skipped sender-key invalid-signature error",
                            vector.name
                        );
                        assert_hex(
                            &mut missing_expected,
                            &format!("{}.invalid_signature_first_message_hex", vector.name),
                            &invalid_signature,
                            invalid_signature_first_message_hex,
                        );
                        assert_hex(
                            &mut missing_expected,
                            &format!(
                                "{}.receiver_record_after_invalid_signature_hex",
                                vector.name
                            ),
                            &second_decrypted.record,
                            receiver_record_after_invalid_signature_hex,
                        );
                    }
                    (None, None, None) => {}
                    _ => panic!(
                        "{} sender-key skipped-message invalid-signature fixture fields must all be present or all be absent",
                        vector.name
                    ),
                }
                let first_decrypted = decrypt_signal_sender_key_record_message(
                    &second_decrypted.record,
                    &first.message_bytes,
                    &XEdDsaNoiseCertificateVerifier,
                )
                .unwrap();
                assert_eq!(
                    first_decrypted.plaintext,
                    bytes_hex(&vector.first_plaintext_hex),
                    "{} first plaintext",
                    vector.name
                );
                let receiver_after_first =
                    decode_signal_sender_key_record(&first_decrypted.record).unwrap();
                assert!(
                    receiver_after_first.states[0].message_keys.is_empty(),
                    "{} skipped key consumed",
                    vector.name
                );
                if let Some(expected_replay_error) = vector.expected_replay_error.as_ref() {
                    let replay_err = decrypt_signal_sender_key_record_message(
                        &first_decrypted.record,
                        &first.message_bytes,
                        &XEdDsaNoiseCertificateVerifier,
                    )
                    .unwrap_err()
                    .to_string();
                    assert_eq!(
                        replay_err, *expected_replay_error,
                        "{} expected exact skipped-key replay rejection",
                        vector.name
                    );
                    assert_eq!(
                        first_decrypted.record,
                        encode_signal_sender_key_record(&receiver_after_first).unwrap(),
                        "{} skipped-key replay must not mutate sender-key record",
                        vector.name
                    );
                }
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.first_ciphertext_hex", vector.name),
                    &first.message.ciphertext,
                    &vector.first_ciphertext_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.second_ciphertext_hex", vector.name),
                    &second.message.ciphertext,
                    &vector.second_ciphertext_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.sender_record_hex", vector.name),
                    &second.record,
                    &vector.sender_record_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_second_hex", vector.name),
                    &second_decrypted.record,
                    &vector.receiver_record_after_second_hex,
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.receiver_record_after_first_hex", vector.name),
                    &first_decrypted.record,
                    &vector.receiver_record_after_first_hex,
                );
            }
            SignalFixture::WhisperMessage(vector) => {
                let message = SignalWhisperMessage {
                    ephemeral_key: bytes_hex(&vector.ephemeral_key_hex),
                    counter: vector.counter,
                    previous_counter: vector.previous_counter,
                    ciphertext: bytes_hex(&vector.ciphertext_hex),
                };
                let encoded = frame_test_whisper(&message);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
                assert_eq!(
                    unframe_test_whisper(&bytes_hex(&vector.encoded_hex)).unwrap(),
                    message,
                    "{}",
                    vector.name
                );
            }
            SignalFixture::WhisperMessageMissingPreviousCounter(vector) => {
                // Build a WhisperMessage protobuf that OMITS previous_counter (field 3);
                // on decode it must default to 0. Frame with 0x33 || protobuf || MAC8.
                let ratchet = bytes_hex(&vector.ephemeral_key_hex);
                let ciphertext = bytes_hex(&vector.ciphertext_hex);
                let mut proto = Vec::new();
                proto.push(0x0a);
                proto.push(ratchet.len() as u8);
                proto.extend_from_slice(&ratchet);
                proto.push(0x10);
                proto.push(vector.counter as u8);
                proto.push(0x22);
                proto.push(ciphertext.len() as u8);
                proto.extend_from_slice(&ciphertext);
                let mut encoded = vec![WHISPER_MESSAGE_VERSION_BYTE];
                encoded.extend_from_slice(&proto);
                let mut mac_input = Vec::new();
                mac_input.extend_from_slice(&whisper_test_sender());
                mac_input.extend_from_slice(&whisper_test_receiver());
                mac_input.extend_from_slice(&encoded);
                let mac = hmac_sha256(&mac_input, &WHISPER_TEST_MAC_KEY).unwrap();
                encoded.extend_from_slice(&mac[..WHISPER_MESSAGE_MAC_LEN]);
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
                let decoded = unframe_test_whisper(&encoded).unwrap_or_else(|err| {
                    panic!(
                        "{} should decode without previous counter: {err}",
                        vector.name
                    )
                });
                assert_eq!(decoded.ephemeral_key, bytes_hex(&vector.ephemeral_key_hex));
                assert_eq!(decoded.counter, vector.counter, "{}", vector.name);
                assert_eq!(decoded.previous_counter, 0, "{}", vector.name);
                assert_eq!(decoded.ciphertext, bytes_hex(&vector.ciphertext_hex));
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.canonical_encoded_hex", vector.name),
                    &frame_test_whisper(&decoded),
                    &vector.canonical_encoded_hex,
                );
            }
            SignalFixture::WhisperMessageUnknownField(vector) => {
                // Build the canonical framed WhisperMessage from the fixture fields, then
                // inject an unknown protobuf field INSIDE the protobuf and re-MAC it.
                let canonical = frame_test_whisper(&SignalWhisperMessage {
                    ephemeral_key: bytes_hex(&vector.ephemeral_key_hex),
                    counter: vector.counter,
                    previous_counter: vector.previous_counter,
                    ciphertext: bytes_hex(&vector.ciphertext_hex),
                });
                let encoded = inner_whisper_with_unknown_field(
                    &canonical,
                    &WHISPER_TEST_MAC_KEY,
                    &whisper_test_sender(),
                    &whisper_test_receiver(),
                );
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.encoded_hex", vector.name),
                    &encoded,
                    &vector.encoded_hex,
                );
                let decoded = unframe_test_whisper(&encoded).unwrap_or_else(|err| {
                    panic!("{} should decode with unknown fields: {err}", vector.name)
                });
                assert_eq!(decoded.ephemeral_key, bytes_hex(&vector.ephemeral_key_hex));
                assert_eq!(decoded.counter, vector.counter, "{}", vector.name);
                assert_eq!(
                    decoded.previous_counter, vector.previous_counter,
                    "{}",
                    vector.name
                );
                assert_eq!(decoded.ciphertext, bytes_hex(&vector.ciphertext_hex));
                assert_hex(
                    &mut missing_expected,
                    &format!("{}.canonical_encoded_hex", vector.name),
                    &frame_test_whisper(&decoded),
                    &vector.canonical_encoded_hex,
                );
            }
            SignalFixture::WhisperInvalidWire(vector) => {
                let encoded = bytes_hex(&vector.encoded_hex);
                let err = unframe_test_whisper(&encoded).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    vector.expected_error,
                    "{} expected exact error",
                    vector.name
                );
            }
        }
    }

    assert!(
        missing_expected.is_empty(),
        "missing Signal fixture expected values:\n{}",
        missing_expected.join("\n")
    );
}

fn workspace_fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures")
        .join(relative)
}

fn bytes_hex(value: &str) -> Bytes {
    decode_fixture_hex(value).unwrap()
}

fn secret_hex(value: &str) -> SecretBytes {
    SecretBytes::from(bytes_hex(value).to_vec())
}

fn fixed_16_hex(value: &str) -> [u8; 16] {
    bytes_hex(value).as_ref().try_into().unwrap()
}

fn fixed_32_hex(value: &str) -> [u8; 32] {
    bytes_hex(value).as_ref().try_into().unwrap()
}

fn key_pair_from_private_hex(value: &str) -> KeyPair {
    let private: [u8; 32] = bytes_hex(value).as_ref().try_into().unwrap();
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    KeyPair {
        public: public.to_bytes(),
        private: SecretBytes::from(private.to_vec()),
    }
}

fn prefixed_public_key(key_pair: &KeyPair) -> Bytes {
    Bytes::copy_from_slice(&prefixed_signal_public_key(&key_pair.public))
}

fn encode_raw_sender_key_record_invalid_signing_key(
    vector: &SignalSenderKeyRecordInvalidSigningKeyFixture,
) -> Bytes {
    encode_raw_sender_key_record(vec![raw_sender_key_state(
        vector.key_id,
        vector.chain_iteration,
        &vector.chain_key_hex,
        &vector.signing_public_key_hex,
        Some(&vector.signing_private_key_hex),
        &[(vector.message_key_iteration, &vector.message_key_seed_hex)],
    )])
}

fn encode_raw_sender_key_record_invalid_state(
    vector: &SignalSenderKeyRecordInvalidStateFixture,
) -> Bytes {
    let mut message_keys = vec![(
        vector.message_key_iteration,
        vector.message_key_seed_hex.as_str(),
    )];
    if let Some(iteration) = vector.second_message_key_iteration {
        message_keys.push((
            iteration,
            vector
                .second_message_key_seed_hex
                .as_deref()
                .expect("second sender-key message seed fixture field"),
        ));
    }
    let mut states = vec![raw_sender_key_state(
        vector.key_id,
        vector.chain_iteration,
        &vector.chain_key_hex,
        &vector.signing_public_key_hex,
        vector.signing_private_key_hex.as_deref(),
        &message_keys,
    )];
    if vector.duplicate_state.unwrap_or(false) {
        states.push(raw_sender_key_state(
            vector.key_id,
            vector.chain_iteration + 1,
            &vector.chain_key_hex,
            &vector.signing_public_key_hex,
            None,
            &[],
        ));
    }
    encode_raw_sender_key_record(states)
}

fn encode_raw_sender_key_record(states: Vec<SenderKeyStateStructure>) -> Bytes {
    SenderKeyRecordStructure {
        sender_key_states: states,
    }
    .encode_to_vec()
    .into()
}

fn raw_sender_key_state(
    key_id: u32,
    chain_iteration: u32,
    chain_key_hex: &str,
    signing_public_key_hex: &str,
    signing_private_key_hex: Option<&str>,
    message_keys: &[(u32, &str)],
) -> SenderKeyStateStructure {
    SenderKeyStateStructure {
        sender_key_id: Some(key_id),
        sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
            iteration: Some(chain_iteration),
            seed: Some(bytes_hex(chain_key_hex)),
        }),
        sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
            public: Some(bytes_hex(signing_public_key_hex)),
            private: signing_private_key_hex.map(bytes_hex),
        }),
        sender_message_keys: message_keys
            .iter()
            .map(
                |(iteration, seed_hex)| sender_key_state_structure::SenderMessageKey {
                    iteration: Some(*iteration),
                    seed: Some(bytes_hex(seed_hex)),
                },
            )
            .collect(),
    }
}

fn invalid_provider_session_message_keys(
    vector: &SignalProviderSessionInvalidRecordFixture,
) -> Vec<SignalProviderStoredMessageKey> {
    let mut message_keys = Vec::new();
    if let Some(counter) = vector.skipped_counter {
        message_keys.push(SignalProviderStoredMessageKey {
            ratchet_key: bytes_hex(
                vector
                    .skipped_ratchet_key_hex
                    .as_deref()
                    .expect("skipped ratchet fixture field"),
            ),
            counter,
            message_keys: SignalMessageKeyMaterial {
                cipher_key: secret_hex(
                    vector
                        .skipped_cipher_key_hex
                        .as_deref()
                        .expect("skipped cipher fixture field"),
                ),
                mac_key: secret_hex(
                    vector
                        .skipped_mac_key_hex
                        .as_deref()
                        .expect("skipped MAC fixture field"),
                ),
                iv: fixed_16_hex(
                    vector
                        .skipped_iv_hex
                        .as_deref()
                        .expect("skipped IV fixture field"),
                ),
            },
        });
    }
    for skipped_key in &vector.extra_skipped_keys {
        message_keys.push(SignalProviderStoredMessageKey {
            ratchet_key: bytes_hex(&skipped_key.ratchet_key_hex),
            counter: skipped_key.counter,
            message_keys: SignalMessageKeyMaterial {
                cipher_key: secret_hex(&skipped_key.cipher_key_hex),
                mac_key: secret_hex(&skipped_key.mac_key_hex),
                iv: fixed_16_hex(&skipped_key.iv_hex),
            },
        });
    }
    message_keys
}

fn encode_raw_provider_session_invalid_skipped_key(
    vector: &SignalProviderSessionInvalidSkippedKeyFixture,
) -> Bytes {
    let local_ratchet = key_pair_from_private_hex(&vector.local_ratchet_private_hex);
    let mut out = BytesMut::with_capacity(180);
    out.put_u8(TEST_PROVIDER_SESSION_VERSION);
    out.put_u8(TEST_PROVIDER_SESSION_RECORD_KIND);
    out.put_u32(vector.remote_registration_id);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.remote_identity_key_hex));
    put_fixture_bytes(&mut out, &bytes_hex(&vector.root_key_hex));
    out.put_u32(vector.sending_counter);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.sending_chain_key_hex));
    put_fixture_bytes(&mut out, &prefixed_signal_public_key(&local_ratchet.public));
    put_fixture_bytes(&mut out, local_ratchet.private.expose());
    out.put_u32(vector.previous_counter);
    out.put_u8(1);
    out.put_u32(vector.receiving_counter);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.receiving_chain_key_hex));
    out.put_u8(1);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.remote_ratchet_key_hex));
    out.put_u32(1);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.remote_ratchet_key_hex));
    out.put_u32(vector.skipped_counter);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.skipped_cipher_key_hex));
    put_fixture_bytes(&mut out, &bytes_hex(&vector.skipped_mac_key_hex));
    put_fixture_bytes(&mut out, &bytes_hex(&vector.skipped_iv_hex));
    out.freeze()
}

fn encode_raw_provider_session_invalid_record(
    vector: &SignalProviderSessionInvalidRecordFixture,
) -> Bytes {
    let local_ratchet = key_pair_from_private_hex(&vector.local_ratchet_private_hex);
    let local_public = vector
        .local_ratchet_public_hex
        .as_deref()
        .map(fixed_32_hex)
        .unwrap_or(local_ratchet.public);
    let mut out = BytesMut::with_capacity(180);
    out.put_u8(TEST_PROVIDER_SESSION_VERSION);
    out.put_u8(TEST_PROVIDER_SESSION_RECORD_KIND);
    out.put_u32(vector.remote_registration_id);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.remote_identity_key_hex));
    put_fixture_bytes(&mut out, &bytes_hex(&vector.root_key_hex));
    out.put_u32(vector.sending_counter);
    put_fixture_bytes(&mut out, &bytes_hex(&vector.sending_chain_key_hex));
    put_fixture_bytes(&mut out, &prefixed_signal_public_key(&local_public));
    put_fixture_bytes(&mut out, local_ratchet.private.expose());
    out.put_u32(vector.previous_counter);
    match (&vector.receiving_chain_key_hex, vector.receiving_counter) {
        (Some(key_hex), Some(counter)) => {
            out.put_u8(1);
            out.put_u32(counter);
            put_fixture_bytes(&mut out, &bytes_hex(key_hex));
        }
        (None, None) => out.put_u8(0),
        _ => panic!(
            "{} receiving-chain fixture fields must be both present or both absent",
            vector.name
        ),
    }
    match &vector.remote_ratchet_key_hex {
        Some(key_hex) => {
            out.put_u8(1);
            put_fixture_bytes(&mut out, &bytes_hex(key_hex));
        }
        None => out.put_u8(0),
    }
    let message_keys = invalid_provider_session_message_keys(vector);
    out.put_u32(u32::try_from(message_keys.len()).expect("fixture skipped-key count fits in u32"));
    for message_key in &message_keys {
        put_fixture_bytes(&mut out, &message_key.ratchet_key);
        out.put_u32(message_key.counter);
        put_fixture_bytes(&mut out, message_key.message_keys.cipher_key.expose());
        put_fixture_bytes(&mut out, message_key.message_keys.mac_key.expose());
        put_fixture_bytes(&mut out, &message_key.message_keys.iv);
    }
    out.freeze()
}

fn put_fixture_bytes(out: &mut BytesMut, value: &[u8]) {
    out.put_u16(u16::try_from(value.len()).expect("fixture field length fits in u16"));
    out.put_slice(value);
}

fn repeated_prefixed_public_key(fill: u8) -> Bytes {
    Bytes::copy_from_slice(&prefixed_signal_public_key(&[fill; 32]))
}

fn uninitialized_message_chain() -> SignalMessageChainKey {
    SignalMessageChainKey {
        key: SecretBytes::from(vec![0u8; 32]),
        counter: 0,
    }
}

struct PreKeyFixtureKeyParams<'a> {
    alice_registration_id: u32,
    bob_registration_id: u32,
    bob_signed_pre_key_id: u32,
    bob_one_time_pre_key_id: u32,
    alice_identity_private_hex: &'a str,
    alice_base_private_hex: &'a str,
    bob_identity_private_hex: &'a str,
    bob_signed_pre_key_private_hex: &'a str,
    bob_one_time_pre_key_private_hex: &'a str,
}

struct PreKeyFixtureKeys {
    alice_material: SignalLocalKeyMaterial,
    alice_base: KeyPair,
    bob_material: SignalLocalKeyMaterial,
    bob_one_time: SignalLocalPreKey,
    bob_session: SignalSession,
}

struct PreKeyNoOneTimeFixtureKeyParams<'a> {
    alice_registration_id: u32,
    bob_registration_id: u32,
    bob_signed_pre_key_id: u32,
    alice_identity_private_hex: &'a str,
    alice_base_private_hex: &'a str,
    bob_identity_private_hex: &'a str,
    bob_signed_pre_key_private_hex: &'a str,
}

struct PreKeyNoOneTimeFixtureKeys {
    alice_material: SignalLocalKeyMaterial,
    alice_base: KeyPair,
    bob_material: SignalLocalKeyMaterial,
    bob_session: SignalSession,
}

fn pre_key_fixture_keys(params: PreKeyFixtureKeyParams<'_>) -> PreKeyFixtureKeys {
    let alice_identity = key_pair_from_private_hex(params.alice_identity_private_hex);
    let alice_base = key_pair_from_private_hex(params.alice_base_private_hex);
    let bob_identity = key_pair_from_private_hex(params.bob_identity_private_hex);
    let bob_signed_pre_key = key_pair_from_private_hex(params.bob_signed_pre_key_private_hex);
    let bob_one_time_pre_key = key_pair_from_private_hex(params.bob_one_time_pre_key_private_hex);

    let alice_material = SignalLocalKeyMaterial {
        registration_id: params.alice_registration_id,
        identity: SignalLocalIdentity {
            public_key: prefixed_public_key(&alice_identity),
            key_pair: alice_identity.clone(),
        },
        signed_pre_key: SignalLocalSignedPreKey {
            key_id: 101,
            public_key: prefixed_public_key(&alice_identity),
            key_pair: alice_identity.clone(),
            signature: Bytes::from(vec![0x11; 64]),
        },
    };
    let bob_material = SignalLocalKeyMaterial {
        registration_id: params.bob_registration_id,
        identity: SignalLocalIdentity {
            public_key: prefixed_public_key(&bob_identity),
            key_pair: bob_identity.clone(),
        },
        signed_pre_key: SignalLocalSignedPreKey {
            key_id: params.bob_signed_pre_key_id,
            public_key: prefixed_public_key(&bob_signed_pre_key),
            key_pair: bob_signed_pre_key.clone(),
            signature: Bytes::from(vec![0x22; 64]),
        },
    };
    let bob_one_time = SignalLocalPreKey {
        key_id: params.bob_one_time_pre_key_id,
        public_key: prefixed_public_key(&bob_one_time_pre_key),
        key_pair: bob_one_time_pre_key,
    };
    let bob_session = SignalSession {
        registration_id: bob_material.registration_id,
        identity_key: prefixed_public_key(&bob_identity),
        signed_pre_key: SignalSignedPreKey {
            key_id: bob_material.signed_pre_key.key_id,
            public_key: bob_material.signed_pre_key.public_key.clone(),
            signature: bob_material.signed_pre_key.signature.clone(),
        },
        pre_key: Some(SignalPreKey {
            key_id: bob_one_time.key_id,
            public_key: bob_one_time.public_key.clone(),
        }),
    };

    PreKeyFixtureKeys {
        alice_material,
        alice_base,
        bob_material,
        bob_one_time,
        bob_session,
    }
}

fn pre_key_fixture_keys_no_one_time(
    params: PreKeyNoOneTimeFixtureKeyParams<'_>,
) -> PreKeyNoOneTimeFixtureKeys {
    let alice_identity = key_pair_from_private_hex(params.alice_identity_private_hex);
    let alice_base = key_pair_from_private_hex(params.alice_base_private_hex);
    let bob_identity = key_pair_from_private_hex(params.bob_identity_private_hex);
    let bob_signed_pre_key = key_pair_from_private_hex(params.bob_signed_pre_key_private_hex);

    let alice_material = SignalLocalKeyMaterial {
        registration_id: params.alice_registration_id,
        identity: SignalLocalIdentity {
            public_key: prefixed_public_key(&alice_identity),
            key_pair: alice_identity.clone(),
        },
        signed_pre_key: SignalLocalSignedPreKey {
            key_id: 101,
            public_key: prefixed_public_key(&alice_identity),
            key_pair: alice_identity,
            signature: Bytes::from(vec![0x11; 64]),
        },
    };
    let bob_material = SignalLocalKeyMaterial {
        registration_id: params.bob_registration_id,
        identity: SignalLocalIdentity {
            public_key: prefixed_public_key(&bob_identity),
            key_pair: bob_identity.clone(),
        },
        signed_pre_key: SignalLocalSignedPreKey {
            key_id: params.bob_signed_pre_key_id,
            public_key: prefixed_public_key(&bob_signed_pre_key),
            key_pair: bob_signed_pre_key,
            signature: Bytes::from(vec![0x22; 64]),
        },
    };
    let bob_session = SignalSession {
        registration_id: bob_material.registration_id,
        identity_key: prefixed_public_key(&bob_identity),
        signed_pre_key: SignalSignedPreKey {
            key_id: bob_material.signed_pre_key.key_id,
            public_key: bob_material.signed_pre_key.public_key.clone(),
            signature: bob_material.signed_pre_key.signature.clone(),
        },
        pre_key: None,
    };

    PreKeyNoOneTimeFixtureKeys {
        alice_material,
        alice_base,
        bob_material,
        bob_session,
    }
}

fn assert_hex(missing: &mut Vec<String>, label: &str, actual: &[u8], expected: &str) {
    let actual = encode_hex(actual);
    if expected.is_empty() {
        missing.push(format!("{label} = {actual}"));
    } else {
        assert_eq!(actual, expected, "{label}");
    }
}

fn encode_hex(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}
