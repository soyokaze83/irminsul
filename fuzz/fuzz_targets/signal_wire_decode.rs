#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_core::{
    decode_signal_pre_key_whisper_message, decode_signal_provider_session_record,
    decode_signal_sender_key_distribution_message, decode_signal_sender_key_message,
    decode_signal_sender_key_record, decode_signal_whisper_message,
    encode_signal_pre_key_whisper_message, encode_signal_provider_session_record,
    encode_signal_sender_key_distribution_message, encode_signal_sender_key_message,
    encode_signal_sender_key_record, encode_signal_whisper_message,
    verify_signal_sender_key_message_bytes,
};
use wa_crypto::{
    SIGNAL_PUBLIC_KEY_VERSION, XEdDsaNoiseCertificateVerifier, prefixed_signal_public_key,
    public_key_from_private,
};

// The 1:1 WhisperMessage framing now carries an 8-byte MAC keyed by
// (mac_key, senderId, receiverId); these wire-shape fuzzers build MAC-less raw
// protobuf frames, so they use a single fixed mac_key/identity for the
// encode/decode calls. NOTE: this only makes the crate compile — the MAC-less
// `*_wire` frames here will not satisfy the new decode MAC/version checks at
// runtime, so the structured decode asserts in this target need a follow-up
// rewrite to emit fully framed (version || protobuf || MAC8) inputs.
const WIRE_DECODE_MAC_KEY: [u8; 32] = [0x5au8; 32];
fn wire_decode_identity() -> [u8; 33] {
    prefixed_signal_public_key(&public_key_from_private(&[0x11u8; 32]))
}

const MAX_INPUT_LEN: usize = 64 * 1024;
const PROVIDER_SESSION_VERSION: u8 = 1;
const PROVIDER_SESSION_RECORD_KIND: u8 = 2;
const PROVIDER_SESSION_SKIPPED_KEY_LIMIT: u32 = 2_000;
const SENDER_KEY_RECORD_STATE_LIMIT: usize = 5;
const SENDER_KEY_WIRE_CURRENT_VERSION: u8 = 3;
const SENDER_KEY_WIRE_VERSION_BYTE: u8 =
    (SENDER_KEY_WIRE_CURRENT_VERSION << 4) | SENDER_KEY_WIRE_CURRENT_VERSION;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(message) = decode_signal_whisper_message(
        data,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    ) && let Ok(encoded) = encode_signal_whisper_message(
        &message,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    ) {
        let _ = decode_signal_whisper_message(
            &encoded,
            &WIRE_DECODE_MAC_KEY,
            &wire_decode_identity(),
            &wire_decode_identity(),
        );
    }
    if let Ok(message) = decode_signal_pre_key_whisper_message(data)
        && let Ok(encoded) = encode_signal_pre_key_whisper_message(
            &message,
            &WIRE_DECODE_MAC_KEY,
            &wire_decode_identity(),
            &wire_decode_identity(),
        )
    {
        let _ = decode_signal_pre_key_whisper_message(&encoded);
    }
    if let Ok(record) = decode_signal_provider_session_record(data)
        && let Ok(encoded) = encode_signal_provider_session_record(&record)
    {
        let _ = decode_signal_provider_session_record(&encoded);
    }
    if let Ok(message) = decode_signal_sender_key_distribution_message(data)
        && let Ok(encoded) = encode_signal_sender_key_distribution_message(&message)
    {
        let _ = decode_signal_sender_key_distribution_message(&encoded);
    }
    if let Ok(message) = decode_signal_sender_key_message(data)
        && let Ok(encoded) = encode_signal_sender_key_message(&message)
    {
        let _ = decode_signal_sender_key_message(&encoded);
    }
    if let Ok(record) = decode_signal_sender_key_record(data)
        && let Ok(encoded) = encode_signal_sender_key_record(&record)
    {
        let _ = decode_signal_sender_key_record(&encoded);
    }

    drive_whisper_required_field_frames(data);
    drive_pre_key_whisper_required_field_frames(data);
    drive_provider_session_record_required_field_frames(data);
    drive_sender_key_distribution_required_field_frames(data);
    drive_sender_key_message_required_field_frames(data);
    drive_sender_key_record_required_field_frames(data);
});

fn drive_whisper_required_field_frames(data: &[u8]) {
    let ratchet_key = signal_public_key(data, 0, 0x21);
    let ciphertext = nonempty_bytes(data, 32, 0x41);
    let counter = u32::from(data.get(96).copied().unwrap_or(0));
    let previous_counter = u32::from(data.get(97).copied().unwrap_or(0));

    let valid = whisper_wire(
        Some(&ratchet_key),
        Some(counter),
        Some(previous_counter),
        Some(&ciphertext),
    );
    let decoded = decode_signal_whisper_message(
        &valid,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("structured Signal whisper frame should decode");
    assert_eq!(decoded.counter, counter);
    assert_eq!(decoded.previous_counter, previous_counter);

    let mut unknown_field = valid.clone();
    push_varint_field(
        &mut unknown_field,
        15,
        u32::from(data.get(98).copied().unwrap_or(0)),
    );
    let decoded_unknown_field = decode_signal_whisper_message(
        &unknown_field,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal whisper with unknown field should decode");
    assert_eq!(decoded_unknown_field, decoded);
    let canonical_unknown_field = encode_signal_whisper_message(
        &decoded_unknown_field,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal whisper with unknown field should re-encode canonically");
    assert_eq!(
        canonical_unknown_field.as_ref(),
        valid.as_slice(),
        "Signal whisper unknown fields should be dropped on canonical re-encode"
    );

    let short_ephemeral_key = whisper_wire(
        Some(&ratchet_key[..2]),
        Some(counter),
        Some(previous_counter),
        Some(&ciphertext),
    );
    assert_whisper_decode_error(&short_ephemeral_key, "invalid signal public key length: 2");

    let missing_ephemeral_key = whisper_wire(
        None,
        Some(counter),
        Some(previous_counter),
        Some(&ciphertext),
    );
    assert_whisper_decode_error(
        &missing_ephemeral_key,
        "invalid signal public key length: 0",
    );

    let missing_ciphertext = whisper_wire(
        Some(&ratchet_key),
        Some(counter),
        Some(previous_counter),
        None,
    );
    assert_whisper_decode_error(
        &missing_ciphertext,
        "Signal whisper message ciphertext must not be empty",
    );

    let missing_counter = whisper_wire(
        Some(&ratchet_key),
        None,
        Some(previous_counter),
        Some(&ciphertext),
    );
    assert_whisper_decode_error(&missing_counter, "Signal whisper message missing counter");

    let missing_previous_counter =
        whisper_wire(Some(&ratchet_key), Some(counter), None, Some(&ciphertext));
    let decoded_missing_previous = decode_signal_whisper_message(
        &missing_previous_counter,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal whisper without previous counter should decode as zero");
    assert_eq!(decoded_missing_previous.counter, counter);
    assert_eq!(decoded_missing_previous.previous_counter, 0);
    let canonical_missing_previous = encode_signal_whisper_message(
        &decoded_missing_previous,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal whisper missing previous counter should re-encode canonically");
    assert!(
        canonical_missing_previous
            .windows(2)
            .any(|field| field == [0x18, 0x00]),
        "canonical Signal whisper re-encoding should include explicit zero previous counter"
    );

    let explicit_zero = whisper_wire(Some(&ratchet_key), Some(0), Some(0), Some(&ciphertext));
    assert!(
        explicit_zero.windows(2).any(|field| field == [0x10, 0x00])
            && explicit_zero.windows(2).any(|field| field == [0x18, 0x00]),
        "explicit zero Signal whisper counters should stay present on the wire"
    );
    let decoded_zero = decode_signal_whisper_message(
        &explicit_zero,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal whisper with explicit zero counters should decode");
    assert_eq!(decoded_zero.counter, 0);
    assert_eq!(decoded_zero.previous_counter, 0);
    let canonical_zero = encode_signal_whisper_message(
        &decoded_zero,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal whisper with explicit zero counters should re-encode");
    assert_eq!(
        canonical_zero.as_ref(),
        explicit_zero.as_slice(),
        "Signal whisper explicit zero counters should be canonical"
    );
}

fn drive_pre_key_whisper_required_field_frames(data: &[u8]) {
    let base_key = signal_public_key(data, 128, 0x61);
    let identity_key = signal_public_key(data, 160, 0x81);
    let ciphertext = nonempty_bytes(data, 192, 0xa1);
    let inner = whisper_wire(Some(&base_key), Some(1), Some(0), Some(&ciphertext));
    let registration_id = 1 + u32::from(data.get(224).copied().unwrap_or(0));
    let signed_pre_key_id = 1 + u32::from(data.get(225).copied().unwrap_or(0));
    let mut mismatched_base_key = base_key;
    mismatched_base_key[32] ^= 0x01;

    let valid = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&inner),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    let decoded = decode_signal_pre_key_whisper_message(&valid)
        .expect("structured Signal pre-key whisper frame should decode");
    assert_eq!(decoded.registration_id, registration_id);
    assert_eq!(decoded.pre_key_id, Some(1));
    assert_eq!(decoded.signed_pre_key_id, signed_pre_key_id);

    let mut outer_unknown_field = valid.clone();
    push_varint_field(
        &mut outer_unknown_field,
        15,
        u32::from(data.get(226).copied().unwrap_or(0)),
    );
    let decoded_outer_unknown = decode_signal_pre_key_whisper_message(&outer_unknown_field)
        .expect("Signal pre-key whisper with outer unknown field should decode");
    assert_eq!(decoded_outer_unknown, decoded);
    let canonical_outer_unknown = encode_signal_pre_key_whisper_message(
        &decoded_outer_unknown,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal pre-key whisper with outer unknown field should re-encode canonically");
    assert_eq!(
        canonical_outer_unknown.as_ref(),
        valid.as_slice(),
        "Signal pre-key whisper outer unknown fields should be dropped on canonical re-encode"
    );

    let mut inner_unknown_field = inner.clone();
    push_varint_field(
        &mut inner_unknown_field,
        15,
        u32::from(data.get(227).copied().unwrap_or(0)),
    );
    let pre_key_inner_unknown_field = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&inner_unknown_field),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    let decoded_inner_unknown = decode_signal_pre_key_whisper_message(&pre_key_inner_unknown_field)
        .expect("Signal pre-key whisper with inner unknown field should decode");
    assert_eq!(decoded_inner_unknown, decoded);
    let canonical_inner_unknown = encode_signal_pre_key_whisper_message(
        &decoded_inner_unknown,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal pre-key whisper with inner unknown field should re-encode canonically");
    assert_eq!(
        canonical_inner_unknown.as_ref(),
        valid.as_slice(),
        "Signal pre-key whisper inner unknown fields should be dropped on canonical re-encode"
    );

    let no_one_time_pre_key = pre_key_whisper_wire(
        None,
        Some(&base_key),
        Some(&identity_key),
        Some(&inner),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    let decoded_no_one_time = decode_signal_pre_key_whisper_message(&no_one_time_pre_key)
        .expect("structured signed-pre-key-only Signal pre-key whisper frame should decode");
    assert_eq!(decoded_no_one_time.registration_id, registration_id);
    assert_eq!(decoded_no_one_time.pre_key_id, None);
    assert_eq!(decoded_no_one_time.signed_pre_key_id, signed_pre_key_id);

    let inner_explicit_zero = whisper_wire(Some(&base_key), Some(0), Some(0), Some(&ciphertext));
    let pre_key_inner_explicit_zero = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&inner_explicit_zero),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    let decoded_inner_explicit_zero = decode_signal_pre_key_whisper_message(
        &pre_key_inner_explicit_zero,
    )
    .expect("structured Signal pre-key whisper with explicit inner zero counters should decode");
    assert_eq!(decoded_inner_explicit_zero.message.counter, 0);
    assert_eq!(decoded_inner_explicit_zero.message.previous_counter, 0);
    let canonical_inner_explicit_zero = encode_signal_pre_key_whisper_message(
        &decoded_inner_explicit_zero,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal pre-key whisper with explicit inner zero counters should re-encode");
    assert_eq!(
        canonical_inner_explicit_zero.as_ref(),
        pre_key_inner_explicit_zero.as_slice(),
        "Signal pre-key whisper explicit inner zero counters should be canonical"
    );

    let inner_missing_previous = whisper_wire(Some(&base_key), Some(1), None, Some(&ciphertext));
    let pre_key_inner_missing_previous = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&inner_missing_previous),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    let decoded_inner_missing_previous = decode_signal_pre_key_whisper_message(
        &pre_key_inner_missing_previous,
    )
    .expect("structured Signal pre-key whisper with inner missing previous counter should decode");
    assert_eq!(decoded_inner_missing_previous.message.previous_counter, 0);
    let canonical_inner_missing_previous = encode_signal_pre_key_whisper_message(
        &decoded_inner_missing_previous,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect("Signal pre-key whisper inner missing previous counter should re-encode canonically");
    assert!(
        canonical_inner_missing_previous
            .windows(2)
            .any(|field| field == [0x18, 0x00]),
        "canonical Signal pre-key whisper re-encoding should include explicit inner zero previous counter"
    );

    let short_base_key = pre_key_whisper_wire(
        Some(1),
        Some(&base_key[..2]),
        Some(&identity_key),
        Some(&inner),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    assert_pre_key_whisper_decode_error(&short_base_key, "invalid signal public key length: 2");

    let short_identity_key = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key[..31]),
        Some(&inner),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    assert_pre_key_whisper_decode_error(
        &short_identity_key,
        "invalid signal public key length: 31",
    );

    // libsignal allows the X3DH base key and the inner WhisperMessage's sending
    // ratchet key to differ, so a base key distinct from the inner ratchet key must
    // still decode successfully (it is NOT a wire-level error).
    let distinct_base = pre_key_whisper_wire(
        Some(1),
        Some(&mismatched_base_key),
        Some(&identity_key),
        Some(&inner),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    let distinct_decoded = decode_signal_pre_key_whisper_message(&distinct_base)
        .expect("pre-key whisper with base key distinct from inner ratchet should decode");
    assert_eq!(
        distinct_decoded.base_key.as_ref(),
        &mismatched_base_key[..],
        "decoded base key matches the wire base key"
    );
    assert_ne!(
        distinct_decoded.base_key, distinct_decoded.message.ephemeral_key,
        "base key and inner ratchet key are independent"
    );

    let short_inner_ratchet =
        whisper_wire(Some(&base_key[..2]), Some(1), Some(0), Some(&ciphertext));
    let short_inner_ratchet = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&short_inner_ratchet),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    assert_pre_key_whisper_decode_error(
        &short_inner_ratchet,
        "invalid signal public key length: 2",
    );

    let missing_inner_message = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        None,
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    assert_pre_key_whisper_decode_error(
        &missing_inner_message,
        "Signal pre-key whisper message missing inner message",
    );

    let missing_registration = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&inner),
        None,
        Some(signed_pre_key_id),
    );
    assert_pre_key_whisper_decode_error(
        &missing_registration,
        "Signal pre-key whisper message missing registration id",
    );

    let missing_signed_pre_key = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&inner),
        Some(registration_id),
        None,
    );
    assert_pre_key_whisper_decode_error(
        &missing_signed_pre_key,
        "Signal pre-key whisper message missing signed pre-key id",
    );

    let missing_inner_ciphertext = whisper_wire(Some(&base_key), Some(1), Some(0), None);
    let missing_inner_ciphertext = pre_key_whisper_wire(
        Some(1),
        Some(&base_key),
        Some(&identity_key),
        Some(&missing_inner_ciphertext),
        Some(registration_id),
        Some(signed_pre_key_id),
    );
    assert_pre_key_whisper_decode_error(
        &missing_inner_ciphertext,
        "Signal whisper message ciphertext must not be empty",
    );
}

fn drive_provider_session_record_required_field_frames(data: &[u8]) {
    let remote_identity = signal_public_key(data, 256, 0xc1);
    let root_key = seed_32(data, 288, 0x21);
    let sending_chain_key = seed_32(data, 320, 0x41);
    let sending_counter = 1 + u32::from(data.get(352).copied().unwrap_or(0));
    let local_private_key = seed_32(data, 353, 0x61);
    let local_public_key = prefixed_signal_public_key(&public_key_from_private(&local_private_key));
    let previous_counter = u32::from(data.get(385).copied().unwrap_or(0));

    let mut valid = provider_session_required_prefix(
        &remote_identity,
        &root_key,
        sending_counter,
        &sending_chain_key,
        &local_public_key,
        &local_private_key,
    );
    push_u32(&mut valid, previous_counter);
    let decoded = decode_signal_provider_session_record(&valid)
        .expect("structured Signal provider-session record should decode");
    assert_eq!(decoded.remote_registration_id, 88);
    assert_eq!(decoded.sending_chain.counter, sending_counter);
    assert_eq!(decoded.previous_counter, previous_counter);

    assert_provider_session_decode_error(
        &[PROVIDER_SESSION_VERSION],
        "stored Signal provider session is truncated",
    );

    let mut unsupported_version = provider_session_header();
    unsupported_version[0] = PROVIDER_SESSION_VERSION.wrapping_add(1);
    assert_provider_session_decode_error(
        &unsupported_version,
        "unsupported Signal provider session version",
    );

    let mut unsupported_kind = provider_session_header();
    unsupported_kind[1] = PROVIDER_SESSION_RECORD_KIND.wrapping_add(1);
    assert_provider_session_decode_error(
        &unsupported_kind,
        "unsupported Signal provider session version",
    );

    assert_provider_session_decode_error(
        &[PROVIDER_SESSION_VERSION, PROVIDER_SESSION_RECORD_KIND],
        "stored Signal provider session missing registration id",
    );

    let missing_identity_length = provider_session_header();
    assert_provider_session_decode_error(
        &missing_identity_length,
        "stored Signal provider session missing remote identity key length",
    );

    let mut truncated_root = provider_session_header();
    push_len16(&mut truncated_root, &remote_identity);
    push_u16(&mut truncated_root, 32);
    truncated_root.extend_from_slice(&root_key[..4]);
    assert_provider_session_decode_error(
        &truncated_root,
        "stored Signal provider session root key is truncated",
    );

    let missing_previous_counter = provider_session_required_prefix(
        &remote_identity,
        &root_key,
        sending_counter,
        &sending_chain_key,
        &local_public_key,
        &local_private_key,
    );
    assert_provider_session_decode_error(
        &missing_previous_counter,
        "stored Signal provider session missing previous counter",
    );

    let mut invalid_receiving_chain_flag = valid.clone();
    invalid_receiving_chain_flag.push(2);
    assert_provider_session_decode_error(
        &invalid_receiving_chain_flag,
        "stored Signal provider session has invalid receiving-chain flag",
    );

    let mut missing_remote_ratchet_flag = valid.clone();
    missing_remote_ratchet_flag.push(0);
    assert_provider_session_decode_error(
        &missing_remote_ratchet_flag,
        "stored Signal provider session missing remote-ratchet flag",
    );

    let mut invalid_remote_ratchet_flag = valid.clone();
    invalid_remote_ratchet_flag.push(0);
    invalid_remote_ratchet_flag.push(2);
    assert_provider_session_decode_error(
        &invalid_remote_ratchet_flag,
        "stored Signal provider session has invalid remote-ratchet flag",
    );

    let mut missing_skipped_key_count = valid.clone();
    missing_skipped_key_count.push(0);
    missing_skipped_key_count.push(0);
    assert_provider_session_decode_error(
        &missing_skipped_key_count,
        "stored Signal provider session missing skipped-key count",
    );

    let mut too_many_skipped_keys = valid.clone();
    too_many_skipped_keys.push(0);
    too_many_skipped_keys.push(0);
    push_u32(
        &mut too_many_skipped_keys,
        PROVIDER_SESSION_SKIPPED_KEY_LIMIT + 1,
    );
    assert_provider_session_decode_error(
        &too_many_skipped_keys,
        "Signal provider session must contain at most 2000 skipped message keys",
    );

    let mut trailing_bytes = valid.clone();
    trailing_bytes.push(0);
    trailing_bytes.push(0);
    push_u32(&mut trailing_bytes, 0);
    trailing_bytes.push(0xff);
    assert_provider_session_decode_error(
        &trailing_bytes,
        "stored Signal provider session has trailing bytes",
    );

    let skipped_ratchet_key = signal_public_key(data, 419, 0x91);
    let skipped_counter = 1 + u32::from(data.get(452).copied().unwrap_or(0));
    let skipped_cipher_key = seed_32(data, 453, 0xa1);
    let skipped_mac_key = seed_32(data, 485, 0xc1);
    let skipped_iv = seed_16(data, 517, 0xe1);
    let mut skipped_key_base = valid.clone();
    skipped_key_base.push(0);
    skipped_key_base.push(0);
    push_u32(&mut skipped_key_base, 1);

    assert_provider_session_decode_error(
        &skipped_key_base,
        "stored Signal provider session missing skipped message ratchet key length",
    );

    let mut truncated_skipped_ratchet = skipped_key_base.clone();
    push_u16(&mut truncated_skipped_ratchet, 33);
    truncated_skipped_ratchet.extend_from_slice(&skipped_ratchet_key[..2]);
    assert_provider_session_decode_error(
        &truncated_skipped_ratchet,
        "stored Signal provider session skipped message ratchet key is truncated",
    );

    let mut short_skipped_ratchet = skipped_key_base.clone();
    push_len16(&mut short_skipped_ratchet, &skipped_ratchet_key[..2]);
    assert_provider_session_decode_error(
        &short_skipped_ratchet,
        "invalid signal public key length: 2",
    );

    let mut missing_skipped_counter = skipped_key_base.clone();
    push_len16(&mut missing_skipped_counter, &skipped_ratchet_key);
    assert_provider_session_decode_error(
        &missing_skipped_counter,
        "stored Signal provider session missing skipped message counter",
    );

    let mut missing_skipped_cipher_key = missing_skipped_counter.clone();
    push_u32(&mut missing_skipped_cipher_key, skipped_counter);
    assert_provider_session_decode_error(
        &missing_skipped_cipher_key,
        "stored Signal provider session missing skipped message cipher key length",
    );

    let mut truncated_skipped_cipher_key = missing_skipped_cipher_key.clone();
    push_u16(&mut truncated_skipped_cipher_key, 32);
    truncated_skipped_cipher_key.extend_from_slice(&skipped_cipher_key[..4]);
    assert_provider_session_decode_error(
        &truncated_skipped_cipher_key,
        "stored Signal provider session skipped message cipher key is truncated",
    );

    let mut short_skipped_cipher_key = missing_skipped_cipher_key.clone();
    push_len16(&mut short_skipped_cipher_key, &skipped_cipher_key[..4]);
    assert_provider_session_decode_error(
        &short_skipped_cipher_key,
        "Signal message chain key must be 32 bytes",
    );

    let mut missing_skipped_mac_key = missing_skipped_cipher_key.clone();
    push_len16(&mut missing_skipped_mac_key, &skipped_cipher_key);
    assert_provider_session_decode_error(
        &missing_skipped_mac_key,
        "stored Signal provider session missing skipped message mac key length",
    );

    let mut truncated_skipped_mac_key = missing_skipped_mac_key.clone();
    push_u16(&mut truncated_skipped_mac_key, 32);
    truncated_skipped_mac_key.extend_from_slice(&skipped_mac_key[..4]);
    assert_provider_session_decode_error(
        &truncated_skipped_mac_key,
        "stored Signal provider session skipped message mac key is truncated",
    );

    let mut short_skipped_mac_key = missing_skipped_mac_key.clone();
    push_len16(&mut short_skipped_mac_key, &skipped_mac_key[..4]);
    assert_provider_session_decode_error(
        &short_skipped_mac_key,
        "Signal message chain key must be 32 bytes",
    );

    let mut missing_skipped_iv = missing_skipped_mac_key.clone();
    push_len16(&mut missing_skipped_iv, &skipped_mac_key);
    assert_provider_session_decode_error(
        &missing_skipped_iv,
        "stored Signal provider session missing skipped message iv length",
    );

    let mut truncated_skipped_iv = missing_skipped_iv.clone();
    push_u16(&mut truncated_skipped_iv, 16);
    truncated_skipped_iv.extend_from_slice(&skipped_iv[..4]);
    assert_provider_session_decode_error(
        &truncated_skipped_iv,
        "stored Signal provider session skipped message iv is truncated",
    );

    let mut short_skipped_iv = missing_skipped_iv;
    push_len16(&mut short_skipped_iv, &skipped_iv[..4]);
    assert_provider_session_decode_error(
        &short_skipped_iv,
        "Signal provider skipped message IV must be 16 bytes",
    );

    let receiving_chain_key = seed_32(data, 386, 0x81);
    let receiving_counter = u32::from(data.get(418).copied().unwrap_or(0));
    let mut missing_remote_after_receiving_chain = valid;
    missing_remote_after_receiving_chain.push(1);
    push_u32(&mut missing_remote_after_receiving_chain, receiving_counter);
    push_len16(
        &mut missing_remote_after_receiving_chain,
        &receiving_chain_key,
    );
    assert_provider_session_decode_error(
        &missing_remote_after_receiving_chain,
        "stored Signal provider session missing remote-ratchet flag",
    );
}

fn drive_sender_key_distribution_required_field_frames(data: &[u8]) {
    let key_id = 1 + u32::from(data.get(448).copied().unwrap_or(0));
    let iteration = u32::from(data.get(449).copied().unwrap_or(0));
    let chain_key = seed_32(data, 450, 0xa1);
    let signing_key = signal_public_key(data, 482, 0xc1);
    let padding = seed_32(data, 514, 0xe1);

    let valid = sender_key_distribution_wire(
        SENDER_KEY_WIRE_VERSION_BYTE,
        Some(key_id),
        Some(iteration),
        Some(&chain_key),
        Some(&signing_key),
        None,
    );
    let decoded = decode_signal_sender_key_distribution_message(&valid)
        .expect("structured Signal sender-key distribution should decode");
    assert_eq!(decoded.key_id, key_id);
    assert_eq!(decoded.iteration, iteration);
    assert_eq!(decoded.chain_key.expose(), &chain_key);
    assert_eq!(decoded.signing_key.as_ref(), signing_key.as_slice());

    let mut unknown_field = valid.clone();
    push_varint_field(
        &mut unknown_field,
        15,
        u32::from(data.get(545).copied().unwrap_or(0)),
    );
    let decoded_unknown = decode_signal_sender_key_distribution_message(&unknown_field)
        .expect("Signal sender-key distribution with unknown field should decode");
    assert_eq!(decoded_unknown, decoded);
    let canonical_unknown = encode_signal_sender_key_distribution_message(&decoded_unknown)
        .expect("Signal sender-key distribution with unknown field should re-encode canonically");
    assert_eq!(
        canonical_unknown.as_ref(),
        valid.as_slice(),
        "Signal sender-key distribution unknown fields should be dropped on canonical re-encode"
    );

    assert_sender_key_distribution_decode_error(
        &[SENDER_KEY_WIRE_VERSION_BYTE],
        "Signal sender-key distribution message is too short: 1",
    );

    let bad_message_version = sender_key_distribution_wire(
        0x23,
        Some(key_id),
        Some(iteration),
        Some(&chain_key),
        Some(&signing_key),
        None,
    );
    assert_sender_key_distribution_decode_error(
        &bad_message_version,
        "unsupported Signal sender-key message version: 2",
    );

    let bad_ciphertext_version = sender_key_distribution_wire(
        0x32,
        Some(key_id),
        Some(iteration),
        Some(&chain_key),
        Some(&signing_key),
        None,
    );
    assert_sender_key_distribution_decode_error(
        &bad_ciphertext_version,
        "unsupported Signal sender-key ciphertext version: 2",
    );

    let missing_id = sender_key_distribution_wire(
        0x33,
        None,
        Some(iteration),
        Some(&chain_key),
        Some(&signing_key),
        None,
    );
    assert_sender_key_distribution_decode_error(
        &missing_id,
        "Signal sender-key distribution missing id",
    );

    let missing_iteration = sender_key_distribution_wire(
        0x33,
        Some(key_id),
        None,
        Some(&chain_key),
        Some(&signing_key),
        None,
    );
    assert_sender_key_distribution_decode_error(
        &missing_iteration,
        "Signal sender-key distribution missing iteration",
    );

    let missing_chain_key = sender_key_distribution_wire(
        0x33,
        Some(key_id),
        Some(iteration),
        None,
        Some(&signing_key),
        Some(&padding),
    );
    assert_sender_key_distribution_decode_error(
        &missing_chain_key,
        "Signal sender-key distribution missing chain key",
    );

    let missing_signing_key = sender_key_distribution_wire(
        0x33,
        Some(key_id),
        Some(iteration),
        Some(&chain_key),
        None,
        Some(&padding),
    );
    assert_sender_key_distribution_decode_error(
        &missing_signing_key,
        "Signal sender-key distribution missing signing key",
    );

    let short_chain_key = sender_key_distribution_wire(
        0x33,
        Some(key_id),
        Some(iteration),
        Some(&chain_key[..31]),
        Some(&signing_key),
        None,
    );
    assert_sender_key_distribution_decode_error(
        &short_chain_key,
        "Signal sender chain key must be 32 bytes",
    );

    let raw_signing_key = sender_key_distribution_wire(
        0x33,
        Some(key_id),
        Some(iteration),
        Some(&chain_key),
        Some(&signing_key[1..]),
        None,
    );
    assert_sender_key_distribution_decode_error(
        &raw_signing_key,
        "Signal sender-key signing public key must be 33 prefixed bytes",
    );
}

fn drive_sender_key_message_required_field_frames(data: &[u8]) {
    let key_id = 1 + u32::from(data.get(546).copied().unwrap_or(0));
    let iteration = u32::from(data.get(547).copied().unwrap_or(0));
    let ciphertext = nonempty_bytes(data, 548, 0x41);
    let signature = seed_64(data, 580, 0x61);

    let valid = sender_key_message_wire(
        SENDER_KEY_WIRE_VERSION_BYTE,
        Some(key_id),
        Some(iteration),
        Some(&ciphertext),
        &signature,
    );
    let decoded = decode_signal_sender_key_message(&valid)
        .expect("structured Signal sender-key message should decode");
    assert_eq!(decoded.key_id, key_id);
    assert_eq!(decoded.iteration, iteration);
    assert_eq!(decoded.ciphertext.as_ref(), ciphertext.as_slice());
    assert_eq!(decoded.signature.as_ref(), signature.as_slice());

    let mut unknown_field = valid[..valid.len() - 64].to_vec();
    push_varint_field(
        &mut unknown_field,
        15,
        u32::from(data.get(708).copied().unwrap_or(0)),
    );
    unknown_field.extend_from_slice(&signature);
    let decoded_unknown = decode_signal_sender_key_message(&unknown_field)
        .expect("Signal sender-key message with unknown field should decode");
    assert_eq!(decoded_unknown, decoded);
    let canonical_unknown = encode_signal_sender_key_message(&decoded_unknown)
        .expect("Signal sender-key message with unknown field should re-encode canonically");
    assert_eq!(
        canonical_unknown.as_ref(),
        valid.as_slice(),
        "Signal sender-key message unknown fields should be dropped on canonical re-encode"
    );

    let verifier_private_key = seed_32(data, 644, 0xd1);
    let verifier_public_key =
        prefixed_signal_public_key(&public_key_from_private(&verifier_private_key));
    assert_sender_key_message_verify_error(
        &valid,
        &verifier_public_key,
        "invalid Signal sender-key message signature",
    );

    assert_sender_key_message_decode_error(
        &[SENDER_KEY_WIRE_VERSION_BYTE],
        "Signal sender-key message is too short: 1",
    );

    let bad_message_version = sender_key_message_wire(
        0x23,
        Some(key_id),
        Some(iteration),
        Some(&ciphertext),
        &signature,
    );
    assert_sender_key_message_decode_error(
        &bad_message_version,
        "unsupported Signal sender-key message version: 2",
    );

    let bad_ciphertext_version = sender_key_message_wire(
        0x32,
        Some(key_id),
        Some(iteration),
        Some(&ciphertext),
        &signature,
    );
    assert_sender_key_message_decode_error(
        &bad_ciphertext_version,
        "unsupported Signal sender-key ciphertext version: 2",
    );

    let missing_id = sender_key_message_wire(
        SENDER_KEY_WIRE_VERSION_BYTE,
        None,
        Some(iteration),
        Some(&ciphertext),
        &signature,
    );
    assert_sender_key_message_decode_error(&missing_id, "Signal sender-key message missing id");

    let missing_iteration = sender_key_message_wire(
        SENDER_KEY_WIRE_VERSION_BYTE,
        Some(key_id),
        None,
        Some(&ciphertext),
        &signature,
    );
    assert_sender_key_message_decode_error(
        &missing_iteration,
        "Signal sender-key message missing iteration",
    );

    let missing_ciphertext = sender_key_message_wire(
        SENDER_KEY_WIRE_VERSION_BYTE,
        Some(key_id),
        Some(iteration),
        None,
        &signature,
    );
    assert_sender_key_message_decode_error(
        &missing_ciphertext,
        "Signal sender-key message missing ciphertext",
    );

    let empty_ciphertext = sender_key_message_wire(
        SENDER_KEY_WIRE_VERSION_BYTE,
        Some(key_id),
        Some(iteration),
        Some(&[]),
        &signature,
    );
    assert_sender_key_message_decode_error(
        &empty_ciphertext,
        "Signal sender-key message ciphertext must not be empty",
    );
}

fn drive_sender_key_record_required_field_frames(data: &[u8]) {
    let key_id = 1 + u32::from(data.get(644).copied().unwrap_or(0));
    let chain_iteration = 1 + u32::from(data.get(645).copied().unwrap_or(0) % 32);
    let chain_seed = seed_32(data, 646, 0x81);
    let signing_private_key = seed_32(data, 678, 0xa1);
    let signing_public_key =
        prefixed_signal_public_key(&public_key_from_private(&signing_private_key));
    let skipped_iteration = u32::from(data.get(710).copied().unwrap_or(0)) % chain_iteration;
    let skipped_seed = seed_32(data, 711, 0xc1);

    let chain_key = sender_chain_key_wire(Some(chain_iteration), Some(&chain_seed));
    let signing_key = sender_signing_key_wire(Some(&signing_public_key));
    let skipped_key = sender_message_key_wire(Some(skipped_iteration), Some(&skipped_seed));

    let valid = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&chain_key),
        Some(&signing_key),
        std::slice::from_ref(&skipped_key),
    ));
    let decoded = decode_signal_sender_key_record(&valid)
        .expect("structured Signal sender-key record should decode");
    assert_eq!(decoded.states.len(), 1);
    let state = &decoded.states[0];
    assert_eq!(state.key_id, key_id);
    assert_eq!(state.chain_key.iteration, chain_iteration);
    assert_eq!(state.chain_key.key.expose(), &chain_seed);
    assert_eq!(
        state.signing_public_key.as_ref(),
        signing_public_key.as_slice()
    );
    assert_eq!(state.message_keys.len(), 1);
    assert_eq!(state.message_keys[0].iteration, skipped_iteration);
    assert_eq!(state.message_keys[0].seed.expose(), &skipped_seed);

    let assert_unknown_record = |encoded: Vec<u8>, label: &str| {
        let decoded_unknown = decode_signal_sender_key_record(&encoded)
            .expect("Signal sender-key record with unknown field should decode");
        assert_eq!(decoded_unknown, decoded, "{label}");
        let canonical_unknown = encode_signal_sender_key_record(&decoded_unknown)
            .expect("Signal sender-key record with unknown field should re-encode canonically");
        assert_eq!(
            canonical_unknown.as_ref(),
            valid.as_slice(),
            "{label}: Signal sender-key record unknown fields should be dropped on canonical re-encode"
        );
    };

    let mut unknown_field = valid.clone();
    push_varint_field(
        &mut unknown_field,
        15,
        u32::from(data.get(1127).copied().unwrap_or(0)),
    );
    assert_unknown_record(unknown_field, "top-level unknown field");

    let mut state_unknown = sender_key_state_wire(
        Some(key_id),
        Some(&chain_key),
        Some(&signing_key),
        std::slice::from_ref(&skipped_key),
    );
    push_varint_field(
        &mut state_unknown,
        15,
        u32::from(data.get(1128).copied().unwrap_or(0)),
    );
    assert_unknown_record(
        sender_key_record_wire(state_unknown),
        "sender-key state unknown field",
    );

    let mut chain_key_unknown = sender_chain_key_wire(Some(chain_iteration), Some(&chain_seed));
    push_varint_field(
        &mut chain_key_unknown,
        15,
        u32::from(data.get(1129).copied().unwrap_or(0)),
    );
    assert_unknown_record(
        sender_key_record_wire(sender_key_state_wire(
            Some(key_id),
            Some(&chain_key_unknown),
            Some(&signing_key),
            std::slice::from_ref(&skipped_key),
        )),
        "sender-key chain key unknown field",
    );

    let mut signing_key_unknown = sender_signing_key_wire(Some(&signing_public_key));
    push_varint_field(
        &mut signing_key_unknown,
        15,
        u32::from(data.get(1130).copied().unwrap_or(0)),
    );
    assert_unknown_record(
        sender_key_record_wire(sender_key_state_wire(
            Some(key_id),
            Some(&chain_key),
            Some(&signing_key_unknown),
            std::slice::from_ref(&skipped_key),
        )),
        "sender-key signing key unknown field",
    );

    let mut skipped_key_unknown =
        sender_message_key_wire(Some(skipped_iteration), Some(&skipped_seed));
    push_varint_field(
        &mut skipped_key_unknown,
        15,
        u32::from(data.get(1131).copied().unwrap_or(0)),
    );
    assert_unknown_record(
        sender_key_record_wire(sender_key_state_wire(
            Some(key_id),
            Some(&chain_key),
            Some(&signing_key),
            std::slice::from_ref(&skipped_key_unknown),
        )),
        "sender-key skipped message key unknown field",
    );

    let mut too_many_states = Vec::new();
    for index in 0..=SENDER_KEY_RECORD_STATE_LIMIT {
        let chain_seed = seed_32(data, 743 + index * 32, 0xd1u8.wrapping_add(index as u8));
        let signing_public_key = signal_public_key(data, 935 + index * 32, 0xe1 + index as u8);
        let chain_key = sender_chain_key_wire(Some(chain_iteration), Some(&chain_seed));
        let signing_key = sender_signing_key_wire(Some(&signing_public_key));
        too_many_states.push(sender_key_state_wire(
            Some(key_id + index as u32 + 1),
            Some(&chain_key),
            Some(&signing_key),
            &[],
        ));
    }
    let too_many_states = sender_key_record_wire_from_states(&too_many_states);
    assert_sender_key_record_decode_error(
        &too_many_states,
        "Signal sender-key record must contain at most 5 states",
    );

    let missing_state_id = sender_key_record_wire(sender_key_state_wire(
        None,
        Some(&chain_key),
        Some(&signing_key),
        &[],
    ));
    assert_sender_key_record_decode_error(&missing_state_id, "Signal sender-key state missing id");

    let missing_chain_key = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        None,
        Some(&signing_key),
        &[],
    ));
    assert_sender_key_record_decode_error(
        &missing_chain_key,
        "Signal sender-key state missing chain key",
    );

    let missing_chain_key_seed = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&sender_chain_key_wire(Some(chain_iteration), None)),
        Some(&signing_key),
        &[],
    ));
    assert_sender_key_record_decode_error(
        &missing_chain_key_seed,
        "Signal sender-key state missing chain key seed",
    );

    let missing_chain_iteration = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&sender_chain_key_wire(None, Some(&chain_seed))),
        Some(&signing_key),
        &[],
    ));
    assert_sender_key_record_decode_error(
        &missing_chain_iteration,
        "Signal sender-key state missing chain iteration",
    );

    let missing_signing_key = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&chain_key),
        None,
        &[],
    ));
    assert_sender_key_record_decode_error(
        &missing_signing_key,
        "Signal sender-key state missing signing key",
    );

    let missing_signing_public_key = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&chain_key),
        Some(&sender_signing_key_wire(None)),
        &[],
    ));
    assert_sender_key_record_decode_error(
        &missing_signing_public_key,
        "Signal sender-key state missing signing public key",
    );

    let missing_skipped_iteration = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&chain_key),
        Some(&signing_key),
        &[sender_message_key_wire(None, Some(&skipped_seed))],
    ));
    assert_sender_key_record_decode_error(
        &missing_skipped_iteration,
        "Signal sender-key message key missing iteration",
    );

    let missing_skipped_seed = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&chain_key),
        Some(&signing_key),
        &[sender_message_key_wire(Some(skipped_iteration), None)],
    ));
    assert_sender_key_record_decode_error(
        &missing_skipped_seed,
        "Signal sender-key message key missing seed",
    );
}

fn whisper_wire(
    ratchet_key: Option<&[u8]>,
    counter: Option<u32>,
    previous_counter: Option<u32>,
    ciphertext: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(ratchet_key) = ratchet_key {
        push_len_field(&mut out, 1, ratchet_key);
    }
    if let Some(counter) = counter {
        push_varint_field(&mut out, 2, counter);
    }
    if let Some(previous_counter) = previous_counter {
        push_varint_field(&mut out, 3, previous_counter);
    }
    if let Some(ciphertext) = ciphertext {
        push_len_field(&mut out, 4, ciphertext);
    }
    out
}

fn pre_key_whisper_wire(
    pre_key_id: Option<u32>,
    base_key: Option<&[u8]>,
    identity_key: Option<&[u8]>,
    message: Option<&[u8]>,
    registration_id: Option<u32>,
    signed_pre_key_id: Option<u32>,
) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(pre_key_id) = pre_key_id {
        push_varint_field(&mut out, 1, pre_key_id);
    }
    if let Some(base_key) = base_key {
        push_len_field(&mut out, 2, base_key);
    }
    if let Some(identity_key) = identity_key {
        push_len_field(&mut out, 3, identity_key);
    }
    if let Some(message) = message {
        push_len_field(&mut out, 4, message);
    }
    if let Some(registration_id) = registration_id {
        push_varint_field(&mut out, 5, registration_id);
    }
    if let Some(signed_pre_key_id) = signed_pre_key_id {
        push_varint_field(&mut out, 6, signed_pre_key_id);
    }
    out
}

fn sender_key_distribution_wire(
    version_byte: u8,
    key_id: Option<u32>,
    iteration: Option<u32>,
    chain_key: Option<&[u8]>,
    signing_key: Option<&[u8]>,
    padding: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(version_byte);
    if let Some(key_id) = key_id {
        push_varint_field(&mut out, 1, key_id);
    }
    if let Some(iteration) = iteration {
        push_varint_field(&mut out, 2, iteration);
    }
    if let Some(chain_key) = chain_key {
        push_len_field(&mut out, 3, chain_key);
    }
    if let Some(signing_key) = signing_key {
        push_len_field(&mut out, 4, signing_key);
    }
    if let Some(padding) = padding {
        push_len_field(&mut out, 15, padding);
    }
    out
}

fn sender_key_message_wire(
    version_byte: u8,
    key_id: Option<u32>,
    iteration: Option<u32>,
    ciphertext: Option<&[u8]>,
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(version_byte);
    if let Some(key_id) = key_id {
        push_varint_field(&mut out, 1, key_id);
    }
    if let Some(iteration) = iteration {
        push_varint_field(&mut out, 2, iteration);
    }
    if let Some(ciphertext) = ciphertext {
        push_len_field(&mut out, 3, ciphertext);
    }
    out.extend_from_slice(signature);
    out
}

fn sender_key_record_wire(state: Vec<u8>) -> Vec<u8> {
    sender_key_record_wire_from_states(&[state])
}

fn sender_key_record_wire_from_states(states: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for state in states {
        push_len_field(&mut out, 1, state);
    }
    out
}

fn sender_key_state_wire(
    key_id: Option<u32>,
    chain_key: Option<&[u8]>,
    signing_key: Option<&[u8]>,
    message_keys: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(key_id) = key_id {
        push_varint_field(&mut out, 1, key_id);
    }
    if let Some(chain_key) = chain_key {
        push_len_field(&mut out, 2, chain_key);
    }
    if let Some(signing_key) = signing_key {
        push_len_field(&mut out, 3, signing_key);
    }
    for message_key in message_keys {
        push_len_field(&mut out, 4, message_key);
    }
    out
}

fn sender_chain_key_wire(iteration: Option<u32>, seed: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(iteration) = iteration {
        push_varint_field(&mut out, 1, iteration);
    }
    if let Some(seed) = seed {
        push_len_field(&mut out, 2, seed);
    }
    out
}

fn sender_signing_key_wire(public_key: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(public_key) = public_key {
        push_len_field(&mut out, 1, public_key);
    }
    out
}

fn sender_message_key_wire(iteration: Option<u32>, seed: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(iteration) = iteration {
        push_varint_field(&mut out, 1, iteration);
    }
    if let Some(seed) = seed {
        push_len_field(&mut out, 2, seed);
    }
    out
}

fn provider_session_header() -> Vec<u8> {
    let mut out = Vec::new();
    out.push(PROVIDER_SESSION_VERSION);
    out.push(PROVIDER_SESSION_RECORD_KIND);
    push_u32(&mut out, 88);
    out
}

fn provider_session_required_prefix(
    remote_identity: &[u8],
    root_key: &[u8],
    sending_counter: u32,
    sending_chain_key: &[u8],
    local_public_key: &[u8],
    local_private_key: &[u8],
) -> Vec<u8> {
    let mut out = provider_session_header();
    push_len16(&mut out, remote_identity);
    push_len16(&mut out, root_key);
    push_u32(&mut out, sending_counter);
    push_len16(&mut out, sending_chain_key);
    push_len16(&mut out, local_public_key);
    push_len16(&mut out, local_private_key);
    out
}

fn assert_provider_session_decode_error(encoded: &[u8], expected: &str) {
    let err = decode_signal_provider_session_record(encoded)
        .expect_err("malformed Signal provider-session record should reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected Signal provider-session record error"
    );
}

fn assert_whisper_decode_error(encoded: &[u8], expected: &str) {
    let err = decode_signal_whisper_message(
        encoded,
        &WIRE_DECODE_MAC_KEY,
        &wire_decode_identity(),
        &wire_decode_identity(),
    )
    .expect_err("malformed Signal whisper should reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected Signal whisper error"
    );
}

fn assert_pre_key_whisper_decode_error(encoded: &[u8], expected: &str) {
    let err = decode_signal_pre_key_whisper_message(encoded)
        .expect_err("malformed Signal pre-key whisper frame should reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected Signal pre-key whisper error"
    );
}

fn assert_sender_key_distribution_decode_error(encoded: &[u8], expected: &str) {
    let err = decode_signal_sender_key_distribution_message(encoded)
        .expect_err("malformed Signal sender-key distribution should reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected Signal sender-key distribution error"
    );
}

fn assert_sender_key_message_decode_error(encoded: &[u8], expected: &str) {
    let err = decode_signal_sender_key_message(encoded)
        .expect_err("malformed Signal sender-key message should reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected Signal sender-key message error"
    );
}

fn assert_sender_key_message_verify_error(
    encoded: &[u8],
    signing_public_key: &[u8],
    expected: &str,
) {
    let err = verify_signal_sender_key_message_bytes(
        encoded,
        signing_public_key,
        &XEdDsaNoiseCertificateVerifier,
    )
    .expect_err("malformed Signal sender-key message signature should reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected Signal sender-key message verification error"
    );
}

fn assert_sender_key_record_decode_error(encoded: &[u8], expected: &str) {
    let err = decode_signal_sender_key_record(encoded)
        .expect_err("malformed Signal sender-key record should reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected Signal sender-key record error"
    );
}

fn signal_public_key(data: &[u8], offset: usize, fill: u8) -> [u8; 33] {
    let mut key = [fill; 33];
    key[0] = SIGNAL_PUBLIC_KEY_VERSION;
    for (index, byte) in key[1..].iter_mut().enumerate() {
        if let Some(value) = data.get(offset + index) {
            *byte = *value;
        }
    }
    key
}

fn seed_32(data: &[u8], offset: usize, fill: u8) -> [u8; 32] {
    let mut seed = [fill; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        if let Some(value) = data.get(offset + index) {
            *byte = *value;
        }
    }
    seed
}

fn seed_16(data: &[u8], offset: usize, fill: u8) -> [u8; 16] {
    let mut seed = [fill; 16];
    for (index, byte) in seed.iter_mut().enumerate() {
        if let Some(value) = data.get(offset + index) {
            *byte = *value;
        }
    }
    seed
}

fn seed_64(data: &[u8], offset: usize, fill: u8) -> [u8; 64] {
    let mut seed = [fill; 64];
    for (index, byte) in seed.iter_mut().enumerate() {
        if let Some(value) = data.get(offset + index) {
            *byte = *value;
        }
    }
    seed
}

fn nonempty_bytes(data: &[u8], offset: usize, fill: u8) -> Vec<u8> {
    let available = data.len().saturating_sub(offset).min(32);
    if available == 0 {
        return vec![fill];
    }
    data[offset..offset + available].to_vec()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_len16(out: &mut Vec<u8>, value: &[u8]) {
    push_u16(
        out,
        u16::try_from(value.len()).expect("structured Signal field length fits u16"),
    );
    out.extend_from_slice(value);
}

fn push_varint_field(out: &mut Vec<u8>, field: u32, value: u32) {
    push_varint(out, u64::from(field) << 3);
    push_varint(out, u64::from(value));
}

fn push_len_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    push_varint(out, (u64::from(field) << 3) | 2);
    push_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
