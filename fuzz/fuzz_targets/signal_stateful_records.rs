#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use prost::Message as ProstMessage;
use wa_core::signal::SignalProviderStoredMessageKey;
use wa_core::{
    SignalLocalIdentity, SignalLocalKeyMaterial, SignalLocalPreKey, SignalLocalSignedPreKey,
    SignalMessageChainKey, SignalMessageKeyMaterial, SignalPreKey,
    SignalProviderPreKeySessionEncryption, SignalProviderSessionRecord, SignalRootKey,
    SignalSenderChainKey, SignalSenderKeyMessage, SignalSenderKeyRecord, SignalSenderKeyState,
    SignalSenderStoredMessageKey, SignalSession, SignalSignedPreKey, SignalWhisperMessage,
    XEdDsaNoiseCertificateVerifier, build_signal_sender_key_distribution_message,
    decode_signal_pre_key_whisper_message, decode_signal_provider_session_record,
    decode_signal_sender_key_distribution_message, decode_signal_sender_key_message,
    decode_signal_sender_key_record, decode_signal_whisper_message,
    decrypt_signal_inbound_pre_key_session_message, decrypt_signal_provider_session_record_message,
    decrypt_signal_sender_key_record_message, encode_signal_pre_key_whisper_message,
    encode_signal_provider_session_record, encode_signal_sender_key_message,
    encode_signal_sender_key_record, encode_signal_whisper_message, encrypt_signal_message_body,
    encrypt_signal_outbound_pre_key_session_message,
    encrypt_signal_provider_session_record_message, encrypt_signal_sender_key_record_message,
    process_signal_sender_key_distribution_record, ratchet_signal_message_chain,
    ratchet_signal_root_key, sign_signal_sender_key_message,
};
use wa_crypto::{KeyPair, SecretBytes, prefixed_signal_public_key, public_key_from_private};
use wa_proto::proto::PreKeySignalMessage;

const MAX_INPUT_LEN: usize = 128 * 1024;
const MAX_PLAINTEXT_LEN: usize = 4 * 1024;
const STRUCTURED_PLAINTEXT_LEN: usize = 256;
const STRUCTURED_FAR_FUTURE_COUNTER_JUMP: u32 = 25_001;
const STRUCTURED_SENDER_KEY_STATE_LIMIT: usize = 5;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let [
        provider_record,
        provider_message,
        sender_record,
        sender_message,
        distribution,
        plaintext,
    ] = split_six(data);
    let plaintext = cap_plaintext(plaintext);

    let _ = decrypt_signal_provider_session_record_message(provider_record, provider_message);
    if !plaintext.is_empty()
        && let Ok(encrypted) =
            encrypt_signal_provider_session_record_message(provider_record, plaintext)
    {
        let _ = decode_signal_provider_session_record(&encrypted.record);
        let _ = decode_signal_whisper_message(&encrypted.message_bytes);
    }

    let verifier = XEdDsaNoiseCertificateVerifier;
    let _ = decrypt_signal_sender_key_record_message(sender_record, sender_message, &verifier);
    if !plaintext.is_empty()
        && let Ok(encrypted) = encrypt_signal_sender_key_record_message(sender_record, plaintext)
    {
        let _ = decode_signal_sender_key_record(&encrypted.record);
        let _ = decode_signal_sender_key_message(&encrypted.message_bytes);
    }

    if let Ok(distribution) = decode_signal_sender_key_distribution_message(distribution) {
        let _ = process_signal_sender_key_distribution_record(None, &distribution);
        let _ = process_signal_sender_key_distribution_record(Some(sender_record), &distribution);
    }

    drive_provider_previous_chain_replay(data);
    drive_provider_stale_previous_counter_rejection(data);
    drive_provider_far_future_counter_rejection(data);
    drive_provider_far_future_previous_counter_rejection(data);
    drive_provider_record_invariant_rejection(data);
    drive_provider_whisper_unknown_field_decrypt(data);
    drive_pre_key_whisper_unknown_field_decrypt(data);
    drive_provider_active_chain_failed_decrypt_preservation(data);
    drive_provider_new_ratchet_failed_decrypt_preservation(data);
    drive_sender_key_out_of_order_replay(data);
    drive_sender_key_distribution_stale_replacement(data);
    drive_sender_key_distribution_same_signer_stale_chain_retry(data);
    drive_sender_key_distribution_full_record_truncation(data);
    drive_sender_key_required_field_rejection(data);
    drive_sender_key_record_invariant_rejection(data);
    drive_sender_key_multi_state_decrypt(data);
});

fn split_six(data: &[u8]) -> [&[u8]; 6] {
    let first = data.len() / 6;
    let second = data.len() / 5;
    let third = data.len() / 4;
    let fourth = data.len() / 3;
    let fifth = data.len() / 2;

    let (a, rest) = data.split_at(first);
    let (b, rest) = rest.split_at(second.min(rest.len()));
    let (c, rest) = rest.split_at(third.min(rest.len()));
    let (d, rest) = rest.split_at(fourth.min(rest.len()));
    let (e, f) = rest.split_at(fifth.min(rest.len()));
    [a, b, c, d, e, f]
}

fn cap_plaintext(data: &[u8]) -> &[u8] {
    let len = data.len().min(MAX_PLAINTEXT_LEN);
    &data[..len]
}

fn drive_provider_previous_chain_replay(data: &[u8]) {
    let local_ratchet = key_pair_from_seed(data, 0, 0x11);
    let old_remote_ratchet = key_pair_from_seed(data, 32, 0x31);
    let new_remote_ratchet = key_pair_from_seed(data, 64, 0x51);
    let receiving_counter = data.get(96).copied().unwrap_or(0) as u32 % 3;
    let skipped_count = 2 + (data.get(97).copied().unwrap_or(0) as u32 % 4);
    let previous_counter = data.get(98).copied().unwrap_or(0) as u32 % 8;
    let sending_counter = data.get(99).copied().unwrap_or(0) as u32 % 8;
    let message_previous_counter = receiving_counter + skipped_count;
    let old_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&old_remote_ratchet.public));
    let new_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&new_remote_ratchet.public));

    let record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5678,
        remote_identity_key: prefixed_seed_public(data, 100, 0x71),
        root_key: SignalRootKey {
            key: secret_from_seed(data, 132, 0x91),
        },
        sending_chain: SignalMessageChainKey {
            key: secret_from_seed(data, 164, 0xb1),
            counter: sending_counter,
        },
        receiving_chain: Some(SignalMessageChainKey {
            key: secret_from_seed(data, 196, 0xd1),
            counter: receiving_counter,
        }),
        remote_ratchet_key: Some(old_remote_ratchet_key.clone()),
        local_ratchet_key_pair: local_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };

    let mut old_chain = record
        .receiving_chain
        .clone()
        .expect("structured record has receiving chain");
    let mut old_messages = Vec::new();
    while old_chain.counter < message_previous_counter {
        let Ok(step) = ratchet_signal_message_chain(&old_chain) else {
            return;
        };
        old_chain = step.next_chain_key;
        let plaintext = structured_plaintext(data, 228, step.message_counter);
        let Ok(ciphertext) = encrypt_signal_message_body(&plaintext, &step.message_keys) else {
            return;
        };
        let message = SignalWhisperMessage {
            ephemeral_key: old_remote_ratchet_key.clone(),
            counter: step.message_counter,
            previous_counter,
            ciphertext,
        };
        let Ok(message_bytes) = encode_signal_whisper_message(&message) else {
            return;
        };
        old_messages.push(message_bytes);
    }

    let Ok(root_step) = ratchet_signal_root_key(
        &record.root_key,
        record.local_ratchet_key_pair.private.expose(),
        &new_remote_ratchet_key,
    ) else {
        return;
    };
    let Ok(new_step) = ratchet_signal_message_chain(&root_step.chain_key) else {
        return;
    };
    let new_plaintext = structured_plaintext(data, 260, 1);
    let Ok(new_ciphertext) = encrypt_signal_message_body(&new_plaintext, &new_step.message_keys)
    else {
        return;
    };
    let new_message = SignalWhisperMessage {
        ephemeral_key: new_remote_ratchet_key.clone(),
        counter: new_step.message_counter,
        previous_counter: message_previous_counter,
        ciphertext: new_ciphertext,
    };
    let Ok(new_message_bytes) = encode_signal_whisper_message(&new_message) else {
        return;
    };
    let Ok(record_bytes) = encode_signal_provider_session_record(&record) else {
        return;
    };
    let Ok(new_decrypted) =
        decrypt_signal_provider_session_record_message(&record_bytes, &new_message_bytes)
    else {
        return;
    };
    if new_decrypted.plaintext != new_plaintext {
        return;
    }

    let mut current_record = new_decrypted.record;
    if let Some(first_old_message) = old_messages.first() {
        let Ok(first_decoded) = decode_signal_whisper_message(first_old_message) else {
            return;
        };
        let mut tampered_first = first_decoded.clone();
        let mut tampered_ciphertext = tampered_first.ciphertext.to_vec();
        let Some(last) = tampered_ciphertext.last_mut() else {
            return;
        };
        *last ^= 1;
        tampered_first.ciphertext = Bytes::from(tampered_ciphertext);
        if let Ok(tampered_first) = encode_signal_whisper_message(&tampered_first) {
            assert!(
                decrypt_signal_provider_session_record_message(&current_record, &tampered_first)
                    .is_err(),
                "tampered provider previous-chain skipped message should fail to decrypt"
            );
        }
        let Ok(decrypted) =
            decrypt_signal_provider_session_record_message(&current_record, first_old_message)
        else {
            return;
        };
        current_record = decrypted.record;
    }
    if let Some(last_old_message) = old_messages.last() {
        let Ok(decrypted) =
            decrypt_signal_provider_session_record_message(&current_record, last_old_message)
        else {
            return;
        };
        current_record = decrypted.record;
    }

    let Ok(next_new_step) = ratchet_signal_message_chain(&new_step.next_chain_key) else {
        return;
    };
    let next_new_plaintext = structured_plaintext(data, 292, 2);
    let Ok(next_new_ciphertext) =
        encrypt_signal_message_body(&next_new_plaintext, &next_new_step.message_keys)
    else {
        return;
    };
    let next_new_message = SignalWhisperMessage {
        ephemeral_key: new_remote_ratchet_key,
        counter: next_new_step.message_counter,
        previous_counter: message_previous_counter,
        ciphertext: next_new_ciphertext,
    };
    let Ok(next_new_message_bytes) = encode_signal_whisper_message(&next_new_message) else {
        return;
    };
    if let Ok(decrypted) =
        decrypt_signal_provider_session_record_message(&current_record, &next_new_message_bytes)
    {
        let _ = decode_signal_provider_session_record(&decrypted.record);
    }
}

fn drive_provider_stale_previous_counter_rejection(data: &[u8]) {
    let local_ratchet = key_pair_from_seed(data, 421, 0x73);
    let old_remote_ratchet = key_pair_from_seed(data, 453, 0x83);
    let new_remote_ratchet = key_pair_from_seed(data, 485, 0x93);
    let old_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&old_remote_ratchet.public));
    let new_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&new_remote_ratchet.public));
    if old_remote_ratchet_key == new_remote_ratchet_key {
        return;
    }

    let receiving_counter = 1 + (data.get(517).copied().unwrap_or(0) as u32 % 4);
    let stale_previous_counter = data.get(518).copied().unwrap_or(0) as u32 % receiving_counter;
    let previous_counter = data.get(519).copied().unwrap_or(0) as u32 % 8;
    let receiving_chain = SignalMessageChainKey {
        key: secret_from_seed(data, 520, 0xa3),
        counter: receiving_counter,
    };
    let record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5679,
        remote_identity_key: prefixed_seed_public(data, 552, 0xb3),
        root_key: SignalRootKey {
            key: secret_from_seed(data, 584, 0xc3),
        },
        sending_chain: SignalMessageChainKey {
            key: secret_from_seed(data, 616, 0xd3),
            counter: data.get(648).copied().unwrap_or(0) as u32 % 8,
        },
        receiving_chain: Some(receiving_chain.clone()),
        remote_ratchet_key: Some(old_remote_ratchet_key.clone()),
        local_ratchet_key_pair: local_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(record_bytes) = encode_signal_provider_session_record(&record) else {
        return;
    };

    let stale_message = SignalWhisperMessage {
        ephemeral_key: new_remote_ratchet_key,
        counter: 1,
        previous_counter: stale_previous_counter,
        ciphertext: structured_plaintext(data, 649, stale_previous_counter),
    };
    let Ok(stale_message_bytes) = encode_signal_whisper_message(&stale_message) else {
        return;
    };
    let err = decrypt_signal_provider_session_record_message(&record_bytes, &stale_message_bytes)
        .expect_err("stale previous-counter message must be rejected");
    assert_eq!(
        err.to_string(),
        format!(
            "protocol error: Signal previous chain counter moved backwards: message {stale_previous_counter}, current {receiving_counter}"
        ),
        "unexpected stale previous-counter error"
    );

    let Ok(message_step) = ratchet_signal_message_chain(&receiving_chain) else {
        return;
    };
    let old_plaintext = structured_plaintext(data, 681, message_step.message_counter);
    let Ok(old_ciphertext) =
        encrypt_signal_message_body(&old_plaintext, &message_step.message_keys)
    else {
        return;
    };
    let old_message = SignalWhisperMessage {
        ephemeral_key: old_remote_ratchet_key,
        counter: message_step.message_counter,
        previous_counter,
        ciphertext: old_ciphertext,
    };
    let Ok(old_message_bytes) = encode_signal_whisper_message(&old_message) else {
        return;
    };
    let Ok(decrypted) =
        decrypt_signal_provider_session_record_message(&record_bytes, &old_message_bytes)
    else {
        return;
    };
    assert_eq!(decrypted.plaintext, old_plaintext);
    let _ = decode_signal_provider_session_record(&decrypted.record);
}

fn drive_provider_far_future_counter_rejection(data: &[u8]) {
    let local_ratchet = key_pair_from_seed(data, 1512, 0x3b);
    let remote_ratchet = key_pair_from_seed(data, 1544, 0x5b);
    let remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&remote_ratchet.public));
    let receiving_counter = data.get(1576).copied().unwrap_or(0) as u32 % 8;
    let previous_counter = data.get(1577).copied().unwrap_or(0) as u32 % 8;
    let receiving_chain = SignalMessageChainKey {
        key: secret_from_seed(data, 1578, 0x7b),
        counter: receiving_counter,
    };
    let record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5682,
        remote_identity_key: prefixed_seed_public(data, 1610, 0x9b),
        root_key: SignalRootKey {
            key: secret_from_seed(data, 1642, 0xbb),
        },
        sending_chain: SignalMessageChainKey {
            key: secret_from_seed(data, 1674, 0xdb),
            counter: data.get(1706).copied().unwrap_or(0) as u32 % 8,
        },
        receiving_chain: Some(receiving_chain.clone()),
        remote_ratchet_key: Some(remote_ratchet_key.clone()),
        local_ratchet_key_pair: local_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(record_bytes) = encode_signal_provider_session_record(&record) else {
        return;
    };

    let far_future_message = SignalWhisperMessage {
        ephemeral_key: remote_ratchet_key.clone(),
        counter: receiving_counter + STRUCTURED_FAR_FUTURE_COUNTER_JUMP,
        previous_counter,
        ciphertext: structured_plaintext(data, 1707, receiving_counter),
    };
    let Ok(far_future_message_bytes) = encode_signal_whisper_message(&far_future_message) else {
        return;
    };
    let err =
        decrypt_signal_provider_session_record_message(&record_bytes, &far_future_message_bytes)
            .expect_err("far-future provider active-chain message must be rejected");
    assert_eq!(
        err.to_string(),
        format!(
            "protocol error: Signal message is too far in the future: {STRUCTURED_FAR_FUTURE_COUNTER_JUMP}"
        ),
        "unexpected far-future provider counter error"
    );

    let Ok(message_step) = ratchet_signal_message_chain(&receiving_chain) else {
        return;
    };
    let plaintext = structured_plaintext(data, 1739, message_step.message_counter);
    let Ok(ciphertext) = encrypt_signal_message_body(&plaintext, &message_step.message_keys) else {
        return;
    };
    let message = SignalWhisperMessage {
        ephemeral_key: remote_ratchet_key.clone(),
        counter: message_step.message_counter,
        previous_counter,
        ciphertext,
    };
    let Ok(message_bytes) = encode_signal_whisper_message(&message) else {
        return;
    };
    let Ok(decrypted) =
        decrypt_signal_provider_session_record_message(&record_bytes, &message_bytes)
    else {
        return;
    };
    assert_eq!(decrypted.plaintext, plaintext);
    let replay_err =
        decrypt_signal_provider_session_record_message(&decrypted.record, &message_bytes)
            .expect_err("consumed provider active-chain message should reject replay");
    assert_eq!(
        replay_err.to_string(),
        format!(
            "protocol error: duplicate or old Signal message counter: {}",
            message_step.message_counter
        ),
        "unexpected provider active-chain replay error"
    );

    let Ok(next_message_step) = ratchet_signal_message_chain(&message_step.next_chain_key) else {
        return;
    };
    let next_plaintext = structured_plaintext(data, 1215, next_message_step.message_counter);
    let Ok(next_ciphertext) =
        encrypt_signal_message_body(&next_plaintext, &next_message_step.message_keys)
    else {
        return;
    };
    let next_message = SignalWhisperMessage {
        ephemeral_key: remote_ratchet_key,
        counter: next_message_step.message_counter,
        previous_counter,
        ciphertext: next_ciphertext,
    };
    let Ok(next_message_bytes) = encode_signal_whisper_message(&next_message) else {
        return;
    };
    let Ok(next_decrypted) =
        decrypt_signal_provider_session_record_message(&decrypted.record, &next_message_bytes)
    else {
        return;
    };
    assert_eq!(next_decrypted.plaintext, next_plaintext);
    let _ = decode_signal_provider_session_record(&decrypted.record);
}

fn drive_provider_far_future_previous_counter_rejection(data: &[u8]) {
    let local_ratchet = key_pair_from_seed(data, 1772, 0x3d);
    let old_remote_ratchet = key_pair_from_seed(data, 1804, 0x5d);
    let new_remote_ratchet = key_pair_from_seed(data, 1836, 0x7d);
    let old_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&old_remote_ratchet.public));
    let new_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&new_remote_ratchet.public));
    if old_remote_ratchet_key == new_remote_ratchet_key {
        return;
    }

    let receiving_counter = data.get(1868).copied().unwrap_or(0) as u32 % 8;
    let previous_counter = data.get(1869).copied().unwrap_or(0) as u32 % 8;
    let receiving_chain = SignalMessageChainKey {
        key: secret_from_seed(data, 1870, 0x9d),
        counter: receiving_counter,
    };
    let record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5683,
        remote_identity_key: prefixed_seed_public(data, 1902, 0xbd),
        root_key: SignalRootKey {
            key: secret_from_seed(data, 1934, 0xdd),
        },
        sending_chain: SignalMessageChainKey {
            key: secret_from_seed(data, 1966, 0xfd),
            counter: data.get(1998).copied().unwrap_or(0) as u32 % 8,
        },
        receiving_chain: Some(receiving_chain.clone()),
        remote_ratchet_key: Some(old_remote_ratchet_key.clone()),
        local_ratchet_key_pair: local_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(record_bytes) = encode_signal_provider_session_record(&record) else {
        return;
    };

    let far_future_message = SignalWhisperMessage {
        ephemeral_key: new_remote_ratchet_key,
        counter: 1,
        previous_counter: receiving_counter + STRUCTURED_FAR_FUTURE_COUNTER_JUMP,
        ciphertext: structured_plaintext(data, 1999, receiving_counter),
    };
    let Ok(far_future_message_bytes) = encode_signal_whisper_message(&far_future_message) else {
        return;
    };
    let err =
        decrypt_signal_provider_session_record_message(&record_bytes, &far_future_message_bytes)
            .expect_err("far-future provider previous-counter message must be rejected");
    assert_eq!(
        err.to_string(),
        format!(
            "protocol error: Signal previous chain is too far in the future: {STRUCTURED_FAR_FUTURE_COUNTER_JUMP}"
        ),
        "unexpected far-future provider previous-counter error"
    );

    let Ok(message_step) = ratchet_signal_message_chain(&receiving_chain) else {
        return;
    };
    let plaintext = structured_plaintext(data, 2031, message_step.message_counter);
    let Ok(ciphertext) = encrypt_signal_message_body(&plaintext, &message_step.message_keys) else {
        return;
    };
    let message = SignalWhisperMessage {
        ephemeral_key: old_remote_ratchet_key,
        counter: message_step.message_counter,
        previous_counter,
        ciphertext,
    };
    let Ok(message_bytes) = encode_signal_whisper_message(&message) else {
        return;
    };
    let Ok(decrypted) =
        decrypt_signal_provider_session_record_message(&record_bytes, &message_bytes)
    else {
        return;
    };
    assert_eq!(decrypted.plaintext, plaintext);
    let _ = decode_signal_provider_session_record(&decrypted.record);
}

fn drive_provider_record_invariant_rejection(data: &[u8]) {
    let local_key_pair = key_pair_from_seed(data, 2300, 0x13);
    let remote_ratchet = key_pair_from_seed(data, 2332, 0x33);
    let skipped_ratchet = key_pair_from_seed(data, 2364, 0x53);
    let receiving_counter = 2 + (data.get(2396).copied().unwrap_or(0) as u32 % 8);
    let sending_counter = 1 + (data.get(2397).copied().unwrap_or(0) as u32 % 8);
    let previous_counter = data.get(2398).copied().unwrap_or(0) as u32 % 8;
    let remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&remote_ratchet.public));
    let skipped_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&skipped_ratchet.public));
    let receiving_chain = SignalMessageChainKey {
        key: secret_from_seed(data, 2399, 0x73),
        counter: receiving_counter,
    };
    let skipped_key = provider_skipped_message_key(
        skipped_ratchet_key.clone(),
        1,
        seed_32(data, 2431, 0x83),
        seed_32(data, 2463, 0x93),
        seed_16(data, 2495, 0xa3),
    );
    let active_future_skipped_key = provider_skipped_message_key(
        remote_ratchet_key.clone(),
        receiving_counter,
        seed_32(data, 2511, 0xb3),
        seed_32(data, 2543, 0xc3),
        seed_16(data, 2575, 0xd3),
    );

    let valid = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5684,
        remote_identity_key: prefixed_seed_public(data, 2591, 0xe3),
        root_key: SignalRootKey {
            key: secret_from_seed(data, 2623, 0xf3),
        },
        sending_chain: SignalMessageChainKey {
            key: secret_from_seed(data, 2655, 0x17),
            counter: sending_counter,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: local_key_pair.clone(),
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(valid_bytes) = encode_signal_provider_session_record(&valid) else {
        return;
    };
    let decoded =
        decode_signal_provider_session_record(&valid_bytes).expect("valid provider record decodes");
    assert_eq!(decoded.remote_registration_id, valid.remote_registration_id);
    assert_eq!(decoded.sending_chain.counter, sending_counter);
    assert_eq!(decoded.previous_counter, previous_counter);

    let mut mismatched_local = valid.clone();
    mismatched_local.local_ratchet_key_pair.public[0] ^= 1;
    assert_provider_record_encode_error(
        &mismatched_local,
        "Signal provider session local ratchet public key does not match private key",
    );

    let mut receiving_without_remote = valid.clone();
    receiving_without_remote.receiving_chain = Some(receiving_chain.clone());
    assert_provider_record_encode_error(
        &receiving_without_remote,
        "Signal provider session receiving chain and remote ratchet key must be stored together",
    );

    let mut remote_without_receiving = valid.clone();
    remote_without_receiving.remote_ratchet_key = Some(remote_ratchet_key.clone());
    assert_provider_record_encode_error(
        &remote_without_receiving,
        "Signal provider session receiving chain and remote ratchet key must be stored together",
    );

    let mut skipped_without_remote = valid.clone();
    skipped_without_remote.message_keys = vec![skipped_key.clone()];
    assert_provider_record_encode_error(
        &skipped_without_remote,
        "Signal provider skipped message keys require remote ratchet key",
    );

    let mut uninitialized_without_remote = valid.clone();
    uninitialized_without_remote.sending_chain = SignalMessageChainKey {
        key: SecretBytes::from(vec![0u8; 32]),
        counter: 0,
    };
    assert_provider_record_encode_error(
        &uninitialized_without_remote,
        "Signal provider session uninitialized sending chain requires remote ratchet key",
    );

    let mut valid_with_remote = valid.clone();
    valid_with_remote.receiving_chain = Some(receiving_chain);
    valid_with_remote.remote_ratchet_key = Some(remote_ratchet_key);

    let mut zero_counter_skipped = valid_with_remote.clone();
    zero_counter_skipped.message_keys = vec![provider_skipped_message_key(
        skipped_ratchet_key.clone(),
        0,
        seed_32(data, 2687, 0x27),
        seed_32(data, 2719, 0x37),
        seed_16(data, 2751, 0x47),
    )];
    assert_provider_record_encode_error(
        &zero_counter_skipped,
        "Signal provider skipped message counter must be greater than zero",
    );

    let mut duplicate_skipped = valid_with_remote.clone();
    duplicate_skipped.message_keys = vec![skipped_key.clone(), skipped_key];
    assert_provider_record_encode_error(
        &duplicate_skipped,
        "duplicate Signal provider skipped message key",
    );

    let mut active_future_skipped = valid_with_remote;
    active_future_skipped.message_keys = vec![active_future_skipped_key];
    assert_provider_record_encode_error(
        &active_future_skipped,
        "Signal provider skipped message counter must be below active receiving counter",
    );
}

fn drive_provider_active_chain_failed_decrypt_preservation(data: &[u8]) {
    let local_ratchet = key_pair_from_seed(data, 988, 0x37);
    let remote_ratchet = key_pair_from_seed(data, 1020, 0x57);
    let remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&remote_ratchet.public));
    let receiving_counter = data.get(1052).copied().unwrap_or(0) as u32 % 8;
    let previous_counter = data.get(1053).copied().unwrap_or(0) as u32 % 8;
    let receiving_chain = SignalMessageChainKey {
        key: secret_from_seed(data, 1054, 0x77),
        counter: receiving_counter,
    };
    let skipped_count = 2 + (data.get(1183).copied().unwrap_or(0) as u32 % 4);
    let target_counter = receiving_counter + skipped_count;
    let record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5680,
        remote_identity_key: prefixed_seed_public(data, 1086, 0x97),
        root_key: SignalRootKey {
            key: secret_from_seed(data, 1118, 0xb7),
        },
        sending_chain: SignalMessageChainKey {
            key: secret_from_seed(data, 1150, 0xd7),
            counter: data.get(1182).copied().unwrap_or(0) as u32 % 8,
        },
        receiving_chain: Some(receiving_chain.clone()),
        remote_ratchet_key: Some(remote_ratchet_key.clone()),
        local_ratchet_key_pair: local_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(record_bytes) = encode_signal_provider_session_record(&record) else {
        return;
    };

    let mut chain = receiving_chain;
    let mut skipped_messages = Vec::new();
    let mut target_plaintext = None;
    let mut target_message = None;
    let mut target_message_bytes = None;
    let mut target_next_chain = None;
    while chain.counter < target_counter {
        let Ok(step) = ratchet_signal_message_chain(&chain) else {
            return;
        };
        chain = step.next_chain_key.clone();
        let plaintext = structured_plaintext(data, 1184, step.message_counter);
        let Ok(ciphertext) = encrypt_signal_message_body(&plaintext, &step.message_keys) else {
            return;
        };
        let message = SignalWhisperMessage {
            ephemeral_key: remote_ratchet_key.clone(),
            counter: step.message_counter,
            previous_counter,
            ciphertext,
        };
        let Ok(message_bytes) = encode_signal_whisper_message(&message) else {
            return;
        };
        if step.message_counter == target_counter {
            target_plaintext = Some(plaintext);
            target_message = Some(message);
            target_message_bytes = Some(message_bytes);
            target_next_chain = Some(step.next_chain_key);
        } else {
            skipped_messages.push((plaintext, message_bytes));
        }
    }
    let Some(plaintext) = target_plaintext else {
        return;
    };
    let Some(message) = target_message else {
        return;
    };
    let Some(message_bytes) = target_message_bytes else {
        return;
    };
    let Some(target_next_chain) = target_next_chain else {
        return;
    };

    let mut tampered = message.clone();
    let mut tampered_ciphertext = tampered.ciphertext.to_vec();
    let Some(last) = tampered_ciphertext.last_mut() else {
        return;
    };
    *last ^= 1;
    tampered.ciphertext = Bytes::from(tampered_ciphertext);
    if let Ok(tampered_bytes) = encode_signal_whisper_message(&tampered) {
        assert!(
            decrypt_signal_provider_session_record_message(&record_bytes, &tampered_bytes).is_err(),
            "tampered provider active-chain message should fail to decrypt"
        );
    }

    let Ok(decrypted) =
        decrypt_signal_provider_session_record_message(&record_bytes, &message_bytes)
    else {
        return;
    };
    assert_eq!(decrypted.plaintext, plaintext);
    let replay_err =
        decrypt_signal_provider_session_record_message(&decrypted.record, &message_bytes)
            .expect_err("consumed provider active-chain message should reject replay");
    assert_eq!(
        replay_err.to_string(),
        format!("protocol error: duplicate or old Signal message counter: {target_counter}"),
        "unexpected provider active-chain replay error"
    );
    let mut current_record = decrypted.record;
    if let Some((skipped_plaintext, skipped_message_bytes)) = skipped_messages.first() {
        let Ok(skipped_decrypted) =
            decrypt_signal_provider_session_record_message(&current_record, skipped_message_bytes)
        else {
            return;
        };
        assert_eq!(&skipped_decrypted.plaintext, skipped_plaintext);
        current_record = skipped_decrypted.record;
    }

    let Ok(next_message_step) = ratchet_signal_message_chain(&target_next_chain) else {
        return;
    };
    let next_plaintext = structured_plaintext(data, 1215, next_message_step.message_counter);
    let Ok(next_ciphertext) =
        encrypt_signal_message_body(&next_plaintext, &next_message_step.message_keys)
    else {
        return;
    };
    let next_message = SignalWhisperMessage {
        ephemeral_key: remote_ratchet_key,
        counter: next_message_step.message_counter,
        previous_counter,
        ciphertext: next_ciphertext,
    };
    let Ok(next_message_bytes) = encode_signal_whisper_message(&next_message) else {
        return;
    };
    let Ok(next_decrypted) =
        decrypt_signal_provider_session_record_message(&current_record, &next_message_bytes)
    else {
        return;
    };
    assert_eq!(next_decrypted.plaintext, next_plaintext);
    let _ = decode_signal_provider_session_record(&current_record);
}

fn drive_provider_whisper_unknown_field_decrypt(data: &[u8]) {
    let sender_ratchet = key_pair_from_seed(data, 2304, 0x3b);
    let receiver_ratchet = key_pair_from_seed(data, 2336, 0x5b);
    let root_key = SignalRootKey {
        key: secret_from_seed(data, 2368, 0x7b),
    };
    let chain_key = secret_from_seed(data, 2400, 0x9b);
    let sending_counter = data.get(2432).copied().unwrap_or(0) as u32 % 8;
    let previous_counter = data.get(2433).copied().unwrap_or(0) as u32 % 8;
    let sender_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_ratchet.public));

    let sender_record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5683,
        remote_identity_key: prefixed_seed_public(data, 2434, 0xbb),
        root_key: root_key.clone(),
        sending_chain: SignalMessageChainKey {
            key: chain_key.clone(),
            counter: sending_counter,
        },
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: sender_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(sender_record) = encode_signal_provider_session_record(&sender_record) else {
        return;
    };
    let plaintext = structured_plaintext(data, 2466, sending_counter + 1);
    let Ok(encrypted) = encrypt_signal_provider_session_record_message(&sender_record, &plaintext)
    else {
        return;
    };

    let receiver_record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5683,
        remote_identity_key: prefixed_seed_public(data, 2498, 0xdb),
        root_key,
        sending_chain: SignalMessageChainKey {
            key: SecretBytes::from(vec![0u8; 32]),
            counter: 0,
        },
        receiving_chain: Some(SignalMessageChainKey {
            key: chain_key,
            counter: sending_counter,
        }),
        remote_ratchet_key: Some(sender_ratchet_key),
        local_ratchet_key_pair: receiver_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(receiver_record) = encode_signal_provider_session_record(&receiver_record) else {
        return;
    };
    let Ok(canonical_decrypted) =
        decrypt_signal_provider_session_record_message(&receiver_record, &encrypted.message_bytes)
    else {
        return;
    };
    assert_eq!(canonical_decrypted.plaintext, plaintext);

    let mut unknown_message = encrypted.message_bytes.to_vec();
    unknown_message.extend_from_slice(&[0x78, 0x63]);
    let Ok(decoded_unknown) = decode_signal_whisper_message(&unknown_message) else {
        return;
    };
    let Ok(canonical_unknown) = encode_signal_whisper_message(&decoded_unknown) else {
        return;
    };
    assert_eq!(
        canonical_unknown, encrypted.message_bytes,
        "provider whisper unknown field should canonicalize before decrypt"
    );
    let Ok(unknown_decrypted) =
        decrypt_signal_provider_session_record_message(&receiver_record, &unknown_message)
    else {
        return;
    };
    assert_eq!(unknown_decrypted.plaintext, plaintext);
    assert_eq!(unknown_decrypted.record, canonical_decrypted.record);
}

fn drive_pre_key_whisper_unknown_field_decrypt(data: &[u8]) {
    let alice_identity_key = key_pair_from_seed(data, 2530, 0x3d);
    let alice_base_key = key_pair_from_seed(data, 2562, 0x5d);
    let alice_signed_key = key_pair_from_seed(data, 2594, 0x7d);
    let bob_identity_key = key_pair_from_seed(data, 2626, 0x9d);
    let bob_signed_key = key_pair_from_seed(data, 2658, 0xbd);
    let bob_one_time_key = key_pair_from_seed(data, 2690, 0xdd);

    let alice_material = SignalLocalKeyMaterial {
        registration_id: 0x1234_5684,
        identity: SignalLocalIdentity {
            public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &alice_identity_key.public,
            )),
            key_pair: alice_identity_key,
        },
        signed_pre_key: SignalLocalSignedPreKey {
            key_id: 0x2101,
            public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &alice_signed_key.public,
            )),
            key_pair: alice_signed_key,
            signature: Bytes::from(vec![0u8; 64]),
        },
    };
    let bob_material = SignalLocalKeyMaterial {
        registration_id: 0x1234_5685,
        identity: SignalLocalIdentity {
            public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &bob_identity_key.public,
            )),
            key_pair: bob_identity_key,
        },
        signed_pre_key: SignalLocalSignedPreKey {
            key_id: 0x2201,
            public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(&bob_signed_key.public)),
            key_pair: bob_signed_key,
            signature: Bytes::from(vec![0u8; 64]),
        },
    };
    let bob_one_time = SignalLocalPreKey {
        key_id: 0x2301,
        public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(&bob_one_time_key.public)),
        key_pair: bob_one_time_key,
    };
    let bob_signed_pre_key = SignalSignedPreKey {
        key_id: bob_material.signed_pre_key.key_id,
        public_key: bob_material.signed_pre_key.public_key.clone(),
        signature: Bytes::from(vec![0u8; 64]),
    };
    let bob_session = SignalSession {
        registration_id: bob_material.registration_id,
        identity_key: bob_material.identity.public_key.clone(),
        signed_pre_key: bob_signed_pre_key.clone(),
        pre_key: Some(SignalPreKey {
            key_id: bob_one_time.key_id,
            public_key: bob_one_time.public_key.clone(),
        }),
    };
    let plaintext = structured_plaintext(data, 2722, 1);
    let accept_all = |_: &[u8], _: &[u8], _: &[u8]| true;
    let Ok(encrypted) = encrypt_signal_outbound_pre_key_session_message(
        &alice_material,
        &alice_base_key,
        &bob_session,
        &accept_all,
        &plaintext,
    ) else {
        return;
    };
    let _ = drive_pre_key_unknown_field_decrypt_case(
        &bob_material,
        Some(&bob_one_time),
        &encrypted,
        &plaintext,
    );

    let signed_only_session = SignalSession {
        registration_id: bob_material.registration_id,
        identity_key: bob_material.identity.public_key.clone(),
        signed_pre_key: bob_signed_pre_key,
        pre_key: None,
    };
    let signed_only_plaintext = structured_plaintext(data, 2754, 1);
    let Ok(signed_only_encrypted) = encrypt_signal_outbound_pre_key_session_message(
        &alice_material,
        &alice_base_key,
        &signed_only_session,
        &accept_all,
        &signed_only_plaintext,
    ) else {
        return;
    };
    let _ = drive_pre_key_unknown_field_decrypt_case(
        &bob_material,
        None,
        &signed_only_encrypted,
        &signed_only_plaintext,
    );
}

fn drive_pre_key_unknown_field_decrypt_case(
    bob_material: &SignalLocalKeyMaterial,
    local_one_time: Option<&SignalLocalPreKey>,
    encrypted: &SignalProviderPreKeySessionEncryption,
    plaintext: &Bytes,
) -> Option<()> {
    let canonical_decrypted = decrypt_signal_inbound_pre_key_session_message(
        bob_material,
        local_one_time,
        &encrypted.message_bytes,
    )
    .ok()?;
    assert_eq!(&canonical_decrypted.plaintext, plaintext);
    assert_eq!(
        canonical_decrypted.used_one_time_pre_key,
        local_one_time.is_some()
    );

    let mut outer_unknown = encrypted.message_bytes.to_vec();
    outer_unknown.extend_from_slice(&[0x78, 0x63]);
    let decoded_outer_unknown = decode_signal_pre_key_whisper_message(&outer_unknown).ok()?;
    let canonical_outer_unknown =
        encode_signal_pre_key_whisper_message(&decoded_outer_unknown).ok()?;
    assert_eq!(
        canonical_outer_unknown, encrypted.message_bytes,
        "pre-key outer unknown field should canonicalize before decrypt"
    );
    let Ok(outer_unknown_decrypted) = decrypt_signal_inbound_pre_key_session_message(
        bob_material,
        local_one_time,
        &outer_unknown,
    ) else {
        return None;
    };
    assert_eq!(&outer_unknown_decrypted.plaintext, plaintext);
    assert_eq!(outer_unknown_decrypted.record, canonical_decrypted.record);

    let Ok(inner_message) = encode_signal_whisper_message(&encrypted.message.message) else {
        return None;
    };
    let mut inner_unknown = inner_message.to_vec();
    inner_unknown.extend_from_slice(&[0x78, 0x63]);
    let Ok(decoded_inner_unknown) = decode_signal_whisper_message(&inner_unknown) else {
        return None;
    };
    let Ok(canonical_inner_unknown) = encode_signal_whisper_message(&decoded_inner_unknown) else {
        return None;
    };
    assert_eq!(
        canonical_inner_unknown, inner_message,
        "pre-key inner unknown field should canonicalize before decrypt"
    );
    let inner_unknown_message = PreKeySignalMessage {
        registration_id: Some(encrypted.message.registration_id),
        pre_key_id: encrypted.message.pre_key_id,
        signed_pre_key_id: Some(encrypted.message.signed_pre_key_id),
        base_key: Some(encrypted.message.base_key.clone()),
        identity_key: Some(encrypted.message.identity_key.clone()),
        message: Some(Bytes::from(inner_unknown)),
    }
    .encode_to_vec();
    let Ok(decoded_inner_unknown_message) =
        decode_signal_pre_key_whisper_message(&inner_unknown_message)
    else {
        return None;
    };
    let Ok(canonical_inner_unknown_message) =
        encode_signal_pre_key_whisper_message(&decoded_inner_unknown_message)
    else {
        return None;
    };
    assert_eq!(
        canonical_inner_unknown_message, encrypted.message_bytes,
        "pre-key inner unknown outer message should canonicalize before decrypt"
    );
    let Ok(inner_unknown_decrypted) = decrypt_signal_inbound_pre_key_session_message(
        bob_material,
        local_one_time,
        &inner_unknown_message,
    ) else {
        return None;
    };
    assert_eq!(&inner_unknown_decrypted.plaintext, plaintext);
    assert_eq!(inner_unknown_decrypted.record, canonical_decrypted.record);
    Some(())
}

fn drive_provider_new_ratchet_failed_decrypt_preservation(data: &[u8]) {
    let local_ratchet = key_pair_from_seed(data, 1240, 0x39);
    let old_remote_ratchet = key_pair_from_seed(data, 1272, 0x59);
    let new_remote_ratchet = key_pair_from_seed(data, 1304, 0x79);
    let old_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&old_remote_ratchet.public));
    let new_remote_ratchet_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&new_remote_ratchet.public));
    if old_remote_ratchet_key == new_remote_ratchet_key {
        return;
    }

    let receiving_counter = data.get(1336).copied().unwrap_or(0) as u32 % 3;
    let skipped_count = 1 + (data.get(1337).copied().unwrap_or(0) as u32 % 4);
    let message_previous_counter = receiving_counter + skipped_count;
    let previous_counter = data.get(1338).copied().unwrap_or(0) as u32 % 8;
    let record = SignalProviderSessionRecord {
        remote_registration_id: 0x1234_5681,
        remote_identity_key: prefixed_seed_public(data, 1339, 0x99),
        root_key: SignalRootKey {
            key: secret_from_seed(data, 1371, 0xb9),
        },
        sending_chain: SignalMessageChainKey {
            key: secret_from_seed(data, 1403, 0xd9),
            counter: data.get(1435).copied().unwrap_or(0) as u32 % 8,
        },
        receiving_chain: Some(SignalMessageChainKey {
            key: secret_from_seed(data, 1436, 0xf9),
            counter: receiving_counter,
        }),
        remote_ratchet_key: Some(old_remote_ratchet_key),
        local_ratchet_key_pair: local_ratchet,
        previous_counter,
        message_keys: Vec::new(),
    };
    let Ok(record_bytes) = encode_signal_provider_session_record(&record) else {
        return;
    };

    let Ok(root_step) = ratchet_signal_root_key(
        &record.root_key,
        record.local_ratchet_key_pair.private.expose(),
        &new_remote_ratchet_key,
    ) else {
        return;
    };
    let Ok(new_step) = ratchet_signal_message_chain(&root_step.chain_key) else {
        return;
    };
    let plaintext = structured_plaintext(data, 1468, new_step.message_counter);
    let Ok(ciphertext) = encrypt_signal_message_body(&plaintext, &new_step.message_keys) else {
        return;
    };
    let message = SignalWhisperMessage {
        ephemeral_key: new_remote_ratchet_key.clone(),
        counter: new_step.message_counter,
        previous_counter: message_previous_counter,
        ciphertext,
    };
    let Ok(message_bytes) = encode_signal_whisper_message(&message) else {
        return;
    };

    let mut tampered = message.clone();
    let mut tampered_ciphertext = tampered.ciphertext.to_vec();
    let Some(last) = tampered_ciphertext.last_mut() else {
        return;
    };
    *last ^= 1;
    tampered.ciphertext = Bytes::from(tampered_ciphertext);
    if let Ok(tampered_bytes) = encode_signal_whisper_message(&tampered) {
        assert!(
            decrypt_signal_provider_session_record_message(&record_bytes, &tampered_bytes).is_err(),
            "tampered provider new-ratchet message should fail to decrypt"
        );
    }

    let Ok(decrypted) =
        decrypt_signal_provider_session_record_message(&record_bytes, &message_bytes)
    else {
        return;
    };
    assert_eq!(decrypted.plaintext, plaintext);
    let replay_err =
        decrypt_signal_provider_session_record_message(&decrypted.record, &message_bytes)
            .expect_err("consumed provider new-ratchet message should reject replay");
    assert_eq!(
        replay_err.to_string(),
        format!(
            "protocol error: duplicate or old Signal message counter: {}",
            new_step.message_counter
        ),
        "unexpected provider new-ratchet replay error"
    );

    let Ok(next_new_step) = ratchet_signal_message_chain(&new_step.next_chain_key) else {
        return;
    };
    let next_plaintext = structured_plaintext(data, 1500, next_new_step.message_counter);
    let Ok(next_ciphertext) =
        encrypt_signal_message_body(&next_plaintext, &next_new_step.message_keys)
    else {
        return;
    };
    let next_message = SignalWhisperMessage {
        ephemeral_key: new_remote_ratchet_key,
        counter: next_new_step.message_counter,
        previous_counter: message_previous_counter,
        ciphertext: next_ciphertext,
    };
    let Ok(next_message_bytes) = encode_signal_whisper_message(&next_message) else {
        return;
    };
    let Ok(next_decrypted) =
        decrypt_signal_provider_session_record_message(&decrypted.record, &next_message_bytes)
    else {
        return;
    };
    assert_eq!(next_decrypted.plaintext, next_plaintext);
    let _ = decode_signal_provider_session_record(&decrypted.record);
}

fn drive_sender_key_out_of_order_replay(data: &[u8]) {
    let signing_key = key_pair_from_seed(data, 324, 0x21);
    let key_id = 1 + u32::from(data.get(356).copied().unwrap_or(0));
    let initial_iteration = u32::from(data.get(357).copied().unwrap_or(0) % 4);
    let message_count = 2 + usize::from(data.get(358).copied().unwrap_or(0) % 4);
    let chain_key = seed_32(data, 359, 0x41);
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));

    let local_record = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: initial_iteration,
            },
            signing_public_key: signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    };
    let Ok(mut local_record_bytes) = encode_signal_sender_key_record(&local_record) else {
        return;
    };

    let mut messages = Vec::new();
    for index in 0..message_count {
        let plaintext =
            structured_plaintext(data, 391 + (index * 17), initial_iteration + index as u32);
        let Ok(encrypted) =
            encrypt_signal_sender_key_record_message(&local_record_bytes, &plaintext)
        else {
            return;
        };
        let _ = decode_signal_sender_key_message(&encrypted.message_bytes);
        local_record_bytes = encrypted.record;
        messages.push((plaintext, encrypted.message_bytes));
    }

    let Ok(distribution) = build_signal_sender_key_distribution_message(
        key_id,
        initial_iteration,
        &chain_key,
        &signing_public_key,
    ) else {
        return;
    };
    let Ok(mut receiver_record) =
        process_signal_sender_key_distribution_record(None, &distribution)
    else {
        return;
    };
    let verifier = XEdDsaNoiseCertificateVerifier;

    let Some((last_plaintext, last_message)) = messages.last() else {
        return;
    };
    let Ok(decrypted) =
        decrypt_signal_sender_key_record_message(&receiver_record, last_message, &verifier)
    else {
        return;
    };
    if decrypted.plaintext.as_ref() != last_plaintext.as_ref() {
        return;
    }
    let _ = decode_signal_sender_key_record(&decrypted.record);
    receiver_record = decrypted.record;

    let Some((first_plaintext, first_message)) = messages.first() else {
        return;
    };
    let Ok(first_decoded) = decode_signal_sender_key_message(first_message) else {
        return;
    };
    let tampered_ciphertext = Bytes::copy_from_slice(
        &first_decoded.ciphertext[..first_decoded.ciphertext.len().saturating_sub(1)],
    );
    let Ok(tampered_first) = sign_signal_sender_key_message(
        first_decoded.key_id,
        first_decoded.iteration,
        tampered_ciphertext,
        signing_key.private.expose(),
    ) else {
        return;
    };
    if let Ok(tampered_first) = encode_signal_sender_key_message(&tampered_first) {
        assert!(
            decrypt_signal_sender_key_record_message(&receiver_record, &tampered_first, &verifier)
                .is_err(),
            "tampered sender-key skipped message should fail to decrypt"
        );
    }

    let invalid_signature_first = SignalSenderKeyMessage {
        signature: Bytes::from(vec![0u8; 64]),
        ..first_decoded.clone()
    };
    if let Ok(invalid_signature_first) = encode_signal_sender_key_message(&invalid_signature_first)
    {
        let invalid_signature_err = decrypt_signal_sender_key_record_message(
            &receiver_record,
            &invalid_signature_first,
            &verifier,
        )
        .expect_err("invalid sender-key skipped message signature should fail");
        assert_eq!(
            invalid_signature_err.to_string(),
            "protocol error: invalid Signal sender-key message signature",
            "unexpected sender-key invalid-signature error"
        );
    }

    let Ok(decrypted) =
        decrypt_signal_sender_key_record_message(&receiver_record, first_message, &verifier)
    else {
        return;
    };
    if decrypted.plaintext.as_ref() != first_plaintext.as_ref() {
        return;
    }
    let replay_err =
        decrypt_signal_sender_key_record_message(&decrypted.record, first_message, &verifier)
            .expect_err("consumed sender-key skipped message should reject replay");
    assert_eq!(
        replay_err.to_string(),
        format!(
            "protocol error: duplicate Signal sender-key message iteration: {}",
            first_decoded.iteration
        ),
        "unexpected consumed sender-key replay error"
    );
    let _ = decode_signal_sender_key_record(&decrypted.record);
}

fn drive_sender_key_distribution_stale_replacement(data: &[u8]) {
    let signing_key = key_pair_from_seed(data, 760, 0x25);
    let replacement_signing_key = key_pair_from_seed(data, 792, 0x45);
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let replacement_signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&replacement_signing_key.public));
    if signing_public_key == replacement_signing_public_key {
        return;
    }

    let key_id = 1 + u32::from(data.get(824).copied().unwrap_or(0));
    let current_iteration = 2 + u32::from(data.get(825).copied().unwrap_or(0) % 8);
    let stale_iteration = u32::from(data.get(826).copied().unwrap_or(0)) % current_iteration;
    let replacement_iteration = u32::from(data.get(827).copied().unwrap_or(0) % 8);
    let existing_chain_key = seed_32(data, 828, 0x65);
    let stale_chain_key = seed_32(data, 860, 0x85);
    let replacement_chain_key = seed_32(data, 892, 0xa5);
    let skipped_seed = seed_32(data, 924, 0xc5);

    let existing_record = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(existing_chain_key.to_vec()),
                iteration: current_iteration,
            },
            signing_public_key: signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: vec![SignalSenderStoredMessageKey {
                iteration: current_iteration - 1,
                seed: SecretBytes::from(skipped_seed.to_vec()),
            }],
        }],
    };
    let Ok(existing_record_bytes) = encode_signal_sender_key_record(&existing_record) else {
        return;
    };

    let Ok(stale_distribution) = build_signal_sender_key_distribution_message(
        key_id,
        stale_iteration,
        &stale_chain_key,
        &signing_public_key,
    ) else {
        return;
    };
    let Ok(stale_record_bytes) = process_signal_sender_key_distribution_record(
        Some(&existing_record_bytes),
        &stale_distribution,
    ) else {
        return;
    };
    let Ok(stale_record) = decode_signal_sender_key_record(&stale_record_bytes) else {
        return;
    };
    assert_eq!(stale_record.states.len(), 1);
    assert_eq!(stale_record.states[0].key_id, key_id);
    assert_eq!(
        stale_record.states[0].chain_key.iteration,
        current_iteration
    );
    assert_eq!(
        stale_record.states[0].chain_key.key.expose(),
        &existing_chain_key
    );
    assert!(stale_record.states[0].signing_private_key.is_some());
    assert_eq!(stale_record.states[0].message_keys.len(), 1);
    assert_eq!(
        stale_record.states[0].message_keys[0].iteration,
        current_iteration - 1
    );
    assert_eq!(
        stale_record.states[0].message_keys[0].seed.expose(),
        &skipped_seed
    );

    let Ok(replacement_distribution) = build_signal_sender_key_distribution_message(
        key_id,
        replacement_iteration,
        &replacement_chain_key,
        &replacement_signing_public_key,
    ) else {
        return;
    };
    let Ok(replaced_record_bytes) = process_signal_sender_key_distribution_record(
        Some(&stale_record_bytes),
        &replacement_distribution,
    ) else {
        return;
    };
    let Ok(replaced_record) = decode_signal_sender_key_record(&replaced_record_bytes) else {
        return;
    };
    assert_eq!(replaced_record.states.len(), 1);
    assert_eq!(replaced_record.states[0].key_id, key_id);
    assert_eq!(
        replaced_record.states[0].chain_key.iteration,
        replacement_iteration
    );
    assert_eq!(
        replaced_record.states[0].chain_key.key.expose(),
        &replacement_chain_key
    );
    assert_eq!(
        replaced_record.states[0].signing_public_key,
        replacement_signing_public_key
    );
    assert!(replaced_record.states[0].signing_private_key.is_none());
    assert!(replaced_record.states[0].message_keys.is_empty());

    let local_replacement_record = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(replacement_chain_key.to_vec()),
                iteration: replacement_iteration,
            },
            signing_public_key: replacement_signing_public_key,
            signing_private_key: Some(SecretBytes::from(
                replacement_signing_key.private.expose().to_vec(),
            )),
            message_keys: Vec::new(),
        }],
    };
    let Ok(local_replacement_record_bytes) =
        encode_signal_sender_key_record(&local_replacement_record)
    else {
        return;
    };
    let replacement_plaintext = structured_plaintext(data, 956, replacement_iteration);
    let Ok(encrypted) = encrypt_signal_sender_key_record_message(
        &local_replacement_record_bytes,
        &replacement_plaintext,
    ) else {
        return;
    };
    let verifier = XEdDsaNoiseCertificateVerifier;
    let Ok(decrypted) = decrypt_signal_sender_key_record_message(
        &replaced_record_bytes,
        &encrypted.message_bytes,
        &verifier,
    ) else {
        return;
    };
    assert_eq!(decrypted.plaintext, replacement_plaintext);
    let _ = decode_signal_sender_key_record(&decrypted.record);
}

fn drive_sender_key_distribution_same_signer_stale_chain_retry(data: &[u8]) {
    let signing_key = key_pair_from_seed(data, 3016, 0x2b);
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let key_id = 1 + u32::from(data.get(3048).copied().unwrap_or(0));
    let stale_iteration = u32::from(data.get(3049).copied().unwrap_or(0) % 4);
    let fresh_iteration = stale_iteration + 1 + u32::from(data.get(3050).copied().unwrap_or(0) % 4);
    let stale_chain_key = seed_32(data, 3051, 0x4b);
    let fresh_chain_key = seed_32(data, 3083, 0x6b);

    let stale_record = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(stale_chain_key.to_vec()),
                iteration: stale_iteration,
            },
            signing_public_key: signing_public_key.clone(),
            signing_private_key: None,
            message_keys: Vec::new(),
        }],
    };
    let fresh_sender_record = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(fresh_chain_key.to_vec()),
                iteration: fresh_iteration,
            },
            signing_public_key: signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    };
    let Ok(stale_record_bytes) = encode_signal_sender_key_record(&stale_record) else {
        return;
    };
    let Ok(fresh_sender_record_bytes) = encode_signal_sender_key_record(&fresh_sender_record)
    else {
        return;
    };

    let fresh_plaintext = structured_plaintext(data, 3115, fresh_iteration);
    let Ok(fresh_encrypted) =
        encrypt_signal_sender_key_record_message(&fresh_sender_record_bytes, &fresh_plaintext)
    else {
        return;
    };
    let verifier = XEdDsaNoiseCertificateVerifier;
    let stale_decrypt_err = decrypt_signal_sender_key_record_message(
        &stale_record_bytes,
        &fresh_encrypted.message_bytes,
        &verifier,
    )
    .expect_err("same-signer stale sender-key chain should fail body decrypt");
    assert_eq!(
        stale_decrypt_err.to_string(),
        "crypto error: decryption failed",
        "unexpected same-signer stale-chain sender-key error"
    );

    let Ok(distribution) = build_signal_sender_key_distribution_message(
        key_id,
        fresh_iteration,
        &fresh_chain_key,
        &signing_public_key,
    ) else {
        return;
    };
    let Ok(candidate_record) =
        process_signal_sender_key_distribution_record(Some(&stale_record_bytes), &distribution)
    else {
        return;
    };

    let truncated_ciphertext = Bytes::copy_from_slice(
        &fresh_encrypted.message.ciphertext[..fresh_encrypted.message.ciphertext.len() - 1],
    );
    let Ok(tampered) = sign_signal_sender_key_message(
        fresh_encrypted.message.key_id,
        fresh_encrypted.message.iteration,
        truncated_ciphertext,
        signing_key.private.expose(),
    ) else {
        return;
    };
    let Ok(tampered) = encode_signal_sender_key_message(&tampered) else {
        return;
    };
    assert!(
        decrypt_signal_sender_key_record_message(&candidate_record, &tampered, &verifier).is_err(),
        "same-signer distribution candidate must reject tampered sender-key body"
    );
    assert_eq!(
        decode_signal_sender_key_record(&stale_record_bytes)
            .expect("stale sender-key record remains decodable"),
        stale_record
    );

    let Ok(recovered) = decrypt_signal_sender_key_record_message(
        &candidate_record,
        &fresh_encrypted.message_bytes,
        &verifier,
    ) else {
        return;
    };
    assert_eq!(recovered.plaintext, fresh_plaintext);
    let Ok(recovered_record) = decode_signal_sender_key_record(&recovered.record) else {
        return;
    };
    assert_eq!(recovered_record.states.len(), 1);
    assert_eq!(recovered_record.states[0].key_id, key_id);
    assert_eq!(
        recovered_record.states[0].chain_key.iteration,
        fresh_iteration + 1
    );
    assert_eq!(
        recovered_record.states[0].signing_public_key,
        signing_public_key
    );
    assert!(recovered_record.states[0].signing_private_key.is_none());
}

fn drive_sender_key_distribution_full_record_truncation(data: &[u8]) {
    let key_id = 1 + u32::from(data.get(1215).copied().unwrap_or(0));
    let distribution_iteration = u32::from(data.get(1216).copied().unwrap_or(0) % 16);
    let distribution_chain_key = seed_32(data, 1217, 0x17);
    let distribution_signing_public_key = prefixed_seed_public(data, 1249, 0x37);
    let mut chain_keys = Vec::with_capacity(STRUCTURED_SENDER_KEY_STATE_LIMIT);
    let mut signing_public_keys = Vec::with_capacity(STRUCTURED_SENDER_KEY_STATE_LIMIT);
    let mut existing_states = Vec::with_capacity(STRUCTURED_SENDER_KEY_STATE_LIMIT);
    for index in 0..STRUCTURED_SENDER_KEY_STATE_LIMIT {
        let chain_key = seed_32(data, 1281 + (index * 32), 0x57 + index as u8);
        let signing_public_key =
            prefixed_seed_public(data, 1441 + (index * 32), 0x77 + index as u8);
        chain_keys.push(chain_key);
        signing_public_keys.push(signing_public_key.clone());
        existing_states.push(SignalSenderKeyState {
            key_id: key_id + 1 + index as u32,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 3 + index as u32,
            },
            signing_public_key,
            signing_private_key: None,
            message_keys: Vec::new(),
        });
    }

    let Ok(existing_record_bytes) = encode_signal_sender_key_record(&SignalSenderKeyRecord {
        states: existing_states,
    }) else {
        return;
    };
    let Ok(distribution) = build_signal_sender_key_distribution_message(
        key_id,
        distribution_iteration,
        &distribution_chain_key,
        &distribution_signing_public_key,
    ) else {
        return;
    };
    let Ok(updated_record_bytes) =
        process_signal_sender_key_distribution_record(Some(&existing_record_bytes), &distribution)
    else {
        return;
    };
    let Ok(updated_record) = decode_signal_sender_key_record(&updated_record_bytes) else {
        return;
    };

    assert_eq!(
        updated_record.states.len(),
        STRUCTURED_SENDER_KEY_STATE_LIMIT
    );
    assert_eq!(updated_record.states[0].key_id, key_id);
    assert_eq!(
        updated_record.states[0].chain_key.iteration,
        distribution_iteration
    );
    assert_eq!(
        updated_record.states[0].chain_key.key.expose(),
        &distribution_chain_key
    );
    assert_eq!(
        updated_record.states[0].signing_public_key,
        distribution_signing_public_key
    );
    assert!(updated_record.states[0].signing_private_key.is_none());
    assert!(updated_record.states[0].message_keys.is_empty());

    for (index, state) in updated_record.states.iter().skip(1).enumerate() {
        assert_eq!(state.key_id, key_id + 1 + index as u32);
        assert_eq!(state.chain_key.iteration, 3 + index as u32);
        assert_eq!(state.chain_key.key.expose(), &chain_keys[index]);
        assert_eq!(state.signing_public_key, signing_public_keys[index]);
    }
    assert!(
        !updated_record
            .states
            .iter()
            .any(|state| state.key_id == key_id + STRUCTURED_SENDER_KEY_STATE_LIMIT as u32)
    );
}

fn drive_sender_key_required_field_rejection(data: &[u8]) {
    let key_id = 1 + u32::from(data.get(1420).copied().unwrap_or(0));
    let iteration = 1 + u32::from(data.get(1421).copied().unwrap_or(0) % 32);
    let chain_seed = seed_32(data, 1422, 0x91);
    let signing_public_key = prefixed_seed_public(data, 1454, 0xa1);
    let skipped_iteration = u32::from(data.get(1486).copied().unwrap_or(0)) % iteration;
    let skipped_seed = seed_32(data, 1487, 0xb1);

    let chain_key = sender_chain_key_wire(Some(iteration), Some(&chain_seed));
    let signing_key = sender_signing_key_wire(Some(&signing_public_key));
    let skipped_key = sender_message_key_wire(Some(skipped_iteration), Some(&skipped_seed));

    let valid = sender_key_record_wire(sender_key_state_wire(
        Some(key_id),
        Some(&chain_key),
        Some(&signing_key),
        std::slice::from_ref(&skipped_key),
    ));
    let decoded =
        decode_signal_sender_key_record(&valid).expect("structured sender-key record must decode");
    assert_eq!(decoded.states.len(), 1);
    let state = &decoded.states[0];
    assert_eq!(state.key_id, key_id);
    assert_eq!(state.chain_key.iteration, iteration);
    assert_eq!(state.chain_key.key.expose(), &chain_seed);
    assert_eq!(state.signing_public_key, signing_public_key);
    assert_eq!(state.message_keys.len(), 1);
    assert_eq!(state.message_keys[0].iteration, skipped_iteration);
    assert_eq!(state.message_keys[0].seed.expose(), &skipped_seed);

    let cases = [
        (
            sender_key_record_wire(sender_key_state_wire(
                None,
                Some(&chain_key),
                Some(&signing_key),
                &[],
            )),
            "Signal sender-key state missing id",
        ),
        (
            sender_key_record_wire(sender_key_state_wire(
                Some(key_id),
                None,
                Some(&signing_key),
                &[],
            )),
            "Signal sender-key state missing chain key",
        ),
        (
            sender_key_record_wire(sender_key_state_wire(
                Some(key_id),
                Some(&sender_chain_key_wire(Some(iteration), None)),
                Some(&signing_key),
                &[],
            )),
            "Signal sender-key state missing chain key seed",
        ),
        (
            sender_key_record_wire(sender_key_state_wire(
                Some(key_id),
                Some(&sender_chain_key_wire(None, Some(&chain_seed))),
                Some(&signing_key),
                &[],
            )),
            "Signal sender-key state missing chain iteration",
        ),
        (
            sender_key_record_wire(sender_key_state_wire(
                Some(key_id),
                Some(&chain_key),
                None,
                &[],
            )),
            "Signal sender-key state missing signing key",
        ),
        (
            sender_key_record_wire(sender_key_state_wire(
                Some(key_id),
                Some(&chain_key),
                Some(&sender_signing_key_wire(None)),
                &[],
            )),
            "Signal sender-key state missing signing public key",
        ),
        (
            sender_key_record_wire(sender_key_state_wire(
                Some(key_id),
                Some(&chain_key),
                Some(&signing_key),
                &[sender_message_key_wire(None, Some(&skipped_seed))],
            )),
            "Signal sender-key message key missing iteration",
        ),
        (
            sender_key_record_wire(sender_key_state_wire(
                Some(key_id),
                Some(&chain_key),
                Some(&signing_key),
                &[sender_message_key_wire(Some(skipped_iteration), None)],
            )),
            "Signal sender-key message key missing seed",
        ),
    ];

    for (record, expected_error) in cases {
        let err = decode_signal_sender_key_record(&record)
            .expect_err("structured malformed sender-key record must be rejected");
        assert_eq!(
            err.to_string(),
            format!("protocol error: {expected_error}"),
            "unexpected sender-key required-field error"
        );
    }
}

fn drive_sender_key_record_invariant_rejection(data: &[u8]) {
    let signing_key = key_pair_from_seed(data, 2752, 0x29);
    let other_signing_key = key_pair_from_seed(data, 2784, 0x49);
    let signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public));
    let other_signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&other_signing_key.public));
    if signing_public_key == other_signing_public_key {
        return;
    }

    let key_id = 1 + u32::from(data.get(2816).copied().unwrap_or(0));
    let chain_iteration = 2 + u32::from(data.get(2817).copied().unwrap_or(0) % 32);
    let skipped_iteration = u32::from(data.get(2818).copied().unwrap_or(0)) % chain_iteration;
    let valid = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: secret_from_seed(data, 2819, 0x69),
                iteration: chain_iteration,
            },
            signing_public_key: signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: vec![SignalSenderStoredMessageKey {
                iteration: skipped_iteration,
                seed: secret_from_seed(data, 2851, 0x89),
            }],
        }],
    };
    let Ok(valid_bytes) = encode_signal_sender_key_record(&valid) else {
        return;
    };
    let decoded =
        decode_signal_sender_key_record(&valid_bytes).expect("valid sender-key record decodes");
    assert_eq!(decoded.states.len(), 1);
    assert_eq!(decoded.states[0].key_id, key_id);
    assert_eq!(decoded.states[0].chain_key.iteration, chain_iteration);
    assert_eq!(
        decoded.states[0].message_keys[0].iteration,
        skipped_iteration
    );

    let mut mismatched_signing_key = valid.clone();
    mismatched_signing_key.states[0].signing_public_key = other_signing_public_key.clone();
    assert_sender_key_record_encode_error(
        &mismatched_signing_key,
        "Signal sender-key signing public key does not match private key",
    );

    let mut duplicate_state = valid.clone();
    let mut duplicate = duplicate_state.states[0].clone();
    duplicate.chain_key.key = secret_from_seed(data, 2883, 0xa9);
    duplicate.chain_key.iteration = chain_iteration + 1;
    duplicate.signing_private_key = None;
    duplicate_state.states.push(duplicate);
    assert_sender_key_record_encode_error(&duplicate_state, "duplicate Signal sender-key state");

    let mut duplicate_skipped = valid.clone();
    duplicate_skipped.states[0]
        .message_keys
        .push(SignalSenderStoredMessageKey {
            iteration: skipped_iteration,
            seed: secret_from_seed(data, 2915, 0xc9),
        });
    assert_sender_key_record_encode_error(
        &duplicate_skipped,
        "duplicate Signal sender-key skipped message iteration",
    );

    let mut future_skipped = valid;
    future_skipped.states[0].message_keys = vec![SignalSenderStoredMessageKey {
        iteration: chain_iteration,
        seed: secret_from_seed(data, 2947, 0xe9),
    }];
    assert_sender_key_record_encode_error(
        &future_skipped,
        "Signal sender-key skipped iteration must be below chain iteration",
    );
}

fn drive_sender_key_multi_state_decrypt(data: &[u8]) {
    let old_signing_key = key_pair_from_seed(data, 2040, 0x27);
    let replacement_signing_key = key_pair_from_seed(data, 2072, 0x47);
    let old_signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&old_signing_key.public));
    let replacement_signing_public_key =
        Bytes::copy_from_slice(&prefixed_signal_public_key(&replacement_signing_key.public));
    if old_signing_public_key == replacement_signing_public_key {
        return;
    }

    let key_id = 1 + u32::from(data.get(2104).copied().unwrap_or(0));
    let old_iteration = u32::from(data.get(2105).copied().unwrap_or(0) % 8);
    let replacement_iteration = u32::from(data.get(2106).copied().unwrap_or(0) % 8);
    let old_chain_key = seed_32(data, 2107, 0x67);
    let replacement_chain_key = seed_32(data, 2139, 0x87);

    let old_sender_record = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(old_chain_key.to_vec()),
                iteration: old_iteration,
            },
            signing_public_key: old_signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(old_signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    };
    let replacement_sender_record = SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(replacement_chain_key.to_vec()),
                iteration: replacement_iteration,
            },
            signing_public_key: replacement_signing_public_key.clone(),
            signing_private_key: Some(SecretBytes::from(
                replacement_signing_key.private.expose().to_vec(),
            )),
            message_keys: Vec::new(),
        }],
    };
    let receiver_record = SignalSenderKeyRecord {
        states: vec![
            SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(replacement_chain_key.to_vec()),
                    iteration: replacement_iteration,
                },
                signing_public_key: replacement_signing_public_key.clone(),
                signing_private_key: None,
                message_keys: Vec::new(),
            },
            SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(old_chain_key.to_vec()),
                    iteration: old_iteration,
                },
                signing_public_key: old_signing_public_key.clone(),
                signing_private_key: None,
                message_keys: Vec::new(),
            },
        ],
    };

    let Ok(old_sender_record) = encode_signal_sender_key_record(&old_sender_record) else {
        return;
    };
    let Ok(replacement_sender_record) = encode_signal_sender_key_record(&replacement_sender_record)
    else {
        return;
    };
    let Ok(receiver_record) = encode_signal_sender_key_record(&receiver_record) else {
        return;
    };

    let old_plaintext = structured_plaintext(data, 2171, old_iteration);
    let replacement_plaintext = structured_plaintext(data, 2203, replacement_iteration);
    let Ok(old_encrypted) =
        encrypt_signal_sender_key_record_message(&old_sender_record, &old_plaintext)
    else {
        return;
    };
    let Ok(replacement_encrypted) = encrypt_signal_sender_key_record_message(
        &replacement_sender_record,
        &replacement_plaintext,
    ) else {
        return;
    };

    let verifier = XEdDsaNoiseCertificateVerifier;
    let mut invalid_signature_message = old_encrypted.message_bytes.to_vec();
    let Some(signature_byte) = invalid_signature_message.last_mut() else {
        return;
    };
    *signature_byte ^= 1;
    let invalid_signature_err = decrypt_signal_sender_key_record_message(
        &receiver_record,
        &invalid_signature_message,
        &verifier,
    )
    .expect_err("tampered multi-state sender-key message should reject before decrypt");
    assert_eq!(
        invalid_signature_err.to_string(),
        "protocol error: invalid Signal sender-key message signature",
        "unexpected multi-state sender-key invalid-signature error"
    );

    let Ok(failed_decrypt_message) = sign_signal_sender_key_message(
        key_id,
        old_iteration,
        Bytes::from_static(b"not-a-valid-cbc-frame"),
        old_signing_key.private.expose(),
    ) else {
        return;
    };
    let Ok(failed_decrypt_message) = encode_signal_sender_key_message(&failed_decrypt_message)
    else {
        return;
    };
    let failed_decrypt_err = decrypt_signal_sender_key_record_message(
        &receiver_record,
        &failed_decrypt_message,
        &verifier,
    )
    .expect_err("valid-signature multi-state sender-key message should fail body decrypt");
    assert_eq!(
        failed_decrypt_err.to_string(),
        "crypto error: decryption failed",
        "unexpected multi-state sender-key failed-decrypt error"
    );

    let Ok(far_future_message) = sign_signal_sender_key_message(
        key_id,
        old_iteration + STRUCTURED_FAR_FUTURE_COUNTER_JUMP,
        Bytes::from_static(b"far-future-ciphertext"),
        old_signing_key.private.expose(),
    ) else {
        return;
    };
    let Ok(far_future_message) = encode_signal_sender_key_message(&far_future_message) else {
        return;
    };
    let far_future_err =
        decrypt_signal_sender_key_record_message(&receiver_record, &far_future_message, &verifier)
            .expect_err("far-future multi-state sender-key message should reject before decrypt");
    assert_eq!(
        far_future_err.to_string(),
        format!(
            "protocol error: Signal sender-key message is too far in the future: {STRUCTURED_FAR_FUTURE_COUNTER_JUMP}"
        ),
        "unexpected multi-state sender-key far-future error"
    );

    let Ok(old_decrypted) = decrypt_signal_sender_key_record_message(
        &receiver_record,
        &old_encrypted.message_bytes,
        &verifier,
    ) else {
        return;
    };
    assert_eq!(old_decrypted.plaintext, old_plaintext);
    let Ok(after_old) = decode_signal_sender_key_record(&old_decrypted.record) else {
        return;
    };
    assert_eq!(after_old.states.len(), 2);
    assert_eq!(
        after_old.states[0].signing_public_key,
        replacement_signing_public_key
    );
    assert_eq!(
        after_old.states[0].chain_key.iteration,
        replacement_iteration
    );
    assert_eq!(
        after_old.states[1].signing_public_key,
        old_signing_public_key
    );
    assert_eq!(after_old.states[1].chain_key.iteration, old_iteration + 1);

    let replay_err = decrypt_signal_sender_key_record_message(
        &old_decrypted.record,
        &old_encrypted.message_bytes,
        &verifier,
    )
    .expect_err("consumed multi-state sender-key message should reject replay");
    assert_eq!(
        replay_err.to_string(),
        format!("protocol error: duplicate Signal sender-key message iteration: {old_iteration}"),
        "unexpected multi-state sender-key replay error"
    );

    let Ok(replacement_decrypted) = decrypt_signal_sender_key_record_message(
        &old_decrypted.record,
        &replacement_encrypted.message_bytes,
        &verifier,
    ) else {
        return;
    };
    assert_eq!(replacement_decrypted.plaintext, replacement_plaintext);
    let Ok(after_replacement) = decode_signal_sender_key_record(&replacement_decrypted.record)
    else {
        return;
    };
    assert_eq!(after_replacement.states.len(), 2);
    assert_eq!(
        after_replacement.states[0].chain_key.iteration,
        replacement_iteration + 1
    );
    assert_eq!(
        after_replacement.states[1].chain_key.iteration,
        old_iteration + 1
    );
}

fn key_pair_from_seed(data: &[u8], offset: usize, fill: u8) -> KeyPair {
    let private = seed_32(data, offset, fill);
    KeyPair {
        public: public_key_from_private(&private),
        private: SecretBytes::from(private.to_vec()),
    }
}

fn prefixed_seed_public(data: &[u8], offset: usize, fill: u8) -> Bytes {
    let private = seed_32(data, offset, fill);
    let public = public_key_from_private(&private);
    Bytes::copy_from_slice(&prefixed_signal_public_key(&public))
}

fn secret_from_seed(data: &[u8], offset: usize, fill: u8) -> SecretBytes {
    SecretBytes::from(seed_32(data, offset, fill).to_vec())
}

fn provider_skipped_message_key(
    ratchet_key: Bytes,
    counter: u32,
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
) -> SignalProviderStoredMessageKey {
    SignalProviderStoredMessageKey {
        ratchet_key,
        counter,
        message_keys: SignalMessageKeyMaterial {
            cipher_key: SecretBytes::from(cipher_key.to_vec()),
            mac_key: SecretBytes::from(mac_key.to_vec()),
            iv,
        },
    }
}

fn assert_provider_record_encode_error(record: &SignalProviderSessionRecord, expected: &str) {
    let err = encode_signal_provider_session_record(record)
        .expect_err("invalid provider session record must reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected provider session record error"
    );
}

fn assert_sender_key_record_encode_error(record: &SignalSenderKeyRecord, expected: &str) {
    let err =
        encode_signal_sender_key_record(record).expect_err("invalid sender-key record must reject");
    assert_eq!(
        err.to_string(),
        format!("protocol error: {expected}"),
        "unexpected sender-key record error"
    );
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

fn structured_plaintext(data: &[u8], offset: usize, counter: u32) -> Bytes {
    let available = data
        .len()
        .saturating_sub(offset)
        .min(STRUCTURED_PLAINTEXT_LEN);
    if available == 0 {
        return Bytes::from(format!("signal-structured-{counter}"));
    }
    Bytes::copy_from_slice(&data[offset..offset + available])
}

fn sender_key_record_wire(state: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_field(&mut out, 1, &state);
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
