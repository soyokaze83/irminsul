#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use prost::Message as _;
use wa_core::{
    APP_STATE_HASH_LEN, AppStateCollection, AppStateHashMutation, AppStatePatchState,
    ChatMutationPatch, LabelEditMutation, QuickReplyMutation, build_app_state_patch_bundle,
    build_label_edit_patch, build_pin_chat_patch, build_push_name_patch, build_quick_reply_patch,
    decode_app_state_patch, decode_app_state_snapshot, encrypt_chat_mutation_patch_with_iv,
    event_batch_from_decoded_app_state_patch, event_batch_from_decoded_app_state_snapshot,
};
use wa_proto::proto::{KeyId, SyncdPatch, SyncdSnapshot, SyncdVersion};

const MAX_INPUT_LEN: usize = 128 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    drive_raw_patch_decode(data);
    drive_raw_snapshot_decode(data);
    drive_structured_patch_decode(data);
    drive_structured_snapshot_decode(data);
});

fn drive_raw_patch_decode(data: &[u8]) {
    let Ok(patch) = SyncdPatch::decode(data) else {
        return;
    };
    let collection = collection(data.first().copied().unwrap_or_default());
    let previous = previous_state_for_patch(&patch, data);
    let key_data = fixed_bytes(data, 32, 32);
    let _ = decode_app_state_patch(collection, &previous, &patch, &key_data);

    let encoded = patch.encode_to_vec();
    if let Ok(decoded_again) = SyncdPatch::decode(encoded.as_slice()) {
        let _ = decode_app_state_patch(collection, &previous, &decoded_again, &key_data);
    }
}

fn drive_raw_snapshot_decode(data: &[u8]) {
    let Ok(snapshot) = SyncdSnapshot::decode(data) else {
        return;
    };
    let collection = collection(data.get(1).copied().unwrap_or_default());
    let key_data = fixed_bytes(data, 64, 32);
    let _ = decode_app_state_snapshot(collection, &snapshot, &key_data);

    let encoded = snapshot.encode_to_vec();
    if let Ok(decoded_again) = SyncdSnapshot::decode(encoded.as_slice()) {
        let _ = decode_app_state_snapshot(collection, &decoded_again, &key_data);
    }
}

fn drive_structured_patch_decode(data: &[u8]) {
    let Some((collection, previous, key_id, key_data, patch_a, patch_b)) =
        structured_patch_inputs(data)
    else {
        return;
    };
    let iv_a = fixed_bytes(data, 96, 16);
    let iv_b = fixed_bytes(data, 112, 16);
    let Ok(mutation_a) = encrypt_chat_mutation_patch_with_iv(&patch_a, &key_id, &key_data, &iv_a)
    else {
        return;
    };
    let Ok(mutation_b) = encrypt_chat_mutation_patch_with_iv(&patch_b, &key_id, &key_data, &iv_b)
    else {
        return;
    };
    let Ok(bundle) = build_app_state_patch_bundle(
        collection,
        &previous,
        &key_id,
        &key_data,
        [mutation_a, mutation_b],
    ) else {
        return;
    };

    if let Ok(decoded) = decode_app_state_patch(collection, &previous, &bundle.patch, &key_data) {
        let _ = event_batch_from_decoded_app_state_patch(&decoded, bool_flag(data, 0));
    }

    let mut bad_patch_mac = bundle.patch.clone();
    if let Some(patch_mac) = bad_patch_mac.patch_mac.as_mut() {
        flip_first_byte(patch_mac);
    }
    let _ = decode_app_state_patch(collection, &previous, &bad_patch_mac, &key_data);

    let mut bad_operation = bundle.patch.clone();
    if let Some(first) = bad_operation.mutations.first_mut() {
        first.operation = Some(99);
    }
    let _ = decode_app_state_patch(collection, &previous, &bad_operation, &key_data);

    let wrong_previous = AppStatePatchState::new(
        previous.version(),
        Bytes::from(vec![data.get(2).copied().unwrap_or(9); APP_STATE_HASH_LEN]),
    )
    .unwrap_or_else(|_| AppStatePatchState::empty());
    let _ = decode_app_state_patch(collection, &wrong_previous, &bundle.patch, &key_data);

    let wrong_key_data = fixed_bytes(data, 128, 32);
    let _ = decode_app_state_patch(collection, &previous, &bundle.patch, &wrong_key_data);
}

fn drive_structured_snapshot_decode(data: &[u8]) {
    let Some((collection, _previous, key_id, key_data, patch_a, _patch_b)) =
        structured_patch_inputs(data)
    else {
        return;
    };
    let iv = fixed_bytes(data, 160, 16);
    let Ok(mutation) = encrypt_chat_mutation_patch_with_iv(&patch_a, &key_id, &key_data, &iv)
    else {
        return;
    };
    let version = u64::from(data.get(3).copied().unwrap_or_default()) + 1;
    let Ok(expected_state) = AppStatePatchState::empty().apply_hash_mutations_at_version(
        version,
        [AppStateHashMutation::from_encrypted(&mutation).unwrap()],
    ) else {
        return;
    };
    let Ok(keys) = wa_crypto::derive_app_state_keys(&key_data) else {
        return;
    };
    let Ok(snapshot_mac) =
        wa_crypto::app_state_snapshot_mac(expected_state.hash(), version, collection.name(), &keys)
    else {
        return;
    };
    let Some(record) = mutation.mutation.record.clone() else {
        return;
    };
    let snapshot = SyncdSnapshot {
        version: Some(SyncdVersion {
            version: Some(version),
        }),
        records: vec![record],
        mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
        key_id: Some(KeyId {
            id: Some(key_id.clone()),
        }),
    };

    if let Ok(decoded) = decode_app_state_snapshot(collection, &snapshot, &key_data) {
        let _ = event_batch_from_decoded_app_state_snapshot(&decoded);
    }

    let mut bad_mac = snapshot.clone();
    if let Some(mac) = bad_mac.mac.as_mut() {
        flip_first_byte(mac);
    }
    let _ = decode_app_state_snapshot(collection, &bad_mac, &key_data);

    let mut mismatched_key = snapshot.clone();
    mismatched_key.key_id = Some(KeyId {
        id: Some(fixed_bytes(data, 192, 32)),
    });
    let _ = decode_app_state_snapshot(collection, &mismatched_key, &key_data);

    let wrong_key_data = fixed_bytes(data, 224, 32);
    let _ = decode_app_state_snapshot(collection, &snapshot, &wrong_key_data);
}

fn structured_patch_inputs(
    data: &[u8],
) -> Option<(
    AppStateCollection,
    AppStatePatchState,
    Bytes,
    Bytes,
    ChatMutationPatch,
    ChatMutationPatch,
)> {
    let collection = collection(data.get(4).copied().unwrap_or_default());
    let previous = AppStatePatchState::new(
        u64::from(data.get(5).copied().unwrap_or_default()),
        Bytes::from(vec![0u8; APP_STATE_HASH_LEN]),
    )
    .ok()?;
    let key_id = fixed_bytes(data, 6, 32);
    let key_data = fixed_bytes(data, 38, 32);
    let patch_a = structured_chat_patch(data.get(70).copied().unwrap_or_default(), data)?;
    let patch_b = structured_chat_patch(data.get(71).copied().unwrap_or_default(), data)?;
    Some((collection, previous, key_id, key_data, patch_a, patch_b))
}

fn structured_chat_patch(selector: u8, data: &[u8]) -> Option<ChatMutationPatch> {
    let timestamp = u64::from(selector) + 1;
    match selector % 4 {
        0 => build_pin_chat_patch(user_jid(data, 72), bool_flag(data, 73), timestamp).ok(),
        1 => build_push_name_patch(
            fuzz_text("Agent", data.get(74).copied().unwrap_or_default()),
            timestamp,
        )
        .ok(),
        2 => build_quick_reply_patch(
            QuickReplyMutation::new(
                fuzz_text("qr", data.get(75).copied().unwrap_or_default()),
                fuzz_text("/", data.get(76).copied().unwrap_or_default()),
                fuzz_text("hello", data.get(77).copied().unwrap_or_default()),
            ),
            timestamp,
        )
        .ok(),
        _ => build_label_edit_patch(
            LabelEditMutation::new(
                fuzz_text("label", data.get(78).copied().unwrap_or_default()),
                fuzz_text("Important", data.get(79).copied().unwrap_or_default()),
            ),
            timestamp,
        )
        .ok(),
    }
}

fn previous_state_for_patch(patch: &SyncdPatch, data: &[u8]) -> AppStatePatchState {
    let version = patch
        .version
        .as_ref()
        .and_then(|version| version.version)
        .and_then(|version| version.checked_sub(1))
        .unwrap_or_else(|| u64::from(data.get(80).copied().unwrap_or_default()));
    AppStatePatchState::new(version, fixed_bytes(data, 81, APP_STATE_HASH_LEN))
        .unwrap_or_else(|_| AppStatePatchState::empty())
}

fn collection(byte: u8) -> AppStateCollection {
    let collections = AppStateCollection::all();
    collections[usize::from(byte) % collections.len()]
}

fn fixed_bytes(data: &[u8], offset: usize, len: usize) -> Bytes {
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        out.push(
            data.get(offset + index)
                .copied()
                .unwrap_or((offset + index) as u8),
        );
    }
    Bytes::from(out)
}

fn user_jid(data: &[u8], offset: usize) -> String {
    format!(
        "{}@s.whatsapp.net",
        10_000 + u32::from(data.get(offset).copied().unwrap_or_default())
    )
}

fn bool_flag(data: &[u8], offset: usize) -> bool {
    data.get(offset)
        .copied()
        .unwrap_or_default()
        .is_multiple_of(2)
}

fn fuzz_text(prefix: &str, byte: u8) -> String {
    format!("{prefix}-{byte}")
}

fn flip_first_byte(bytes: &mut Bytes) {
    let mut raw = bytes.to_vec();
    if let Some(first) = raw.first_mut() {
        *first ^= 1;
    }
    *bytes = Bytes::from(raw);
}
