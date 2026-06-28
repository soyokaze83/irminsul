---
title: App-State & History Sync
type: concept
sources:
  - crates/wa-core/src/app_state.rs
  - crates/wa-core/src/history.rs
  - crates/wa-crypto/src/app_state.rs
related:
  - "[[wa-crypto]]"
  - "[[wa-core]]"
  - "[[Event Model]]"
  - "[[Media Transfer]]"
  - "[[wa-store]]"
summary: Encrypted, MAC-verified app-state collections (archive/mute/pin/…) synced via LT-hash patches, and bounded decoding of history-sync blobs.
updated: 2026-06-28
source_commit: ace4f9c
---

# App-State & History Sync

Two related sync mechanisms keep a companion device consistent with the phone:

- **App-state sync** — small, ongoing, **bidirectional** mutations of chat/contact
  settings (archive, mute, pin, star, mark-read, labels, contacts, push name),
  organized into versioned, MAC-verified *collections*.
- **History sync** — large, one-directional **bootstrap** dumps of past
  conversations, contacts, and metadata, delivered as compressed protobuf blobs.

## App-state crypto (`wa-crypto/src/app_state.rs`)

`derive_app_state_keys` expands key material into five keys — index, value-encrypt,
value-MAC, snapshot-MAC, patch-MAC (`crates/wa-crypto/src/app_state.rs:78`). MAC
helpers cover each level: `app_state_index_mac`, `app_state_value_mac` (truncated
HMAC-SHA512), `app_state_patch_mac`, `app_state_snapshot_mac` (`:111`–`:138`).
Values are AES-256-CBC (`encrypt_app_state_value_with_iv` / `decrypt_app_state_value`,
`:92`, `:104`). Integrity over a whole collection uses an **LT-hash** (a 128-byte
homomorphic hash): `app_state_lt_hash_subtract_then_add` removes old and adds new
operands so the running hash can be advanced per mutation without rehashing
everything (`:167`).

## App-state patches (`wa-core/src/app_state.rs`)

- **Collections** — `AppStateCollection` enumerates `CriticalBlock`,
  `CriticalUnblock(Low)`, `CriticalIdentity`, `Regular(High/Low)`
  (`crates/wa-core/src/app_state.rs:44`); each mutation targets a collection with a
  specific API version.
- **Build** — `build_*_patch` constructs a `ChatMutationPatch` per action:
  `build_mute_chat_patch` (`:2210`), `build_archive_chat_patch` (`:2230`),
  `build_mark_chat_read_patch` (`:2253`), `build_pin_chat_patch` (`:2276`),
  `build_star_message_patch` (`:2294`), `build_delete_chat_patch` (`:2318`),
  `build_push_name_patch` (`:2339`), `build_contact_patch` (`:2354`), label and
  quick-reply patches, etc.
- **Encrypt & bundle** — `encrypt_chat_mutation_patch[_with_iv]` (`:904`, `:961`)
  produces an `EncryptedAppStateMutation` (index_mac, value_mac, encrypted_value);
  `build_app_state_patch_bundle` (`:971`) advances the `AppStatePatchState`
  (version + LT-hash + index→value-MAC map, `:677`) and computes the snapshot/patch
  MACs, yielding a `SyncdPatch`.
- **Decode & verify** — `decode_app_state_patch` (`:1044`) decrypts mutations and
  verifies the patch MAC then the snapshot MAC against the advanced hash;
  `decode_app_state_snapshot` (`:1141`) does the same for a full snapshot.
- **Apply** — `apply_app_state_sync_response_to_store` (`:1568`) iterates
  collections/patches, decodes each, converts mutations to an [[Event Model|EventBatch]]
  (`event_batch_from_decoded_app_state_patch`, `:1203`), and persists the new state.
- **Keys & blocked collections** — sync keys arrive in messages
  (`save_app_state_sync_key_share`, `:1522`); a collection whose key hasn't arrived
  yet is parked as an `AppStateBlockedCollection` (`:1358`) and retried later.
  State and keys persist under the `AppStateSyncVersion`/`AppStateSyncKey`
  [[wa-store|namespaces]].
- **Dirty bits** — `build_clean_dirty_bits_node` clears server "dirty" flags after
  a resync (`:2014`).

## History sync (`wa-core/src/history.rs`)

History notifications carry either an inline payload or an external blob reference.
`decode_compressed_history_sync` zlib-inflates with a **bounded** ceiling
(`DEFAULT_MAX_HISTORY_INFLATED_BYTES` = 128 MiB) before protobuf-decoding
(`crates/wa-core/src/history.rs:178`, `:26`). External blobs download via
[[Media Transfer]] (`download_history_sync*`, `:120`). `process_history_sync`
(`:301`) walks the `HistorySync` by type (initial bootstrap / full / recent / …),
emitting `ChatEvent`/`ContactEvent`/`MessageEvent`s into a `ProcessedHistorySync`
(`:78`) under configurable caps — `DEFAULT_MAX_HISTORY_CHATS` (50k),
`_CONTACTS` (100k), `_MESSAGES` (100k) (`:27`). It also harvests
`HistoryLidPnMapping`s (`:72`, `collect_*_mappings` at `:1739`) to seed the
[[Signal Protocol|LID↔PN]] store.

Both flows are deliberately bounded — capped inflation and capped item counts —
consistent with the project's "bounded buffers on network parsers" stance.
