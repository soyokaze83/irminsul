---
title: Send Message Flow
type: flow
sources:
  - crates/wa-core/src/message.rs
  - crates/wa-core/src/retry.rs
  - crates/wa-core/src/placeholder.rs
related:
  - "[[Signal Protocol]]"
  - "[[Receive Message Flow]]"
  - "[[Connection Stack]]"
  - "[[Media Transfer]]"
  - "[[wa-client]]"
summary: Building a message, encoding to protobuf, per-recipient Signal encryption, relay-node assembly, and the retry/resend path on decryption failure.
updated: 2026-06-28
source_commit: ace4f9c
---

# Send Message Flow

How an outgoing message travels from a typed content value to encrypted stanzas on
the wire, and what happens when a recipient can't decrypt it.

## 1. Build content

`MessageContent` (`crates/wa-core/src/message.rs:1486`) is the union of every
supported type — text, image/video/audio/document/sticker, location/contact,
poll/event, reaction/edit/delete/pin, buttons/lists/templates, group-invite,
sender-key distribution, view-once, … Each has a validating builder, e.g.
`build_text_message` (`:1937`), `build_image_message` (`:2528`),
`build_poll_message` (which enforces ≥2 unique options and a 32-byte secret,
`:2053`). Media builders consume an `UploadedMedia` descriptor from
[[Media Transfer]]. The result is a [[wa-proto|`Message`]] protobuf.

## 2. Message id & encode

`generate_message_id` produces a `3EB0…` id from random bytes; `generate_message_id_v2`
derives a deterministic id from timestamp + user + random, SHA-256'd (`:3952`,
`:3967`). `encode_message` serializes the `Message` to bytes via prost (`:3993`).

## 3. Encrypt per recipient

`build_direct_message_relay` (`crates/wa-core/src/message.rs:3666`) loops over the
target devices (`MessageRelayRecipient`, `:1762`). For each:

- own devices get wrapped in a `device_sent` envelope (`build_device_sent_message`,
  `:3623`);
- the plaintext is handed to a `MessageEncryptor` (`:1752`) — the
  [[Signal Protocol]] provider — returning a `MessageEncryption` whose
  `MessageCiphertextType` is `msg` (existing session), `pkmsg` (pre-key /
  first contact), or `skmsg` (group sender key) (`:1719`).

When any recipient produced a `pkmsg`, the relay attaches the device-identity node.
Group sends additionally relay a `SenderKeyDistributionMessage` so members can
derive the sender key.

## 4. Assemble the relay node

Each ciphertext becomes `<to jid><enc v="2" type="msg|pkmsg|skmsg">…</enc></to>`,
collected under `<participants>`, wrapped in a root `<message id=… to=… type=…>`
node, with a participant hash (`generate_participant_hash_v2`, `:3754`). The
finished `MessageRelay` (`:1848`) is sent through the
[[Connection Stack|Connection]]. The server later returns an `ack`, surfaced as a
`MessageUpdate` ([[Event Model]]).

`MessageRelayOptions` (`:1786`) lets callers tune relay/encryption attributes and
attach extra nodes. [[wa-client|`Client::send_*`]] methods wrap all of this.

## 5. Receipts

Inbound delivery/read receipts are parsed into `MessageReceipt`
(`MessageReceiptType` covers Delivery/Read/Played/…, `:1856`) and the client
replies with `build_receipt_node` (`:3341`), batching ids via
`aggregate_receipts_from_message_keys` (`:3575`).

## Retry & resend (`retry.rs`)

If a recipient device fails to decrypt, it sends a `receipt type="retry"`.
`parse_retry_receipt` (`crates/wa-core/src/retry.rs:688`) extracts the failed
message ids, retry count, sender registration id, and any attached key bundle.

- `MessageRetryManager` keeps a TTL-bounded **recent-message cache**
  (`add_recent_message`, `:277`) so the original plaintext can be re-encrypted.
- `should_recreate_session` (`:358`) decides whether to rebuild the
  [[Signal Protocol]] session — always on a missing session or MAC error, otherwise
  honoring a cooldown.
- `plan_retry_resend` (`:495`) yields a `RetryReceiptPlan`: a resend target
  (all-devices vs a specific participant) and a `RetrySessionAction`
  (`InjectBundle` / `Refresh` / `DeleteAndRefresh`), including base-key-collision
  detection across retry attempts (`:546`).
- `prepare_retry_resends` (`:595`) turns the plan into `RetryResendJob`s for cached
  messages, listing any `missing_message_ids` it couldn't satisfy.

## Placeholders (`placeholder.rs`)

When *we* receive a ciphertext we can't open ("Message absent from node"), the
client can ask the phone to resend it. `PlaceholderResendTracker`
(`crates/wa-core/src/placeholder.rs:48`) atomically de-dupes resend requests
(`begin_request`, `:70`), bounded by capacity/TTL and a 14-day age limit, excluding
the "unavailable fanout" stub types (`:124`).
