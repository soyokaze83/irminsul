---
title: Receive Message Flow
type: flow
sources:
  - crates/wa-core/src/router.rs
  - crates/wa-core/src/inbound.rs
  - crates/wa-core/src/receive.rs
related:
  - "[[Connection Stack]]"
  - "[[Signal Protocol]]"
  - "[[Event Model]]"
  - "[[Send Message Flow]]"
  - "[[Binary Node Codec]]"
summary: From a decoded inbound node to typed events — classify by tag, decrypt, unpad, convert to an EventBatch, and ack/nack.
updated: 2026-06-28
source_commit: ace4f9c
---

# Receive Message Flow

The mirror of the [[Send Message Flow]]: a decrypted frame becomes a
[[Binary Node Codec|node]], gets classified and (if encrypted) decrypted, and is
turned into [[Event Model|events]] the application consumes — with an ack or nack
returned to the server.

## 1. Classify & dispatch (`router.rs`)

`decode_inbound_binary_node` wraps a decoded node with its response tag
(`crates/wa-core/src/router.rs:23`). `dispatch_binary_node` (`:32`) first tries to
match the tag against a pending [[Connection Stack|query]]; an unmatched node is
emitted as a `RawNode` event for processing.

## 2. Route by top-level tag (`receive.rs`)

`process_inbound_node` (`crates/wa-core/src/receive.rs:202`) switches on the tag:
`message` → decode+decrypt; `receipt`, `ack`, `notification`, `call`,
`presence`/`chatstate` → their respective handlers; anything else is ignored. Each
returns an `InboundNodeProcessing` (`:125`) carrying the action, an optional
ack/nack response, an event count, and an optional error. `process_offline_node`
(`:226`) batches the initial offline dump, yielding periodically so the runtime
stays responsive.

## 3. Decode & decrypt a message (`inbound.rs`)

`decode_inbound_message` (`crates/wa-core/src/inbound.rs:555`):

1. `decode_inbound_message_info` (`:450`) reads id/from/participant/recipient,
   classifies the message (`InboundMessageKind`: chat/group/broadcast/newsletter,
   `:170`) by the sender's [[JID]] server, and extracts the addressing context
   (LID vs phone, `extract_addressing_context`, `:414`).
2. For each `<enc>` child it decrypts via the `InboundMessageDecryptor` trait
   (`:282`) — the [[Signal Protocol]] provider — per `InboundCiphertextType`
   (`msg`/`pkmsg`/`skmsg`, `:208`); `<plaintext>` children pass through.
3. `unpad_random_max16` strips the 1–16 byte random padding (`:582`), and the bytes
   are protobuf-decoded into a `Message`, unwrapping any `device_sent` envelope.

The result is a `DecodedInboundMessage` (`:269`).

## 4. Convert to events (`receive.rs`)

`event_batch_from_decoded_message` (`crates/wa-core/src/receive.rs:3355`) builds a
`MessageEvent` plus any reaction events, message updates (edits, poll updates,
event responses, pin actions), and deletes.
`push_decoded_message_to_buffer` (`:3759`) pushes the batch into the
[[Event Model|EventBuffer]] and returns the event count.

Non-message nodes have their own factories:

- **receipts** → `event_batch_from_inbound_receipt_node` (`:3937`) — including
  `<rmr>` media-retry receipts;
- **acks** → `event_batch_from_inbound_ack` (`:4000`) — status/error updates for
  sent messages;
- **notifications** → group updates
  (`event_batch_from_group_notification_node`, `:1164`), account/blocklist/server-sync,
  newsletter (reactions/views/participants/settings), business, default
  disappearing mode, media-retry, and presence — a fan-out over
  `*_events_from_notification_node` helpers;
- **calls** → `call_events_from_node`; **presence** → `presence_event_from_node`.

## 5. Acknowledge

`process_message_node` returns an ack on success or a nack on failure
(`build_ack_node` / `build_nack_node`, `crates/wa-core/src/inbound.rs:294`, `:338`).
Nack reasons are explicit codes — e.g. `NACK_INVALID_PROTOBUF` (491),
`NACK_SIGNAL_ERROR_OLD_COUNTER` (496), `NACK_MESSAGE_DELETED_ON_PEER` (499)
(`:9`). The [[Connection Stack|Connection]]'s inbound loop sends the response back.

A failure to decrypt may trigger a retry on the *sender's* side — see the retry
half of the [[Send Message Flow]] — or a placeholder-resend request from ours.

[[wa-client]] wires this whole pipeline with `spawn_incoming_processor_with_signal_provider`,
which runs it in a background task and emits the resulting events on the hub.
