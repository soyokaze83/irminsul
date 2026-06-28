---
title: Event Model
type: concept
sources:
  - crates/wa-core/src/event.rs
related:
  - "[[wa-core]]"
  - "[[wa-client]]"
  - "[[Receive Message Flow]]"
  - "[[App-State & History Sync]]"
  - "[[wa-store]]"
summary: The typed Event enum, EventBatch, the EventHub broadcast, and the dedup EventBuffer — plus durable encode/decode of stored events.
updated: 2026-06-28
source_commit: ace4f9c
---

# Event Model

Everything the client learns about the world surfaces as an **`Event`**. The
inbound pipeline ([[Receive Message Flow]]) converts decoded nodes into events;
applications consume them via `Client::subscribe()` ([[wa-client]]).

## `Event` and friends

- **`Event`** (`crates/wa-core/src/event.rs:2070`) — a wide enum (40+ variants):
  `ConnectionUpdate`, `Qr`, `CredentialsUpdated`, `Frame`, `RawNode`, `Batch`,
  `HistorySet`, `MessagesUpsert`/`Update`/`Delete`,
  `ChatsUpsert`/`Update`/`Delete`, `ContactsUpsert`/`…`, `ReceiptsUpdate`,
  `ReactionsUpdate`, `GroupsUpdate`, `PresenceUpdate`, `CallsUpdate`, `MediaRetry`,
  `LidMappingUpdate`, `BlocklistUpdate`, the newsletter/business/account-settings
  updates, and more.
- **`ConnectionState`** — `Connecting` / `Open` / `Closed` (`:40`).
- **Payload structs** — typed per kind: `MessageEvent` (`:70`), `MessageUpdate`
  (`:108`), `ReceiptEvent` (`:422`), `ReactionEvent` (`:469`), `PresenceEvent`
  (`:182`), `ChatEvent` (`:138`), `ContactEvent` (`:160`), `GroupUpdateEvent`
  (`:400`), `CallEvent` (`:755`), `MediaRetryEvent` (`:514`), etc. Most carry a key,
  a timestamp, and a `fields` string-map for the long tail of attributes.

## Batching and delivery

- **`EventBatch`** (`crates/wa-core/src/event.rs:828`) — a container the inbound
  factory fills for one node; it groups all event kinds produced together and has
  `is_empty()` / `pending_items()`.
- **`EventHub`** (`:2115`) — a `tokio::sync::broadcast` wrapper with
  `subscribe()`, `emit()`, `emit_batch()`. This is what `Client::subscribe()`
  hands out.
- **`EventBuffer`** / `EventBufferConfig` (`:2155`, `:2142`) — a per-kind
  `BTreeMap` buffer (default `max_pending_items = 4096`) that **deduplicates on
  insert** before flushing to the hub, so repeated upserts collapse.

## Durable events

Events are also serialized to [[wa-store|storage]] for replay/recovery. Each kind
has an `encode_stored_*` / `decode_stored_*` pair and a `*_store_key` helper
(e.g. `encode_stored_message_event` at `crates/wa-core/src/event.rs:1018`). The
format is a 4-byte magic (`MSEV`, `CHTE`, `RCPT`, `CALL`, `PRES`, …), a version
byte (`STORED_EVENT_RECORD_VERSION = 1`, `:34`), then the typed fields, capped at
8 MiB per record (`:35`). This append-only journal lets the client persist
history-sync and live events and reload them across restarts.
