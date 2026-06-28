---
title: wa-client
type: module
sources:
  - crates/wa-client/src/lib.rs
  - crates/wa-client/Cargo.toml
  - crates/wa-client/examples/**
related:
  - "[[wa-core]]"
  - "[[wa-store]]"
  - "[[Event Model]]"
  - "[[Connection Stack]]"
  - "[[Pairing Flow]]"
  - "[[Send Message Flow]]"
  - "[[wa-client Test Chunking]]"
  - "[[Irminsul Overview]]"
summary: The public async facade — Client<S>, its builder, the prelude, and the runnable examples; a thin orchestration layer over wa-core.
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-client

The crate applications depend on. It exposes a single ergonomic facade —
`Client<S>` — plus a `prelude`, and curates re-exports from [[wa-core]],
[[wa-binary]], [[wa-crypto]], and [[wa-store]]. The `Client` is **thin**: it owns
the long-lived state and delegates the real work to `wa-core`'s `build_*`/`parse_*`
functions and the [[Signal Protocol]] repository.

## `Client<S>`

Generic over the auth store `S: AuthStore`
(`crates/wa-client/src/lib.rs:194`). It owns:

- `store: S`, `config: ClientConfig`, `events: EventHub`, `queries: QueryManager`;
- (feature `noise`) `credentials: AuthCredentials`, plus the stateful coordinators
  `media_retry`, `message_retry`, `placeholder_resend`, `tc_token_issuance`, and
  the `signal_mutation_locks`.

Build it via the builder: `Client::builder(store).browser(..).config(..).connect()`
(`crates/wa-client/src/lib.rs:681`, builder at `:12664`). `connect()` initializes
the `EventHub`/`QueryManager` and loads-or-creates credentials.

### Representative API

- **Events**: `subscribe() -> broadcast::Receiver<Event>`
  (`crates/wa-client/src/lib.rs:698`) — see [[Event Model]].
- **Transport**: `connect_websocket() -> ValidatedConnection`
  (`:1252`) — runs the [[Noise Handshake]] and validates the cert chain. See
  [[Connection Stack]].
- **Pairing** (`noise`): `pairing_qr_data(reference)` (`:1261`),
  `prepare_pairing_code_request(phone, custom?)` (`:1266`). See [[Pairing Flow]].
- **Sending**: `send_text`, `send_message`, `send_poll`, `send_event`,
  `send_reaction`, `send_edit`, `send_delete`, `send_pin`, … each with a
  `_with_signal_provider` overload (`:6196`, `:4808`, …). See [[Send Message Flow]].
- **Incoming**: `spawn_incoming_processor_with_signal_provider(connection, buffer)`
  (`:8419`) and placeholder/retry/media-retry variants spawn a background task that
  decodes inbound nodes into `Event`s. See [[Receive Message Flow]].
- **Chats / groups / queries**: `set_chat_pinned`/`archived`/`muted`/`read`,
  `delete_chat`, `create_group`, `fetch_group_metadata`,
  `update_group_participants`, `prepare_pre_key_upload`, etc.

> Most send/query methods take a `&Connection` argument — the `Client` holds
> session state, but the caller threads the live connection returned by
> `connect_websocket()`. This keeps connection lifetime explicit.

## Feature flags

`default = ["sqlite-store", "bundled-sqlite", "rustls", "noise"]`
(`crates/wa-client/Cargo.toml:10`). Optional: `memory-store`, `native-tls`,
`http-media`, `image`, `link-preview`. `noise` gates all sending and pairing;
`websocket` is pulled in transitively by `rustls`/`native-tls`. The `wat1`..`wat8`
flags are **test-only** partitions — see [[wa-client Test Chunking]].

## Examples (`examples/`)

Runnable programs that double as live smoke tests. The common pattern: read
`WA_SESSION_DB` (default `.wa/session.sqlite`), open a `SqliteAuthStore`, build a
`Client`, `subscribe()`, and — for live ones — `connect_websocket()`. Each exits
cleanly if its `WA_*` variables are unset.

- `session_pairing` — offline: print QR/pairing material.
- `live_pairing_code` — pairing-code login.
- `custom_auth_store` — a minimal hand-written `AuthStore`.
- `live_text`, `live_receive`, `live_media`, `live_group(_send)`,
  `live_history_sync`, `live_chat_pin`, `live_community`, `live_newsletter`,
  `live_business_*`, `live_*_thumbnail`, … — one per surface.

All example variables are documented in `.env.example`.
