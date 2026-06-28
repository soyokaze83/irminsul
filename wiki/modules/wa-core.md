---
title: wa-core
type: module
sources:
  - crates/wa-core/src/lib.rs
  - crates/wa-core/src/**
related:
  - "[[wa-client]]"
  - "[[wa-binary]]"
  - "[[wa-crypto]]"
  - "[[wa-store]]"
  - "[[Signal Protocol]]"
  - "[[Event Model]]"
  - "[[Connection Stack]]"
  - "[[Send Message Flow]]"
  - "[[Receive Message Flow]]"
  - "[[App-State & History Sync]]"
  - "[[Media Transfer]]"
  - "[[Irminsul Overview]]"
summary: The protocol engine — connection, pairing, Signal, messaging, media, app-state, history, and every WhatsApp surface (groups, communities, newsletters, business).
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-core

The heart of the project: ~30 modules implementing the WhatsApp Web multi-device
protocol on top of [[wa-binary]] (nodes/JIDs), [[wa-crypto]] (ciphers/Noise/Signal
primitives), [[wa-proto]] (protobufs), and [[wa-store]] (persistence). It is
**transport-light and stateless-by-default**: most modules are pure
`build_*_query` / `parse_*_result` functions over `BinaryNode`, plus a few
stateful coordinators (retry, media-retry, placeholder, query manager). The
public [[wa-client|`Client`]] facade is a thin async wrapper over these functions.

`lib.rs` (`crates/wa-core/src/lib.rs:1`) is `#![forbid(unsafe_code)]` and re-exports
each module's surface. Several modules are gated behind the `noise` feature (auth,
pairing, signal, pre_keys, reporting, validation, noise) and `image`/`http-media`/
`link-preview` for media extras.

## Transport & session

| Module | Responsibility | Detail |
|---|---|---|
| `connection.rs` | `Connection`, `FrameSink`/`FrameStream`, send/query loops | [[Connection Stack]] |
| `websocket.rs` | Tungstenite WebSocket transport (`connect_websocket`) | [[Connection Stack]] |
| `noise.rs` | `NoiseFrameSink`/`Stream` wrapping the transport | [[Noise Handshake]] |
| `validation.rs` | `validate_connection` — drives the XX handshake | [[Noise Handshake]] |
| `payload.rs` | login/registration ClientPayload builders | [[Noise Handshake]] |
| `auth.rs` | `AuthCredentials`, credential init/load/save | [[Pairing Flow]] |
| `pairing.rs` | QR + pairing-code + pair-success handling | [[Pairing Flow]] |
| `pre_keys.rs` | pre-key generation, upload, signed-pre-key rotation | [[Pairing Flow]] |
| `query.rs` | `QueryManager` — tag allocation + response matching | — |

## Encryption

| Module | Responsibility | Detail |
|---|---|---|
| `signal.rs` | 1:1 + group Signal E2E (X3DH, ratchets, sender keys) | [[Signal Protocol]] |

## Messaging

| Module | Responsibility | Detail |
|---|---|---|
| `message.rs` | content model + `build_*_message` + relay/encrypt + receipts | [[Send Message Flow]] |
| `retry.rs` | retry receipts, session-recreate decisions, resend jobs | [[Send Message Flow]] |
| `placeholder.rs` | placeholder-resend tracking | [[Send Message Flow]] |
| `inbound.rs` | decrypt inbound stanzas, ack/nack, padding | [[Receive Message Flow]] |
| `router.rs` | classify/dispatch a decoded node by tag | [[Receive Message Flow]] |
| `receive.rs` | node → events; the inbound event factory (~8.9k lines) | [[Receive Message Flow]] |
| `event.rs` | the typed `Event`/`EventBatch`/`EventHub` model | [[Event Model]] |

## State, media & sync

| Module | Responsibility | Detail |
|---|---|---|
| `app_state.rs` | app-state patches/snapshots (archive, mute, pin, …) | [[App-State & History Sync]] |
| `history.rs` | history-sync decode/download/process | [[App-State & History Sync]] |
| `media.rs` | upload/download transport, cache, media-retry coordinator | [[Media Transfer]] |
| `thumbnail.rs` | image/video/PDF thumbnail generation (`image` feature) | [[Media Transfer]] |
| `usync.rs` | USync: on-WhatsApp, device lists, status, LID mapping | — |

## WhatsApp surfaces

Each is a `build_*_query` / `parse_*` module producing/consuming `BinaryNode`s:

- **`group.rs`** — group metadata, participants (add/remove/promote/demote),
  invites, settings, join requests (`GroupMetadata`,
  `crates/wa-core/src/group.rs:34`).
- **`community.rs`** — communities: linked groups, participants, invites
  (`CommunityLinkedGroup`, `crates/wa-core/src/community.rs:19`).
- **`newsletter.rs`** — newsletters via WMex GraphQL: metadata, messages,
  reactions, views, admin/participant updates (`crates/wa-core/src/newsletter.rs:45`).
- **`business.rs`** — business profile, catalog, products, collections, orders,
  cover photo (`BusinessProfile`, `crates/wa-core/src/business.rs:16`).
- **`chat.rs`** — privacy settings, presence, profile picture, blocklist
  (`PrivacyCategory`, `crates/wa-core/src/chat.rs:10`).
- **`account.rs`** — account updates: reachout timelock, message capping
  (`crates/wa-core/src/account.rs:19`).
- **`mex.rs`** — WMex GraphQL query/parse helpers (`build_wmex_query`,
  `crates/wa-core/src/mex.rs:10`).

## Reliability

- **`tctoken.rs`** — trusted-contact token storage/issuance/pruning
  (`TcTokenRecord`, `crates/wa-core/src/tctoken.rs:25`).
- **`reporting.rs`** — privacy-preserving message-report tokens
  (`crates/wa-core/src/reporting.rs`).

## Errors

`error.rs` defines `CoreError` / `CoreResult<T>` — a unified error spanning store,
binary, protobuf, connection, crypto, HTTP, noise, and protocol failures
(`crates/wa-core/src/error.rs:4`).
