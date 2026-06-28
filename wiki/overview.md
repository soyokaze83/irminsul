---
title: Irminsul Overview
type: overview
sources:
  - README.md
  - Cargo.toml
  - docs/feature_support_matrix.md
  - crates/wa-core/src/lib.rs
related:
  - "[[wa-client]]"
  - "[[wa-core]]"
  - "[[wa-crypto]]"
  - "[[wa-binary]]"
  - "[[wa-store]]"
  - "[[wa-proto]]"
  - "[[wa-testkit]]"
  - "[[Connection Stack]]"
  - "[[Signal Protocol]]"
  - "[[Pairing Flow]]"
  - "[[Send Message Flow]]"
  - "[[Receive Message Flow]]"
  - "[[Clean-Room & Permissive Licensing]]"
  - "[[Glossary]]"
summary: Start here — what Irminsul is, how the Cargo workspace is layered, and how data flows from socket to typed events.
updated: 2026-06-28
source_commit: ace4f9c
---

# Irminsul Overview

**Irminsul** is a clean-room, library-first Rust implementation of the **WhatsApp
Web multi-device protocol** — pairing, end-to-end Signal encryption, messaging,
media, groups, communities, newsletters, business tools, and app-state/history
sync — exposed through an idiomatic async API (`README.md:1`). It is **not**
affiliated with or endorsed by WhatsApp/Meta, and it speaks an undocumented private
protocol that can change without notice.

Status: pre-1.0, MIT-licensed, a "mock/fixture-green beta". The Signal crypto layer
(1:1 and group) is verified byte-compatible with reference libsignal via conformance
gates; broad live validation is still pending (`README.md:13`, `:176`). See
`docs/feature_support_matrix.md` for per-capability status.

New to the domain? Start with the [[Glossary]].

## Workspace layout

A Cargo workspace (Rust 2024, `rust-version = 1.96`) of focused crates
(`Cargo.toml:3`), every one `#![forbid(unsafe_code)]`:

| Crate | Layer | Responsibility |
|---|---|---|
| [[wa-client]] | facade | Public async `Client<S>`, builder, prelude, examples |
| [[wa-core]] | engine | The protocol: connection, pairing, Signal, messaging, media, app-state, history, USync, and all WhatsApp surfaces |
| [[wa-crypto]] | crypto | AES/HKDF/HMAC/SHA, X25519/XEdDSA, Noise XX, media & app-state crypto, zeroized secrets |
| [[wa-binary]] | wire | Binary-node codec + JID parsing/encoding |
| [[wa-proto]] | wire | Checked-in `prost`-generated protobuf types |
| [[wa-store]] | storage | `AuthStore`/`SignalKeyStore` traits; SQLite + in-memory backends |
| [[wa-testkit]] | test | Golden-vector fixtures & loaders |

Dependency direction is strictly downward: `wa-client → wa-core → {wa-crypto,
wa-binary, wa-proto, wa-store}`, with `wa-binary` at the bottom.

## How it fits together

```
        ┌────────────────────────── wa-client (Client<S>) ──────────────────────────┐
        │  builder · subscribe() · send_* · spawn_incoming_processor · prelude       │
        └───────────────┬───────────────────────────────────────────┬───────────────┘
                        │                                           │ Event
   ┌────────────────────▼───────────────────── wa-core ────────────▼───────────────┐
   │ Connection Stack ── Noise Handshake ── Pairing ── Pre-keys                     │
   │ Signal Protocol (1:1 + sender keys)                                           │
   │ Send / Receive message · Retry · Placeholder · Media Transfer                 │
   │ App-State & History sync · USync · Groups/Communities/Newsletters/Business    │
   │ Event Model (EventHub / EventBuffer)                                          │
   └──────┬────────────────┬─────────────────┬─────────────────┬───────────────────┘
   wa-binary           wa-crypto          wa-proto           wa-store
   (nodes/JIDs)        (ciphers/Noise)    (protobufs)        (sessions/keys/state)
```

## Data flow at a glance

1. **Connect** — open a WebSocket, run the [[Noise Handshake]], and bring up a
   framed [[Connection Stack|`Connection`]] with query/response matching.
2. **Authenticate the device** — first time via the [[Pairing Flow]] (QR or pairing
   code), then upload pre-keys; later, restore from the stored session.
3. **Send** — build a typed message, encode to protobuf, [[Signal Protocol|encrypt
   per recipient device]], assemble a relay node, transmit; recover via the
   retry/resend path. See [[Send Message Flow]].
4. **Receive** — decode each inbound frame to a node, classify by tag, decrypt,
   convert to an [[Event Model|`EventBatch`]], and ack/nack. See
   [[Receive Message Flow]].
5. **Sync** — reconcile chat/contact settings and pull message history. See
   [[App-State & History Sync]].
6. **Consume** — applications read everything as typed `Event`s via
   `Client::subscribe()`.

## Design commitments

- **Permissive & clean-room.** MIT throughout; no copyleft deps. The Signal layer
  is reimplemented (not `libsignal`) and proven against libsignal vectors. See
  [[Clean-Room & Permissive Licensing]].
- **Safety.** `#![forbid(unsafe_code)]` everywhere; zeroized + redacted secrets;
  bounded buffers on every network parser; transactional storage writes
  (`README.md:184`).
- **Library-first.** The protocol engine is mostly pure `build_*`/`parse_*`
  functions; the `Client` is a thin orchestration layer, and transports/stores are
  pluggable behind traits and feature flags.

## Where to go next

- Public API & examples → [[wa-client]]
- The protocol engine map → [[wa-core]]
- Crypto details → [[Signal Protocol]], [[Noise Handshake]], [[Media Transfer]]
- Wire format → [[Binary Node Codec]], [[JID]]
- Lifecycles → [[Pairing Flow]], [[Send Message Flow]], [[Receive Message Flow]]
