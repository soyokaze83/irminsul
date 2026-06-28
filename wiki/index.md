# Index

_Catalog of 22 wiki page(s). Maintained by hephaes._

## Overview

- [Irminsul Overview](overview.md) — Start here — what Irminsul is, how the Cargo workspace is layered, and how data flows from socket to typed events.

## Architecture

- [Connection Stack](architecture/connection-stack.md) — The layered transport — raw WebSocket → Noise encryption → framed Connection with query/response matching → decoded nodes.

## Modules

- [wa-binary](modules/wa-binary.md) — WhatsApp binary-node wire codec, JID parsing/encoding, and the protocol token dictionaries.
- [wa-client](modules/wa-client.md) — The public async facade — Client<S>, its builder, the prelude, and the runnable examples; a thin orchestration layer over wa-core.
- [wa-core](modules/wa-core.md) — The protocol engine — connection, pairing, Signal, messaging, media, app-state, history, and every WhatsApp surface (groups, communities, newsletters, business).
- [wa-crypto](modules/wa-crypto.md) — Crypto primitives — AES, HKDF/HMAC/SHA, X25519/XEdDSA, the Noise XX handshake, media crypto, app-state crypto, and zeroized secrets.
- [wa-proto](modules/wa-proto.md) — Checked-in prost-generated protobuf types for the WhatsApp wire protocol (messages, app-state, history, handshake, certs).
- [wa-store](modules/wa-store.md) — Storage abstraction — AuthStore/SignalKeyStore traits, transactional KV with namespaces, and SQLite + in-memory backends.
- [wa-testkit](modules/wa-testkit.md) — Golden-vector loaders and fixtures for binary-node and Signal-protocol conformance tests.

## Concepts

- [App-State & History Sync](concepts/app-state-sync.md) — Encrypted, MAC-verified app-state collections (archive/mute/pin/…) synced via LT-hash patches, and bounded decoding of history-sync blobs.
- [Binary Node Codec](concepts/binary-node.md) — WhatsApp's compact binary stanza format — tags, token dictionaries, packed strings, JID pairs, and zlib framing.
- [Event Model](concepts/event-model.md) — The typed Event enum, EventBatch, the EventHub broadcast, and the dedup EventBuffer — plus durable encode/decode of stored events.
- [JID](concepts/jid.md) — WhatsApp addressing — phone (PN), LID, group, newsletter, hosted domains; device/agent suffixes; user normalization.
- [Media Transfer](concepts/media-transfer.md) — Per-kind media encryption (streaming AES-CBC + HMAC), HTTP upload/download with hash verification, an upload cache, and the media-retry flow.
- [Noise Handshake](concepts/noise-handshake.md) — The Noise_XX_25519_AESGCM_SHA256 handshake that authenticates the server and encrypts the WhatsApp WebSocket.
- [Signal Protocol](concepts/signal-protocol.md) — Clean-room X3DH + Double Ratchet (1:1) and sender-key (group) end-to-end encryption, wire-compatible with libsignal.

## Flows

- [Pairing Flow](flows/pairing.md) — How a new device registers — credential init, QR / pairing-code link, pair-success verification, and pre-key upload — then restores on reconnect.
- [Receive Message Flow](flows/receive-message.md) — From a decoded inbound node to typed events — classify by tag, decrypt, unpad, convert to an EventBatch, and ack/nack.
- [Send Message Flow](flows/send-message.md) — Building a message, encoding to protobuf, per-recipient Signal encryption, relay-node assembly, and the retry/resend path on decryption failure.

## Decisions

- [Clean-Room & Permissive Licensing](decisions/permissive-clean-room.md) — Why Irminsul reimplements the Signal layer instead of using libsignal — to keep the whole project MIT — and how it proves wire-compatibility.
- [wa-client Test Chunking](decisions/wa-client-test-chunking.md) — Why wa-client's ~95K-line test module is split into eight feature-gated chunks compiled one at a time.

## Glossary

- [Glossary](glossary.md) — Short definitions of WhatsApp-protocol and project-specific terms used across the wiki.
