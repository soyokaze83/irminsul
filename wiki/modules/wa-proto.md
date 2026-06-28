---
title: wa-proto
type: module
sources:
  - crates/wa-proto/src/lib.rs
  - crates/wa-proto/src/generated.rs
  - crates/wa-proto/Cargo.toml
related:
  - "[[wa-core]]"
  - "[[Send Message Flow]]"
  - "[[App-State & History Sync]]"
  - "[[Irminsul Overview]]"
summary: Checked-in prost-generated protobuf types for the WhatsApp wire protocol (messages, app-state, history, handshake, certs).
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-proto

The protobuf types that WhatsApp uses inside binary-node payloads — `Message`,
`WebMessageInfo`, `MessageKey`, `HistorySync`, `SyncdPatch`/`SyncdSnapshot`,
`HandshakeMessage`, `CertChain`, and many more. The messaging, app-state, history,
and noise layers all encode/decode through these.

## Structure

`lib.rs` is tiny: it declares `pub mod proto` whose body is
`include!("generated.rs")` (`crates/wa-proto/src/lib.rs:4`), and forbids unsafe
code. The real content is **`generated.rs`** (~17k lines) — `prost`-generated Rust
checked **into version control** rather than produced by a build script, so a
normal `cargo build` does no codegen and needs no `protoc`. Dependencies are just
`bytes` and `prost` (`crates/wa-proto/Cargo.toml`).

## Usage

[[wa-core]] re-exports the commonly used types, and [[wa-client]] re-exports a
curated subset through its prelude (e.g. `ProtoMessage`, `MessageKey`,
`WebMessageInfo`, `HistorySync`, `SyncdMutations`,
`HistorySyncNotification`). Encoding a message is `prost::Message::encode` on the
generated `Message` (see [[Send Message Flow]]); decoding inbound ciphertext yields
a generated `Message` (see [[Receive Message Flow]]).

## Regeneration & drift

The repo `README.md` describes `wa-proto` as "checked-in generated protobuf types
(with regeneration & drift-check tooling)". Because the generated source is
committed, changes to the `.proto` schema are reviewable as ordinary diffs; the
tooling regenerates and checks the committed output stays in sync.
