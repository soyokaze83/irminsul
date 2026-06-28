---
title: wa-testkit
type: module
sources:
  - crates/wa-testkit/src/lib.rs
  - crates/wa-testkit/Cargo.toml
  - tests/fixtures/binary_nodes/manifest.json
  - tests/fixtures/signal/manifest.json
related:
  - "[[Signal Protocol]]"
  - "[[Binary Node Codec]]"
  - "[[Clean-Room & Permissive Licensing]]"
  - "[[Irminsul Overview]]"
summary: Golden-vector loaders and fixtures for binary-node and Signal-protocol conformance tests.
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-testkit

Shared test fixtures and the loaders that read them. It exists so conformance tests
across crates can assert against the **same golden vectors** — most importantly the
Signal wire vectors generated from real libsignal (see
[[Clean-Room & Permissive Licensing]]).

## What it provides (`lib.rs`, ~1290 lines)

- **`BinaryNodeFixtureManifest`** / `BinaryNodeFixture` / `FixtureNode` /
  `FixtureContent` — declarative [[Binary Node Codec|binary-node]] cases with
  `encoded_hex` and an expected node tree, loaded via `load()`
  (`crates/wa-testkit/src/lib.rs:16`, `:1198`).
- **`SignalFixtureManifest`** / `SignalFixture` — a 67-variant enum of
  [[Signal Protocol]] vector kinds (message body, message chain, pre-key root
  chains, provider sessions, sender-key distribution/records, whisper messages, …)
  and their typed fixture structs (`crates/wa-testkit/src/lib.rs:30`, `:44`).
- Hex helpers (`decode_hex`, `decode_fixture_hex`) and a `ping_node()` convenience
  (`:11`, `:1214`), with a typed `FixtureError` (`:1264`).

## Inputs

Manifests and vectors live under `tests/fixtures/` (`binary_nodes/manifest.json`,
`signal/manifest.json`, `signal_conformance.json`,
`signal_group_conformance.json`). The Signal JSON is emitted by the dev-only oracle
in `tools/compat/` and committed as plain data.

## Dependencies

Library deps are minimal (`bytes`, `serde`, `serde_json`, `wa-binary`); the
heavier crates (`wa-core`, `wa-crypto`, `wa-proto`, `x25519-dalek`) are
**dev-dependencies** used by the in-crate tests, not by consumers
(`crates/wa-testkit/Cargo.toml`).
