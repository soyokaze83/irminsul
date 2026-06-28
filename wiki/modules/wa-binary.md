---
title: wa-binary
type: module
sources:
  - crates/wa-binary/src/lib.rs
  - crates/wa-binary/src/codec.rs
  - crates/wa-binary/src/node.rs
  - crates/wa-binary/src/jid.rs
  - crates/wa-binary/src/tokens.rs
related:
  - "[[Binary Node Codec]]"
  - "[[JID]]"
  - "[[wa-core]]"
  - "[[Irminsul Overview]]"
summary: WhatsApp binary-node wire codec, JID parsing/encoding, and the protocol token dictionaries.
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-binary

The lowest layer of the stack: it turns the WhatsApp Web **binary XMPP-like node**
format into Rust values and back, and parses/encodes **JIDs** (WhatsApp addresses).
It has no async, no I/O, and no crypto — pure (de)serialization. Every other crate
that talks to the server builds on the `BinaryNode` type defined here.

`lib.rs` exposes four modules — `codec`, `jid`, `node`, `tokens`
(`crates/wa-binary/src/lib.rs:1`).

## Core types

- **`BinaryNode`** — a stanza: a `tag: String`, ordered `attrs: BTreeMap<String,String>`,
  and optional `content` (`crates/wa-binary/src/node.rs:4`). Built fluently with
  `BinaryNode::new(tag).with_attr(k, v).with_content(c)`
  (`crates/wa-binary/src/node.rs:11`).
- **`BinaryNodeContent`** — `Nodes(Vec<BinaryNode>)`, `Text(String)`, or `Bytes(Bytes)`,
  with `From` conversions for ergonomic construction
  (`crates/wa-binary/src/node.rs:34`).

## Codec

`encode_binary_node` / `decode_binary_node` are the public entry points
(`crates/wa-binary/src/codec.rs:56`, `:63`). Decoding first calls
`decompress_if_required`, which zlib-inflates when bit `0x02` of the leading flag
byte is set (`crates/wa-binary/src/codec.rs:69`). The token dictionaries
(`tokens.rs`, ≈1300 lines of single/double-byte tokens) compress common protocol
strings. See [[Binary Node Codec]] for the full tag/wire-format breakdown.

## JID

`jid.rs` models a WhatsApp address as `FullJid { user, server, device, agent, … }`
(`crates/wa-binary/src/jid.rs:102`) and supplies `jid_encode`/`jid_decode`,
`jid_normalized_user`, and `are_jids_same_user`. It distinguishes phone (`@s.whatsapp.net`),
LID (`@lid`), group (`@g.us`), newsletter, and hosted domains via `JidServer` and
`WaJidDomain` (`crates/wa-binary/src/jid.rs:11`, `:32`). See [[JID]].

## Dependencies & guarantees

- Depends only on `bytes`, `flate2`, and `thiserror`; `#![forbid(unsafe_code)]`.
- Decoding is bounded and total — every malformed input maps to a typed
  `BinaryDecodeError` (`crates/wa-binary/src/codec.rs:36`), never a panic. This is
  the first line of the project's "bounded buffers on network parsers" guarantee.
- Both `codec` and `jid` carry property-test suites (`proptest`) that round-trip
  generated nodes/JIDs (`crates/wa-binary/src/codec.rs` `mod tests`,
  `crates/wa-binary/src/jid.rs` `mod tests`).

Consumed by [[wa-core]] (every query/relay builds `BinaryNode`s) and re-exported
from [[wa-client]] as `BinaryNode` / `BinaryNodeContent`.
