---
title: Binary Node Codec
type: concept
sources:
  - crates/wa-binary/src/codec.rs
  - crates/wa-binary/src/node.rs
  - crates/wa-binary/src/tokens.rs
related:
  - "[[wa-binary]]"
  - "[[JID]]"
  - "[[Connection Stack]]"
  - "[[Receive Message Flow]]"
summary: WhatsApp's compact binary stanza format — tags, token dictionaries, packed strings, JID pairs, and zlib framing.
updated: 2026-06-28
source_commit: ace4f9c
---

# Binary Node Codec

WhatsApp Web does not send XML on the wire. It sends a compact binary encoding of
an XMPP-like tree of stanzas. A stanza is a [[wa-binary|`BinaryNode`]]:
`{ tag, attrs, content }` (`crates/wa-binary/src/node.rs:4`). This page describes
how that tree is serialized.

## Framing

`encode_binary_node` prepends a single `0x00` flag byte, then the node body
(`crates/wa-binary/src/codec.rs:56`). On decode, `decompress_if_required` reads the
flag byte: if bit `0x02` is set, the remainder is zlib-compressed and inflated;
otherwise it is used as-is (`crates/wa-binary/src/codec.rs:69`). The encoder here
never sets the compression bit — it always emits plaintext frames.

## Node layout

A node is written as a **list** whose length is `1 + 2·attr_count + has_content`:
the tag string, then alternating attr key/value strings, then (optionally) the
content (`crates/wa-binary/src/codec.rs:84`). Content is one of:

- **child nodes** → a nested list (`crates/wa-binary/src/codec.rs:101`);
- **text** → a string (`:107`);
- **bytes** → a length-prefixed byte blob (`:108`).

## Tag bytes

The codec uses sentinel tag bytes (`crates/wa-binary/src/codec.rs:9`):

| Tag | Byte | Meaning |
|---|---|---|
| `LIST_EMPTY` | 0 | zero-length list |
| `LIST_8` / `LIST_16` | 248 / 249 | list with u8 / u16 length |
| `JID_PAIR` | 250 | `user@server` pair |
| `HEX_8` | 251 | packed hex string |
| `BINARY_8/20/32` | 252/253/254 | byte blob with 8/20/32-bit length |
| `NIBBLE_8` | 255 | packed nibble string |
| `DICTIONARY_0..3` | 236..239 | double-byte token, dictionary selector |

`BINARY_20` packs its length into 20 bits across 3 bytes
(`crates/wa-binary/src/codec.rs:140`).

## String compression

`write_string` tries strategies in order (`crates/wa-binary/src/codec.rs:152`):

1. **Token lookup** — `token_for` matches a known protocol string to a single- or
   double-byte token from the dictionaries (`crates/wa-binary/src/tokens.rs`); a
   double token emits `DICTIONARY_0 + dict` then the index
   (`crates/wa-binary/src/codec.rs:155`).
2. **Nibble packing** — strings of `0-9`, `-`, `.` pack two chars per byte
   (`is_nibble`, `:161`).
3. **Hex packing** — `0-9A-F` strings pack two chars per byte (`is_hex`, `:163`).
4. **JID pair** — strings that parse as a JID are emitted as a JID/AD-JID pair,
   using tag `247` for addresses with a device id (`:165`). See [[JID]].
5. **Raw string** — otherwise length-prefixed UTF-8.

Decoding mirrors this via a `Cursor` that reads tags and dispatches to
`read_string`, `read_jid_pair`, `read_ad_jid`, `read_packed`, etc. Tokens are the
key size win: common strings like message/iq/receipt tag names cost one byte.

## Robustness

Decoding is total: out-of-range tags, truncated input, bad UTF-8, and bad packed
bytes all return typed `BinaryDecodeError` variants
(`crates/wa-binary/src/codec.rs:36`) rather than panicking. Round-trip and
zlib-decode property tests cover bounded generated trees
(`crates/wa-binary/src/codec.rs` `mod tests`). Higher layers
([[Connection Stack]], [[Receive Message Flow]]) treat every inbound frame as a
node decoded here.
