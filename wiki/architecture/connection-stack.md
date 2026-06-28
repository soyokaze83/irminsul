---
title: Connection Stack
type: architecture
sources:
  - crates/wa-core/src/connection.rs
  - crates/wa-core/src/websocket.rs
  - crates/wa-core/src/noise.rs
  - crates/wa-core/src/validation.rs
  - crates/wa-core/src/query.rs
related:
  - "[[Noise Handshake]]"
  - "[[Binary Node Codec]]"
  - "[[Receive Message Flow]]"
  - "[[Event Model]]"
  - "[[wa-core]]"
summary: The layered transport — raw WebSocket → Noise encryption → framed Connection with query/response matching → decoded nodes.
updated: 2026-06-28
source_commit: ace4f9c
---

# Connection Stack

Outbound stanzas and inbound frames pass through four composable layers. Each layer
is a `FrameSink`/`FrameStream` pair, so they nest cleanly.

```
application (Client, wa-core builders)
   ▲ BinaryNode
   │  encode_binary_node / decode_binary_node   ([[Binary Node Codec]])
Connection            send_node / query_node / events  (connection.rs)
   ▲ Bytes (plaintext frames)
NoiseFrameSink / NoiseFrameStream   encrypt/decrypt   (noise.rs, [[Noise Handshake]])
   ▲ Bytes (ciphertext frames)
TungsteniteFrameSink / Stream       Message::Binary   (websocket.rs)
   ▲
WhatsApp WebSocket
```

## Frame transport (`connection.rs`)

The transport contract is small (`crates/wa-core/src/connection.rs:35`):

- `FrameSink` — `async send(Bytes)`, `async close()`.
- `FrameStream` — `async recv() -> Option<InboundFrame>`, where `InboundFrame`
  carries an optional `tag` and a `payload` (`:14`).

`Connection::spawn(sink, stream, queries, events, capacity)` (`:52`) starts two
tasks — an **outbound** loop draining an mpsc channel into the sink (`:183`) and an
**inbound** loop reading the stream (`:212`) — and emits
`ConnectionUpdate(Open)` (`:84`). Public methods:

- `send_frame` / `send_node` — fire-and-forget; `send_node` encodes a `BinaryNode`
  first (`:99`, `:111`).
- `query(tag, frame)` / `query_node(node)` — register the tag with the
  `QueryManager` (see [Query matching](#query-matching)), send, and await the response
  (`:115`, `:121`).
- `close()` — flush, mark closed, emit `ConnectionUpdate(Closed)` (`:135`).

The inbound loop's rule: a frame with a tag that matches a pending query resolves
that query; otherwise it is emitted as an event for the [[Receive Message Flow]] to
process (`:212`).

## WebSocket (`websocket.rs`)

`connect_websocket_transport(url)` opens a Tungstenite WebSocket and returns a
`TungsteniteFrameSink`/`Stream` (`crates/wa-core/src/websocket.rs:19`). The sink
sends each `Bytes` as `Message::Binary`; the stream filters ping/pong, rejects text
frames, and yields binary payloads as `InboundFrame`s (`:46`, `:73`).
`connect_websocket(...)` wires that transport straight into `Connection::spawn`
(`:30`). TLS backend is `rustls` (default) or `native-tls`.

## Noise layer (`noise.rs`)

`NoiseFrameSink`/`NoiseFrameStream` wrap an inner sink/stream and a
`SharedNoiseHandshake = Arc<Mutex<NoiseHandshake>>`
(`crates/wa-core/src/noise.rs:9`, `:16`, `:51`): the sink encrypts each outgoing
frame, the stream decrypts inbound frames (buffering several decoded frames in a
`VecDeque`). They only exist *after* the handshake completes.

## Handshake & validation (`validation.rs`)

`validate_connection(sink, stream, request, events, queries, verifier, capacity)`
(`crates/wa-core/src/validation.rs:119`) orchestrates the whole bring-up: emits
`Connecting`, runs the [[Noise Handshake|XX handshake]] over the raw transport,
builds the login/registration ClientPayload, calls `finish_transport()`, wraps the
transport in the Noise sink/stream, and finally spawns a `Connection` over the
encrypted frames — returning a `ValidatedConnection` (`:97`). On any error it emits
`Closed`.

## Query matching (`query.rs`)

`QueryManager` (`crates/wa-core/src/query.rs:10`) allocates request tags
(`next_tag`), registers waiters with an optional timeout, and `resolve`s them when a
tagged response arrives. `close_pending` fails all in-flight queries on disconnect.
This is what turns WhatsApp's async request/response IQs into awaitable futures.
