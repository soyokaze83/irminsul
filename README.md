# Irminsul

A clean-room, library-first Rust implementation of the **WhatsApp Web multi-device
protocol** — pairing, end-to-end Signal encryption, messaging, media, groups,
communities, newsletters, business tools, and app-state/history sync — exposed
through an idiomatic async API.

> ⚠️ **Unofficial / private protocol.** This implements WhatsApp's undocumented
> multi-device web protocol, which can change without notice. It is **not**
> affiliated with, authorized, or endorsed by WhatsApp or Meta. Live use requires
> an account you control; use responsibly and at your own risk.

> **Status:** pre-1.0, under active development. The Signal cryptographic layer
> (1:1 **and** group) is verified byte-compatible with the reference libsignal
> implementation. See [Project status](#project-status).

## Features

**Connection & auth**
- QR pairing, pairing-code login, and session restore
- WhatsApp Noise XX handshake; crash-safe SQLite session store (plus an in-memory store)

**End-to-end encryption (Signal)** — *verified against real libsignal*
- One-to-one X3DH + double-ratchet encrypt/decrypt
- Sender-key (group) encryption and distribution messages
- Identity management, LID/PN mapping, and session migration

**Messaging**
- Text with quotes, mentions, and forwarding; contacts; location & live location
- Reactions, polls, events; edit / delete / pin; disappearing messages
- Buttons / templates / lists; link previews (with generated thumbnails)

**Media**
- Image, video, GIF, PTV (video note), audio, PTT (voice note), document, sticker
- Streaming encrypt/upload and download/decrypt; upload cache; media-retry flow
- Optional thumbnails (image; video via `ffmpeg`; PDF via `pdftoppm`)

**Chats, state & sync**
- App-state sync: archive, mute, pin, star, mark read/unread, labels, contacts
- History sync (inline + external-blob download)
- USync (on-WhatsApp checks, device lists, status, LID mapping)
- Privacy settings, presence, profile name/picture, blocklist

**Groups, communities, newsletters, business**
- Groups: create/leave, subject/description/settings, participants, invites, join requests, sender-key messaging
- Communities: metadata, link/unlink subgroups, participants, invites
- Newsletters: metadata, messages, reactions, views, admin/participant updates
- Business: profile, catalog, products, collections, orders, cover photo

**Reliability**
- Receipts, retry/resend with session recovery, trusted-contact & reporting tokens, placeholder resend

## Architecture

A library-first Cargo workspace of focused crates:

| Crate | Responsibility |
|---|---|
| **`wa-client`** | Public async facade: `Client`, builder, config, typed events, examples |
| **`wa-core`** | Protocol logic: pairing, Signal sessions/sender-keys, send/receive, media, app-state, history, USync, groups/communities/newsletters/business |
| **`wa-crypto`** | Crypto primitives: AES-GCM/CTR/CBC, HKDF/HMAC/SHA-256, X25519, XEdDSA, Noise XX, media crypto; zeroized + redacted secrets |
| **`wa-binary`** | WhatsApp binary-node codec and JID parsing/encoding |
| **`wa-proto`** | Checked-in generated protobuf types (with regeneration & drift-check tooling) |
| **`wa-store`** | Storage traits (`AuthStore`, `SignalKeyStore`, transactions); SQLite + in-memory stores |
| **`wa-testkit`** | Test fixtures and golden-vector loaders |

## Requirements

- Rust **1.96+** (pinned via `rust-toolchain.toml`)

## Quickstart

Initialize a local session and print pairing material — no network connection:

```sh
cargo run -p wa-client --example session_pairing
```

Set `WA_SESSION_DB` to choose the SQLite session path (default `.wa/session.sqlite`).

Use it as a dependency:

```toml
[dependencies]
wa-client = { git = "https://github.com/soyokaze83/irminsul" }
```

```rust
use wa_client::prelude::*;

// `store` implements `AuthStore` (e.g. the bundled SQLite store).
let client = Client::builder(store).connect().await?;
let mut events = client.subscribe();
// drive pairing, then send/receive — see crates/wa-client/examples/.
```

## Feature flags (`wa-client`)

| Feature | Default | Enables |
|---|:---:|---|
| `sqlite-store`, `bundled-sqlite` | ✅ | SQLite auth/key store (statically bundled SQLite) |
| `rustls` | ✅ | WebSocket TLS via rustls |
| `noise` | ✅ | Noise handshake + Signal crypto |
| `websocket` | ✅¹ | WebSocket transport |
| `memory-store` | | In-memory store (useful for tests) |
| `native-tls` | | WebSocket TLS via native-tls (needs system OpenSSL) |
| `http-media` | | HTTP media upload/download (reqwest) |
| `image` | | Thumbnail / profile-picture image processing |
| `link-preview` | | Link-preview metadata fetch + thumbnails |

¹ pulled in transitively by `rustls`/`native-tls`. `wa-core` exposes the matching
`noise`, `http-media`, `image`, `link-preview`, `rustls`, and `native-tls` flags.

## Examples

Runnable examples live in [`crates/wa-client/examples/`](crates/wa-client/examples).
Most are **live**: they exit before connecting unless their `WA_*` variables are
set and — except `live_pairing_code` — require an already-paired session in
`WA_SESSION_DB`.

| Example | Purpose | Extra features |
|---|---|---|
| `session_pairing` | Initialize credentials; print pairing material (offline) | — |
| `live_pairing_code` | Pairing-code login for an unregistered session | — |
| `custom_auth_store` | Minimal custom `AuthStore` implementation | — |
| `live_text` | Send text / contact / location / poll / event / reaction / edit / delete / pin | — |
| `live_receive` | Live Signal-provider incoming processor (typed message events) | — |
| `live_media` | Send image / video / gif / ptv / audio / ptt / document / sticker | `http-media` |
| `live_media_retry` | Send a media-retry request (optionally download the response) | `http-media`² |
| `live_status` | Status/broadcast: text / media / poll / event | varies |
| `live_history_sync` | Download + process history-sync notifications | `http-media` |
| `live_chat_pin` | App-state chat-pin mutation | — |
| `live_group`, `live_group_send` | Group metadata/actions; sender-key group send | — |
| `live_community` | Community metadata / linked groups / participants | — |
| `live_newsletter` | Newsletter metadata / messages / counts | — |
| `live_business_profile`(`_update`), `live_business_catalog`, `live_business_collections`, `live_business_order_details` | Business reads + profile update | — |
| `live_business_media`, `live_business_cover_photo` | Business product-image / cover-photo upload | `http-media` |
| `live_profile_picture` | Update profile picture | `image` |
| `live_link_preview`, `live_generated_link_preview` | Link-preview sends with thumbnails | `http-media,link-preview,image` |
| `live_video_thumbnail`, `live_document_thumbnail` | Remote-thumbnail media sends | `http-media,image` |

² optional, for downloading the retry response.

Common variables: `WA_SESSION_DB`, `WA_TARGET_JID`, `WA_MESSAGE_KIND`,
`WA_MEDIA_KIND` / `WA_MEDIA_PATH`, `WA_STATUS_JIDS`, …

➡️ **Full per-example environment-variable reference: [docs/examples.md](docs/examples.md)**

## Running the tests

```sh
# Core + leaf crates (run-verified)
cargo test -p wa-core --features http-media,link-preview,image
cargo test -p wa-binary -p wa-crypto -p wa-proto -p wa-store -p wa-testkit --all-features
```

`wa-client`'s test module is large, so it is split into memory-bounded,
feature-gated chunks (`wat1`..`wat8`) — building it as one unit can exceed the RAM
of small CI runners. Run every chunk via:

```sh
./tools/run_wa_client_tests.sh
```

Opt-in live smoke tests (require a paired account):

```sh
WA_LIVE_E2E=1 WA_TARGET_JID=...@s.whatsapp.net \
  cargo test -p wa-client --test live_e2e -- --ignored --nocapture
```

## Project status

Pre-1.0 and under active development; currently a mock/fixture-green beta. The
Signal cryptographic layer (1:1 and sender-key/group) is **verified byte-compatible
with the reference libsignal implementation** via conformance gates. End-to-end
validation against live WhatsApp at scale is pending (it requires test accounts).
See [docs/feature_support_matrix.md](docs/feature_support_matrix.md) for capability
status and the pre-1.0 compatibility policy.

## Safety & security

- `#![forbid(unsafe_code)]` across every crate — no `unsafe`
- Secret key material is zeroized and uses redacted `Debug`
- Bounded buffers on network parsers; transactional storage writes
- No WhatsApp analytics/telemetry is collected, persisted, or sent

## Documentation

- [docs/examples.md](docs/examples.md) — full example environment-variable reference
- [docs/api_transition_guide.md](docs/api_transition_guide.md) — API concept mapping from the upstream TypeScript reference to Rust
- [docs/feature_support_matrix.md](docs/feature_support_matrix.md) — capability status & pre-1.0 compatibility policy

## License

Licensed under the [MIT License](LICENSE). The project deliberately avoids
copyleft dependencies so it can stay permissively licensed.
