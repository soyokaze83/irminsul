# Feature Support Matrix

This matrix describes the current Rust workspace state. It is not a promise of
production readiness. WhatsApp Web is a private protocol and can change without
notice.

Status legend:

- `Foundation`: implemented and covered by focused tests, but not full parity.
- `Partial`: usable API exists for some flows, with known missing edge cases.
- `Planned`: not yet implemented as a supported surface.
- `Live validation needed`: mock/unit coverage exists, but ignored-by-default
  live e2e coverage still needs to be completed.

## User-Facing Capabilities

| Capability | Status | Notes |
| --- | --- | --- |
| Native auth store | Foundation | `SqliteAuthStore` is the default; `MemoryAuthStore` is feature-gated for tests/examples. |
| Custom auth store | Foundation | Implement `AuthStore`; see `custom_auth_store` example. |
| QR pairing payload | Foundation | `pairing_qr_data` builds payloads from server references and local credentials. |
| Pairing-code request | Foundation | Request nodes, state persistence, and a live pairing-code example are implemented; broader live pairing validation remains. |
| Session restore | Foundation | Reopen the same native SQLite store; foreign session import/export is out of scope. |
| Websocket transport | Foundation | Rustls default, native-tls optional; mock and local-server coverage exists. |
| Noise validation | Foundation | Handshake and transport wrappers are implemented with mock validation coverage. |
| Text send | Partial | High-level Signal-provider facade exists; broader real Signal compatibility proof remains. |
| Contact/location send | Partial | Typed direct contact, contact-array, location, and live-location facades exist with Signal-provider variants, `live_text` modes, and ignored live send smokes; broader receive/update/live parity remains. |
| Media send | Partial | Encrypted upload helpers plus typed direct image/video/GIF/PTV/audio/PTT/document/sticker and view-once image/video facades with Signal-provider variants, `live_media` direct and view-once image/video modes, status image/audio/sticker, status generated-thumbnail video/document examples, media retry request smoke, and optional live media-retry response processing exist; broader live/e2e media retry validation remains. |
| Poll/event send | Partial | Typed direct and status poll/event helpers, retry sidecar-suppression coverage, `live_text`/`live_status` modes, and ignored live direct/status smokes exist; broader receive/update/live parity remains. |
| Reaction send | Partial | Typed direct reaction helper, receive/persistence mapping, `live_text` reaction mode, and ignored live reaction smoke exist; broader reaction edge-case parity remains. |
| Edit/delete/pin send | Partial | Typed direct edit/delete/pin helpers, receive mapping, `live_text` protocol modes, and ignored live protocol smokes exist; broader protocol edge-case parity remains. |
| Receive events | Partial | Typed event hub, inbound node processing, persistence, live receive example, and ignored receive smoke exist; full live receive parity remains. |
| Groups | Partial | Metadata, participant actions, invites, settings, dirty refresh, and examples exist; broader edge cases and live e2e remain. |
| App-state/chat mutations | Partial | Upload-and-apply helpers, live chat-pin example, and ignored chat-pin smoke persist local state after server acceptance; broader resync/retry/live validation remains. |
| History sync | Partial | Bounded decode, external download, deduped event scanning, persistence, live history-sync example, and ignored smoke exist. |
| Newsletter | Partial | Metadata/action/message/reaction/view/participant/settings foundations exist with live metadata/count/message/live-update example modes and ignored smoke; broader workflows remain. |
| Business helpers | Partial | Profile/catalog/product/collection/order/media foundations exist with live business-profile fetch/update, cover-photo update/remove, catalog, collections, order-details, and business-media upload examples plus ignored smokes; broader notification and workflow coverage remains. |
| Communities | Partial | Query/facade/dirty-refresh foundations exist with live metadata/participating/linked-groups/join-request/invite-info example and ignored smoke; broader edge cases remain. |
| Live e2e harnesses | Foundation | Ignored text-send, receive, history-sync, chat-pin mutation, status text/poll/event, status media and generated-thumbnail, direct image/video/document/view-once image/video/GIF/PTV/PTT/audio/sticker media, media-retry request/response, generated video/document thumbnail, link-preview thumbnail, profile-picture, newsletter metadata/count/message/live-update, community read, business profile/cover-photo update/remove, business catalog/collections/order-details fetch, business media upload, group send, and group-metadata smoke tests exist; broader live coverage remains. |

## Crate Feature Flags

| Feature | Crate | Default | Purpose |
| --- | --- | --- | --- |
| `sqlite-store` | `wa-client` | Yes | Re-export and use the SQLite auth/key store. |
| `bundled-sqlite` | `wa-client`, `wa-store` | Yes | Build SQLite with bundled sources. |
| `memory-store` | `wa-client` | No | Re-export in-memory store for tests/examples. |
| `noise` | `wa-client`, `wa-core` | Yes | Noise handshake, credentials, Signal/media helpers. |
| `websocket` | `wa-client`, `wa-core` | Via `rustls` | Async websocket transport. |
| `rustls` | `wa-client`, `wa-core` | Yes | Default TLS backend for websocket transport. |
| `native-tls` | `wa-client`, `wa-core` | No | Optional native TLS backend. |
| `http-media` | `wa-client`, `wa-core` | No | Concrete HTTP media upload/download transport. |
| `image` | `wa-client`, `wa-core` | No | Bounded thumbnail/profile-picture generation helpers. |
| `link-preview` | `wa-client`, `wa-core` | No | Link preview fetching and thumbnail upload helpers. |

Planned feature boundaries such as broad `media`, `serde`, and `mock` are not
supported flags until crate manifests define them.

## Compatibility Policy

The workspace is pre-1.0. Public APIs may change while the rewrite closes parity
gaps, especially around Signal provider integration, live send/receive, media
retry, app-state recovery, and live e2e harnesses.

During the pre-1.0 period:

- Patch releases should avoid needless churn but may adjust APIs to fix protocol
  correctness, safety, or feature-gating issues.
- Minor releases may change public APIs when needed to reach parity or improve
  typed protocol boundaries.
- Security fixes, secret-redaction fixes, parser bounds, and protocol safety
  fixes take priority over preserving unstable API details.
- Feature status should be updated in this matrix when a capability moves from
  foundation to broader parity.

Before a 1.0 release, the workspace should have a completed parity matrix,
broader ignored-by-default live e2e coverage, fuzz coverage for network parsers,
and documented exclusions for any unsupported upstream reference behavior.
