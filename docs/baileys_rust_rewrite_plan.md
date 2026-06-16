# WhatsApp Web API Rust Rewrite Plan

Created: 2026-06-15
Last consistency review: 2026-06-16
Last VM handoff update: 2026-06-16

This document plans a Rust rewrite of the cloned upstream TypeScript reference
project. The goal is functional parity with its WhatsApp Web multi-device API
features while using Rust's strengths for memory safety, predictable resource
usage, typed protocol boundaries, and efficient binary/media processing.

Implementation work should proceed through the single-go `/goal` run described
below. If that goal is already active, continue from the recorded implementation
progress instead of restarting completed foundation work.

## Execution Directive For Coding Agent

The coding agent that implements this rewrite should use the `/goal` command to
create one explicit, long-running objective for the full Rust rewrite. If a
matching rewrite goal is already active, continue that goal rather than creating
a second objective. Treat the goal as an end-to-end implementation run across
all phases in this document, not as a request to stop after a single milestone.

During the `/goal` run:

- Implement all phases in one continuous pass unless a real blocker requires
  user input.
- Treat the phases as ordered checkpoints for unfinished work, not optional or
  separately scoped projects. Section 13 remains authoritative for foundations
  already landed, even when they came from a later phase area.
- After each implemented feature or module, run the most focused relevant tests,
  fix failures immediately, and rerun those tests before moving on.
- After each major phase, run broader workspace verification such as
  `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and
  `cargo test --workspace --all-features` as soon as the workspace supports
  those commands.
- Use a strict test-fix-retest loop. Any bug found while implementing a feature
  should get a focused regression test where practical.
- Prefer mock protocol tests and compatibility fixtures when live WhatsApp e2e
  tests are unavailable or unsafe to run.
- Keep memory-safety, secret redaction, bounded buffering, and no-`unsafe` policy
  active throughout the entire run, not only during final hardening.
- Update this document or a companion parity checklist whenever an implemented
  feature materially changes scope, exposes a gap, or completes a phase.

Decision precedence for implementers:

- Treat the Naming Directive, Non-Goals, and Decisions sections as authoritative
  over older or broader phase wording.
- Treat Section 13 as the source of truth for landed foundations and remaining
  gaps. A completed foundation does not imply full parity when the remaining-gap
  list still names unfinished work in that area.
- Treat phase deliverables as acceptance criteria for unfinished work, not as
  permission to reopen settled architecture, storage, telemetry, protobuf, or
  test-location decisions.

## Naming Directive

The Rust implementation must take the upstream project's features and protocol
behavior, not its naming. Do not use the upstream project name in any new crate,
module, source file, public type, function, constant, feature flag, environment
variable, binary name, package name, generated artifact, fixture path, or code
comment.

Use neutral project names such as `wa-client`, `wa-core`, `wa-proto`,
`wa-binary`, `wa-crypto`, `wa-store`, and `wa-testkit` for crate or module
boundaries. Public APIs should be idiomatic Rust names such as `Client`,
`ClientBuilder`, `Event`, `AuthStore`, and `SignalKeyStore`, not transliterated
or inherited names from the TypeScript package.

The existing cloned source directory may remain as a local reference input, but
implementation files should not copy its package, crate, or API naming. Any
compatibility notes should refer to it as the upstream TypeScript reference or
reference implementation.

The existing plan document path is a user-specified planning artifact. Do not use
its filename pattern for implementation files, generated files, fixtures, or
public package naming.

## 1. Goals

- Build a Rust library that exposes the same WhatsApp Web API capabilities in an
  idiomatic Rust shape.
- Preserve protocol compatibility with the cloned TypeScript reference, package
  version 7.0.0-rc13, as cloned locally.
- Prioritize memory safety, secret handling, and bounded concurrency over direct
  TypeScript-to-Rust transliteration.
- Keep the public API ergonomic for async Rust applications and suitable for a
  future CLI or service wrapper.
- Support QR pairing, pairing code login, session restore, message send/receive,
  media upload/download, group/chat operations, app-state sync, USync, Signal
  sessions, newsletters, business helpers, and communities in phased order.
- Build a test suite from upstream unit tests plus Rust-native golden vectors,
  fuzz tests, and integration tests.

## Compatibility Baseline

- Reference package version: 7.0.0-rc13.
- Reference commit: `78e7e4e2cfcb1935629173427bc3292b95f61a95`.
- Compatibility target: protocol behavior and supported WhatsApp Web
  multi-device features from that local reference snapshot, exposed through
  idiomatic Rust APIs and neutral implementation naming.
- Compatibility excludes the explicit non-goals below, such as the removed mobile
  API and WAM telemetry.

Reference directory names in this document identify the local TypeScript source
areas to study. They do not authorize using those names for Rust crate, module,
file, package, fixture, generated-artifact, or public API names when the Naming
Directive says otherwise.

## 2. Non-Goals

- Do not implement the removed mobile API. The reference implementation
  explicitly rejects mobile mode.
- Do not clone the JavaScript event emitter or object-spread socket layering
  directly. Rust should use explicit services, typed events, and shared inner
  state.
- Do not expose raw mutable protocol state broadly. State transitions should
  happen through typed methods and store transactions.
- Do not use `unsafe` in the main rewrite. Keep crate-level unsafe forbids in
  place; any future unsafe optimization requires a separate post-rewrite design
  decision, benchmark, documentation, and focused tests.
- Do not hardcode credentials, session material, or environment-specific test
  accounts.
- Do not implement WAM telemetry in the main rewrite. The Rust client should keep
  normal application logs separate through `tracing` and should not collect,
  persist, or send WhatsApp analytics/statistics payloads.

## 3. Source Inventory

The local upstream source clone has these major areas:

- `WAProto/WAProto.proto`, `WAProto/index.js`, `WAProto/index.d.ts`: generated
  WhatsApp protobuf model.
- `src/WABinary`: WhatsApp binary node tokenizer, encoder, decoder, JID helpers,
  and token dictionaries.
- `src/Socket/socket.ts`: base WebSocket connection, Noise handshake, query
  manager, keepalive, pairing, connection lifecycle, USync entrypoint.
- `src/Socket/chats.ts`: privacy, presence, profile, app-state sync, history sync,
  chat modification, labels, contact updates, business profile helpers.
- `src/Socket/messages-send.ts`: message generation, device fanout, session
  assertion, Signal encryption, media connection, receipts, tctoken issuance,
  retry cache.
- `src/Socket/messages-recv.ts`: inbound node processing, decrypt/ack/retry,
  notification handling, call handling, placeholder resend, media retry.
- `src/Socket/groups.ts`: group metadata, participant actions, invites, group
  settings, dirty-bit sync.
- `src/Socket/newsletter.ts`, `business.ts`, `communities.ts`: extended socket
  capabilities layered above groups/messages.
- `src/Signal`: libsignal repository adapter, LID mapping, group sender-key
  implementation.
- `src/Utils`: crypto, Noise, auth stores, app-state patching, message creation,
  media streaming/encryption, retry manager, event buffer, history processing,
  reporting tokens, link previews, browser/client helpers.
- `src/WAUSync`: USync query builder and protocols.
- `src/WAM`: WhatsApp analytics/statistics binary encoding. This is reference
  context only and is out of scope for the main Rust rewrite.
- `src/Types`: public TypeScript API surface and event map.
- `src/__tests__`: unit and e2e behavior references to port into Rust tests and
  golden fixtures.

## 4. Target Rust Architecture

Start as an immediate multi-crate Cargo workspace. This is a settled decision,
not an optional starting point. The workspace keeps protocol code, public API
code, stores, test utilities, and optional integrations separated from day one.

Settled workspace layout:

```text
.
|-- Cargo.toml
|-- crates/
|   |-- wa-client/            # Public facade: Client, config, events, examples
|   |-- wa-core/              # Socket runtime, query manager, state machines
|   |-- wa-proto/             # prost-generated WhatsApp protobuf types
|   |-- wa-binary/            # WABinary codec, JID parser, token dictionaries
|   |-- wa-crypto/            # Noise, media crypto, Signal abstractions
|   |-- wa-store/             # Auth/key-store traits and reference stores
|   `-- wa-testkit/           # Fixtures, mock server, compatibility helpers
|-- examples/
|-- tests/
`-- docs/
```

### Public API Shape

Target the final public API around an explicit client instead of JavaScript
spread-composed sockets. The exact convenience method names should track the
landed facade as it matures; Section 13 remains authoritative for which send
helpers are already implemented.

```rust
let auth = SqliteAuthStore::open("./auth/session.db").await?;
let client = Client::builder(auth)
    .browser(Browser::macos_chrome())
    .connect()
    .await?;

let mut events = client.subscribe();
client.send_message(jid, MessageContent::text("hello")).await?;
```

Core public types:

- `Client`: high-level facade for connection, messaging, chats, groups, media,
  privacy, profile, newsletters, communities, and business helpers.
- `ClientBuilder`: validates configuration before any network work starts.
- `ClientConfig`: Rust version of `SocketConfig`, with typed defaults.
- `AuthStore` and `SignalKeyStore`: async traits for credentials and key material.
- `Event` enum: typed replacement for string event names.
- `EventStream`: `tokio_stream::Stream<Item = Event>` backed by bounded channels.
- `BinaryNode`, `Jid`, `MessageId`, `MessageKey`, `DeviceJid`, `GroupJid`,
  `NewsletterJid`: newtypes with validation.
- `Error`: structured `thiserror` enum with protocol, crypto, io, timeout,
  websocket, auth, store, and server error variants.

### Internal Composition

Use shared connection state with explicit services:

- `Connection`: owns WebSocket, Noise transport, lifecycle, keepalive, send queue.
- `QueryManager`: allocates tags, maps response IDs to waiters, applies timeouts.
- `EventHub`: buffers and consolidates events with bounded memory.
- `SignalService`: wraps Signal repository, session assertion, LID mapping,
  sender-key operations, and key-store transactions.
- `MessageService`: message generation, fanout, encryption, receipts, retries.
- `IncomingService`: inbound node routing, decrypt, ack, retry, notification
  handling.
- `ChatService`: app-state sync, history sync, presence, profile, privacy.
- `GroupService`, `NewsletterService`, `BusinessService`, `CommunityService`.
- `MediaService`: upload/download, streaming encryption/decryption, thumbnails.
- `USyncService`: query builder and protocol parsers.

These services can share `Arc<ClientInner>` but should avoid exposing mutable
shared fields directly. Use small `Mutex`/`RwLock` scopes, keyed locks for Signal
sessions, and store transactions for durable state.

## 5. Rust Best Practices To Apply

### Safety Defaults

- Add `#![forbid(unsafe_code)]` to all crates and keep it in force for the main
  rewrite.
- Prefer total parsers that return `Result` over panics for malformed network
  input.
- Use newtypes for protocol identifiers instead of raw strings where possible.
- Use enums for closed protocol choices: presence, receipt type, privacy values,
  socket state, disconnect reason, message upsert type, media type.
- Mark externally extensible enums as `#[non_exhaustive]`.
- Use `#[must_use]` on builders, futures that represent important operations,
  and generated request objects where dropping them is likely a bug.
- Avoid `unwrap` and `expect` in library code. Allow them only in tests and
  examples.

### Secret Handling

- Store private keys, adv secrets, media keys, Noise chaining keys, and pairing
  keys in `zeroize`/`secrecy` wrappers.
- Do not log secret material, raw plaintext message bytes, private keys, media
  keys, or session records.
- Zeroize temporary key material when possible after handshake, media processing,
  and Signal operations.
- Separate display/debug implementations: sensitive types should redact.
- Prefer `rustls` for TLS dependencies where the ecosystem allows it.

### Efficient Buffering

- Use `bytes::Bytes` and `bytes::BytesMut` for frames and binary nodes to avoid
  repeated copying.
- Preallocate output buffers in `wa-binary` based on known lengths.
- Represent binary node content as bytes without converting to `String` unless
  the protocol requires text.
- Use `Cow<'a, str>` or interned static token tables for dictionaries where it
  avoids allocations without complicating ownership.
- Final media upload/download paths should stream through crypto transforms and
  HTTP bodies. Byte-oriented helpers are acceptable only for small,
  caller-supplied buffers or as temporary foundations, and must remain covered by
  explicit size limits until true streaming media crypto is complete.
- Use bounded LRU/TTL caches. Never allow history, retries, device lists, or
  event buffers to grow without limits.
- Use `SmallVec` only after profiling shows small-array allocation hotspots.

### Async and Concurrency

- Use `tokio` as the async runtime.
- Use `tokio-tungstenite` or an equivalent async WebSocket client with TLS.
- Use bounded `mpsc` channels for outbound frames and events to apply backpressure.
- Use `oneshot` channels for query responses keyed by message tag.
- Use `CancellationToken` or equivalent shutdown signaling for connection tasks.
- Use keyed mutexes for per-JID Signal session mutation and app-state patch
  mutation.
- Keep locks out of `.await` sections unless the protected data is specifically
  async state and the lock scope is minimal.
- Make reconnect/session recovery explicit rather than hidden in background
  tasks.

### Error Design

- Use `thiserror` for internal/public errors.
- Keep server stanza errors as structured data: code, text, stanza, disconnect
  reason.
- Preserve source errors for observability while redacting sensitive payloads.
- Distinguish timeout, cancellation, connection closed, authentication rejected,
  protocol parse failure, crypto verification failure, and store transaction
  failure.

### Feature Flags

Feature flag status and targets:

Current implemented defaults:

- `wa-client`: `["sqlite-store", "bundled-sqlite", "rustls", "noise"]`.
- `wa-core`: `["websocket", "rustls", "noise"]`.
- `wa-store`: `["sqlite", "bundled-sqlite"]`.

Current implemented feature flags:

- `websocket`: async WebSocket transport support.
- `rustls`: default TLS backend; enables `websocket`.
- `native-tls`: optional TLS backend if needed by a consumer.
- `sqlite-store`: facade-level default SQLite auth/key store.
- `sqlite`: store-crate SQLite backend.
- `bundled-sqlite`: bundled SQLite build for easier cross-platform setup by
  default; can be disabled by consumers that require system SQLite.
- `noise`: Noise authentication and transport-state helpers.
- `http-media`: optional HTTP media upload/download transport over the existing
  encrypted media transfer boundary.
- `memory-store`: facade-level in-memory store wiring for tests and examples.
- `memory`: store-crate in-memory backend.

Planned feature-flag boundaries that do not exist in crate manifests yet:

- `media`: broad media-service API grouping once upload/download, retry, and
  thumbnail/profile-picture processing are split behind a dedicated feature
  boundary.
- `link-preview`: link preview fetching and thumbnail helpers.
- `image`: thumbnail/profile-picture generation.
- `serde`: serialize selected public types.
- `mock`: mock server/test utilities.

Only flags already present in crate manifests are considered implemented feature
flags. Existing media modules may still provide always-compiled core helpers
until a dedicated media feature flag is introduced.

## 6. Dependency Strategy

This plan lists dependency families and constraints, not exact versions. The
workspace manifests own the selected crate versions. Choose current maintained
crates when adding or updating dependencies.

Likely dependencies:

- Async/network: `tokio`, `futures`, `tokio-stream`, `tokio-tungstenite`,
  optional `reqwest` for the concrete HTTP media transport.
- Buffers: `bytes`.
- Protobuf: `prost`; use `prost-build` only in regeneration tooling and drift
  checks, not in ordinary consumer builds.
- Storage: `rusqlite` behind the default SQLite store features; keep the public
  store boundary trait-based so tests can use memory stores without changing the
  native runtime format decision.
- Serialization: `serde`, `serde_json`, `base64`.
- Crypto: `aes-gcm`, `aes`, `ctr`, `hkdf`, `hmac`, `sha2`, `md-5`, `rand`,
  `zeroize`, `secrecy`, plus a Signal-compatible crate or audited adapter.
- Compression: `flate2` is currently selected for zlib-compatible payloads; add
  or replace with an async-compatible wrapper only if streaming requirements
  justify the extra boundary.
- Errors/logging: `thiserror`, `tracing`, `tracing-subscriber`.
- Caches: prefer small internal bounded TTL/LRU caches for protocol-critical
  state; consider `moka` later only if profiling shows a maintained external
  cache would simplify shared cache behavior without weakening memory bounds.
- Testing: `proptest`, `insta`, `criterion`, `cargo-fuzz`, `wiremock` or a custom
  WebSocket mock server.
- CLI/examples only: `clap`, `qrcode` or terminal QR renderer if needed.

Signal implementation decision:

- Keep the project-owned `SignalRepository` boundary as the stable store and
  runtime API for sessions, identities, and LID/PN mappings.
- Start by integrating the best maintained Rust Signal protocol implementation
  available behind that boundary, then drive it through compatibility tests for
  WhatsApp-compatible sessions and sender keys.
- If that dependency becomes difficult to adapt or repeatedly fails protocol
  compatibility tests, keep the same repository boundary and replace only the
  crypto/session adapter with a project-owned implementation.
- Keep native Signal/session storage schema explicit and versioned so SQLite
  migrations are possible. This is separate from the explicitly deferred
  import/export tooling decision.

## 7. Module Mapping From Reference To Rust

The Rust target column describes logical ownership inside the settled workspace
from Section 4. It does not introduce additional crates unless a later
project-level decision explicitly amends the workspace layout.

| Reference area | Rust target | Notes |
| --- | --- | --- |
| `WAProto` | `wa-proto` | Use checked-in Rust code generated from `WAProto.proto`; regeneration tooling and drift checks keep it current, while ordinary builds consume the checked-in output. |
| `WABinary` | `wa-binary` | Zero-copy decoder where possible; fuzz all network-facing parsers. |
| `WAM` | out of scope | Do not implement WAM telemetry in the main rewrite. |
| `WAUSync` | `usync` module | Builder API with typed protocols and typed result enum/structs. |
| `Types` | public model modules | Convert string unions to enums and validated newtypes. |
| `Defaults` | `config::defaults` | Typed constants; avoid mutable globals. |
| `Utils/crypto` | `wa-crypto` | Crypto helpers with zeroized secrets and typed key material. |
| `Utils/noise-handler` | `noise` module | WA Noise XX handshake, certificate verification, frame codec. |
| `Utils/auth-utils` | `wa-store` plus `auth` | Transactions, cache layer, initial credential generation. |
| `Utils/event-buffer` | `EventHub` | Bounded consolidation with max size and timeout. |
| `Utils/messages*` | `message` and `media` services | Builder APIs, streaming media, retry support. |
| `Utils/history`, `chat-utils`, `process-message` | `history`, `app_state`, `chat` | Preserve tests and app-state MAC behavior. |
| `Signal` | `SignalService` plus `wa-crypto`/`wa-core` signal modules | Project-owned repository/adapter boundary inside the settled workspace, with a maintained Rust implementation preferred behind it; project-owned crypto/session adapter only if compatibility testing requires it. |
| `Socket/socket.ts` | `Connection`, `QueryManager` | State-machine driven socket lifecycle. |
| `Socket/chats.ts` | `ChatService` | Privacy, presence, app-state, profile. |
| `Socket/groups.ts` | `GroupService` | Group metadata, participant operations, dirty refresh, invite workflows, and group update events; current progress is tracked in Section 13. |
| `Socket/messages-send.ts` | `MessageService` | Fanout, session assertion, encryption, media upload. |
| `Socket/messages-recv.ts` | `IncomingService` | Routing, decrypt, ack, retry, notifications. |
| `Socket/newsletter.ts` | `NewsletterService` | Newsletter metadata/actions, messages, reactions, views, linked-profile mapping, and admin/participant workflows; current progress is tracked in Section 13. |
| `Socket/business.ts` | `BusinessService` | Business profile, catalog, product/media helpers, collections, orders, notifications, and broader business workflows; current progress is tracked in Section 13. |
| `Socket/communities.ts` | `CommunityService` | Community metadata/actions, linked groups, participant/join-request flows, invites, and dirty refresh; current progress is tracked in Section 13. |

## 8. Implementation Phases

For the `/goal` implementation run, the phases below are the preferred execution
order for unfinished work in one continuous rewrite. For new or still-unfinished
work, complete the touched phase area's local validation loop before advancing
to unrelated work, but do not treat phase completion as a stopping point.

Because implementation has already started, phase deliverables are acceptance
criteria and remaining-work guides, not instructions to recreate foundations
that the progress section already records as landed. Section 13 can record
capabilities from later phase areas when they have already been implemented and
verified; that does not make earlier incomplete phase deliverables complete.

### Phase 0: Planning And Compatibility Baseline

Deliverables:

- Keep this plan document updated.
- Maintain and extend the API parity checklist extracted from the reference
  README and exported socket methods.
- Keep the reference commit hash and package version recorded in the
  compatibility baseline.
- Keep the settled immediate multi-crate Cargo workspace decision and target
  crate layout aligned with Section 4.

Validation:

- `cargo check --workspace --all-features` passes once the workspace scaffold
  exists.
- Before creating or resuming the `/goal`, review this plan. If a matching goal
  is already active, continue it unless a material plan change requires user
  input.

### Phase 1: Rust Project Foundation

Deliverables:

- Convert project to a library-first multi-crate Cargo workspace.
- Set Rust 1.96 as the project toolchain/MSRV using `rust-toolchain.toml` and
  workspace `rust-version` metadata.
- Add formatting, clippy, docs, test, and benchmark commands.
- Add crate-level safety lints.
- Add `tracing`-based logging.
- Add base `Error`, `Result`, config, and public prelude.
- Add CI-ready commands in docs.

Status note:

- The multi-crate workspace scaffold and Rust 1.96 toolchain metadata have
  landed. Keep this phase open only for missing foundation hygiene such as docs,
  CI command coverage, and any lint/check wiring not yet represented in the
  workspace.

Validation:

- `cargo fmt --all --check`
- `cargo check --workspace --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`

### Phase 2: Protobuf Generation

Deliverables:

- Generate Rust types from the reference `WAProto/WAProto.proto`.
- Check the generated Rust protobuf code into the repo under the `wa-proto`
  crate so normal builds do not require protobuf tooling.
- Provide a regeneration script or task that updates the checked-in generated
  code from `WAProto.proto`.
- Add a drift-check command and wire it into CI so stale checked-in generated
  code is detected when `WAProto.proto` changes.
- Wrap generated proto types where stronger Rust types are needed.
- Confirm large integer handling matches reference behavior.
- Add compatibility tests for selected messages from reference fixtures.

Implementation notes:

- Keep generated files out of hand-written modules.
- Do not require `protoc` or `prost-build` for ordinary consumer builds.
- Avoid cloning large protobuf payloads during encode/decode paths.

Status note:

- The checked-in protobuf crate, regeneration script, and drift-check tooling
  have landed. Remaining work in this phase is compatibility coverage and
  wrapper refinement, not reopening the checked-in-versus-build-time generation
  decision.

Validation:

- Round-trip encode/decode tests for representative WhatsApp messages.
- Snapshot tests for JSON/proto conversion only if public API requires it.

### Phase 3: Binary Node Codec And JID Model

Deliverables:

- Port token dictionaries to static Rust tables.
- Implement `BinaryNode` encode/decode including compression prefix handling.
- Implement JID parsing/encoding for PN, LID, hosted, group, broadcast,
  newsletter, interop, and device JIDs.
- Implement binary node helpers: child lookup, child buffer/string/uint,
  dictionary reduction, XML/debug rendering.

Efficiency focus:

- Decode from `Bytes`/`&[u8]` with index cursor and no unchecked indexing.
- Encode into preallocated `BytesMut`.
- Return borrowed data where practical, but do not overfit lifetimes before the
  API stabilizes.

Validation:

- Golden vectors generated by the reference `encodeBinaryNode` and
  `decodeBinaryNode`.
- Property tests: decode(encode(node)) for valid generated nodes.
- Fuzz tests for decoder, decompressor, JID parser, and packed nibble/hex parser.

### Phase 4: Auth Store And Key Store

Deliverables:

- Define `AuthStore`, `SignalKeyStore`, and transaction traits.
- Implement SQLite as the default native auth/key store.
- Add schema migrations and explicit schema versioning.
- Provide an in-memory store for focused unit tests.
- Implement transaction retry semantics matching reference defaults.
- Implement cacheable key store with bounded TTL and explicit invalidation.
- Implement credential initialization.

Safety focus:

- Secret fields use redacted debug and zeroization.
- SQLite writes must use transactions for related auth/key/session updates.
- Configure SQLite for crash-safe local use, such as WAL mode and appropriate
  synchronous settings after evaluating durability/performance tradeoffs.
- Store transactions must avoid duplicate pre-key IDs under retry/failure.

Validation:

- Auth init compatibility tests.
- Transaction collision tests.
- SQLite migration tests.
- Store crash-safety tests for interrupted transactions where feasible.

### Phase 5: Crypto And Noise Transport

Deliverables:

- Implement Signal-compatible curve helpers needed for auth and Noise.
- Implement AES-GCM, AES-CTR, AES-CBC where the reference uses them.
- Implement HKDF, HMAC, SHA-256, MD5 helpers.
- Implement WhatsApp Noise XX handshake:
  - WA header/routing info intro.
  - handshake hash/chaining key.
  - certificate verification.
  - transport-state frame encryption/decryption.
  - frame length prefixing and incremental reads.
- Implement pairing code key derivation and QR data construction.

Safety focus:

- Zeroize Noise chaining keys and temporary shared secrets.
- Reject malformed certs and invalid signatures with typed errors.
- Bound frame sizes to avoid memory exhaustion.

Validation:

- Unit tests from the reference `noise-handler.test.ts`.
- Golden handshake vectors from a mock server.
- Fuzz transport frame parser with max-frame limits.

### Phase 6: WebSocket Connection And Query Manager

Deliverables:

- Implement WebSocket client lifecycle and shutdown.
- Implement outbound send queue and inbound frame task.
- Implement message tags, query waiters, default/custom timeouts.
- Implement keepalive ping and connection-lost detection.
- Implement connection update events.
- Implement QR pairing and pairing code requests.
- Implement pre-key upload, digest, signed pre-key rotation hooks.

Rust shape:

- `Connection` owns tasks and abort handles.
- `Client::connect()` returns only after the socket task is running.
- `Client::wait_for_connection_update(predicate)` replaces ad hoc event waits.

Validation:

- Mock WebSocket server tests for open, close, timeout, query response, stream
  errors, QR pair-device, pair-success, and success events.
- No leaked tasks after `Client::close().await`.

### Phase 7: Event Hub And Initial State Machine

Deliverables:

- Implement typed `Event` enum covering the reference event map.
- Implement bounded event buffering and consolidation:
  - history set consolidation.
  - chat/contact/message upsert/update/delete merging.
  - reaction and receipt aggregation.
  - group update aggregation.
- Implement sync states: connecting, awaiting initial sync, syncing, online.
- Implement timeouts for initial sync and paused history sync.

Efficiency focus:

- Avoid unbounded history caches.
- Coalesce events by typed keys instead of stringly maps.
- Use bounded channels and expose lag/overflow errors.

Validation:

- Port `event-buffer.test.ts`.
- Stress test with high-volume history sync fixtures.

### Phase 8: USync

Deliverables:

- Implement `USyncQuery` and `USyncUser`.
- Implement contact, device, disappearing mode, status, username, bot profile,
  and LID protocols.
- Parse and store LID/PN mappings.
- Support `on_whatsapp`, device enumeration, status fetch, and disappearing
  duration fetch.

Validation:

- Unit tests with recorded USync result nodes.
- Device cache behavior tests.

### Phase 9: Signal Repository

Deliverables:

- Implement the project-owned `SignalRepository` boundary and integrate the best
  maintained Rust Signal protocol provider behind it first:
  - one-to-one session encrypt/decrypt.
  - pre-key and signed pre-key injection.
  - sender-key group encryption/decryption.
  - sender-key distribution messages.
  - session validation and deletion.
  - LID/PN in-store session-address migration, which is internal account
    identity maintenance and not legacy or foreign session-store import/export.
- Keep fallback project-owned crypto/session adapter work behind the same
  boundary and use it only if the maintained provider cannot pass compatibility
  testing.
- Implement LID mapping store.
- Implement keyed locks around session mutation.

Consistency note:

- The completed repository, address mapping, and store-backed codec boundaries
  are foundation work only. Phase 9 remains incomplete until a real Signal
  provider or compatibility-proven fallback adapter performs one-to-one ratchets
  and sender-key group cryptographic operations through that boundary.

Safety focus:

- All session records treated as secret data.
- Store mutations are transactional.
- Validate identity changes and expose events/errors clearly.

Validation:

- Port reference Signal tests.
- Cross-validate encryption/decryption with reference fixtures.
- Regression tests for sender-key state.

### Phase 10: Message Generation And Sending

Deliverables:

- Implement message content builders:
  - text, quote, mention, forward basics.
  - contact/contact array.
  - location/live location.
  - reactions.
  - poll and event message creation.
  - pin/edit/delete.
  - group invite.
  - product where proto support is ready.
  - disappearing mode setting.
- Implement message ID generation.
- Implement message relay:
  - recipient device enumeration for direct sends; extend fanout to group and
    status sends.
  - group/status participant nodes.
  - own-device DSM handling through the full send pipeline.
  - missing-session key-bundle assertion before direct sends.
  - Signal encryption.
  - participant hash for fanout stanzas.
  - device identity node.
  - reporting token.
  - tctoken handling.
- Implement receipts and read messages.
- Implement retry manager and wire it into inbound retry receipts.

Consistency note:

- The completed message builders, direct-device relay helpers, receipt helpers,
  reporting-token node generation and direct-send attachment, tctoken one-to-one
  attachment, explicit issuance query/result/store facade, bounded automatic
  post-send issuance scheduling for eligible one-to-one sends, retry planning,
  prepared retry resend execution, and placeholder resend foundations through
  explicit peer-data requests, decoded-stub
  detection, opt-in live incoming-node dispatch, opt-in spawned raw-node
  dispatch, tracker resolution, and cleanup are not full send parity.
  Phase 10 remains incomplete until real Signal-backed relay, group/status
  fanout, group sender-key cryptographic retry/redistribution edge cases, retry
  key-bundle device-identity reissuance edge cases, reporting-token edge cases,
  and remaining tctoken orchestration edge cases are implemented and validated.
  This does not reopen the separate landed
  outbound pre-key relay behavior that attaches the stored device identity node,
  the landed retry key-bundle device-identity payload preservation, or the landed
  explicit tctoken issuance query/result/store facade or the landed bounded
  automatic post-send issuance scheduler, the landed identity-change token
  reissue foundation, bounded pruning and connection-open maintenance, or
  profile-picture URL IQ and presence-subscribe token attachment.

Efficiency focus:

- Encode protobuf once per recipient class where possible.
- Avoid cloning large media/message payloads per device.
- Use per-JID encryption locks only around session mutation.

Validation:

- Golden generated message snapshots compared with the reference.
- Mock server tests for send stanza shape.
- Unit tests for retry counters and tctoken storage.

### Phase 11: Message Receiving, Acks, And Notifications

Deliverables:

- Route inbound binary nodes by tag/attrs/content.
- Decode message nodes.
- Decrypt one-to-one and group messages.
- Handle ciphertext stubs, missing keys, retry receipts, placeholder resend.
- Send message/call/receipt/notification acks.
- Handle receipts, calls, bad acks, media retry notification parsing/dispatch,
  identity changes.
- Handle MEX notifications and message capping/reachout timelock updates.
- Process offline nodes with fair yielding.

Consistency note:

- The completed inbound parsers, event mappers, raw-node pump, retry receipt
  planners, media retry notification parsers/event emitters, receive-side
  message/chat/contact/group/label/quick-reply/receipt/reaction/media-retry/call
  native-store persistence, account restriction/new-chat cap WMex notification
  mappers, fair-yielding offline-node child processing, and placeholder
  unavailable-stub mapping plus opt-in live and spawned raw-node placeholder
  resend dispatch are foundation work only.
  Phase 11 remains incomplete until real Signal-backed decryptor/session
  operations are wired in and retry, broader call edge cases, remaining
  notification edge cases, and broader offline-node behavior are complete.
  End-to-end media retry execution remains owned by Phase 12.

Validation:

- Port process-message, decode-message, stanza-ack, offline-node, and retry
  tests.
- Mock inbound message/call/receipt flows.

### Phase 12: Media

Deliverables:

- Implement media key derivation by media type.
- Implement streaming upload:
  - encrypt stream.
  - compute file SHA-256, encrypted SHA-256, HMAC.
  - upload to media hosts with timeout and retry.
  - cache upload results.
- Implement streaming download and decrypt.
- Implement end-to-end media retry request/response orchestration, including the
  descriptor refresh and download retry work triggered by receive-side media
  retry notifications.
- Implement thumbnails/profile picture generation behind feature flags.
- Implement audio duration/waveform only if suitable Rust dependencies are
  selected and kept optional.

Consistency note:

- The completed bounded byte-transfer, metadata, HTTP transfer, upload-cache,
  file-source, media retry application, pending retry coordinator, and batch
  retry handling helpers are foundation work only. Phase 12 remains incomplete
  until true streaming media encryption/decryption, large-media bounded-memory
  validation, full runtime media retry automation, and optional
  thumbnail/profile-picture processing are implemented and validated.

Efficiency focus:

- Stream from file/HTTP/memory uniformly in the final media service.
- Do not load large files fully into memory unless caller supplies bytes; current
  byte-oriented helper paths must reject oversized inputs before transport or
  crypto work begins.
- Apply max content length and timeout controls.

Validation:

- Port messages-media tests.
- Golden media key derivation tests.
- Integration tests with local HTTP server.

### Phase 13: Chat, App-State, History, Privacy, Profile

Deliverables:

- Implement privacy fetch/update APIs.
- Implement presence update/subscribe.
- Implement profile picture/status/name APIs.
- Implement blocklist fetch/update.
- Implement app-state patch encode/decode and LT hash.
- Implement app-state resync with missing-key blocked state.
- Implement history sync processing and event emission.
- Implement chat modifications: archive, mute, mark read/unread, delete, pin,
  star, labels, contacts, quick replies, disappearing settings.

Consistency note:

- The completed app-state patch, snapshot, sync-response, inline patch apply,
  bounded inline pagination, external blob recovery, native sync-key storage,
  missing-key blocked-state handling, app-state-key-share triggered resync, and
  bounded history sync helpers are foundation work only. Phase 13 remains
  incomplete until broader app-state retry/resync orchestration, live history
  sync event-pump coverage beyond the current decode/download/persistence
  foundation, and broader store-integrated chat/profile modification workflows
  beyond the initial upload facades are implemented and validated.

Validation:

- Port app-state, sync-action, lt-hash, history, chat-utils tests.
- Mock app-state sync with snapshots, patches, missing keys, and retries.

### Phase 14: Groups

Deliverables:

- Implement group metadata extraction.
- Implement create, leave, subject, description, settings, member add mode,
  join approval mode.
- Implement participant add/remove/promote/demote.
- Implement invite code, revoke invite, accept invite, invite info.
- Implement request-join list and approve/reject.
- Continue group dirty-bit refresh from the landed explicit refresh helper and
  initial notification-driven automatic refresh path. Remaining work is broader
  dirty-bit detection and refresh orchestration coverage.
- Emit group update and participant events, including edge cases beyond the
  landed initial group-notification mapper.
- Continue v4 invite response-message/update integration around the landed
  accept/revoke query foundation. Opt-in message update/upsert event emission
  and store-backed buffered side-effect persistence have landed; remaining work
  is broader validation and protocol edge-case coverage.

Consistency note:

- The completed group IQ, participant-operation, explicit dirty refresh,
  notification-triggered dirty refresh, notification event, v4 invite query, and
  opt-in persisted v4 invite side-effect event foundations are not full group
  parity.
  Phase 14 remains incomplete until broader dirty-bit refresh
  detection/orchestration, broader group event edge cases, and remaining group
  protocol edge cases are implemented and validated.

Validation:

- Port groups socket tests.
- Mock group IQ responses and error stanzas.

### Phase 15: Newsletters, Business, Communities

Deliverables:

- Implement newsletter message send/receive, metadata, admin/participant updates,
  reactions, views, linked-profile notification parsing, event emission, native
  store persistence, and broader mapping edge-case coverage.
- Continue business socket helpers and business profile/product APIs from the
  landed foundations. Profile fetch/update, profile and cover-photo mutation
  result validation, catalog query parsing, product create/update/delete,
  collection, order-detail, product-image single/batch upload, product
  create/update image-upload orchestration, metadata-preserving cover-photo
  upload, and cover-photo update/delete foundations have landed. Remaining work
  includes media edge cases, any missing business notification flows, broader mock
  validation, and ignored-by-default live e2e validation.
- Continue community metadata and actions from the landed foundations. Typed
  metadata, creation, linking/unlinking, linked-group listing,
  participant/join-request actions, invite, ephemeral, setting,
  member-add-mode, and join-approval IQ foundations have landed; explicit
  dirty-refresh helper and notification-triggered dirty refresh automation have
  landed; opt-in v4 invite message update/upsert event emission and
  store-backed buffered side-effect persistence have landed. Remaining work is
  edge cases, broader mock validation, and ignored-by-default live e2e
  validation.

Consistency note:

- The completed newsletter WMex envelope, metadata/action builders, direct
  message-update/live-update/reaction stanza builders, receive-side direct
  plaintext message, reaction, view, participant, and settings notification event
  mapping, typed fetched-message result parsing, typed reaction result
  validation, MEX settings and admin-promotion notification mapping,
  linked-profile notification parser/event mapping, receive-side native-store
  persistence, parsers, and client facade methods are foundation work only.
- The completed business profile fetch/update, profile and cover-photo mutation
  result validation, catalog query/parser, and product mutation
  builders/parsers, collection/order builders/parsers, business-hours
  parser/serializer, product/catalog parser, product-image single/batch media
  upload bridge, product create/update image-upload orchestration helpers,
  metadata-preserving cover-photo upload bridge, cover-photo update/delete IQ
  builders, client facade methods, and focused core/client mock tests are
  foundation work only.
- Phase 15 remains incomplete until broader newsletter message send/receive,
  broader view-tracking edge cases, broader admin/participant workflow edge
  cases, broader linked-profile mapping edge cases, missing business
  notification flows, business media edge cases, broader community edge cases,
  broader mock validation, and ignored-by-default live e2e validation are
  implemented and validated.

Validation:

- Golden stanza tests.
- Unit tests for parsers.
- Mock e2e flows for newsletter/business/community actions where feasible.
- Live e2e cases for these features must live in this repo and remain ignored by
  default unless required environment variables and test accounts are present.

### Phase 16: Public Examples And API Transition Guide

Deliverables:

- Examples:
  - QR login.
  - pairing code login.
  - session restore.
  - send text.
  - send media.
  - receive messages.
  - group metadata/actions.
  - custom auth store.
- API and concept transition guide from reference TypeScript concepts to Rust
  concepts. This must stay separate from session-store migration, import, or
  export tooling.
- API docs with warnings about private WhatsApp protocol instability.

Validation:

- Examples compile in CI.
- Doctests for public builders and basic APIs.

### Phase 17: Hardening, Performance, And Release

Deliverables:

- Fuzz corpus for binary node decode, JID parse, Noise frame parse, app-state
  patch decode, and selected protobuf wrappers.
- Benchmarks for binary encode/decode, media encryption, event buffering, and
  message fanout.
- Memory profiling for media and history sync.
- Security review of secret handling and log redaction.
- Semver policy and feature support matrix.

Validation:

- `cargo fmt --all --check`
- `cargo test --workspace --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo doc --workspace --no-deps --all-features`
- Fuzz smoke run in CI or nightly job.
- Benchmarks recorded before first release.

## 9. API Parity Checklist

This checklist is the target surface area for parity, not the current progress
ledger. Section 13 remains the source of truth for landed foundations and known
remaining gaps. A checklist bullet is not complete merely because a foundation
with a similar name has landed; confirm the related remaining-gap language
before treating it as done.

Initial MVP:

- Connect with QR.
- Connect with pairing code.
- Restore saved session.
- Emit connection updates.
- Send and receive text messages.
- Send and receive receipts.
- Basic one-to-one Signal encryption/decryption.
- Basic group Signal sender-key encryption/decryption.
- Fetch device list with USync.
- Upload pre-keys and rotate signed pre-key.

Messaging parity:

- Text, quote, mention, forward.
- Contacts, location, reactions.
- Polls, events, pin, edit, delete.
- Media: image, video, gif, audio, ptt, sticker, document.
- Link previews and high-quality thumbnail upload.
- Broadcast/status send.
- Media download and retry.
- Message retry and placeholder resend.
- Reporting token and tctoken behavior. These are message/send protocol features
  and are separate from the out-of-scope WAM analytics telemetry system.

Chat/account parity:

- Initial history sync.
- App-state sync and patches.
- Presence update/subscribe.
- Privacy settings.
- Block/unblock.
- Profile picture/status/name.
- Chat archive/mute/read/unread/delete/pin/star.
- Labels, contacts, quick replies.

Group parity:

- Create/leave.
- Metadata/fetch all participating.
- Participants add/remove/promote/demote.
- Subject/description/settings.
- Invite code/revoke/accept/info.
- Join requests.
- Ephemeral/member-add/join-approval settings.

Extended parity:

- Newsletters.
- Business helpers.
- Communities.
- Reachout timelock and new chat cap updates.

## 10. Testing Strategy

Use four layers of tests:

- Unit tests: deterministic modules such as JID parsing, binary codec, crypto
  helpers, event buffering, app-state patch logic, message builders.
- Golden tests: fixtures generated by the reference TypeScript project for binary nodes,
  message protobufs, media keys, app-state patches, and selected stanzas.
- Mock protocol tests: local WebSocket and HTTP servers for connection, QR,
  pairing, queries, message receive/send, media upload/download.
- Live e2e tests: keep them in this repo under a dedicated e2e test path,
  ignored by default, requiring explicit environment variables and test accounts.

Compatibility fixture approach:

1. Add a reference fixture generator script under `tools/compat/` during the
   compatibility fixture setup.
2. Generate JSON plus binary fixtures from the cloned TypeScript source.
3. Store small deterministic fixtures in `tests/fixtures/`.
4. Keep large or sensitive fixtures out of git.

Fuzz targets:

- `decode_binary_node`.
- `decompressing_if_required`.
- `jid_parse`.
- `noise_frame_decode`.
- `app_state_patch_decode`.
- `media_retry_decode`.

## 11. Performance Targets

Define concrete targets after baseline benchmarks, but design for:

- Binary codec with minimal allocations per node.
- Media upload/download memory proportional to chunk size, not file size.
- Event buffering bounded by configured limits.
- Device fanout parallel where safe, serialized only per JID/session.
- No background task leaks after disconnect.
- No unbounded retry, placeholder, device, call, tctoken, or history caches.

Initial benchmark candidates:

- Encode/decode 10,000 small binary nodes.
- Decode large history sync node.
- Encrypt/decrypt 10 MB media stream.
- Fanout message encryption to 1, 5, 25, and 100 devices.
- Event buffer consolidation for 50,000 history messages.

## 12. Security And Reliability Requirements

- Forbid unsafe code throughout the main rewrite.
- Redact secrets in all logs and debug output.
- Never panic on remote input.
- Bound all remote-controlled frame, node, list, string, media, and decompressed
  sizes.
- Validate certificate signatures and issuer serial during Noise handshake.
- Use constant-time comparison for MAC/signature checks where relevant.
- Isolate auth/key-store writes behind transactions.
- Clean up timers/tasks/channels on disconnect.
- Make reconnect logic explicit and observable.
- Treat WhatsApp protocol changes as expected operational risk; version defaults
  must be easy to update.

## 13. Current Implementation Progress

The phase descriptions above remain the intended execution order for remaining
work and the acceptance criteria for unfinished capabilities. This section
records what has already landed so the active `/goal` run can continue from the
next incomplete capability instead of repeating completed foundation work.

Progress is tracked by capability, not by declaring whole phases complete. A
landed bullet below means that specific foundation has been implemented and
verified; the phase is still incomplete if the remaining-gap list or parity
checklist still names work in that area.

Landed foundation work in the Rust workspace:

- Multi-crate workspace scaffold with Rust 1.96 toolchain metadata.
- Checked-in protobuf crate plus standalone regeneration and drift-check tooling.
- Binary node/JID crate with token tables, encode/decode tests, and generated
  dictionary data.
- Store crate with `AuthStore`, `SignalKeyStore`, transaction traits,
  paginated namespace key listing, default SQLite store, and feature-gated
  in-memory test store.
- SQLite store hardening with connection busy timeout and collision-resistant
  temporary database paths in transaction rollback tests to avoid parallel test
  lock flakes.
- Crypto crate with redacted/zeroized secret bytes, X25519 key helpers,
  Signal public-key prefixing, XEdDSA signatures for signed pre-keys, AES-GCM,
  AES-CTR, AES-CBC, SHA-256, MD5, HMAC, HKDF, pairing-code KDF, bounded Noise
  frame codec, client Noise XX key schedule, handshake transcript
  authentication, intro-header framing, XEdDSA certificate-chain verification,
  media HKDF key derivation, AES-CBC media encryption/decryption with truncated
  HMAC verification, plaintext/encrypted media hash calculation, media retry
  request/notification AES-GCM helpers with retry status mapping, and
  transport-state transition tests.
- Core auth credential model with versioned native store persistence for Noise
  keys, pairing ephemeral keys, signed identity keys, signed pre-key material,
  registration id, adv secret, pre-key upload counters, registration status,
  optional account JID, and optional routing info.
- Transactional load-or-initialize credential flow that generates first-run
  credentials, signs the initial pre-key, persists all credential fields through
  the native store, reloads existing credentials without replacement, and exposes
  registration-payload key material without private-key leakage.
- Pairing preparation helpers that build linked-device QR payload strings from
  stored credentials, generate Crockford pairing codes, derive and zeroize
  pairing-code encryption keys, wrap pairing ephemeral public keys, and construct
  typed pairing-code request binary nodes with platform id/display metadata.
- Pair-device challenge handling that builds the required result ack node,
  converts server refs into QR payload strings, sends pairing-code request nodes
  through an active connection, persists pairing-code/account-JID state, and
  emits QR events from the client facade.
- Pair-success/device-sign handling that verifies the signed device identity
  HMAC, verifies the account signature, signs the local device response, builds
  the result reply node, persists registered account metadata plus relay-ready
  signed device identity bytes, and emits credential-update events through the
  client facade.
- Authenticated key-bundle maintenance primitives for generating and storing
  uploadable pre-keys in a transaction, building and sending pre-key upload
  IQs, querying server pre-key count with error-result validation, typed
  key-bundle digest validation state, explicit upload and signed-pre-key
  rotation result validation, server-accepted pre-key upload confirmation that
  keeps failed uploads retryable, checking local current pre-key availability,
  rotating the signed pre-key, and persisting the rotation only after a
  successful server response.
- Saved-session validation through the client facade: stored registered
  credentials now build login validation requests, malformed registered state is
  rejected before network work starts, and validated transport/WebSocket helpers
  use the loaded credentials with a bounded outbound queue.
- Automatic post-auth key maintenance orchestration that validates key-bundle
  digest state, uploads the initial pre-key batch when the digest is missing,
  uploads the minimum pre-key batch when server/local availability is low, and
  optionally rotates the signed pre-key behind an explicit configuration flag.
- Signal repository boundary with deterministic protocol address mapping,
  server key-bundle parsing into typed E2E session injections, transactional
  store-backed session insertion/validation/deletion/internal address
  migration, identity-change session invalidation, and forward/reverse LID-PN
  mapping persistence.
- Store-backed Signal message codec boundary that implements the existing
  outbound message encryption and inbound message decryption traits through a
  pluggable crypto provider, requires stored sessions before one-to-one
  encrypt/decrypt operations, persists sender-key distribution payloads in the
  native Signal store, and supplies stored sender-key state to group decrypt
  calls.
- E2E session assertion foundation with encrypt-namespace key-bundle query
  construction, duplicate suppression, optional identity-refresh reason
  attributes, LID-preferring session query addressing, response parsing, and
  direct and child error-result validation, plus client-side transactional
  injection before auto-discovered direct sends.
- USync query foundation with typed users/protocol selection, IQ construction,
  contact/device/status/disappearing-mode/LID/username result parsing, direct
  and child error-result validation, and a client execution helper over the
  existing binary-node query path.
- Higher-level USync convenience helpers for phone existence checks, LID mapping
  fetch-and-persist flows, and device-JID extraction with hosted/LID domain
  handling, current-device exclusion, zero-device filtering, and missing
  key-index filtering for non-zero devices.
- Additional USync facade coverage for status fetch, disappearing-mode duration
  fetch, and bot-profile lookup, with typed query builders, result mappers, and
  mock connection tests.
- Message-generation foundation with WhatsApp-compatible random and v2 message
  ID generation, validated message keys, text-message protobuf construction
  with quote/mention/forwarding context and typed text/audio styling fields,
  supplied-metadata link-preview fields including in-message JPEG thumbnails and
  high-quality thumbnail media metadata,
  contact and contact-array builders, location/live-location builders, reaction
  builders, poll/event creation builders with message-secret validation and
  event join-link support,
  edit/delete/pin/disappearing-mode protocol builders, group invite builders,
  typed uploaded-media descriptor plus image/video/ptv/audio/document/sticker
  protobuf builders with strict media key and hash validation, product/catalog
  snapshot builders that reuse the uploaded image path, boxed content enum
  variants to keep the send API small in memory, top-level view-once and
  disappearing-setting future-proof message wrapping, album placeholders,
  request/share-phone-number builders, limit-sharing protocol builders,
  button/template/list reply builders, and encoded protobuf output helpers.
  Automatic link-preview fetching, image thumbnail generation, and high-quality
  thumbnail upload remain unfinished.
- Direct-device message relay foundation with a provider-based encryption
  boundary, participant `to`/`enc` node construction, own-device
  device-sent-message protobuf wrapping, stanza type detection, client
  `send_text_to_devices`/`relay_message_to_devices` methods over the connection,
  auto-discovered direct-send `send_text`/`relay_message` helpers, discovered
  device recipient classification for PN/LID/hosted linked devices,
  missing-session assertion before relay, v2 participant hash generation for
  fanout stanzas, automatic stored device identity inclusion for pre-key
  ciphertext relay stanzas, explicit duplicate avoidance for caller-supplied
  identity nodes, and focused relay stanza tests.
- Reporting-token foundation with eligibility checks for excluded message
  classes, message-secret and message-id validation, allowlisted protobuf field
  filtering over encoded message bytes, HKDF/HMAC token derivation, typed
  `reporting/reporting_token` node construction, high-level direct-send
  attachment after final message-id preparation, duplicate caller-supplied node
  avoidance, and focused core/client tests. Broader send-parity edge cases
  remain unfinished.
- Receipt/read-message foundation with typed receipt kinds, receipt stanza
  construction including timestamped read/read-self receipts and multi-id
  `list/item` payloads, sender-receipt addressing, aggregation of non-own
  message keys by chat/participant, and client `send_receipt`, `send_receipts`,
  and `read_messages` helpers.
- Media retry receipt-node foundation with encrypted retry request stanza
  construction, media retry update parsing from `rmr` receipt nodes, error/status
  mapping, requester JID normalization, and client helpers for sending
  caller-supplied or media-key-encrypted retry payloads.
- Media metadata bridge helpers that convert encrypted media output into uploaded
  media descriptors, derive download URLs from direct paths, verify plaintext and
  encrypted SHA-256 hashes, and decrypt media bytes with metadata validation for
  focused in-memory test coverage.
- Bounded media transfer foundation with a pluggable transport trait,
  encryption-before-upload orchestration, uploaded-media metadata construction,
  hash-verified download/decrypt orchestration, configurable upload/download
  size limits, and client facade helpers for upload/download byte workflows.
- Media connection and HTTP transfer foundation with typed media-connection IQ
  construction/parsing, host/auth/TTL extraction, direct and child error-result
  validation, URL-safe upload-token generation from encrypted media hashes,
  kind-to-upload-path mapping, optional `http-media` transport backed by
  `reqwest`, local HTTP upload/download test coverage, and client facade support
  for fetching media connection info.
- Bounded media upload-cache foundation with typed cache keys based on media kind,
  plaintext SHA-256, and length; cache-entry validation before reuse; a
  capacity-limited TTL in-memory cache with LRU eviction; cached upload transfer
  and client facade helpers; and focused tests proving reuse, expiry, eviction,
  and bad-entry rejection.
- Bounded file-source media helper foundation with async chunked file reads and
  writes, pre-read file-size validation, upload/download-to-file helpers,
  cached file upload facade methods, file size-limit rejection before transport
  work, and focused core/client tests. This still uses the byte-oriented crypto
  path internally, so true streaming encryption remains unfinished.
- Receive-side stanza foundation with typed ACK/NACK construction, client
  `send_ack`/`send_nack` helpers, known NACK and server ACK error constants,
  inbound ACK/receipt/notification metadata parsers, addressing-context
  extraction, and message-stanza metadata decoding into typed keys, authors,
  senders, and message classes without panicking on malformed network input.
- Inbound message payload decode boundary with strict random-padding removal,
  plaintext node decoding, encrypted `msg`/`pkmsg`/`skmsg` payload extraction
  through an async decryptor trait, device-sent-message unwrapping,
  sender-key-distribution callback handling, and focused malformed-payload
  tests in both all-feature and no-default builds.
- Receive-event mapping helpers that convert decoded inbound messages into
  typed message upsert events with encoded protobuf payloads and stable metadata
  fields, convert inbound receipts into receipt update events, convert inbound
  message ACKs into message status updates, convert inbound media retry receipt
  nodes into typed media retry events that retain encrypted retry payloads and
  error status data, convert inbound call stanzas into typed call events, and
  push decoded messages through the bounded event buffer without bypassing
  pending-item limits.
- Receive-side native-store persistence that writes typed message
  upsert/update/delete events, chat upsert/update/delete events, contact
  upsert/update/delete events, group update events, receipt update events,
  reaction update events, label edit events, label association events,
  quick-reply update events, media-retry events, call events, and history
  chat/contact/message batches from direct receive calls and spawned
  incoming-processor events into the versioned native store while preserving the
  existing bounded event-buffer emission path and LID/PN mapping persistence.
- Fair-yielding offline-node processing that walks offline child nodes through
  the same inbound message/receipt/ack/notification router, returns every child
  response for ACK/NACK emission, integrates with the spawned raw-node processor,
  and keeps the bounded event-buffer and native-store persistence paths intact.
- Media retry application foundation with deterministic mock notification
  encryption for protocol tests, encrypted media retry notification decryption,
  stanza/result validation, refreshed media descriptor construction from retry
  direct paths, message-secret retention, retry-download helpers over the
  existing media transfer boundary, and client facade coverage for descriptor
  refresh plus retry downloads.
- Bounded media retry coordinator foundation with message-keyed pending media
  descriptors, media-kind and fallback-host retention, strict descriptor
  validation, configurable capacity and TTL eviction, LRU pressure handling,
  pending-state removal after successful retry downloads, a client-owned default
  coordinator, and facade helpers for registering pending media plus consuming
  typed retry events.
- Media retry batch handling foundation that consumes typed retry events from an
  `EventBatch`, drives the bounded pending-media coordinator and transfer path,
  downloads successful retry results, ignores unmatched retry events without
  allocating new state, collects per-message retry errors, and exposes the path
  through the client facade.
- Opt-in incoming-node media retry processing that routes a live received node
  through the inbound parser, sends required ACK/NACK responses, flushes typed
  event batches, drives the client-owned pending-media coordinator and transfer
  path for retry events, returns downloaded retry media or per-message retry
  errors to the caller, and still emits the typed batch to subscribers.
- Inbound node processor foundation that routes `message`, `receipt`, `ack`, and
  `notification` stanzas through the receive parsers/event mappers, returns
  typed processing results, builds ACK/NACK response nodes where required, and
  preserves bounded event-buffer enforcement for queued events.
- Client incoming-node facade that uses authenticated account JID/LID metadata
  to drive the inbound node processor, writes required ACK/NACK response stanzas
  over the active connection, and flushes typed receive events into the bounded
  client event stream.
- Automatic incoming processor task handle that subscribes to raw socket node
  events, routes them through the same inbound processor, sends required
  ACK/NACK responses, flushes typed events into the client event stream, stops
  on connection close, reports lag as a protocol error, and aborts on drop so no
  background task is silently detached.
- Raw-node event boundary for connection/router dispatch so socket-originated
  nodes can be consumed by the incoming processor without reprocessing
  post-processor node events such as notifications.
- Bounded retry/session-recovery manager foundation with recent-message cache,
  retry counters, MAC-error and missing-session recreation decisions, session
  recreation cooldowns, base-key collision tracking, deterministic delayed phone
  request scheduling without runtime timers, statistics, and explicit cache
  capacity/TTL configuration.
- Retry receipt handling foundation with strict inbound retry receipt parsing,
  multi-id receipt extraction, retry reason/error parsing, registration-id
  parsing, key-bundle presence detection, resend target selection for primary
  versus specific device requesters, group sender-key clear decisions, and
  session recovery action planning for refresh, bundle injection, stale
  registration, base-key collision cases, and recent-message cache resend
  preparation that reports missing message IDs without reconstructing
  unavailable payloads.
- Retry resend execution foundation with a client-owned bounded message retry
  manager, automatic recent-message caching after successful direct relay,
  public plan/prepare/statistics facades, prepared-job execution to requesting
  devices or rediscovered direct-send device sets through the existing relay
  pipeline, successful retry cache cleanup, automatic retry session-action
  handling for stale-session deletion and forced session refresh, opt-in
  incoming-node and spawned raw-node retry receipt handling that ACKs then
  replays cached messages, inline retry key-bundle payload parsing/injection,
  typed retry key-bundle device-identity payload preservation/exposure, group
  sender-key memory cleanup for group retry receipts, and focused replay tests.
  Outbound pre-key relay identity-node attachment is covered by the direct-device
  relay foundation above; group sender-key cryptographic retry/redistribution
  edge cases and retry key-bundle device-identity reissuance edge cases remain
  unfinished.
- Placeholder resend request/response foundation with a typed peer-data operation
  protocol-message builder, validated batched message keys, high-priority peer
  relay to the authenticated account JID, default meta-node attachment,
  caller-option preservation, peer-data response decoding from embedded
  `WebMessageInfo` bytes into recovered message-upsert events, request-id/source
  metadata retention, integration with decoded-message event batches, a bounded
  duplicate-request tracker with TTL/capacity, duplicate rejection before
  network work, explicit response-event pending-request resolution, eligible
  unavailable-stub detection from decoded `WebMessageInfo` with age and excluded
  unavailable-type filters, a client facade that drives peer-data requests from
  those detected stubs while suppressing duplicates, manual expired-request
  purge support, an owned background cleanup task that purges expired pending
  requests without detaching, receive-side raw unavailable-message stub mapping
  with ACK/no-event handling for excluded unavailable fanouts, opt-in live
  incoming-node processing that emits the placeholder stub then sends the
  peer-data request, automatic pending-request resolution from live
  placeholder-response batches, opt-in spawned raw-node processor dispatch for
  direct and offline unavailable-message stubs, and focused core/client mock
  coverage.
- Typed tctoken native-store foundation with size-bounded binary records,
  validated JID keys, received-token and sender-marker timestamp retention,
  load/save/delete helpers, malformed record rejection, marker-preserving expiry
  cleanup, one-to-one send-node construction and high-level send attachment,
  privacy-token issue IQ construction, trusted-contact token result parsing,
  merge-and-store helpers, explicit client issuance facade, SQLite-backed
  helper plus mock-query tests, and bounded automatic fire-and-forget post-send
  issuance for eligible one-to-one sends with in-flight coalescing and mock
  transport coverage. Identity-change token reissue foundation has landed with
  typed encrypt-notification outcomes, bounded debounce, existing-session and
  recent-sender-timestamp gates, pre-refresh reissue scheduling, live and
  spawned incoming-node hooks, and mock coverage. Bounded token pruning has
  landed with paginated store scans, malformed-record cleanup, regular-user
  gating, sender-marker preservation for recently issued tokens, and client
  facade coverage. Connection-open prune maintenance has landed with interval
  throttling, bounded batch sizing, an owned abort-on-drop task handle, and
  event-driven mock coverage. Profile-picture URL token attachment has landed
  with LID-aware storage lookup, regular-user gating, self-target skips,
  group-target skips, duplicate avoidance, and mock query coverage.
  Presence-subscribe token attachment has landed with LID-aware storage lookup,
  regular-user gating that skips group targets, and sent-node coverage. Broader
  tctoken orchestration edge cases remain unfinished.
- Chat/account operations foundation with typed privacy settings fetch/update
  IQs, default disappearing-mode updates, profile status and profile-picture
  URL/update/remove IQ helpers, shared account mutation result validation for
  privacy/default-disappearing/profile-status/profile-picture/blocklist updates,
  blocklist fetch/update parsing, LID/PN-aware block/unblock facade behavior
  through the native mapping store, presence and chat-state node builders,
  presence subscription helpers, public client facade methods, and mock
  connection coverage for stanza shape plus parsed results.
- App-state/chat-mutation foundation with typed app-state collection requests,
  dirty-bit clean IQ construction, raw encoded patch upload IQ construction,
  app-state sync and patch-upload result validation, pre-encryption chat
  mutation builders for mute/archive/read-pin-star/delete/push-name sync
  actions, message-range conversion to generated protobuf types, exact
  sync-action protobuf encoding from JSON index bytes, app-state key expansion
  plus index/value/snapshot/patch MAC helpers, deterministic encrypted
  mutation-record construction, native LT-hash add/subtract arithmetic,
  outbound app-state hash/index-value-MAC state evolution for set/overwrite/
  remove mutations, typed `SyncdPatch` bundle construction with derived next
  version/snapshot/patch MAC fields, inbound patch decode with value/index/
  patch/snapshot MAC verification and state advancement, verified snapshot
  decode/application into exact-version app-state baselines, typed sync response
  extraction for collections, patch bytes, has-more flags, and snapshot blob
  references, bounded external app-state blob download/decrypt/decode helpers
  for snapshots and mutation blobs, random-IV chat mutation encryption, initial
  high-level pin/archive/mute/read/delete/star/profile-name/contact/
  quick-reply/label mutation upload facades, pure receive-side decoded
  sync-action to `EventBatch` mapping for chat/contact/message/label/
  quick-reply store updates, compact native-store app-state patch-state
  persistence, decoded patch/snapshot apply helpers that save state and emit
  mapped event batches through the client facade, inline sync-response
  orchestration that fetches a sync response, decodes inline patches in order
  from native store state, persists advanced state, emits mapped event batches,
  reports pending snapshots/has-more flags, and follows bounded has-more inline
  patch pages until current, plus external snapshot recovery that downloads,
  MAC-verifies, applies, persists, and emits recovered snapshot batches before
  continuing any remaining pages, native app-state sync-key load/save helpers,
  store-key sync application that parks collections blocked on missing sync keys
  without treating the whole sync as fatal, and bounded store-key pagination that
  stops retrying blocked collections until their key arrives, app-state
  sync-key-share extraction from self-originated protocol messages, key-share
  persistence, and automatic blocked-collection resync through manual and
  spawned incoming-node processing paths; public client facade methods; and mock
  connection coverage for stanza shape, inline patch application, snapshot
  recovery, and missing-key retry-after-key-arrival.
- History sync foundation with bounded zlib inflate/decode for inline and
  downloaded history payloads, media-key verified external history download
  using the existing pluggable media transfer boundary, typed conversion into
  `HistorySetEvent`/`EventBatch` values for chats, contacts, and messages,
  native-store persistence for those chat/contact/message history events, LID/PN
  mapping extraction from direct mapping records and conversation fields,
  item-count limits for mapped history events, public client facade methods, and
  focused core/client mock transport coverage.
- Group operations foundation with typed `w:g2` IQ builders, metadata and
  participating-group parsers, create/leave/subject/description helpers with
  mutation result validation, participant add/remove/promote/demote result
  mapping, invite code/revoke/accept/info helpers, ephemeral/settings/
  member-add/join-approval helpers with mutation result validation, join-request
  list and approve/reject helpers, client facade methods, and mock connection
  coverage for outbound stanza shape plus parsed results.
- Group notification event foundation that maps recognized inbound group
  notifications for subject, description, announcement/restrict settings,
  ephemeral duration, member-add/join-approval mode, and participant add/remove/
  promote/demote changes into typed group update batches while retaining raw
  notification delivery and ACK behavior.
- Group dirty refresh workflow that fetches the participating-group snapshot
  first, then marks the group dirty bit clean only after the refresh query
  succeeds, returning both refreshed group metadata and the clean marker node
  through the client facade, with typed dirty-notification processing,
  notification-triggered refresh through the incoming processor, and focused
  group-update event emission from refreshed metadata.
- Group v4 invite query foundation with validated typed invite descriptors,
  accept and revoke IQ builders, result parsing, client facade methods, opt-in
  accepted-invite message update/upsert event emission, transactional native
  store persistence for those side effects, buffered emission variants, and mock
  connection coverage for stanza shape plus emitted and persisted side effects.
- Newsletter foundation with reusable bounded WMex JSON IQ envelope handling
  including direct and child stanza-error validation, typed metadata
  lookup/create/update/follow/mute/delete/admin-count builders, metadata and
  count parsers, direct message-update/live-update/reaction stanza builders,
  typed fetched-message result parsing into message events, typed reaction
  result validation, receive-side direct plaintext message, reaction, view,
  participant, and settings notification event mapping, MEX settings and
  admin-promotion notification mapping, linked-profile notification parser/event
  mapping, receive-side native-store persistence for linked-profile mappings,
  client facade methods, and focused mock connection coverage.
- Business profile, catalog, and product mutation foundation with typed profile
  fetch/update IQ builders, profile and cover-photo mutation result validation,
  business-hours serialization/parsing, catalog query builder, product/catalog
  parser, product create/update/delete builders/parsers, typed pre-uploaded
  product image references, product-image single/batch upload bridge methods,
  product create/update image-upload orchestration methods, metadata-preserving
  media upload results, cover-photo update/delete profile IQ builders,
  collection query/parser, order detail query/parser, client facade methods,
  focused core parser tests, and mock connection facade coverage.
  Business media edge cases, notifications, broader business workflows,
  broader mock validation, and ignored-by-default live e2e validation remain
  unfinished.
- Community IQ/facade foundation with typed metadata and participating-community
  queries, community create/subgroup-create/leave/subject/description helpers,
  link/unlink and linked-group parsing, participant and join-request actions,
  invite/v4-invite query helpers, ephemeral/settings/member-add/join-approval
  helpers, shared community mutation result validation for leave/subject/
  description/link/unlink/ephemeral/settings/member-add/join-approval updates,
  explicit participating-community dirty refresh that cleans the group dirty bit
  only after a successful refresh query, typed dirty-notification parsing,
  notification-triggered refresh through the incoming processor, public client
  facade methods, opt-in accepted-invite message update/upsert event emission,
  transactional native store persistence for those side effects, buffered
  emission variants, and focused core/client mock coverage. Broader protocol
  edge cases, broader mock validation, and ignored-by-default live e2e validation
  remain unfinished.
- Account restriction and new-chat capping foundation with typed WMex query
  builders/parsers, direct and child stanza-error validation, typed account
  update events, receive-side WMex notification parsing for reachout timelock
  and message-capping updates, client facade fetch methods, and focused mock
  connection plus inbound processing coverage.
- Core query manager with unique tags, duplicate protection, response waiters,
  timeout cleanup, pending-waiter shutdown, and tests.
- Core connection runtime scaffold with mockable frame sink/stream traits,
  bounded outbound queue, typed inbound frame events, tagged query-response
  routing, lifecycle close handling, and task-cleanup regression tests.
- Binary-node dispatch helpers that decode inbound protocol frames, extract
  `attrs.id` response tags, resolve pending query waiters, and emit unmatched
  decoded nodes as typed events.
- Connection runtime binary-node integration with encoded node send/query
  helpers, inbound binary-node decoding, query resolution by node id, and
  fallback raw-frame emission for non-node payloads.
- Feature-gated WebSocket transport adapter using `tokio-tungstenite`, default
  Rustls TLS support, optional native TLS support, binary-frame send/receive
  tests against a local server, text-frame rejection, and connection-runtime
  integration tests.
- Feature-gated Noise frame sink/stream runtime wrappers that encode outbound
  frames, decode fragmented inbound Noise frames, avoid holding handshake locks
  across network awaits, and plug into the same connection runtime traits.
- Typed client payload builders for login and registration, including user
  agent/web info fields, device pairing key bundle encoding, app-version hash,
  device properties, history sync capabilities, JID validation, and focused
  protobuf field tests.
- Basic event hub foundation with bounded broadcast capacity and typed
  connection, frame, node, QR, and credential-update events.
- Bounded event-buffer foundation with typed batch events for history snapshots,
  message upsert/update/delete, chat/contact upsert/update/delete, label edits,
  label associations, quick-reply updates, group updates, receipts, and
  reactions; consolidation merges updates by typed keys, applies deletes, keeps
  immediate lifecycle events ordered before batches, and rejects pushes that
  would exceed the configured pending-item limit.
- End-to-end mock connection validation that sends the client Noise hello, reads
  a mock server hello, encrypts login or registration payloads into the client
  finish, sends that finish before transport-state encryption begins, transitions
  into the shared Noise transport, spawns the bounded connection runtime, and
  emits typed connection updates for success and failure paths.
- Client facade scaffold with builder/config/prelude, event subscription, store
  ownership, query-manager ownership, initialized credential access, pairing QR
  data generation, pairing-code request preparation with credential persistence,
  and exported connection runtime types.

Known major remaining gaps before the rewrite can be considered complete:

- Signal provider integration: plug a real maintained Signal protocol provider
  into the `SignalCryptoProvider` interface for one-to-one ratchets and
  sender-key group cryptographic operations. The landed repository and
  store-backed codec boundaries are not full Signal protocol parity by
  themselves.
- Receive and sync-state integration: finish wiring remaining inbound/history
  state surfaces beyond the current persisted message/chat/contact/group/
  label/quick-reply/receipt/reaction/media-retry/call event records, connect the
  automatic raw-node pump to real Signal-backed decryptor/session operations,
  and complete sync-state behavior beyond the current bounded
  broadcast/consolidation foundations.
- Test parity: add compatibility fixture generation, broader golden-vector
  coverage, property tests, and fuzz targets beyond the focused tests already
  added.
- Message send/decryption parity: complete real Signal-backed direct encryption,
  group sender-key relay, status/broadcast fanout, group sender-key
  cryptographic retry/redistribution beyond the current prepared resend
  execution plus session-action refresh/delete, inline key-bundle injection, and
  group sender-key memory cleanup foundation, retry key-bundle device-identity
  reissuance handling where required, reporting-token edge cases beyond the
  current allowlisted node generation and direct-send attachment foundation,
  remaining tctoken orchestration beyond the current typed native-store,
  one-to-one attachment, explicit issuance facade, bounded automatic post-send
  issuance scheduler, identity-change reissue foundation, bounded pruning facade
  plus connection-open maintenance task, profile-picture URL IQ attachment,
  presence-subscribe attachment, link-preview fetching/thumbnail generation and
  upload beyond the current supplied-metadata protobuf builder, and remaining
  poll/event send/receive edge cases.
- Media parity: implement true streaming media encryption/decryption and
  large-media bounded-memory validation beyond the current byte-oriented
  HTTP/file helpers, fully automatic background media retry orchestration beyond
  the current typed event, retry-download, bounded pending coordinator, batch
  handling, and opt-in incoming-node processing helpers, and optional generated
  profile-picture and thumbnail processing.
- App-state, history, and chat parity: implement broader app-state retry/resync
  orchestration beyond the current inline patch application, bounded has-more
  pagination, external snapshot recovery, native sync-key storage, missing-key
  blocked-state, and key-share-triggered resync path; finish live history sync
  event-pump coverage and broader edge cases beyond the current bounded decode,
  external-download, event-mapping, native-store persistence, and facade
  foundation; complete store-integrated high-level chat/profile modification
  workflows beyond the initial pin/archive/mute/read/delete/star/profile-name/
  contact/quick-reply/label upload facades; and broaden recovered remote
  snapshot coverage through the current native-state persistence and decoded
  sync-action event mapping.
- Group parity: broaden dirty-bit notification detection and automatic refresh
  orchestration beyond the current typed dirty-node refresh path, expand group
  notification edge-case coverage beyond the initial typed event mapper, and
  complete remaining group protocol edge cases beyond the landed group IQ,
  participant-operation, dirty-refresh, v4 invite query, and persisted opt-in
  side-effect event foundations.
- Extended surface parity: complete broader newsletter send/receive, broader
  view tracking, broader linked-profile mapping edge cases, and
  admin/participant workflow edge cases beyond the current newsletter
  metadata/action/query/fetched-message/plaintext-message/reaction/view/
  reaction-result/participant/settings/MEX-admin-promotion/linked-profile event
  and receive-side persistence foundation; complete
  missing business notifications, business media edge cases, and broader
  workflows beyond the current
  profile/catalog/product/collection/order/product-image/cover-photo foundation;
  complete broader community edge cases beyond the current community IQ/facade,
  dirty-refresh, notification-triggered refresh, and persisted opt-in
  side-effect event foundations.
- Release/user-facing readiness: add public examples, API docs, the transition
  guide, and live e2e harnesses. Live e2e tests remain in this repository and
  ignored by default unless explicitly configured.

## VM Handoff Snapshot

This section is the fast source of truth when moving the work to a new VM. It
summarizes the current state without replacing the detailed progress ledger
above.

### Current State Summary

The Rust workspace has broad foundations in place across protocol types, binary
node handling, auth/key storage, Noise setup, connection/query management,
message construction, direct-device relay scaffolding, receive-side parsing,
event buffering, native-store persistence, media helper foundations,
app-state/history foundations, groups, newsletters, business helpers,
communities, and account restriction/capping helpers.

The most recent completed work expanded message-generation parity. The message
builder foundation now includes typed builders for text styling, supplied link
preview metadata, contacts, locations, reactions, polls, events with optional
join links, edit/delete/pin/disappearing-mode protocol messages, group invites,
uploaded image/video/ptv/audio/document/sticker descriptors, products/catalogs,
view-once and disappearing-setting wrappers, album placeholders,
request/share-phone-number messages, limit-sharing protocol messages, and
button/template/list replies.

The project is not production-complete. The biggest remaining blockers are real
Signal provider integration, full Signal-backed send/decrypt relay behavior,
group/status fanout, true streaming media encryption/decryption, broader
receive/sync-state integration, compatibility fixtures, fuzz/property coverage,
public examples/docs, and ignored-by-default live e2e harnesses.

### Worktree Transfer Note

Before moving to a VM, transfer the full workspace state, not only files already
known to the original git baseline. In the current environment, key rewrite
files show as untracked relative to that baseline. Either copy the whole working
directory, create a patch bundle, or commit the current state before moving.

At minimum, preserve these paths:

- `Cargo.toml`
- `rust-toolchain.toml`
- `crates/`
- `docs/`
- `tools/`
- `tests/`
- the local TypeScript reference directory used only as protocol reference input

### Latest Verified Gates

The latest completed implementation slices were verified with:

- `cargo check -p wa-client --no-default-features --quiet`
- `cargo test -p wa-core --all-features --quiet`
- `cargo test -p wa-client --all-features --quiet`
- `cargo fmt --all --check`
- `cargo clippy -p wa-store -p wa-core -p wa-client --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features --quiet`
- naming scan over `docs`, `crates`, root manifests, toolchain file, and `tools`
- trailing-whitespace scan over touched Rust files and this plan
- `git diff --check` over touched Rust files and this plan

On the VM, run the same gates first after copying the workspace. If a command
fails because dependencies are not yet downloaded, install the Rust toolchain
from `rust-toolchain.toml` and allow Cargo to fetch dependencies.

### Recommended Next Implementation Order

1. Resume from the remaining-gap list in Section 13, not from the earliest phase
   header.
2. Integrate the best maintained Rust Signal provider behind the existing
   `SignalCryptoProvider`/`SignalRepository` boundary. This is the highest-risk
   and highest-value remaining task.
3. Wire real Signal-backed direct encryption/decryption through send and receive
   paths, then add group sender-key relay and status/broadcast fanout.
4. Replace byte-oriented media crypto transfer foundations with true streaming
   upload/download encryption/decryption and large-file bounded-memory tests.
5. Add compatibility fixture generation from the local reference, then broaden
   golden vectors, property tests, and fuzz targets.
6. Finish receive/sync-state integration around the real decryptor, app-state
   retry/resync edge cases, live history event pumping, and broader notification
   edge cases.
7. Broaden group/newsletter/business/community edge-case coverage and ignored
   live e2e validation.
8. Add public examples, API docs, transition guide, release matrix, and final
   hardening/performance review.

### Progress And Time Estimate

Risk-adjusted overall rewrite progress is approximately 50 percent complete.
The foundation surface is broader than that number suggests, but the unfinished
parts include the highest-risk work: real Signal cryptographic compatibility,
full live send/receive behavior, streaming media, compatibility fixture
coverage, and live e2e validation.

Estimated remaining effort for one senior Rust engineer already familiar with
this codebase:

- Serious mock-tested beta: 8 to 12 full-time engineering weeks.
- Production-quality parity target with live e2e harnesses, broader fixtures,
  fuzzing, docs, and release hardening: 12 to 20 full-time engineering weeks.
- Add 3 to 6 weeks if the preferred Signal provider cannot be adapted cleanly
  and a project-owned compatibility adapter must be completed instead.

These estimates assume continued single-go implementation with focused
test-fix-retest loops and no major upstream protocol breakage during the move.

## 14. Settled Decisions And Open-Decision Status

Decided:

- Use an immediate multi-crate Cargo workspace. Do not start as a single crate.
- Use neutral crate, module, file, package, and public API names. Do not inherit
  upstream package naming.
- Keep the project-owned `SignalRepository` boundary and integrate the best
  maintained Rust Signal implementation behind it first. If that dependency is
  difficult to adapt or repeatedly fails compatibility tests, replace the
  crypto/session adapter behind the same boundary with a project-owned
  implementation.
- Use SQLite as the default native, versioned, transaction-safe runtime store.
- Check in generated Rust protobuf code and provide an explicit regeneration
  script plus drift-check tooling.
- Do not implement WAM telemetry in the main rewrite.
- Use Rust 1.96 as the project toolchain/MSRV.
- Keep live e2e tests in this repository.
- Treat current feature flags as manifest-defined. Planned flags such as
  `media`, `link-preview`, `image`, `serde`, and `mock` remain planned until
  crate manifests add them.

Storage format decision:

- The primary store is what the Rust client reads and writes during normal use.
  It should be SQLite by default and designed for Rust safety and reliability:
  explicit schema versions, migrations, transactions, redacted debug output, and
  zeroized secret fields.
- The rewrite will not implement import/export as part of the main `/goal`.
- Users should pair/login fresh into the native Rust store.
- Do not make legacy or foreign session formats part of the runtime path.
- Import/export may be considered later as a separate optional tool if a real
  migration or interoperability requirement appears.
- If import/export is added later, it must be explicit conversion tooling with
  careful validation and secret-handling warnings, not something the client
  depends on during normal operation.

Open decisions:

- None at the top-level as of this revision. New implementation findings should
  be added here only when they require a real project-level decision.

## 15. Single-Go Goal Operating Mode

Use exactly one `/goal` for the complete rewrite. If none exists when
implementation resumes, create it. If that goal has already started, continue it.
Section 13 is the source of truth for landed foundations and known remaining
gaps. Do not recreate completed crates or capabilities; verify them when touched
and continue from the next incomplete capability named in the remaining-gap list,
parity checklist, or phase acceptance criteria.

Operating checklist:

1. Keep continuing the existing single-go implementation objective instead of
   opening separate phase goals.
2. Treat completed foundations as reusable implementation substrate, not as
   whole-phase completion unless all phase deliverables and validation are done.
3. Keep focused test-fix-retest loops active for every touched capability.
4. Continue adding compatibility fixtures, property tests, and fuzz targets; the
   focused unit tests already present do not satisfy those validation
   requirements by themselves.
5. Prefer mock protocol coverage until live e2e tests are explicitly configured;
   live e2e tests still belong in this repository and remain ignored by default.
6. Continue directly into the next incomplete capability rather than stopping at
   any foundation checkpoint.

## 16. Definition Of Done For The Rewrite

The rewrite is complete when:

- The public Rust client can perform QR login, pairing code login, session
  restore, Signal-backed send/receive messaging, media transfer, USync, group
  operations, app-state sync, core privacy/profile operations, newsletters,
  business helpers, and communities.
- The API parity checklist in Section 9 is complete, or each unmet item has a
  documented exclusion or version-specific limitation.
- Key reference tests have Rust equivalents or documented exclusions.
- Binary/protobuf/crypto behavior is covered by golden compatibility fixtures.
- Secrets are redacted and zeroized where practical.
- Network parsers are fuzzed and bounded.
- The workspace passes fmt, clippy, tests, docs, and release checks.
- Examples compile and demonstrate the supported public workflows.
- Any explicitly excluded behavior or version-specific limitation is documented
  in a parity matrix.
