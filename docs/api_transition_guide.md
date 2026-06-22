# API Transition Guide

This guide maps concepts from the upstream TypeScript reference to the Rust
workspace. It is about API shape and mental model only. It is not session-store
migration, import, or export tooling.

WhatsApp Web is a private protocol and can change without notice. Live examples
and live e2e tests should use accounts you control.

## Core Model

| TypeScript reference concept | Rust workspace concept |
| --- | --- |
| Socket factory | `Client::builder(store).connect().await?` |
| Auth state object | `AuthStore` trait, usually `SqliteAuthStore` |
| In-memory auth state | `MemoryAuthStore` behind `memory-store` |
| Event emitter | `client.subscribe()` returning typed `Event` values |
| Socket methods mixed into one object | Explicit `Client` methods and typed helper structs |
| Raw connection after login | `ValidatedConnection`, with `connection()` for query/send helpers |
| Message content objects | `MessageContent`, `TextMessage`, `ImageContent`, and related typed structs |
| Store/key callbacks | `AuthStore` and `SignalKeyStore` implementations |
| Optional media/link preview helpers | Feature-gated `http-media`, `image`, and `link-preview` APIs |

`ClientBuilder::connect()` initializes local client state and credentials. It
does not open a websocket. Live protocol traffic is explicit through
`client.connect_websocket().await?`, which returns a `ValidatedConnection`.
Query and send helpers take `validated.connection()`.

## Pairing And Sessions

Use a native Rust store for normal operation:

```rust
use wa_client::prelude::*;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let store = SqliteAuthStore::open(".wa/session.sqlite").await?;
let mut client = Client::builder(store).connect().await?;

let qr_payload = client.pairing_qr_data("reference-from-server");
let pairing_code = client
    .prepare_pairing_code_request("+1234567890", None)
    .await?;
# Ok(())
# }
```

Reusing the same SQLite database restores the Rust session state. Foreign
session formats are intentionally outside the runtime path for this rewrite.

## Events

Rust events are typed enum variants instead of string event names:

```rust
use wa_client::prelude::*;

# async fn example<S: AuthStore>(client: Client<S>) -> Result<(), Box<dyn std::error::Error>> {
let mut events = client.subscribe();
while let Ok(event) = events.recv().await {
    match event {
        Event::MessagesUpsert(messages) => println!("messages: {}", messages.len()),
        Event::ConnectionUpdate(state) => println!("connection: {state:?}"),
        other => println!("event: {other:?}"),
    }
}
# Ok(())
# }
```

`EventBatch` and `EventBuffer` provide bounded consolidation for state-heavy
receive flows such as history sync and app-state updates.

## Sending Messages

Live sends require a validated connection and a paired session:

```rust
use wa_client::prelude::*;

# async fn example(client: Client<SqliteAuthStore>) -> Result<(), Box<dyn std::error::Error>> {
let validated = client.connect_websocket().await?;
let relay = client
    .send_text_with_signal_provider(
        validated.connection(),
        "1234567890@s.whatsapp.net",
        "hello from Rust",
        MessageRelayOptions::new(),
    )
    .await?;
println!("sent {}", relay.message_id);
# Ok(())
# }
```

Media sends are a two-step flow: upload encrypted media through a
`MediaTransfer`, then wrap the returned `UploadedMedia` in message content.
The concrete HTTP transport is behind the `http-media` feature.

## Groups And State

Group operations are typed client methods:

```rust
use wa_client::prelude::*;

# async fn example(client: Client<SqliteAuthStore>) -> Result<(), Box<dyn std::error::Error>> {
let validated = client.connect_websocket().await?;
let group = client
    .fetch_group_metadata(validated.connection(), "1234567890-1234567890@g.us")
    .await?;
println!("participants: {}", group.participants.len());
# Ok(())
# }
```

Chat/profile/app-state helpers are explicit Rust methods rather than hidden
socket layers. Methods that persist local state after server acceptance are
named separately from upload-only helpers where both behaviors exist.

## Custom Stores

Implement `AuthStore` for custom credential storage. `SignalKeyStore` is
blanket-implemented for `AuthStore`, so most callers only implement one trait.
The `custom_auth_store` example shows the required methods and transaction
shape.

## Feature Flags

Default `wa-client` features enable SQLite storage, bundled SQLite, Noise,
websockets, and rustls. Optional surfaces include:

- `memory-store`: in-memory store for tests and examples.
- `http-media`: concrete HTTP media upload/download transport.
- `image`: bounded thumbnail/profile-picture generation helpers.
- `link-preview`: link-preview fetching and thumbnail upload helpers.
- `native-tls`: alternate websocket TLS backend.

Use `required-features` on examples or integration binaries that depend on
optional APIs.

## Current Maturity

The Rust workspace has broad protocol foundations, but this is not production
parity yet. Remaining work includes broader Signal compatibility proof, broader
live send/receive validation, live media retry validation, broader
compatibility fixtures, fuzzing, API docs, and broader ignored-by-default live
e2e coverage.
