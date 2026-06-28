---
title: wa-store
type: module
sources:
  - crates/wa-store/src/lib.rs
  - crates/wa-store/src/traits.rs
  - crates/wa-store/src/memory.rs
  - crates/wa-store/src/sqlite.rs
  - crates/wa-store/Cargo.toml
related:
  - "[[wa-core]]"
  - "[[wa-client]]"
  - "[[Signal Protocol]]"
  - "[[Pairing Flow]]"
  - "[[Irminsul Overview]]"
summary: Storage abstraction — AuthStore/SignalKeyStore traits, transactional KV with namespaces, and SQLite + in-memory backends.
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-store

A namespaced, transactional key-value abstraction for all persistent state:
credentials, Signal sessions/identities/pre-keys, sender keys, app-state version
data, TC tokens, and serialized events. The protocol layer is generic over the
store; you can supply the bundled SQLite store, the in-memory store, or your own.

## Traits (`traits.rs`)

- **`AuthStore`** — the async core API: `get`, `set`, `delete`, `list_keys`
  (paginated), and `transaction(label, closure)`
  (`crates/wa-store/src/traits.rs:120`). Everything is keyed by
  `(KeyNamespace, String)`.
- **`StoreTransaction`** — synchronous `get`/`set`/`delete` executed atomically
  inside `transaction` (`:114`). [[Pairing Flow|Credential]] and
  [[Signal Protocol|session]] mutations run here so partial writes can't corrupt
  state.
- **`KeyNamespace`** — a closed enum (~43 variants: `Credentials`, `PreKey`,
  `Session`, `SenderKey`, `IdentityKey`, `AppStateSyncKey`,
  `AppStateSyncVersion`, `TcToken`, `LidMapping`, …) with `as_str()` for wire
  encoding (`crates/wa-store/src/traits.rs:18`, `:64`). Namespacing keeps the flat
  KV space collision-free across subsystems.
- **`SignalKeyStore`** — a thin sibling API for Signal records
  (`get_signal_key`/`set_signal_key`/`delete_signal_key`/`signal_transaction`),
  with a **blanket impl for any `AuthStore`** (`:138`, `:159`) — so implementing
  `AuthStore` is sufficient to also be a `SignalKeyStore`.
- Errors are a typed `StoreError` (`Sqlite`, `Join`, `MissingParent`,
  `InvalidData`) with `StoreResult<T>` (`:3`).

## Backends

- **`SqliteAuthStore`** (`sqlite.rs`, feature `sqlite`) — `Arc<Mutex<Connection>>`
  over a single `kv_store(namespace, key)` table plus a `schema_meta` table
  (`crates/wa-store/src/sqlite.rs:58`). Opens with WAL journaling, `NORMAL` sync,
  foreign keys, and a 5-second busy timeout (`:50`); `transaction` uses native
  SQLite transactions (`:159`). This is the default, durable, crash-safe store.
- **`MemoryAuthStore`** (`memory.rs`, feature `memory`) — `Arc<Mutex<HashMap<…>>>`
  with snapshot-isolation transactions and `Zeroize`-on-drop `SecretValue`s
  (`crates/wa-store/src/memory.rs:11`, `:132`). For tests and examples.

## Features

`default = ["sqlite", "bundled-sqlite"]`; `memory` is opt-in
(`crates/wa-store/Cargo.toml`). `bundled-sqlite` statically compiles SQLite so no
system library is needed. See the `custom_auth_store` example
([[wa-client]]) for a minimal hand-written `AuthStore`.
