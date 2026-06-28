---
title: Signal Protocol
type: concept
sources:
  - crates/wa-core/src/signal.rs
  - crates/wa-crypto/src/keys.rs
  - tools/compat/README_signal_conformance.md
  - tests/fixtures/signal_conformance.json
  - tests/fixtures/signal_group_conformance.json
related:
  - "[[wa-core]]"
  - "[[wa-crypto]]"
  - "[[Send Message Flow]]"
  - "[[Receive Message Flow]]"
  - "[[Clean-Room & Permissive Licensing]]"
  - "[[JID]]"
summary: Clean-room X3DH + Double Ratchet (1:1) and sender-key (group) end-to-end encryption, wire-compatible with libsignal.
updated: 2026-06-28
source_commit: ace4f9c
---

# Signal Protocol

`crates/wa-core/src/signal.rs` (~21.7k lines) is the project's clean-room
implementation of WhatsApp's end-to-end encryption — the libsignal-equivalent layer.
It covers **1:1** sessions (X3DH key agreement + Double Ratchet) and **group**
encryption (sender keys), the wire formats for both, and the store/repository
abstractions that persist session state. It is the single largest and most
sensitive module in the codebase; it depends on [[wa-crypto]] for primitives and on
[[wa-store]] (via `SignalKeyStore`) for persistence.

> Why own this code at all? libsignal is AGPL. To stay MIT, Irminsul reimplements
> the protocol and proves byte-compatibility against the real thing — see
> [[Clean-Room & Permissive Licensing]].

## 1:1 sessions — X3DH + Double Ratchet

- **Session establishment (X3DH).** Outbound:
  `derive_verified_signal_outbound_pre_key_root_chain_keys`
  (`crates/wa-core/src/signal.rs:2654`) verifies the peer's signed pre-key, then
  combines 3–4 DH agreements (identity↔signed-pre-key, base↔identity,
  base↔signed-pre-key, optional base↔one-time-pre-key) and HKDFs them
  (info `"WhisperText"`) into the initial root + chain keys. Inbound:
  `derive_signal_inbound_pre_key_root_chain_keys` (`:2707`).
- **Double Ratchet.** The DH ("root") ratchet is `ratchet_signal_root_key` /
  `derive_signal_root_chain_keys` (`:2589`, `:2563`, HKDF info `"WhisperRatchet"`).
  The symmetric ("chain") ratchet is `ratchet_signal_message_chain` (`:2540`):
  `derive_signal_message_key_seed` = HMAC(0x01, ck), `advance_signal_message_chain_key`
  = HMAC(0x02, ck), and `derive_signal_message_keys` HKDF-expands 80 bytes
  (cipher‖mac‖iv) with info `"WhisperMessageKeys"` (`:2501`).
- **Body crypto.** `encrypt_signal_message_body` / `decrypt_signal_message_body`
  are AES-256-CBC with the derived IV (`:2747`).
- Skipped/out-of-order message keys are buffered up to
  `SIGNAL_MAX_PROVIDER_MESSAGE_KEYS = 2000`, with a forward-jump cap of 25 000
  (`crates/wa-core/src/signal.rs:66`).

## Group encryption — sender keys

Each sender distributes a **SenderKeyDistributionMessage** once per group
(`build_signal_sender_key_distribution_message`, `:2874`); receivers ingest it via
`apply_signal_sender_key_distribution`, keeping up to
`SIGNAL_MAX_SENDER_KEY_STATES = 5` states for key rotation (`:3051`, `:64`).
Per-message: `ratchet_signal_sender_chain` (`:2834`) derives keys (HKDF info
`"WhisperGroup"`, `:2805`); `encrypt_signal_sender_key_record_message` AES-CBC
encrypts and **Ed25519-signs** the message (`:3108`);
`decrypt_signal_sender_key_record_message` verifies the signature and decrypts,
buffering up to 2000 skipped keys (`:3143`).

## Wire format (libsignal-compatible)

- **WhisperMessage**: `version_byte ‖ protobuf{ratchetKey,counter,prevCounter,
  ciphertext} ‖ MAC8`. The version byte is `0x33`
  (`(3<<4)|3`, `crates/wa-core/src/signal.rs:60`); the 8-byte MAC is
  `HMAC-SHA256(macKey, senderIdPub ‖ receiverIdPub ‖ version ‖ protobuf)[..8]`
  (`:2769`). Encode/decode at `:2318`/`:2334`.
- **PreKeyWhisperMessage**: `0x33 ‖ protobuf{preKeyId?, baseKey, identityKey,
  inner WhisperMessage, registrationId, signedPreKeyId}`; no outer MAC — the inner
  message carries it (`:2420`).
- **SenderKeyMessage**: `version ‖ protobuf ‖ Ed25519 signature(64)` (`:3224`);
  **SenderKeyDistributionMessage** at `:2890`. Public keys are normalized to the
  33-byte `0x05`-prefixed form via `normalize_signal_public_key` (`:2295`).

> **Conformance.** These framings are pinned by golden vectors generated from the
> *real* `libsignal` package (`tools/compat/README_signal_conformance.md:1`,
> `tools/compat/signal_wireformat_oracle.cjs`) and committed as
> `tests/fixtures/signal_conformance.json` / `signal_group_conformance.json`. The
> README's "KNOWN GAP (2026-06-22)" note records the *historical* divergence (no
> version byte, MAC misplaced); the code at `signal.rs:60`/`:2769` now implements
> the libsignal framing the vectors target. The repo `README.md` summarizes the
> 1:1 and group layers as "verified byte-compatible with the reference libsignal
> implementation."

## Stores & repository

- **`SignalRepository`** (trait, `crates/wa-core/src/signal.rs:392`) — inject /
  get / validate / delete sessions, migrate sessions between JIDs, save identity,
  cache sender-key distributions. Implemented by **`StoreSignalRepository<S>`**
  (`:966`) over any `SignalKeyStore`, guarded by `SignalMutationLocks`.
- **`SignalProviderStateStore`** (`:997`) is the lower-level keyed record store
  (sessions, identities, pre-keys, signed pre-keys, sender keys), keyed by
  `SignalProviderRecordKind`; mutations run inside store transactions.
- **`SignalCryptoProvider`** (`:536`) is the async encrypt/decrypt interface the
  messaging layer calls; **`StoreSignalSenderKeyProvider`** (`:580`) implements it.
- **`LidPnMappingStore`** (`:3502`) maps between phone-number and LID identities
  (`pn:{user}` / `lid:{user}` keys) — see [[JID]]. Session migration moves records
  when a peer's addressing changes (`SignalSessionMigration`, `:356`).
- **Retry-receipt bundles** (`RetryReceiptSessionBundle`, `:164`) package a session
  injection + device identity so the [[Send Message Flow|retry path]] can rebuild a
  broken session.

## Key constants

`signal.rs:38–67`: 32-byte root/chain keys, 16-byte IV, 8-byte message MAC,
`0x33` wire version, 64-byte sender-key signature, ≤5 sender-key states, ≤2000
buffered message keys, ≤25 000 forward jumps. HKDF info strings: `"WhisperText"`,
`"WhisperRatchet"`, `"WhisperMessageKeys"`, `"WhisperGroup"`.
