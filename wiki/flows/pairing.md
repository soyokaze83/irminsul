---
title: Pairing Flow
type: flow
sources:
  - crates/wa-core/src/auth.rs
  - crates/wa-core/src/pairing.rs
  - crates/wa-core/src/pre_keys.rs
  - crates/wa-core/src/validation.rs
related:
  - "[[Noise Handshake]]"
  - "[[Connection Stack]]"
  - "[[Signal Protocol]]"
  - "[[wa-store]]"
  - "[[wa-client]]"
summary: How a new device registers — credential init, QR / pairing-code link, pair-success verification, and pre-key upload — then restores on reconnect.
updated: 2026-06-28
source_commit: ace4f9c
---

# Pairing Flow

Linking Irminsul as a companion device to a WhatsApp account. There are two entry
methods (QR scan and pairing code); both end with a signed device identity the
client stores and reuses on every later connect.

## 0. Credentials

`create_initial_credentials` (`crates/wa-core/src/auth.rs:80`) generates the
long-lived key material: a Noise key, a pairing-ephemeral key pair, a signed
identity key, a signed pre-key, a 14-bit registration id
(`generate_registration_id`, `:133`), and an adv-secret key — all with
`registered = false`. `load_or_init_credentials` (`:199`) loads them transactionally
from the [[wa-store|store]] (`Credentials` namespace), creating them on first run.

## 1. Connect & handshake

The client opens the [[Connection Stack|WebSocket]] and runs the
[[Noise Handshake]] via `validate_connection`. For an unregistered device the
ClientFinish carries a **registration** ClientPayload
(`build_registration_payload`); for a registered one, a **login** payload keyed by
the stored `account_jid`.

## 2a. QR pairing

The server sends a `pair-device` challenge with one or more `ref` tokens.
`handle_pair_device_challenge` (`crates/wa-core/src/pairing.rs:176`) builds a QR
string per ref via `build_pairing_qr_data` (`:90`) — base64 of the ref plus the
noise, signed-identity, and adv-secret public keys — and returns them as
`PairDeviceChallenge { ack, qr_codes }`. The user scans a QR with their phone. The
client surfaces each as an `Event::Qr` ([[Event Model]]).

## 2b. Pairing code

For phone-number entry instead of scanning: `build_pairing_code_request`
(`crates/wa-core/src/pairing.rs:111`) generates (or accepts a custom) Crockford
pairing code, wraps the pairing-ephemeral public key, and emits a
`link_code_companion_reg` IQ. When the phone enters the code, the server sends a
companion-reg notification; `handle_link_code_companion_reg_notification` (`:350`)
derives an encryption key from the code, decrypts the primary's ephemeral key,
computes the shared secret, and derives a fresh adv-secret key via HKDF.

## 3. Pair-success

Either path culminates in a `pair-success` stanza. `handle_pair_success`
(`crates/wa-core/src/pairing.rs:212`) verifies the `AdvSignedDeviceIdentityHmac`
with the adv-secret key, extracts the account info and device identity, signs the
device message with the identity key, and returns `PairSuccess` with updated
credentials: `registered = true`, `account_jid`/`account_lid`/`account_name` set,
and the `signed_device_identity` stored. The reply IQ returns the signed
device-identity to the server. The client persists credentials and emits
`Event::CredentialsUpdated`.

## 4. Pre-keys

So peers can start [[Signal Protocol]] sessions, the device uploads one-time
pre-keys. `prepare_pre_key_upload` (`crates/wa-core/src/pre_keys.rs:45`) generates a
batch (default `INITIAL_PRE_KEY_COUNT`), stores them in the `PreKey`
[[wa-store|namespace]], and builds the upload IQ (registration id, identity, key
list, signed pre-key). `confirm_pre_key_upload` advances
`first_unuploaded_pre_key_id` after the server acks. `current_pre_key_status` and
`build_signed_pre_key_rotation` (`:195`) maintain the count and rotate the signed
pre-key over time.

## Restore

On a later run, `load_or_init_credentials` finds `registered = true`, so the client
skips pairing entirely: it opens the same store, sends a **login** payload during
the handshake, and resumes. Session restore is just "reopen the same native SQLite
store" — foreign session import/export is out of scope.
