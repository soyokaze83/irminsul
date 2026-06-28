---
title: wa-crypto
type: module
sources:
  - crates/wa-crypto/src/lib.rs
  - crates/wa-crypto/src/primitives.rs
  - crates/wa-crypto/src/keys.rs
  - crates/wa-crypto/src/noise.rs
  - crates/wa-crypto/src/media.rs
  - crates/wa-crypto/src/app_state.rs
  - crates/wa-crypto/src/secret.rs
related:
  - "[[Noise Handshake]]"
  - "[[Signal Protocol]]"
  - "[[Media Transfer]]"
  - "[[App-State & History Sync]]"
  - "[[wa-core]]"
  - "[[Irminsul Overview]]"
summary: Crypto primitives — AES, HKDF/HMAC/SHA, X25519/XEdDSA, the Noise XX handshake, media crypto, app-state crypto, and zeroized secrets.
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-crypto

All cryptography lives here, behind small typed functions. It deliberately uses
only **permissively-licensed** RustCrypto-family crates (see
[[Clean-Room & Permissive Licensing]]) and is `#![forbid(unsafe_code)]`. Higher
layers ([[wa-core]]) never reach for a cipher directly; they call these helpers.

## Primitives (`primitives.rs`)

Thin wrappers returning `CryptoResult` over a typed `CryptoError`
(`crates/wa-crypto/src/primitives.rs`):

- AES: `aes_256_gcm_encrypt/decrypt`, `aes_256_cbc_encrypt/decrypt[_with_iv]`,
  `aes_256_ctr_apply`.
- KDF/MAC/hash: `hkdf_sha256`, `hmac_sha256`/`hmac_sha512`, `verify_hmac_sha256`,
  `sha256_hash`, `md5_hash`, `derive_pairing_code_key`.

## Keys (`keys.rs`)

X25519 / Curve25519 key handling: `KeyPair`, `generate_key_pair`, `shared_key`
(ECDH), `public_key_from_private`, `sign_x25519`, and
`verify_curve25519_signature`. `prefixed_signal_public_key` /
`SIGNAL_PUBLIC_KEY_VERSION` prepend the `0x05` type byte libsignal expects
(`crates/wa-crypto/src/keys.rs:16`). The Curve25519 signature verifier is what
makes [[Signal Protocol]] and [[Noise Handshake]] signatures interoperate with
real WhatsApp.

## Noise (`noise.rs`)

The **Noise XX** handshake (`Noise_XX_25519_AESGCM_SHA256`) and transport framing
used to secure the WebSocket: `NoiseHandshake`, `NoiseFrameCodec`, `NoiseTransport`,
plus certificate-chain validation against the pinned `ROOT_CERT_PUBLIC_KEY`
(`crates/wa-crypto/src/noise.rs:17`). The `XEdDsaNoiseCertificateVerifier`
(`:69`) verifies WhatsApp's libsignal-style Curve25519 certificate signatures.
Full detail in [[Noise Handshake]].

## Media (`media.rs`)

Per-`MediaKind` key derivation (`derive_media_keys`, HKDF with a kind-specific
info string), one-shot and **streaming** AES-CBC encrypt/decrypt with HMAC and MAC
sidecars, and the media-retry notification crypto (AES-GCM). Detailed in
[[Media Transfer]].

## App-state (`app_state.rs`)

The MACs, value encryption, and **LT-hash** arithmetic that secure app-state
patches and snapshots: `derive_app_state_keys`, `app_state_index_mac` /
`app_state_value_mac` / `app_state_patch_mac` / `app_state_snapshot_mac`,
`app_state_lt_hash_subtract_then_add`. Detailed in [[App-State & History Sync]].

## Secrets (`secret.rs`)

`SecretBytes` wraps key material with `Zeroize`-on-drop and a redacted `Debug`
impl, so secrets cannot accidentally leak into logs. This underpins the project's
"secret key material is zeroized and uses redacted Debug" guarantee.

## Notable feature gates

`http-media`, `image`, `link-preview`, `rustls`, `native-tls`, and `noise` mirror
the [[wa-client]] flags so crypto compiled into a build matches transport choices.
