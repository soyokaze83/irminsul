---
title: Noise Handshake
type: concept
sources:
  - crates/wa-crypto/src/noise.rs
  - crates/wa-core/src/noise.rs
  - crates/wa-core/src/validation.rs
  - crates/wa-core/src/payload.rs
related:
  - "[[wa-crypto]]"
  - "[[Connection Stack]]"
  - "[[Pairing Flow]]"
  - "[[Signal Protocol]]"
summary: The Noise_XX_25519_AESGCM_SHA256 handshake that authenticates the server and encrypts the WhatsApp WebSocket.
updated: 2026-06-28
source_commit: ace4f9c
---

# Noise Handshake

Before any stanza flows, the client and WhatsApp server perform a **Noise XX**
handshake over the raw WebSocket. After it completes, every frame is AES-GCM
encrypted. The pattern is `Noise_XX_25519_AESGCM_SHA256`
(`crates/wa-crypto/src/noise.rs:21`).

## Pieces

- **`NoiseHandshake`** (`crates/wa-crypto/src/noise.rs:90`) holds the local
  ephemeral key, the running handshake `hash`/`salt`, the derived enc/dec keys, a
  counter, and the intro header. The intro header defaults to
  `DEFAULT_NOISE_HEADER = [87, 65, 6, 3]` = `"WA\x06\x03"`
  (`crates/wa-crypto/src/noise.rs:15`) and may carry routing info.
- **`NoiseFrameCodec` / `NoiseTransport`** frame and (later) encrypt traffic;
  `DEFAULT_MAX_FRAME_LEN` is 16 MiB (`:14`).
- **Certificate verification** — `validate_noise_certificate_chain` checks the
  server's cert chain terminates at the pinned root
  (`ROOT_CERT_PUBLIC_KEY`/`ROOT_CERT_SERIAL`, `crates/wa-crypto/src/noise.rs:16`).
  `XEdDsaNoiseCertificateVerifier` (`:69`) verifies the Curve25519 signature with
  the libsignal sign-bit convention rather than strict XEdDSA — a deliberate choice
  documented in-source because strict XEdDSA rejects ~half of real WhatsApp
  signatures (`:79`).

## XX message exchange

[[Connection Stack|`validate_connection`]] drives the three XX messages
(`crates/wa-core/src/validation.rs`):

1. **ClientHello** — client sends its ephemeral public key.
2. **ServerHello** — server returns its ephemeral + static keys and certificate;
   the client mixes DH results into the handshake state and verifies the cert
   chain.
3. **ClientFinish** — the client sends its encrypted static key and a
   **ClientPayload**: either a login payload (existing session) or a registration
   payload (first pairing), built by `build_login_payload` /
   `build_registration_payload` (`crates/wa-core/src/payload.rs:25`, `:45`). The
   registration payload embeds the app `version_hash` (MD5 of the version string,
   `crates/wa-core/src/payload.rs:198`) and device props.

`handshake.finish_transport()` then yields the symmetric `NoiseTransport`.

## Wrapping the transport

The handshake is shared as `SharedNoiseHandshake = Arc<Mutex<NoiseHandshake>>`
(`crates/wa-core/src/noise.rs:9`). `NoiseFrameSink` / `NoiseFrameStream`
(`crates/wa-core/src/noise.rs:16`, `:51`) wrap the plaintext
[[Connection Stack|frame transport]]: the sink encrypts each outgoing frame; the
stream decrypts inbound frames (buffering multiple decoded frames in a `VecDeque`).
From there, the [[Binary Node Codec]] decodes each decrypted frame into a node.

The handshake authenticates the **server**; the **client/account** is
authenticated separately by the [[Pairing Flow]] and the [[Signal Protocol]]
identity keys.
