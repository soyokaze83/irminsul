---
title: Media Transfer
type: concept
sources:
  - crates/wa-crypto/src/media.rs
  - crates/wa-core/src/media.rs
related:
  - "[[wa-crypto]]"
  - "[[wa-core]]"
  - "[[Send Message Flow]]"
  - "[[Receive Message Flow]]"
summary: Per-kind media encryption (streaming AES-CBC + HMAC), HTTP upload/download with hash verification, an upload cache, and the media-retry flow.
updated: 2026-06-28
source_commit: ace4f9c
---

# Media Transfer

Media (images, video, audio, documents, stickers, thumbnails, profile pictures,
app-state and history blobs) is end-to-end encrypted with a per-object key, then
uploaded to / downloaded from WhatsApp's media CDN. Crypto lives in
[[wa-crypto]] (`media.rs`); transport, caching, and the retry coordinator live in
[[wa-core]] (`media.rs`).

## Encryption (`wa-crypto/src/media.rs`)

- **`MediaKind`** (`crates/wa-crypto/src/media.rs:24`) — 19 variants, each mapping
  to a distinct HKDF info string (e.g. `"WhatsApp Image Keys"`, `:46`).
- **Key schedule** — `derive_media_keys` expands a 32-byte media key to 112 bytes
  → IV(16) ‖ cipher(32) ‖ mac(32) (`:370`).
- **One-shot** — `encrypt_media_bytes` (random key) / `encrypt_media_bytes_with_key`
  (`:383`, `:388`): AES-256-CBC, then HMAC-SHA256 over IV‖ciphertext, producing
  `EncryptedMedia` with a 10-byte MAC sidecar plus `file_sha256` (plaintext) and
  `file_enc_sha256` (ciphertext+MAC) hashes. `decrypt_media_bytes` verifies the MAC
  then decrypts (`:413`).
- **Streaming** — `MediaStreamEncryptor`/`Decryptor` process block-by-block so
  large files never fully reside in memory (`:146`, `:261`); `finalize` applies
  PKCS7 padding and emits the final MAC.
- **Media-retry crypto** — `derive_media_retry_key` (info
  `"WhatsApp Media Retry Notification"`, `:432`), AES-GCM
  encrypt/decrypt of the retry notification, and `media_retry_status_code`
  mapping result types to HTTP-like codes (`:507`).

## Transport & pipelines (`wa-core/src/media.rs`)

- **`MediaTransport`** (trait, `crates/wa-core/src/media.rs:1083`) — `upload_media`,
  `upload_media_stream`, `download_media[_to_file]`. **`HttpMediaTransport`**
  (`:609`, feature `http-media`) implements it over `reqwest`, iterating candidate
  hosts and enforcing per-host size caps.
- **URLs & connection** — `MediaConnectionInfo` (hosts, auth, TTL) parsed from a
  server node (`:171`, `:207`); `media_download_url` / `media_url_from_direct_path`
  resolve a download URL from a `direct_path` or absolute URL (`:1652`, `:1645`);
  `media_upload_url` builds the POST URL with the `file_enc_sha256` token (`:1684`).
- **`MediaTransfer<T>`** (`:1332`) is the orchestrator:
  - **Upload**: validate size → `encrypt_media_bytes` → upload ciphertext+MAC →
    assemble an `UploadedMedia` descriptor (url, direct_path, key, both hashes,
    length) via `uploaded_media_from_encrypted` (`:1378`, `:1785`).
  - **Download**: resolve URL → download → `decrypt_and_verify_media_bytes`, which
    checks `file_enc_sha256`, decrypts, then checks `file_sha256` (`:1569`,
    `:2706`). `download_to_file` streams to a temp file then decrypts to the final
    path.
- **Upload cache** — `MediaUploadCache` keyed by (kind, plaintext sha256, length);
  `MemoryMediaUploadCache` is a TTL+capacity LRU so re-sending the same bytes skips
  re-upload (`:367`, `:399`).

## Media-retry flow

When a recipient can't decrypt media it returns a retry receipt; when *we* can't
download, we request a fresh `direct_path`. `MediaRetryCoordinator` (`:835`) tracks
`PendingMediaRetry` entries keyed by `MessageEventKey` (TTL + capacity bounded).
`apply_media_retry_event` (`:2638`) decrypts the retry notification, validates the
stanza id, and — on success — updates the media's `direct_path` so
`download_after_retry` can fetch it (`:950`). Retry events arrive through the
[[Event Model]] (`MediaRetryEvent`) and are surfaced by the
[[Receive Message Flow]].

See [[Send Message Flow]] for how an `UploadedMedia` descriptor becomes an outgoing
media message, and [[Receive Message Flow]] for inbound media handling.
