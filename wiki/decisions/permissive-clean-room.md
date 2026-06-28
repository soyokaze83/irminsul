---
title: Clean-Room & Permissive Licensing
type: decision
sources:
  - README.md
  - LICENSE
  - Cargo.toml
  - crates/wa-core/src/signal.rs
  - tools/compat/README_signal_conformance.md
  - tests/fixtures/signal_conformance.json
related:
  - "[[Signal Protocol]]"
  - "[[wa-crypto]]"
  - "[[wa-testkit]]"
  - "[[Irminsul Overview]]"
summary: Why Irminsul reimplements the Signal layer instead of using libsignal — to keep the whole project MIT — and how it proves wire-compatibility.
updated: 2026-06-28
source_commit: ace4f9c
---

# Clean-Room & Permissive Licensing

## Decision

Irminsul is **MIT-licensed** (`LICENSE`) and "deliberately avoids copyleft
dependencies so it can stay permissively licensed" (`README.md:198`). The most
consequential consequence: it does **not** depend on `libsignal` (which is AGPL).
Instead, the end-to-end encryption layer is reimplemented from scratch in
[[Signal Protocol|`crates/wa-core/src/signal.rs`]] (~21.7k lines), and the crypto
primitives come only from permissively-licensed RustCrypto-family crates
([[wa-crypto]]; see `Cargo.toml` workspace deps).

## Why

- **Licensing.** Linking AGPL `libsignal` into a library would force the AGPL onto
  every downstream consumer. A library-first project (see [[Irminsul Overview]])
  that wants broad adoption needs a permissive license end-to-end.
- **No adoptable alternative.** There is no maintained, permissively-licensed Rust
  Signal crate suitable to adopt — so a project-owned implementation is the
  realistic path.

## The risk, and how it's mitigated

Reimplementing a cryptographic wire protocol is the project's highest-risk surface:
a single byte-framing or MAC mismatch makes the client silently incompatible with
real WhatsApp. The mitigation is a **conformance oracle**:

- A dev-only tool (`tools/compat/`) generates authoritative vectors using the
  *same* `libsignal` package Baileys/WhatsApp use — explicitly to "prove the
  project-owned provider wire-compatible with WhatsApp"
  (`tools/compat/README_signal_conformance.md:1`). The copyleft dev deps are
  **not** vendored or distributed (`:7`); only the emitted JSON data is committed.
- Those vectors land as `tests/fixtures/signal_conformance.json` and
  `signal_group_conformance.json` and drive Rust conformance tests via
  [[wa-testkit]].
- The 1:1 whisper framing implemented in `signal.rs` matches the libsignal target:
  `versionByte(0x33) || protobuf || MAC8` with the MAC computed over
  `senderIdPub ‖ receiverIdPub ‖ version ‖ protobuf`
  (`crates/wa-core/src/signal.rs:60`, `:2769`).

> **Historical note / watch item.** The oracle README records a
> "KNOWN GAP (2026-06-22)": an earlier project-owned framing diverged from
> libsignal (no version byte; 8-byte MAC inside the ciphertext field; MAC over
> ciphertext only) (`tools/compat/README_signal_conformance.md:17`). The current
> `signal.rs` implements the corrected framing the vectors pin toward, and
> `README.md:13` now states the Signal layer (1:1 **and** group) is "verified
> byte-compatible with the reference libsignal implementation." If that README note
> still reads "KNOWN GAP" in a future revision, treat it as stale relative to the
> code and reconcile.

## Status caveat

Byte-compatibility of the crypto layer is verified against libsignal vectors, but
end-to-end validation against live WhatsApp at scale is still pending (it needs test
accounts). The project is a "mock/fixture-green beta" (`README.md:176`); see the
feature matrix in `docs/feature_support_matrix.md`.
