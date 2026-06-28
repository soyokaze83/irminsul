---
title: wa-client Test Chunking
type: decision
sources:
  - crates/wa-client/Cargo.toml
  - tools/run_wa_client_tests.sh
  - crates/wa-client/src/tests_chunk_1.rs
related:
  - "[[wa-client]]"
  - "[[Irminsul Overview]]"
summary: Why wa-client's ~95K-line test module is split into eight feature-gated chunks compiled one at a time.
updated: 2026-06-28
source_commit: ace4f9c
---

# wa-client Test Chunking

## Decision

`wa-client`'s in-crate `#[cfg(test)] mod tests` is enormous — roughly **95,000
lines** across eight `tests_chunk_*.rs` files (each ~11–12k lines). Rather than
compile it as one `rustc` unit, the module is partitioned into eight chunks
`wat1`..`wat8`, each a `mod chunk_K` gated behind its own cargo feature
(`crates/wa-client/Cargo.toml:27`). Tests run one chunk at a time via
`tools/run_wa_client_tests.sh`.

## Why

Building all the tests at once **OOM-SIGKILLs** on small runners. The tooling
documents the constraint precisely: the VM has 3.8 GB RAM and no swap, and a
single-unit test build peaks around 3.9 GB
(`tools/run_wa_client_tests.sh:4`, `crates/wa-client/Cargo.toml:24`). Splitting the
module keeps each test build "well under the RAM budget"
(`tools/run_wa_client_tests.sh:9`).

## How it works

- Each chunk is `mod chunk_K` compiled only when feature `watK` is on; shared
  helpers (`mock_connection`, `IncomingDecryptor`, `RelayEncryptor`, …) stay
  ungated in the parent `mod tests` so every chunk reaches them via `use super::*`
  (`tools/run_wa_client_tests.sh:6`).
- The runner builds each chunk with `CARGO_PROFILE_TEST_DEBUG=0` and
  `CARGO_BUILD_JOBS=1` (single codegen job) to cap memory
  (`tools/run_wa_client_tests.sh:29`). Each chunk takes ~3–7 minutes; the whole run
  is ~30–50 minutes.
- Pass/fail is judged by the rust harness `test result:` lines **and** the exit
  code — never by piping through `tail` (`tools/run_wa_client_tests.sh:41`).

## Implications for maintainers

- The `wat*` features are test-only; they enable no library behavior.
- To run the suite: `tools/run_wa_client_tests.sh` (all chunks) or
  `tools/run_wa_client_tests.sh 3 5` (selected chunks).
- The other crates build their tests normally; only `wa-client`'s test module needs
  this treatment. See the run-verified commands in `README.md` ("Running the
  tests").
