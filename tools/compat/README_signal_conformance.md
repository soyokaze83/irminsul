# Signal conformance oracle (dev-only)

Generates authoritative Signal-protocol wire vectors using the SAME `libsignal`
package Baileys/WhatsApp use, so the project-owned provider can be proven
wire-compatible with WhatsApp.

DEV-ONLY. Not part of the shipped library. Requires copyleft dev deps that are
NOT vendored or distributed:

    npm init -y && npm install libsignal @signalapp/libsignal-client
    node signal_wireformat_oracle.cjs        # prints a real WhisperMessage (version||protobuf||mac8)
    node signal_conformance_emit.cjs ../../tests/fixtures/signal_conformance.json

The emitted JSON (committed under tests/fixtures/) is plain data and drives the
Rust conformance tests. Regenerate only if vectors must change.

KNOWN GAP (2026-06-22): the project-owned 1:1 whisper framing currently differs
from libsignal (no version byte; 8-byte MAC inside the ciphertext field; MAC over
ciphertext-only). The conformance tests pin the fix toward libsignal framing:
`versionByte(0x33) || protobuf{ratchetKey,counter,prevCounter,ciphertext=pureAES}
|| MAC8` where MAC = HMAC-SHA256(macKey, senderIdPub‖receiverIdPub‖version‖protobuf)[..8].
