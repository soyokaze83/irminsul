# Signal 1:1 Wire-Format Fix Plan (WhatsApp interop)

Status: PLANNED (2026-06-22). Gate: un-ignore `signal_conformance_decrypts_libsignal_pre_key_message`
in `crates/wa-core/src/signal.rs` (decrypts a real `libsignal` PreKeyWhisperMessage from
`tests/fixtures/signal_conformance.json`). Oracle tooling: `tools/compat/signal_*`.

## Confirmed scope
Message-KEY derivation is ALREADY libsignal-correct (HKDF `WhisperMessageKeys`, 32-byte zero salt,
80-byte output split cipher(32)‖mac(32)‖iv(16); seed=HMAC(chainKey,[0x01]); advance=HMAC(chainKey,[0x02])).
The bug is PURELY framing + MAC. No ratchet/X3DH derivation changes.

## Target wire format (oracle-verified)
- WhisperMessage = `0x33 || protobuf{f1 ratchetKey(0x05+32), f2 counter, f3 prevCounter, f4 ciphertext=PURE AES-CBC} || MAC8`
  where MAC8 = HMAC-SHA256(macKey, senderIdPub(33) ‖ receiverIdPub(33) ‖ 0x33 ‖ protobuf)[..8].
- PreKeyWhisperMessage = `0x33 || protobuf{f1 preKeyId, f2 baseKey, f3 identityKey, f4 message=WhisperMessage above, f5 regId, f6 signedPreKeyId}` (no trailing MAC on the outer; only inner f4 carries one).
- OUTBOUND: sender=local, receiver=remote. INBOUND: sender=remote, receiver=local (order flips).

## Edit steps (crates/wa-core/src/signal.rs unless noted)
- A. `encrypt_signal_message_body`(~2557)/`decrypt_signal_message_body`(~2568) → PURE AES (drop MAC append/split). Keep mac_key in `SignalMessageKeyMaterial` (used one layer up).
- B. `encode/decode_signal_whisper_message`(~2286/2293): add params `(mac_key, sender_id_pub, receiver_id_pub)`; prepend 0x33; append/verify MAC8 over `sender‖receiver‖0x33‖protobuf`. Mirror version nibble logic from sender-key (`signal_sender_key_message_version` ~4825, encode ~2700).
- C. `encode/decode_signal_pre_key_whisper_message`(~2299/2308): prepend/strip outer 0x33; inner WhisperMessage (in `TryFrom` impls ~4434/4449) must be encoded/decoded WITH identities (inline or new fns) — inner uses same sender/receiver identities + the message-key mac_key.
- D. Thread identities into `encrypt_signal_provider_session_record_plaintext`(~3827) & `decrypt_signal_provider_session_record_ciphertext`(~3848) (params sender_id_pub/receiver_id_pub).
- E. Standalone callers: `encrypt_signal_outbound_pre_key_session_message`(~3704) sender=`local_key_material.identity.public_key`, receiver=`record.remote_identity_key`; `decrypt_signal_inbound_pre_key_session_decoded`(~3766) sender=`message.identity_key`, receiver=local. Also `encrypt/decrypt_signal_provider_session_record_message`(~3674/3689) add+forward identity params.
- F. Store-tx callers `encrypt_existing_session_record_message`(~1251)/`decrypt_session_record_message`(~1292): load local identity in-tx via `read_credentials_from_tx(tx)?` → `signal_local_key_material(...).identity.public_key`; remote from `record.remote_identity_key`. Error if no credentials.
- G. **HARDEST**: existing-session pre-key replay helpers (~799/834) re-encode inner whisper via `encode_signal_whisper_message` but lack the mac_key. Fix: refactor `decrypt_session_record_message` to accept a PRE-DECODED `SignalWhisperMessage` + identities (verify MAC once with correct key), OR thread the original raw inner-message bytes unchanged.
- H. Update re-exports `crates/wa-core/src/lib.rs`(~439-452), `crates/wa-testkit/tests/signal_fixtures.rs`(~65), `fuzz/fuzz_targets/signal_stateful_records.rs`(56/156/165/182/192/209/219).
- Un-ignore the conformance gate (~20553).

## Helper to recheck: `pre_key_message_outer_unknown_field`(~20474) appends an unknown field to OUTER pre-key bytes — must account for the new 0x33 prefix offset.

## Tests/golden vectors to update (recompute under new framing)
- Golden: `signal_wire_whisper_message_round_trips_and_validates`(~5382, literals ~5411-5466).
- Body MAC asserts move to whisper layer: `signal_message_body_crypto_derives_encrypts_and_authenticates`(~6458, asserts ~6490-6503). HKDF golden (~6461-6483) STAYS valid.
- Pre-key wire tests ~5470/5546/5566/5608; property tests ~6154/6187.
- ~50 direct-call sites that hand-build messages via `encode_signal_whisper_message{ciphertext: encrypt_signal_message_body(...)}` (e.g. provider-session tests 15254/15398/15481/15585/15882/15951/16021; codec-builder/tamper tests 13228-13663, 16121-16748, plus tamper sites listed in the analysis).
- End-to-end `store_signal_provider_*` tests (16081..20217) should survive unchanged (consistent round-trip) EXCEPT byte-splicing ones using `pre_key_message_outer_unknown_field`.

## Discipline
Commit crypto changes ONLY when the conformance gate passes AND wa-core + wa-client suites are green.
Last clean state: commit 582172d.
