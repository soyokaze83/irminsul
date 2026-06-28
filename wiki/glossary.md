---
title: Glossary
type: glossary
sources:
  - crates/wa-binary/src/jid.rs
  - crates/wa-core/src/signal.rs
  - crates/wa-core/src/app_state.rs
  - README.md
related:
  - "[[Irminsul Overview]]"
  - "[[JID]]"
  - "[[Signal Protocol]]"
  - "[[App-State & History Sync]]"
summary: Short definitions of WhatsApp-protocol and project-specific terms used across the wiki.
updated: 2026-06-28
source_commit: ace4f9c
---

# Glossary

- **Binary node** — WhatsApp's compact binary stanza (tag + attrs + content); the
  unit of the wire protocol. See [[Binary Node Codec]].
- **JID** — a WhatsApp address (`user@server`, optional device/agent). See [[JID]].
- **PN** — phone number; the `@s.whatsapp.net` identity form.
- **LID** — a privacy-preserving linked identity (`@lid`) that hides the phone
  number; mapped to a PN by the [[Signal Protocol|LID↔PN store]].
- **Multi-device** — WhatsApp's protocol where a phone and several companion
  devices each hold independent Signal sessions; Irminsul is a companion device.
- **Noise XX** — the `Noise_XX_25519_AESGCM_SHA256` handshake that authenticates
  the server and encrypts the socket. See [[Noise Handshake]].
- **Signal / libsignal** — the end-to-end encryption protocol (X3DH + Double
  Ratchet for 1:1; sender keys for groups). libsignal is the AGPL reference;
  Irminsul reimplements it permissively. See [[Signal Protocol]],
  [[Clean-Room & Permissive Licensing]].
- **X3DH** — the Extended Triple Diffie-Hellman key agreement that bootstraps a 1:1
  Signal session.
- **Double Ratchet** — Signal's forward-secret message-key schedule (DH "root"
  ratchet + symmetric "chain" ratchet).
- **Sender key** — the symmetric key a group member distributes once
  (SenderKeyDistributionMessage) so others can decrypt its group messages.
- **pkmsg / msg / skmsg** — ciphertext types on `<enc>` nodes: pre-key message
  (new 1:1 session), normal message, and sender-key (group) message.
- **App-state** — the synced collection of chat/contact settings (archive, mute,
  pin, star, labels, …), kept consistent via MAC-verified LT-hash patches. See
  [[App-State & History Sync]].
- **LT-hash** — a 128-byte homomorphic hash used to verify a whole app-state
  collection while advancing it one mutation at a time.
- **History sync** — the bulk transfer of past conversations/contacts when a device
  links. See [[App-State & History Sync]].
- **USync** — the user-sync query family (on-WhatsApp checks, device lists, status,
  LID mapping).
- **Pairing** — linking a new device by QR scan or pairing code. See
  [[Pairing Flow]].
- **Pre-key** — a one-time key uploaded so peers can start a 1:1 session offline.
- **Media-retry** — re-requesting a fresh download path / re-encrypting media when
  a transfer fails. See [[Media Transfer]].
- **Placeholder resend** — asking the phone to resend a ciphertext the companion
  couldn't open.
- **TC token** — trusted-contact token, used in privacy/reporting flows
  (`tctoken.rs`).
- **WMex / MEX** — WhatsApp's GraphQL-style "Meta expression" query channel, used
  for newsletters and business surfaces (`mex.rs`).
- **AuthStore / SignalKeyStore** — the storage traits all persistent state goes
  through. See [[wa-store]].
- **Stanza / IQ** — an XMPP-style request/response node; IQs are matched to
  responses by tag in the [[Connection Stack|QueryManager]].
