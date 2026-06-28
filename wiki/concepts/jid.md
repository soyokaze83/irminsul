---
title: JID
type: concept
sources:
  - crates/wa-binary/src/jid.rs
related:
  - "[[wa-binary]]"
  - "[[Binary Node Codec]]"
  - "[[Signal Protocol]]"
  - "[[Glossary]]"
summary: WhatsApp addressing — phone (PN), LID, group, newsletter, hosted domains; device/agent suffixes; user normalization.
updated: 2026-06-28
source_commit: ace4f9c
---

# JID

A **JID** ("Jabber ID") is how WhatsApp names every addressable entity: users,
groups, broadcasts, newsletters, and the server. Irminsul models it as `FullJid`
(`crates/wa-binary/src/jid.rs:102`):

```
FullJid { user, server: JidServer, server_raw: String,
          device: Option<u16>, agent: Option<u16>, domain_type: WaJidDomain }
```

## Servers and domains

`JidServer` enumerates the domain suffixes (`crates/wa-binary/src/jid.rs:32`,
`as_str` at `:48`):

| Variant | Suffix | Used for |
|---|---|---|
| `SWhatsAppNet` | `s.whatsapp.net` | phone-number (PN) users |
| `CUs` | `c.us` | legacy contact form (normalized to PN) |
| `Lid` | `lid` | privacy-preserving LID identity |
| `GUs` | `g.us` | groups & communities |
| `Broadcast` | `broadcast` | status & broadcast lists |
| `Newsletter` | `newsletter` | newsletters |
| `Bot` | `bot` | bots |
| `Hosted` / `HostedLid` | `hosted` / `hosted.lid` | hosted accounts |

`WaJidDomain` (`:11`) is the on-the-wire domain-type byte (`WhatsApp=0`, `Lid=1`,
`Hosted=128`, `HostedLid=129`) that the [[Binary Node Codec]] writes for AD-JID
pairs. `from_server_str` / `domain_type` map between the string suffix, an optional
agent value, and the domain byte (`:66`, `:82`).

## Encoding & device/agent suffixes

`jid_encode(user, server, device, agent)` formats `user[_agent][:device]@server`
(`crates/wa-binary/src/jid.rs:131`). A `:0` device suffix is omitted, so the
primary device round-trips cleanly. `jid_decode` parses the inverse and backs
`FullJid::from_str` (`:122`).

## Normalization & identity

- `jid_normalized_user` strips device/agent and maps the legacy `c.us` form to
  `s.whatsapp.net`, yielding a stable user key.
- `are_jids_same_user` compares two JIDs ignoring server, device, and agent — the
  predicate used throughout messaging to decide whether two addresses are the same
  human.

These matter because a single user appears under multiple JIDs: a phone number
(PN), a **LID**, and several device-suffixed forms. The [[Signal Protocol]] layer
maintains an explicit LID↔PN mapping store on top of these helpers.

Well-known constants (`server@c.us`, `status@broadcast`, the official business and
Meta-AI JIDs) are defined at `crates/wa-binary/src/jid.rs:4`.
