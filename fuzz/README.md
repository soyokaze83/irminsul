# Fuzz Targets

Run these with `cargo fuzz` from this directory, for example:

```sh
cargo fuzz run binary_node_decode
cargo fuzz run decompressing_if_required
cargo fuzz run jid_decode
cargo fuzz run noise_frame_decode
cargo fuzz run signal_wire_decode
cargo fuzz run signal_stateful_records
cargo fuzz run inbound_node_decode
cargo fuzz run history_sync_decode
cargo fuzz run app_state_node_parse
cargo fuzz run app_state_patch_decode
cargo fuzz run retry_receipt_parse
cargo fuzz run group_notification_parse
cargo fuzz run newsletter_notification_parse
cargo fuzz run business_notification_parse
cargo fuzz run community_surface_parse
cargo fuzz run account_call_notification_parse
cargo fuzz run chat_account_parse
cargo fuzz run tc_token_parse
cargo fuzz run media_retry_parse
cargo fuzz run usync_result_parse
```

The targets focus on network-facing binary-node, zlib-wrapped binary-node
decompression, JID, Noise frame and transport payload decoding, Signal
wire/session, stateful Signal provider and sender-key record operations, and raw
inbound-node router/receive decoders, plus compressed/raw history sync payloads
and structured non-blocking
pushname/status/LID/account/call-log/past-participant/recent-sticker/default-
disappearing-mode/account-settings history records, app-state
dirty/sync/query-result node parsers, app-state encrypted patch and snapshot
decoders, retry receipt parsing/planning surfaces, group notification parsing
plus derived message-stub generation, and structured newsletter notification/MEX,
business notification, community surface receive/result parsing,
account/call notification receive parsing,
chat/account privacy, profile-picture, blocklist, presence, chat-state, and
mutation-result parsing/building, and
trusted-contact-token issue/result, privacy-token notification, and stored-record
parsing, plus media-retry receipt/notification parsing, encrypted retry
notification application, coordinator state, and stored pending-media retry
records, and USync query/result parsing plus derived contact, LID, device,
relay-recipient, status, disappearing-mode, and bot-profile helpers.
Successfully decoded values are re-encoded and decoded again to catch parser
state or normalization issues where the parser surface supports it.
