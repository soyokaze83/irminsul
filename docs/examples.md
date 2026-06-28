# Examples — environment-variable reference

Runnable examples live in [`crates/wa-client/examples/`](../crates/wa-client/examples).
They use a SQLite auth store by default. Most are **live**: they exit before
opening a websocket unless their required `WA_*` variables are set, and — except
`live_pairing_code` — they expect an already-paired, valid session in
`WA_SESSION_DB`.

Global variables:

- `WA_SESSION_DB` — SQLite auth database path (default `.wa/session.sqlite`).
- `WA_QR_REFERENCE` — server-provided pair-device reference for QR payloads.
- `WA_PHONE_NUMBER` — phone number used to prepare a pairing-code request.

Many examples double as **ignored live smoke tests** (`live_e2e`), enabled with
`WA_LIVE_E2E=1` plus the same variables; see [Live smoke tests](#live-smoke-tests).

---

## Pairing & session

### `session_pairing`
Initializes local credentials and prints pairing material without opening a live
websocket.

```sh
cargo run -p wa-client --example session_pairing
```

### `live_pairing_code`
Pairing-code login for an unregistered session. `WA_PHONE_NUMBER` is required.
Optional `WA_PAIRING_CODE` supplies an 8-character custom code;
`WA_PAIRING_TIMEOUT_SECS` changes how long it waits for link-code completion.

```sh
WA_PHONE_NUMBER=1234567890 cargo run -p wa-client --example live_pairing_code
```

### `custom_auth_store`
Shows the minimal `AuthStore` methods needed for custom session storage.

```sh
cargo run -p wa-client --example custom_auth_store
```

---

## Direct messages — `live_text`

`WA_TARGET_JID` is required. `WA_MESSAGE_KIND` selects the payload (`text`
default, or `contact`, `location`, `poll`, `event`, `reaction`, `edit`, `delete`,
`pin`).

```sh
WA_TARGET_JID=1234567890@s.whatsapp.net cargo run -p wa-client --example live_text
```

Per-kind variables:

- **contact** — `WA_CONTACT_DISPLAY_NAME` (+ optional `WA_CONTACT_VCARD`).
- **location** — `WA_LOCATION_LATITUDE`, `WA_LOCATION_LONGITUDE` (+ optional
  `WA_LOCATION_NAME`, `WA_LOCATION_ADDRESS`, `WA_LOCATION_URL`).
- **poll** — `WA_POLL_NAME`, `WA_POLL_OPTIONS`, `WA_POLL_SELECTABLE_COUNT`,
  `WA_POLL_SECRET_HEX`.
- **event** — `WA_EVENT_NAME`, `WA_EVENT_DESCRIPTION`, `WA_EVENT_START_UNIX`,
  `WA_EVENT_END_UNIX`, `WA_EVENT_JOIN_LINK`, `WA_EVENT_SECRET_HEX`.
- **reaction** — `WA_REACTION_MESSAGE_ID` (+ optional `WA_REACTION_REMOTE_JID`,
  `WA_REACTION_FROM_ME`, `WA_REACTION_PARTICIPANT`, `WA_REACTION_TEXT`).
- **edit / delete / pin** — `WA_EDIT_MESSAGE_ID` / `WA_DELETE_MESSAGE_ID` /
  `WA_PIN_MESSAGE_ID`, each with optional `*_REMOTE_JID`, `*_FROM_ME`,
  `*_PARTICIPANT`. Edit adds `WA_EDIT_TEXT`, `WA_EDIT_TIMESTAMP_MS`; pin adds
  `WA_PIN_ACTION`, `WA_PIN_TIMESTAMP_MS`.

```sh
WA_TARGET_JID=...@s.whatsapp.net WA_MESSAGE_KIND=poll cargo run -p wa-client --example live_text
WA_TARGET_JID=...@s.whatsapp.net WA_MESSAGE_KIND=edit \
  WA_EDIT_MESSAGE_ID=ABCDEF WA_EDIT_TEXT="edited" cargo run -p wa-client --example live_text
```

---

## Receiving — `live_receive`

`WA_RECEIVE=1` starts the live Signal-provider incoming processor and waits for
typed message events. Optional `WA_RECEIVE_TIMEOUT_SECS`, and
`WA_RECEIVE_REMOTE_JID` to filter a specific sender/chat.

```sh
WA_RECEIVE=1 cargo run -p wa-client --example live_receive
```

---

## Media — `live_media` (requires `--features http-media`)

`WA_MEDIA_PATH` is required. `WA_MEDIA_KIND` ∈ `image` (default), `video`, `gif`,
`ptv`/`video_note`, `audio`, `ptt`/`push_to_talk`, `document`, `sticker`.

```sh
WA_TARGET_JID=...@s.whatsapp.net WA_MEDIA_KIND=image WA_MEDIA_PATH=./image.jpg \
  cargo run -p wa-client --features http-media --example live_media
```

Optional tuning: `WA_MEDIA_MIMETYPE`, `WA_MEDIA_CAPTION`, `WA_MEDIA_VIEW_ONCE`
(image/video), `WA_MEDIA_AUDIO_PTT`, `WA_MEDIA_AUDIO_SECONDS`,
`WA_MEDIA_VIDEO_SECONDS|HEIGHT|WIDTH`, `WA_MEDIA_GIF_SECONDS|HEIGHT|WIDTH`,
`WA_MEDIA_PTV_SECONDS|HEIGHT|WIDTH`, `WA_MEDIA_PTT_SECONDS`,
`WA_MEDIA_DOCUMENT_TITLE|FILE_NAME|PAGE_COUNT`,
`WA_MEDIA_STICKER_HEIGHT|WIDTH|ANIMATED`.

### `live_media_retry`
`WA_MEDIA_RETRY_REMOTE_JID`, `WA_MEDIA_RETRY_MESSAGE_ID`,
`WA_MEDIA_RETRY_MEDIA_KEY_HEX` send a retry request; `WA_MEDIA_RETRY_FROM_ME`,
`WA_MEDIA_RETRY_PARTICIPANT` refine the key. With `--features http-media`,
`WA_MEDIA_RETRY_WAIT_RESPONSE=1` registers a pending descriptor and downloads the
refreshed media; provide `WA_MEDIA_RETRY_FILE_SHA256_HEX`,
`WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX`, `WA_MEDIA_RETRY_FILE_LENGTH`, and optionally
`WA_MEDIA_RETRY_KIND|FALLBACK_HOST|URL|DIRECT_PATH|MEDIA_KEY_TIMESTAMP_MS|TIMEOUT_SECS`.

### `live_video_thumbnail` / `live_document_thumbnail` (requires `--features http-media,image`)
`WA_VIDEO_PATH` / `WA_DOCUMENT_PATH` send remote-thumbnail media. Override the
tools with `WA_VIDEO_THUMBNAIL_FFMPEG`, `WA_VIDEO_THUMBNAIL_SEEK_TIME` /
`WA_DOCUMENT_THUMBNAIL_PDFTOPPM`, `WA_DOCUMENT_THUMBNAIL_PAGE`,
`WA_DOCUMENT_THUMBNAIL_DPI`.

---

## Status / broadcast — `live_status`

`WA_STATUS_JIDS` (comma-separated user JIDs) is required. `WA_STATUS_KIND` ∈
`text` (default), `image`, `video`, `document`, `audio`, `sticker`, `poll`,
`event`. A media-path variable implies its mode.

```sh
WA_STATUS_JIDS=...@s.whatsapp.net cargo run -p wa-client --example live_status
WA_STATUS_JIDS=...@s.whatsapp.net WA_STATUS_MEDIA_PATH=./image.jpg \
  cargo run -p wa-client --features http-media --example live_status
```

- Image/audio/sticker media require `--features http-media`; video/document
  generated-thumbnail modes require `--features http-media,image`.
- Media paths: `WA_STATUS_MEDIA_PATH`, `WA_STATUS_VIDEO_PATH`,
  `WA_STATUS_DOCUMENT_PATH`, `WA_STATUS_AUDIO_PATH`, `WA_STATUS_STICKER_PATH`.
- Metadata: `WA_STATUS_*_MIMETYPE`, `WA_STATUS_MEDIA_CAPTION`,
  `WA_STATUS_AUDIO_PTT`, `WA_STATUS_STICKER_ANIMATED`,
  `WA_STATUS_VIDEO_CAPTION`, `WA_STATUS_DOCUMENT_CAPTION|TITLE|FILE_NAME`.
- Poll/event: `WA_STATUS_POLL_NAME|OPTIONS|SELECTABLE_COUNT|SECRET_HEX`,
  `WA_STATUS_EVENT_NAME|DESCRIPTION|START_UNIX|END_UNIX|JOIN_LINK|SECRET_HEX`.

---

## App-state & history

### `live_history_sync` (requires `--features http-media`)
`WA_HISTORY_SYNC=1` watches live message events for history-sync notifications,
downloads external payloads, and emits/persists processed batches. Optional
`WA_HISTORY_SYNC_TIMEOUT_SECS`, `WA_HISTORY_SYNC_FALLBACK_HOST`,
`WA_HISTORY_SYNC_LATEST`.

```sh
WA_HISTORY_SYNC=1 cargo run -p wa-client --features http-media --example live_history_sync
```

### `live_chat_pin`
`WA_CHAT_PIN_JID` mutates the target chat's pin state. Set
`WA_APP_STATE_KEY_ID_HEX` (and `WA_APP_STATE_KEY_DATA_HEX` if the key is not in
`WA_SESSION_DB`); optional `WA_CHAT_PINNED=false`, `WA_CHAT_PIN_TIMESTAMP_MS`.

```sh
WA_CHAT_PIN_JID=...@s.whatsapp.net WA_APP_STATE_KEY_ID_HEX=... \
  cargo run -p wa-client --example live_chat_pin
```

---

## Groups & communities

### `live_group` / `live_group_send`
`WA_GROUP_JID` runs group metadata reads; `WA_GROUP_SEND_JID` runs a sender-key
text send (optional `WA_GROUP_TEXT`).

```sh
WA_GROUP_JID=...@g.us cargo run -p wa-client --example live_group
WA_GROUP_SEND_JID=...@g.us cargo run -p wa-client --example live_group_send
```

### `live_community`
`WA_COMMUNITY_JID`, `WA_COMMUNITY_INVITE_CODE`, or
`WA_COMMUNITY_FETCH_PARTICIPATING=1` enable read-only community queries. Optional
`WA_COMMUNITY_FETCH_LINKED_GROUPS=1`, `WA_COMMUNITY_RESOLVE_LINKED_GROUPS=1`,
`WA_COMMUNITY_FETCH_JOIN_REQUESTS=1`.

```sh
WA_COMMUNITY_JID=...@g.us cargo run -p wa-client --example live_community
```

---

## Newsletters — `live_newsletter`

`WA_NEWSLETTER_JID` or `WA_NEWSLETTER_INVITE` enables metadata reads. Optional
`WA_NEWSLETTER_FETCH_COUNTS=1` (subscriber/admin counts);
`WA_NEWSLETTER_FETCH_MESSAGES=1` fetches message updates with
`WA_NEWSLETTER_MESSAGE_COUNT|SINCE|AFTER`; `WA_NEWSLETTER_LIVE_UPDATES=1`
subscribes to live-update metadata.

```sh
WA_NEWSLETTER_JID=...@newsletter cargo run -p wa-client --example live_newsletter
```

---

## Business

| Example | Enable with | Notes |
|---|---|---|
| `live_business_profile` | `WA_BUSINESS_JID` | Fetch business profile |
| `live_business_profile_update` | `WA_BUSINESS_PROFILE_UPDATE=1` | Mutates own profile; set ≥1 of `WA_BUSINESS_PROFILE_ADDRESS|EMAIL|DESCRIPTION|WEBSITES` |
| `live_business_catalog` | `WA_BUSINESS_CATALOG_JID` | Optional `WA_BUSINESS_CATALOG_LIMIT|CURSOR` |
| `live_business_collections` | `WA_BUSINESS_COLLECTIONS_JID` | Optional `WA_BUSINESS_COLLECTION_LIMIT|ITEM_LIMIT` |
| `live_business_order_details` | `WA_BUSINESS_ORDER_ID` + `WA_BUSINESS_ORDER_TOKEN` | Fetch order details |
| `live_business_media` | `WA_BUSINESS_MEDIA_PATH` (+ `--features http-media`) | `WA_BUSINESS_MEDIA_KIND` = `product_image` (default) or `cover_photo`; optional `WA_BUSINESS_MEDIA_FALLBACK_HOST` |
| `live_business_cover_photo` | `WA_BUSINESS_COVER_PHOTO_UPDATE=1` + `WA_BUSINESS_COVER_PHOTO_PATH` (+ `--features http-media`) | Mutates cover photo; remove mode via `WA_BUSINESS_COVER_PHOTO_REMOVE=1` + `WA_BUSINESS_COVER_PHOTO_ID` |

```sh
WA_BUSINESS_JID=...@s.whatsapp.net cargo run -p wa-client --example live_business_profile
WA_BUSINESS_MEDIA_KIND=product_image WA_BUSINESS_MEDIA_PATH=./image.jpg \
  cargo run -p wa-client --features http-media --example live_business_media
```

---

## Profile picture & link previews

### `live_profile_picture` (requires `--features image`)
`WA_PROFILE_PICTURE_PATH` updates the own picture unless
`WA_PROFILE_PICTURE_TARGET_JID` is set. Optional `WA_PROFILE_PICTURE_SIZE`,
`WA_PROFILE_PICTURE_PREVIEW_SIZE`, `WA_PROFILE_PICTURE_QUALITY`.

```sh
WA_PROFILE_PICTURE_PATH=./profile.jpg cargo run -p wa-client --features image --example live_profile_picture
```

### `live_link_preview` / `live_generated_link_preview` (requires `--features http-media,link-preview,image`)
`WA_LINK_PREVIEW_URL` sends a link preview (optional `WA_LINK_PREVIEW_TEXT`).
`WA_LINK_PREVIEW_IMAGE_PATH` drives the generated-thumbnail variant (optional
`WA_LINK_PREVIEW_TITLE`, `WA_LINK_PREVIEW_DESCRIPTION`).

```sh
WA_TARGET_JID=...@s.whatsapp.net WA_LINK_PREVIEW_URL=https://example.com \
  cargo run -p wa-client --features http-media,link-preview,image --example live_link_preview
```

---

## Live smoke tests

The same scenarios run as ignored end-to-end smoke tests when explicitly opted in.
They require a paired, valid session and the relevant `WA_*` variables above.

```sh
WA_LIVE_E2E=1 WA_TARGET_JID=...@s.whatsapp.net \
  cargo test -p wa-client --test live_e2e -- --ignored --nocapture
```

Each variable group described above (`WA_GROUP_JID`, `WA_STATUS_JIDS`,
`WA_MEDIA_PATH`, `WA_NEWSLETTER_JID`, `WA_BUSINESS_*`, …) enables the matching
ignored smoke test in addition to its example.
