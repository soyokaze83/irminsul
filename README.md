# WhatsApp Agent

Rust crates for WhatsApp Web protocol experiments, with a Baileys-compatible API
surface under active development.

This project uses WhatsApp's private web protocol. The protocol can change
without notice, and live examples require an account you control.

## Quickstart

The `wa-client` examples use a SQLite auth store by default:

```sh
cargo run -p wa-client --example session_pairing
```

That command initializes local credentials and prints pairing material without
opening a live websocket. Set `WA_SESSION_DB` to choose a different session
database path.

Useful environment variables:

- `WA_QR_REFERENCE`: server-provided pair-device reference for QR payloads.
- `WA_PHONE_NUMBER`: phone number used to prepare a pairing-code request.
- `WA_SESSION_DB`: SQLite auth database path, default `.wa/session.sqlite`.

## Examples

```sh
cargo run -p wa-client --example session_pairing
cargo run -p wa-client --example custom_auth_store
WA_PHONE_NUMBER=1234567890 cargo run -p wa-client --example live_pairing_code
WA_TARGET_JID=1234567890@s.whatsapp.net cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=contact \
  WA_CONTACT_DISPLAY_NAME="Ada Lovelace" cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=location \
  WA_LOCATION_LATITUDE=37.7786 WA_LOCATION_LONGITUDE=-122.3893 \
  cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=poll \
  cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=event \
  cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=reaction \
  WA_REACTION_MESSAGE_ID=ABCDEF cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=edit \
  WA_EDIT_MESSAGE_ID=ABCDEF WA_EDIT_TEXT="edited from wa-client" \
  cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=delete \
  WA_DELETE_MESSAGE_ID=ABCDEF cargo run -p wa-client --example live_text
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MESSAGE_KIND=pin \
  WA_PIN_MESSAGE_ID=ABCDEF cargo run -p wa-client --example live_text
WA_RECEIVE=1 cargo run -p wa-client --example live_receive
WA_HISTORY_SYNC=1 cargo run -p wa-client --features http-media --example live_history_sync
WA_CHAT_PIN_JID=1234567890@s.whatsapp.net WA_APP_STATE_KEY_ID_HEX=... \
  cargo run -p wa-client --example live_chat_pin
WA_STATUS_JIDS=1234567890@s.whatsapp.net cargo run -p wa-client --example live_status
WA_STATUS_JIDS=1234567890@s.whatsapp.net WA_STATUS_KIND=poll \
  cargo run -p wa-client --example live_status
WA_STATUS_JIDS=1234567890@s.whatsapp.net WA_STATUS_KIND=event \
  cargo run -p wa-client --example live_status
WA_STATUS_JIDS=1234567890@s.whatsapp.net WA_STATUS_MEDIA_PATH=./image.jpg \
  cargo run -p wa-client --features http-media --example live_status
WA_STATUS_JIDS=1234567890@s.whatsapp.net WA_STATUS_AUDIO_PATH=./voice.ogg \
  cargo run -p wa-client --features http-media --example live_status
WA_STATUS_JIDS=1234567890@s.whatsapp.net WA_STATUS_STICKER_PATH=./sticker.webp \
  cargo run -p wa-client --features http-media --example live_status
WA_STATUS_JIDS=1234567890@s.whatsapp.net WA_STATUS_VIDEO_PATH=./video.mp4 \
  cargo run -p wa-client --features http-media,image --example live_status
WA_STATUS_JIDS=1234567890@s.whatsapp.net WA_STATUS_DOCUMENT_PATH=./document.pdf \
  cargo run -p wa-client --features http-media,image --example live_status
WA_GROUP_JID=1234567890-1234567890@g.us cargo run -p wa-client --example live_group
WA_GROUP_SEND_JID=1234567890-1234567890@g.us cargo run -p wa-client --example live_group_send
WA_COMMUNITY_JID=1234567890-1234567890@g.us cargo run -p wa-client --example live_community
WA_NEWSLETTER_JID=1234567890@newsletter cargo run -p wa-client --example live_newsletter
WA_NEWSLETTER_JID=1234567890@newsletter WA_NEWSLETTER_FETCH_MESSAGES=1 \
  cargo run -p wa-client --example live_newsletter
WA_BUSINESS_JID=1234567890@s.whatsapp.net cargo run -p wa-client --example live_business_profile
WA_BUSINESS_PROFILE_UPDATE=1 WA_BUSINESS_PROFILE_DESCRIPTION="Open daily" \
  cargo run -p wa-client --example live_business_profile_update
WA_BUSINESS_CATALOG_JID=1234567890@s.whatsapp.net \
  cargo run -p wa-client --example live_business_catalog
WA_BUSINESS_COLLECTIONS_JID=1234567890@s.whatsapp.net \
  cargo run -p wa-client --example live_business_collections
WA_BUSINESS_ORDER_ID=ORDER_ID WA_BUSINESS_ORDER_TOKEN=TOKEN \
  cargo run -p wa-client --example live_business_order_details
WA_BUSINESS_MEDIA_KIND=product_image WA_BUSINESS_MEDIA_PATH=./image.jpg \
  cargo run -p wa-client --features http-media --example live_business_media
WA_BUSINESS_MEDIA_KIND=cover_photo WA_BUSINESS_MEDIA_PATH=./cover.jpg \
  cargo run -p wa-client --features http-media --example live_business_media
WA_BUSINESS_COVER_PHOTO_UPDATE=1 WA_BUSINESS_COVER_PHOTO_PATH=./cover.jpg \
  cargo run -p wa-client --features http-media --example live_business_cover_photo
WA_BUSINESS_COVER_PHOTO_REMOVE=1 WA_BUSINESS_COVER_PHOTO_ID=PHOTO_ID \
  cargo run -p wa-client --example live_business_cover_photo
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MEDIA_KIND=image WA_MEDIA_PATH=./image.jpg \
  cargo run -p wa-client --features http-media --example live_media
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MEDIA_KIND=video WA_MEDIA_PATH=./video.mp4 \
  cargo run -p wa-client --features http-media --example live_media
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MEDIA_KIND=audio WA_MEDIA_PATH=./voice.ogg \
  cargo run -p wa-client --features http-media --example live_media
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MEDIA_KIND=document WA_MEDIA_PATH=./document.pdf \
  cargo run -p wa-client --features http-media --example live_media
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MEDIA_KIND=gif WA_MEDIA_PATH=./loop.mp4 \
  cargo run -p wa-client --features http-media --example live_media
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MEDIA_KIND=ptv WA_MEDIA_PATH=./video-note.mp4 \
  cargo run -p wa-client --features http-media --example live_media
WA_TARGET_JID=1234567890@s.whatsapp.net WA_MEDIA_KIND=ptt WA_MEDIA_PATH=./voice.ogg \
  cargo run -p wa-client --features http-media --example live_media
WA_MEDIA_RETRY_REMOTE_JID=1234567890@s.whatsapp.net WA_MEDIA_RETRY_MESSAGE_ID=ABCDEF \
  WA_MEDIA_RETRY_MEDIA_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
  cargo run -p wa-client --example live_media_retry
WA_TARGET_JID=1234567890@s.whatsapp.net WA_VIDEO_PATH=./video.mp4 \
  cargo run -p wa-client --features http-media,image --example live_video_thumbnail
WA_TARGET_JID=1234567890@s.whatsapp.net WA_DOCUMENT_PATH=./document.pdf \
  cargo run -p wa-client --features http-media,image --example live_document_thumbnail
WA_PROFILE_PICTURE_PATH=./profile.jpg \
  cargo run -p wa-client --features image --example live_profile_picture
WA_TARGET_JID=1234567890@s.whatsapp.net WA_LINK_PREVIEW_URL=https://example.com \
  cargo run -p wa-client --features http-media,link-preview,image --example live_link_preview
WA_TARGET_JID=1234567890@s.whatsapp.net WA_LINK_PREVIEW_URL=https://example.com \
  WA_LINK_PREVIEW_IMAGE_PATH=./preview.jpg \
  cargo run -p wa-client --features http-media,link-preview,image --example live_generated_link_preview
```

The live examples exit before connecting unless their required `WA_*` variables
are set. Except for `live_pairing_code`, they expect an already paired and valid
session in `WA_SESSION_DB`.

Ignored live smoke tests are available when you explicitly opt in:

```sh
WA_LIVE_E2E=1 WA_TARGET_JID=1234567890@s.whatsapp.net \
  cargo test -p wa-client --test live_e2e -- --ignored --nocapture
```

`WA_GROUP_JID` enables the ignored live group metadata smoke test.
`WA_GROUP_SEND_JID` enables the ignored live group sender-key text-send smoke
test and the `live_group_send` example, with optional `WA_GROUP_TEXT` content.
`WA_COMMUNITY_JID`, `WA_COMMUNITY_INVITE_CODE`, or
`WA_COMMUNITY_FETCH_PARTICIPATING=1` enables the `live_community` example and
ignored live community read smoke test. Optional
`WA_COMMUNITY_FETCH_LINKED_GROUPS=1`,
`WA_COMMUNITY_RESOLVE_LINKED_GROUPS=1`, and
`WA_COMMUNITY_FETCH_JOIN_REQUESTS=1` enable additional read-only community
queries.
`WA_NEWSLETTER_JID` or `WA_NEWSLETTER_INVITE` enables the `live_newsletter`
example and ignored live newsletter metadata smoke test. Optional
`WA_NEWSLETTER_FETCH_COUNTS=1` also fetches subscriber and admin counts when a
newsletter JID is available. Optional `WA_NEWSLETTER_FETCH_MESSAGES=1` fetches
direct newsletter message updates with `WA_NEWSLETTER_MESSAGE_COUNT`,
`WA_NEWSLETTER_MESSAGE_SINCE`, and `WA_NEWSLETTER_MESSAGE_AFTER`; optional
`WA_NEWSLETTER_LIVE_UPDATES=1` subscribes to live-update metadata.
`WA_BUSINESS_JID` enables the `live_business_profile` example and ignored live
business-profile fetch smoke test.
`WA_BUSINESS_PROFILE_UPDATE=1` enables the `live_business_profile_update`
example and ignored live business-profile update smoke test. This mutates the
own business profile. Set at least one of `WA_BUSINESS_PROFILE_ADDRESS`,
`WA_BUSINESS_PROFILE_EMAIL`, `WA_BUSINESS_PROFILE_DESCRIPTION`, or
`WA_BUSINESS_PROFILE_WEBSITES`.
`WA_BUSINESS_CATALOG_JID` enables the `live_business_catalog` example and
ignored live business-catalog fetch smoke test. Optional
`WA_BUSINESS_CATALOG_LIMIT` and `WA_BUSINESS_CATALOG_CURSOR` tune pagination.
`WA_BUSINESS_COLLECTIONS_JID` enables the `live_business_collections` example
and ignored live business-collections fetch smoke test. Optional
`WA_BUSINESS_COLLECTION_LIMIT` and `WA_BUSINESS_COLLECTION_ITEM_LIMIT` tune
collection pagination sizes.
`WA_BUSINESS_ORDER_ID` plus `WA_BUSINESS_ORDER_TOKEN` enables the
`live_business_order_details` example and ignored live business-order details
fetch smoke test.
`WA_BUSINESS_MEDIA_PATH` plus `--features http-media` enables the
`live_business_media` example. `WA_BUSINESS_MEDIA_KIND` can be `product_image`
or `cover_photo`; unset defaults to product image. The ignored live harness also
has product-image and cover-photo upload smokes via
`WA_BUSINESS_PRODUCT_IMAGE_PATH` or `WA_BUSINESS_COVER_PHOTO_PATH`. Optional
`WA_BUSINESS_MEDIA_FALLBACK_HOST` can override product-image URL construction.
`WA_BUSINESS_COVER_PHOTO_UPDATE=1` plus `WA_BUSINESS_COVER_PHOTO_PATH` and
`--features http-media` enables the `live_business_cover_photo` example and
ignored live cover-photo update smoke test. This mutates the own business cover
photo.
`WA_BUSINESS_COVER_PHOTO_REMOVE=1` plus `WA_BUSINESS_COVER_PHOTO_ID` enables
the cover-photo remove mode of the same example and ignored smoke test. This
mutates the own business cover photo.
`WA_MESSAGE_KIND` in the `live_text` example can be `text`, `contact`,
`location`, `poll`, `event`, `reaction`, `edit`, `delete`, or `pin`; unset
defaults to text.
`WA_CONTACT_DISPLAY_NAME` plus `WA_CONTACT_VCARD` enables the ignored live
contact send smoke, and `WA_LOCATION_LATITUDE` plus `WA_LOCATION_LONGITUDE`
enables the ignored live location send smoke. Optional `WA_LOCATION_NAME`,
`WA_LOCATION_ADDRESS`, and `WA_LOCATION_URL` tune the location payload.
`WA_POLL_NAME`, `WA_POLL_OPTIONS`, `WA_POLL_SELECTABLE_COUNT`,
`WA_POLL_SECRET_HEX`, `WA_EVENT_NAME`, `WA_EVENT_DESCRIPTION`,
`WA_EVENT_START_UNIX`, `WA_EVENT_END_UNIX`, `WA_EVENT_JOIN_LINK`, and
`WA_EVENT_SECRET_HEX` tune direct poll/event sends and ignored live smokes.
`WA_REACTION_MESSAGE_ID` enables the ignored live reaction send smoke and the
`live_text` reaction mode. Optional `WA_REACTION_REMOTE_JID`,
`WA_REACTION_FROM_ME`, `WA_REACTION_PARTICIPANT`, and `WA_REACTION_TEXT` tune
the target message key and reaction text.
`WA_EDIT_MESSAGE_ID`, `WA_DELETE_MESSAGE_ID`, and `WA_PIN_MESSAGE_ID` enable
the ignored live edit/delete/pin message smokes and matching `live_text` modes.
Each supports matching optional `*_REMOTE_JID`, `*_FROM_ME`, and
`*_PARTICIPANT` key fields. `WA_EDIT_TEXT`, `WA_EDIT_TIMESTAMP_MS`,
`WA_PIN_ACTION`, and `WA_PIN_TIMESTAMP_MS` tune the protocol payloads.
`WA_STATUS_JIDS` as a comma-separated user JID list enables the ignored live
status text-send smoke test and the `live_status` example, with optional
`WA_STATUS_TEXT` content.
`WA_STATUS_KIND` in the `live_status` example can be `text`, `image`, `video`,
`document`, `audio`, `sticker`, `poll`, or `event`; unset defaults to text,
while `WA_STATUS_MEDIA_PATH`, `WA_STATUS_VIDEO_PATH`,
`WA_STATUS_DOCUMENT_PATH`, `WA_STATUS_AUDIO_PATH`, or
`WA_STATUS_STICKER_PATH` imply their matching media modes. The same
`WA_STATUS_JIDS` audience enables ignored live status poll and event smoke
tests and the matching `live_status` modes, with optional
`WA_STATUS_POLL_NAME`, `WA_STATUS_POLL_OPTIONS`,
`WA_STATUS_POLL_SELECTABLE_COUNT`, `WA_STATUS_POLL_SECRET_HEX`,
`WA_STATUS_EVENT_NAME`, `WA_STATUS_EVENT_DESCRIPTION`,
`WA_STATUS_EVENT_START_UNIX`, `WA_STATUS_EVENT_END_UNIX`,
`WA_STATUS_EVENT_JOIN_LINK`, and `WA_STATUS_EVENT_SECRET_HEX`.
`WA_PHONE_NUMBER` enables the `live_pairing_code` example for an unregistered
session. Optional `WA_PAIRING_CODE` supplies an 8-character custom code, and
`WA_PAIRING_TIMEOUT_SECS` changes how long the example waits for the
link-code completion notification.
`WA_RECEIVE=1` enables the `live_receive` example, which starts the live
Signal-provider incoming processor and waits for typed message events. Optional
`WA_RECEIVE_TIMEOUT_SECS` changes the wait timeout, and `WA_RECEIVE_REMOTE_JID`
filters for a specific sender/chat JID.
`WA_HISTORY_SYNC=1` plus `--features http-media` enables the
`live_history_sync` example, which watches live message events for history-sync
notifications, downloads external payloads, and emits/persists processed
history batches. Optional `WA_HISTORY_SYNC_TIMEOUT_SECS`,
`WA_HISTORY_SYNC_FALLBACK_HOST`, and `WA_HISTORY_SYNC_LATEST` tune the manual
run.
`WA_CHAT_PIN_JID` enables the `live_chat_pin` example and ignored live chat-pin
smoke test. This mutates the target chat's pin state. Set
`WA_APP_STATE_KEY_ID_HEX`, optionally `WA_APP_STATE_KEY_DATA_HEX` when the key
is not already in `WA_SESSION_DB`, and optionally `WA_CHAT_PINNED=false` or
`WA_CHAT_PIN_TIMESTAMP_MS`.
`WA_MEDIA_PATH` plus `--features http-media` enables the `live_media` example.
Set `WA_MEDIA_KIND` to `image`, `video`, `gif`, `ptv`/`video_note`, `audio`,
`ptt`/`push_to_talk`, `document`, or `sticker`; unset defaults to image. Optional
`WA_MEDIA_MIMETYPE`, `WA_MEDIA_CAPTION`, `WA_MEDIA_VIEW_ONCE`,
`WA_MEDIA_AUDIO_PTT`, `WA_MEDIA_AUDIO_SECONDS`, `WA_MEDIA_VIDEO_SECONDS`,
`WA_MEDIA_VIDEO_HEIGHT`, `WA_MEDIA_VIDEO_WIDTH`, `WA_MEDIA_GIF_SECONDS`,
`WA_MEDIA_GIF_HEIGHT`, `WA_MEDIA_GIF_WIDTH`, `WA_MEDIA_PTV_SECONDS`,
`WA_MEDIA_PTV_HEIGHT`, `WA_MEDIA_PTV_WIDTH`, `WA_MEDIA_PTT_SECONDS`,
`WA_MEDIA_DOCUMENT_TITLE`, `WA_MEDIA_DOCUMENT_FILE_NAME`,
`WA_MEDIA_DOCUMENT_PAGE_COUNT`, `WA_MEDIA_STICKER_HEIGHT`,
`WA_MEDIA_STICKER_WIDTH`, and `WA_MEDIA_STICKER_ANIMATED` tune typed direct
media payloads. `WA_MEDIA_VIEW_ONCE=1` is supported for image and video. The
ignored live e2e harness also has direct image, video, document, view-once
image/video, GIF, PTV, PTT, audio, and sticker media smokes via `WA_MEDIA_PATH`,
`WA_VIDEO_MEDIA_PATH`, `WA_DOCUMENT_MEDIA_PATH`, `WA_VIEW_ONCE_IMAGE_PATH`,
`WA_VIEW_ONCE_VIDEO_PATH`, `WA_GIF_PATH`, `WA_PTV_PATH`, `WA_PTT_PATH`,
`WA_AUDIO_PATH`, or `WA_STICKER_PATH`.
`WA_STATUS_MEDIA_PATH` plus `WA_STATUS_JIDS` and `--features http-media`
enables the ignored live image status media smoke test and the media mode of
the `live_status` example, with optional `WA_STATUS_MEDIA_MIMETYPE` and
`WA_STATUS_MEDIA_CAPTION`.
`WA_STATUS_AUDIO_PATH` or `WA_STATUS_STICKER_PATH` plus `WA_STATUS_JIDS` and
`--features http-media` enables the ignored live audio or sticker status media
smoke tests and the matching `live_status` modes. `WA_STATUS_AUDIO_MIMETYPE`,
`WA_STATUS_AUDIO_PTT`,
`WA_STATUS_STICKER_MIMETYPE`, and `WA_STATUS_STICKER_ANIMATED` tune the
payload metadata.
`WA_MEDIA_RETRY_REMOTE_JID`, `WA_MEDIA_RETRY_MESSAGE_ID`, and
`WA_MEDIA_RETRY_MEDIA_KEY_HEX` enable the ignored live media retry request smoke
test and the `live_media_retry` example. `WA_MEDIA_RETRY_FROM_ME` and
`WA_MEDIA_RETRY_PARTICIPANT` can refine the retried message key. With
`--features http-media`, `WA_MEDIA_RETRY_WAIT_RESPONSE=1` also registers a
pending media descriptor and waits for the retry response to download refreshed
media. Set `WA_MEDIA_RETRY_FILE_SHA256_HEX`,
`WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX`, `WA_MEDIA_RETRY_FILE_LENGTH`, and
optionally `WA_MEDIA_RETRY_KIND`, `WA_MEDIA_RETRY_FALLBACK_HOST`,
`WA_MEDIA_RETRY_URL`, `WA_MEDIA_RETRY_DIRECT_PATH`,
`WA_MEDIA_RETRY_MEDIA_KEY_TIMESTAMP_MS`, and `WA_MEDIA_RETRY_TIMEOUT_SECS`.
`WA_VIDEO_PATH` plus `--features http-media,image` enables the ignored live
video remote-thumbnail send smoke test and the `live_video_thumbnail` example.
`WA_VIDEO_THUMBNAIL_FFMPEG` and `WA_VIDEO_THUMBNAIL_SEEK_TIME` can override the
ffmpeg command and seek timestamp used for thumbnail extraction.
`WA_DOCUMENT_PATH` plus `--features http-media,image` enables the ignored live
document remote-thumbnail send smoke test and the `live_document_thumbnail`
example. `WA_DOCUMENT_THUMBNAIL_PDFTOPPM`, `WA_DOCUMENT_THUMBNAIL_PAGE`, and
`WA_DOCUMENT_THUMBNAIL_DPI` can override the PDF renderer and thumbnail page.
`WA_STATUS_VIDEO_PATH` or `WA_STATUS_DOCUMENT_PATH` plus `WA_STATUS_JIDS` and
`--features http-media,image` enables ignored live generated-thumbnail status
video or document smoke tests and the matching `live_status` modes.
`WA_STATUS_VIDEO_MIMETYPE`, `WA_STATUS_VIDEO_CAPTION`,
`WA_STATUS_DOCUMENT_MIMETYPE`, `WA_STATUS_DOCUMENT_CAPTION`,
`WA_STATUS_DOCUMENT_TITLE`, and `WA_STATUS_DOCUMENT_FILE_NAME` tune status
media metadata; the same thumbnail tool override variables above apply.
`WA_PROFILE_PICTURE_PATH` plus `--features image` enables the ignored live
profile-picture update smoke test and the `live_profile_picture` example. This
mutates the own profile picture unless `WA_PROFILE_PICTURE_TARGET_JID` is set,
and `WA_PROFILE_PICTURE_SIZE`, `WA_PROFILE_PICTURE_PREVIEW_SIZE`, and
`WA_PROFILE_PICTURE_QUALITY` can override generated image settings.
`WA_LINK_PREVIEW_URL` plus `--features http-media,link-preview,image` enables
the ignored live link-preview thumbnail send smoke test and the
`live_link_preview` example, with optional `WA_LINK_PREVIEW_TEXT` content.
`WA_LINK_PREVIEW_IMAGE_PATH` adds the ignored generated link-preview thumbnail
send smoke test and the `live_generated_link_preview` example, with optional
`WA_LINK_PREVIEW_TITLE` and `WA_LINK_PREVIEW_DESCRIPTION` metadata.

For API concept mapping from the upstream TypeScript reference to Rust, see
[docs/api_transition_guide.md](docs/api_transition_guide.md).
For current capability status and pre-1.0 compatibility policy, see
[docs/feature_support_matrix.md](docs/feature_support_matrix.md).

## Feature Notes

- Default `wa-client` features enable SQLite storage, Noise, websockets, and
  rustls.
- `live_chat_pin`, `live_pairing_code`, `live_receive`, `live_status`, and
  `live_text` use the default live websocket features. `live_business_profile`,
  `live_business_profile_update`, `live_business_catalog`,
  `live_business_collections`, and `live_business_order_details` also use the
  default live websocket features. `live_text` can send text, contact, location,
  poll, event, reaction, edit, delete, or pin messages via `WA_MESSAGE_KIND`.
- `live_history_sync` and `live_media` additionally require `http-media`;
  `live_media` can send image, video, view-once image/video, GIF,
  PTV/video-note, audio, PTT/voice note, document, or sticker media via
  `WA_MEDIA_KIND`.
- `live_business_media` and `live_business_cover_photo` additionally require
  `http-media`.
- `live_status` additionally requires `http-media` when status image, audio, or
  sticker media modes are used.
- `live_status` additionally requires `http-media` and `image` when status
  video or document generated-thumbnail modes are used.
- `live_media_retry` uses the default live websocket features.
- `live_video_thumbnail` and `live_document_thumbnail` additionally require
  `http-media` and `image`.
- `live_profile_picture` additionally requires `image`.
- `live_link_preview` and `live_generated_link_preview` additionally require
  `http-media`, `link-preview`, and `image`.
- `custom_auth_store` shows the minimal `AuthStore` methods needed for custom
  session storage.
