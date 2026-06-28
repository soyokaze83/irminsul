use crate::{CoreError, CoreResult};
use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, jid_decode, jid_normalized_user};
use wa_proto::proto::message::{
    AlbumMessage, AudioMessage, ButtonsResponseMessage, ContactMessage, ContactsArrayMessage,
    DocumentMessage, EncEventResponseMessage, EventMessage, ExtendedTextMessage,
    FutureProofMessage, GroupInviteMessage, ImageMessage, ListResponseMessage, LiveLocationMessage,
    LocationMessage, PeerDataOperationRequestMessage, PeerDataOperationRequestType,
    PinInChatMessage, PollCreationMessage, PollEncValue, PollUpdateMessage,
    PollUpdateMessageMetadata, ProductMessage, ProtocolMessage, ReactionMessage,
    RequestPhoneNumberMessage, SenderKeyDistributionMessage as ProtoSenderKeyDistributionMessage,
    StickerMessage, TemplateButtonReplyMessage, VideoMessage, buttons_response_message,
    event_response_message, extended_text_message, group_invite_message, list_response_message,
    peer_data_operation_request_message, pin_in_chat_message, poll_creation_message,
    product_message, protocol_message,
};
use wa_proto::proto::{
    ContextInfo, DisappearingMode, LimitSharing, Message, MessageContextInfo, MessageKey,
    disappearing_mode, limit_sharing,
};
#[cfg(feature = "noise")]
use zeroize::Zeroize;

const MESSAGE_ID_PREFIX: &str = "3EB0";
#[cfg(feature = "noise")]
const POLL_EVENT_ENCRYPTION_IV_LEN: usize = 12;
#[cfg(feature = "noise")]
const POLL_VOTE_CRYPTO_LABEL: &str = "Poll Vote";
#[cfg(feature = "noise")]
const EVENT_RESPONSE_CRYPTO_LABEL: &str = "Event Response";
pub const STATUS_BROADCAST_JID: &str = "status@broadcast";

#[derive(Clone, Default, PartialEq)]
pub struct MessageContext {
    pub mentioned_jids: Vec<String>,
    pub quoted: Option<QuotedMessage>,
    pub forwarding_score: Option<u32>,
    pub is_forwarded: bool,
    pub expiration: Option<u32>,
}

impl MessageContext {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_mention(mut self, jid: impl Into<String>) -> Self {
        self.mentioned_jids.push(jid.into());
        self
    }

    #[must_use]
    pub fn with_mentions<I, T>(mut self, jids: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.mentioned_jids.extend(jids.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn with_quote(mut self, quoted: QuotedMessage) -> Self {
        self.quoted = Some(quoted);
        self
    }

    #[must_use]
    pub fn forwarded(mut self, forwarding_score: u32) -> Self {
        self.is_forwarded = true;
        self.forwarding_score = Some(forwarding_score);
        self
    }

    #[must_use]
    pub fn with_expiration(mut self, seconds: u32) -> Self {
        self.expiration = Some(seconds);
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct QuotedMessage {
    pub remote_jid: String,
    pub participant: Option<String>,
    pub stanza_id: String,
    pub message: Message,
}

impl QuotedMessage {
    #[must_use]
    pub fn new(
        remote_jid: impl Into<String>,
        stanza_id: impl Into<String>,
        message: Message,
    ) -> Self {
        Self {
            remote_jid: remote_jid.into(),
            participant: None,
            stanza_id: stanza_id.into(),
            message,
        }
    }

    #[must_use]
    pub fn with_participant(mut self, participant: impl Into<String>) -> Self {
        self.participant = Some(participant.into());
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct TextMessage {
    pub text: String,
    pub context: MessageContext,
    pub link_preview: Option<LinkPreviewContent>,
    pub text_argb: Option<u32>,
    pub background_argb: Option<u32>,
    pub font: Option<TextFont>,
}

impl TextMessage {
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            context: MessageContext::default(),
            link_preview: None,
            text_argb: None,
            background_argb: None,
            font: None,
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }

    #[must_use]
    pub fn with_link_preview(mut self, preview: LinkPreviewContent) -> Self {
        self.link_preview = Some(preview);
        self
    }

    #[must_use]
    pub fn with_text_argb(mut self, argb: u32) -> Self {
        self.text_argb = Some(argb);
        self
    }

    #[must_use]
    pub fn with_background_argb(mut self, argb: u32) -> Self {
        self.background_argb = Some(argb);
        self
    }

    #[must_use]
    pub fn with_font(mut self, font: TextFont) -> Self {
        self.font = Some(font);
        self
    }
}

impl From<String> for TextMessage {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<&str> for TextMessage {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TextFont {
    System,
    SystemText,
    Script,
    SystemBold,
    MorningBreeze,
    Calistoga,
    Exo2ExtraBold,
    CourierPrimeBold,
}

impl TextFont {
    #[must_use]
    pub const fn as_proto_i32(self) -> i32 {
        match self {
            Self::System => extended_text_message::FontType::System as i32,
            Self::SystemText => extended_text_message::FontType::SystemText as i32,
            Self::Script => extended_text_message::FontType::FbScript as i32,
            Self::SystemBold => extended_text_message::FontType::SystemBold as i32,
            Self::MorningBreeze => extended_text_message::FontType::MorningbreezeRegular as i32,
            Self::Calistoga => extended_text_message::FontType::CalistogaRegular as i32,
            Self::Exo2ExtraBold => extended_text_message::FontType::Exo2Extrabold as i32,
            Self::CourierPrimeBold => extended_text_message::FontType::CourierprimeBold as i32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkPreviewThumbnail {
    pub direct_path: String,
    pub media_key: Bytes,
    pub media_key_timestamp: Option<i64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub sha256: Bytes,
    pub enc_sha256: Bytes,
}

impl LinkPreviewThumbnail {
    #[must_use]
    pub fn new(
        direct_path: impl Into<String>,
        media_key: impl Into<Bytes>,
        sha256: impl Into<Bytes>,
        enc_sha256: impl Into<Bytes>,
    ) -> Self {
        Self {
            direct_path: direct_path.into(),
            media_key: media_key.into(),
            media_key_timestamp: None,
            width: None,
            height: None,
            sha256: sha256.into(),
            enc_sha256: enc_sha256.into(),
        }
    }

    #[must_use]
    pub fn with_media_key_timestamp(mut self, timestamp: i64) -> Self {
        self.media_key_timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkPreviewContent {
    pub matched_text: String,
    pub title: String,
    pub description: Option<String>,
    pub jpeg_thumbnail: Option<Bytes>,
    pub high_quality_thumbnail: Option<LinkPreviewThumbnail>,
}

impl LinkPreviewContent {
    #[must_use]
    pub fn new(matched_text: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            matched_text: matched_text.into(),
            title: title.into(),
            description: None,
            jpeg_thumbnail: None,
            high_quality_thumbnail: None,
        }
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    #[must_use]
    pub fn with_jpeg_thumbnail(mut self, thumbnail: impl Into<Bytes>) -> Self {
        self.jpeg_thumbnail = Some(thumbnail.into());
        self
    }

    #[must_use]
    pub fn with_high_quality_thumbnail(mut self, thumbnail: LinkPreviewThumbnail) -> Self {
        self.high_quality_thumbnail = Some(thumbnail);
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct ContactContent {
    pub display_name: String,
    pub vcard: String,
    pub context: MessageContext,
}

impl ContactContent {
    #[must_use]
    pub fn new(display_name: impl Into<String>, vcard: impl Into<String>) -> Self {
        Self {
            display_name: display_name.into(),
            vcard: vcard.into(),
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct ContactsContent {
    pub display_name: String,
    pub contacts: Vec<ContactContent>,
    pub context: MessageContext,
}

impl ContactsContent {
    #[must_use]
    pub fn new<I>(display_name: impl Into<String>, contacts: I) -> Self
    where
        I: IntoIterator<Item = ContactContent>,
    {
        Self {
            display_name: display_name.into(),
            contacts: contacts.into_iter().collect(),
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct LocationContent {
    pub latitude: f64,
    pub longitude: f64,
    pub name: Option<String>,
    pub address: Option<String>,
    pub url: Option<String>,
    pub context: MessageContext,
}

impl LocationContent {
    #[must_use]
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
            name: None,
            address: None,
            url: None,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct LiveLocationContent {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_in_meters: Option<u32>,
    pub speed_in_mps: Option<f32>,
    pub degrees_clockwise_from_magnetic_north: Option<u32>,
    pub caption: Option<String>,
    pub sequence_number: Option<i64>,
    pub time_offset: Option<u32>,
    pub context: MessageContext,
}

impl LiveLocationContent {
    #[must_use]
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
            accuracy_in_meters: None,
            speed_in_mps: None,
            degrees_clockwise_from_magnetic_north: None,
            caption: None,
            sequence_number: None,
            time_offset: None,
            context: MessageContext::default(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct ReactionContent {
    pub key: MessageKey,
    pub text: String,
    pub grouping_key: Option<String>,
    pub sender_timestamp_ms: Option<i64>,
}

impl ReactionContent {
    #[must_use]
    pub fn new(key: MessageKey, text: impl Into<String>) -> Self {
        Self {
            key,
            text: text.into(),
            grouping_key: None,
            sender_timestamp_ms: None,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct PollContent {
    pub name: String,
    pub options: Vec<String>,
    pub selectable_options_count: u32,
    pub message_secret: Bytes,
    pub context: MessageContext,
    pub to_announcement_group: bool,
}

impl PollContent {
    #[must_use]
    pub fn new<I, T>(
        name: impl Into<String>,
        options: I,
        selectable_options_count: u32,
        message_secret: Bytes,
    ) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self {
            name: name.into(),
            options: options.into_iter().map(Into::into).collect(),
            selectable_options_count,
            message_secret,
            context: MessageContext::default(),
            to_announcement_group: false,
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }

    #[must_use]
    pub fn to_announcement_group(mut self) -> Self {
        self.to_announcement_group = true;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct EventContent {
    pub name: String,
    pub description: Option<String>,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub is_canceled: bool,
    pub extra_guests_allowed: Option<bool>,
    pub is_schedule_call: bool,
    pub location: Option<LocationContent>,
    pub join_link: Option<String>,
    pub message_secret: Bytes,
    pub context: MessageContext,
}

impl EventContent {
    #[must_use]
    pub fn new(name: impl Into<String>, start_time: i64, message_secret: Bytes) -> Self {
        Self {
            name: name.into(),
            description: None,
            start_time,
            end_time: None,
            is_canceled: false,
            extra_guests_allowed: None,
            is_schedule_call: false,
            location: None,
            join_link: None,
            message_secret,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_join_link(mut self, join_link: impl Into<String>) -> Self {
        self.join_link = Some(join_link.into());
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct PollUpdateContent {
    pub poll_creation_message_key: MessageKey,
    pub encrypted_payload: Bytes,
    pub encrypted_iv: Bytes,
    pub sender_timestamp_ms: Option<i64>,
    pub include_metadata: bool,
}

impl PollUpdateContent {
    #[must_use]
    pub fn new(
        poll_creation_message_key: MessageKey,
        encrypted_payload: impl Into<Bytes>,
        encrypted_iv: impl Into<Bytes>,
    ) -> Self {
        Self {
            poll_creation_message_key,
            encrypted_payload: encrypted_payload.into(),
            encrypted_iv: encrypted_iv.into(),
            sender_timestamp_ms: None,
            include_metadata: true,
        }
    }

    #[must_use]
    pub fn with_sender_timestamp_ms(mut self, sender_timestamp_ms: i64) -> Self {
        self.sender_timestamp_ms = Some(sender_timestamp_ms);
        self
    }

    #[must_use]
    pub fn without_metadata(mut self) -> Self {
        self.include_metadata = false;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct PollVoteContent {
    pub poll_creation_message_key: MessageKey,
    pub selected_option_hashes: Vec<Bytes>,
    pub poll_message_secret: Bytes,
    pub poll_creator_jid: String,
    pub voter_jid: String,
    pub sender_timestamp_ms: Option<i64>,
    pub include_metadata: bool,
}

impl PollVoteContent {
    #[must_use]
    pub fn new<I, T>(
        poll_creation_message_key: MessageKey,
        selected_option_hashes: I,
        poll_message_secret: impl Into<Bytes>,
        poll_creator_jid: impl Into<String>,
        voter_jid: impl Into<String>,
    ) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Bytes>,
    {
        Self {
            poll_creation_message_key,
            selected_option_hashes: selected_option_hashes.into_iter().map(Into::into).collect(),
            poll_message_secret: poll_message_secret.into(),
            poll_creator_jid: poll_creator_jid.into(),
            voter_jid: voter_jid.into(),
            sender_timestamp_ms: None,
            include_metadata: true,
        }
    }

    pub fn from_option_names<I, T>(
        poll_creation_message_key: MessageKey,
        selected_option_names: I,
        poll_message_secret: impl Into<Bytes>,
        poll_creator_jid: impl Into<String>,
        voter_jid: impl Into<String>,
    ) -> CoreResult<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let mut hashes = Vec::new();
        for name in selected_option_names {
            let name = name.into();
            validate_non_empty("selected poll option", &name)?;
            hashes.push(Bytes::copy_from_slice(&Sha256::digest(name.as_bytes())));
        }
        Ok(Self::new(
            poll_creation_message_key,
            hashes,
            poll_message_secret,
            poll_creator_jid,
            voter_jid,
        ))
    }

    #[must_use]
    pub fn with_sender_timestamp_ms(mut self, sender_timestamp_ms: i64) -> Self {
        self.sender_timestamp_ms = Some(sender_timestamp_ms);
        self
    }

    #[must_use]
    pub fn without_metadata(mut self) -> Self {
        self.include_metadata = false;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventResponseKind {
    Unknown,
    Going,
    NotGoing,
    Maybe,
}

impl EventResponseKind {
    #[must_use]
    pub fn as_proto_i32(self) -> i32 {
        match self {
            Self::Unknown => event_response_message::EventResponseType::Unknown as i32,
            Self::Going => event_response_message::EventResponseType::Going as i32,
            Self::NotGoing => event_response_message::EventResponseType::NotGoing as i32,
            Self::Maybe => event_response_message::EventResponseType::Maybe as i32,
        }
    }
}

impl From<event_response_message::EventResponseType> for EventResponseKind {
    fn from(value: event_response_message::EventResponseType) -> Self {
        match value {
            event_response_message::EventResponseType::Unknown => Self::Unknown,
            event_response_message::EventResponseType::Going => Self::Going,
            event_response_message::EventResponseType::NotGoing => Self::NotGoing,
            event_response_message::EventResponseType::Maybe => Self::Maybe,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct EventResponsePayload {
    pub event_creation_message_key: MessageKey,
    pub response: EventResponseKind,
    pub event_message_secret: Bytes,
    pub event_creator_jid: String,
    pub responder_jid: String,
    pub timestamp_ms: Option<i64>,
    pub extra_guest_count: Option<i32>,
}

impl EventResponsePayload {
    #[must_use]
    pub fn new(
        event_creation_message_key: MessageKey,
        response: EventResponseKind,
        event_message_secret: impl Into<Bytes>,
        event_creator_jid: impl Into<String>,
        responder_jid: impl Into<String>,
    ) -> Self {
        Self {
            event_creation_message_key,
            response,
            event_message_secret: event_message_secret.into(),
            event_creator_jid: event_creator_jid.into(),
            responder_jid: responder_jid.into(),
            timestamp_ms: None,
            extra_guest_count: None,
        }
    }

    #[must_use]
    pub fn with_timestamp_ms(mut self, timestamp_ms: i64) -> Self {
        self.timestamp_ms = Some(timestamp_ms);
        self
    }

    #[must_use]
    pub fn with_extra_guest_count(mut self, extra_guest_count: i32) -> Self {
        self.extra_guest_count = Some(extra_guest_count);
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct EventResponseContent {
    pub event_creation_message_key: MessageKey,
    pub encrypted_payload: Bytes,
    pub encrypted_iv: Bytes,
}

impl EventResponseContent {
    #[must_use]
    pub fn new(
        event_creation_message_key: MessageKey,
        encrypted_payload: impl Into<Bytes>,
        encrypted_iv: impl Into<Bytes>,
    ) -> Self {
        Self {
            event_creation_message_key,
            encrypted_payload: encrypted_payload.into(),
            encrypted_iv: encrypted_iv.into(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct EditContent {
    pub key: MessageKey,
    pub message: Message,
    pub timestamp_ms: Option<i64>,
}

#[derive(Clone, PartialEq)]
pub struct DeleteContent {
    pub key: MessageKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinAction {
    Pin,
    Unpin,
}

#[derive(Clone, PartialEq)]
pub struct PinContent {
    pub key: MessageKey,
    pub action: PinAction,
    pub sender_timestamp_ms: Option<i64>,
}

#[derive(Clone, PartialEq)]
pub struct DisappearingModeContent {
    pub ephemeral_expiration: u32,
    pub ephemeral_setting_timestamp: Option<i64>,
    pub initiator_device_jid: Option<String>,
}

impl DisappearingModeContent {
    #[must_use]
    pub fn new(ephemeral_expiration: u32) -> Self {
        Self {
            ephemeral_expiration,
            ephemeral_setting_timestamp: None,
            initiator_device_jid: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadedMedia {
    pub url: Option<String>,
    pub direct_path: Option<String>,
    pub media_key: Bytes,
    pub file_sha256: Bytes,
    pub file_enc_sha256: Bytes,
    pub file_length: u64,
    pub media_key_timestamp: Option<i64>,
}

impl UploadedMedia {
    #[must_use]
    pub fn new(
        media_key: Bytes,
        file_sha256: Bytes,
        file_enc_sha256: Bytes,
        file_length: u64,
    ) -> Self {
        Self {
            url: None,
            direct_path: None,
            media_key,
            file_sha256,
            file_enc_sha256,
            file_length,
            media_key_timestamp: None,
        }
    }

    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_direct_path(mut self, direct_path: impl Into<String>) -> Self {
        self.direct_path = Some(direct_path.into());
        self
    }

    #[must_use]
    pub fn with_media_key_timestamp(mut self, timestamp: i64) -> Self {
        self.media_key_timestamp = Some(timestamp);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMediaThumbnail {
    pub direct_path: String,
    pub sha256: Bytes,
    pub enc_sha256: Bytes,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

impl RemoteMediaThumbnail {
    #[must_use]
    pub fn new(
        direct_path: impl Into<String>,
        sha256: impl Into<Bytes>,
        enc_sha256: impl Into<Bytes>,
    ) -> Self {
        Self {
            direct_path: direct_path.into(),
            sha256: sha256.into(),
            enc_sha256: enc_sha256.into(),
            width: None,
            height: None,
        }
    }

    #[must_use]
    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct ImageContent {
    pub media: UploadedMedia,
    pub mimetype: String,
    pub caption: Option<String>,
    pub height: Option<u32>,
    pub width: Option<u32>,
    pub jpeg_thumbnail: Option<Bytes>,
    pub view_once: bool,
    pub context: MessageContext,
}

impl ImageContent {
    #[must_use]
    pub fn new(media: UploadedMedia, mimetype: impl Into<String>) -> Self {
        Self {
            media,
            mimetype: mimetype.into(),
            caption: None,
            height: None,
            width: None,
            jpeg_thumbnail: None,
            view_once: false,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }

    #[cfg(feature = "image")]
    pub fn with_generated_jpeg_thumbnail(
        mut self,
        source_image: &[u8],
        options: crate::JpegThumbnailOptions,
    ) -> CoreResult<Self> {
        let thumbnail = crate::generate_jpeg_thumbnail(source_image, options)?;
        self.width = Some(thumbnail.source_width);
        self.height = Some(thumbnail.source_height);
        self.jpeg_thumbnail = Some(thumbnail.jpeg);
        Ok(self)
    }
}

#[derive(Clone, PartialEq)]
pub struct VideoContent {
    pub media: UploadedMedia,
    pub mimetype: String,
    pub caption: Option<String>,
    pub seconds: Option<u32>,
    pub height: Option<u32>,
    pub width: Option<u32>,
    pub jpeg_thumbnail: Option<Bytes>,
    pub remote_thumbnail: Option<RemoteMediaThumbnail>,
    pub gif_playback: bool,
    pub view_once: bool,
    pub streaming_sidecar: Option<Bytes>,
    pub context: MessageContext,
}

impl VideoContent {
    #[must_use]
    pub fn new(media: UploadedMedia, mimetype: impl Into<String>) -> Self {
        Self {
            media,
            mimetype: mimetype.into(),
            caption: None,
            seconds: None,
            height: None,
            width: None,
            jpeg_thumbnail: None,
            remote_thumbnail: None,
            gif_playback: false,
            view_once: false,
            streaming_sidecar: None,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }

    #[must_use]
    pub fn with_remote_thumbnail(mut self, thumbnail: RemoteMediaThumbnail) -> Self {
        self.remote_thumbnail = Some(thumbnail);
        self
    }

    #[cfg(feature = "image")]
    pub fn with_generated_jpeg_thumbnail(
        mut self,
        source_image: &[u8],
        options: crate::JpegThumbnailOptions,
    ) -> CoreResult<Self> {
        let thumbnail = crate::generate_jpeg_thumbnail(source_image, options)?;
        self.width = Some(thumbnail.source_width);
        self.height = Some(thumbnail.source_height);
        self.jpeg_thumbnail = Some(thumbnail.jpeg);
        Ok(self)
    }
}

#[derive(Clone, PartialEq)]
pub struct AudioContent {
    pub media: UploadedMedia,
    pub mimetype: String,
    pub seconds: Option<u32>,
    pub ptt: bool,
    pub waveform: Option<Bytes>,
    pub streaming_sidecar: Option<Bytes>,
    pub background_argb: Option<u32>,
    pub context: MessageContext,
}

impl AudioContent {
    #[must_use]
    pub fn new(media: UploadedMedia, mimetype: impl Into<String>) -> Self {
        Self {
            media,
            mimetype: mimetype.into(),
            seconds: None,
            ptt: false,
            waveform: None,
            streaming_sidecar: None,
            background_argb: None,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }

    #[must_use]
    pub fn with_background_argb(mut self, argb: u32) -> Self {
        self.background_argb = Some(argb);
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct DocumentContent {
    pub media: UploadedMedia,
    pub mimetype: String,
    pub title: Option<String>,
    pub file_name: Option<String>,
    pub caption: Option<String>,
    pub page_count: Option<u32>,
    pub jpeg_thumbnail: Option<Bytes>,
    pub thumbnail_height: Option<u32>,
    pub thumbnail_width: Option<u32>,
    pub remote_thumbnail: Option<RemoteMediaThumbnail>,
    pub context: MessageContext,
}

impl DocumentContent {
    #[must_use]
    pub fn new(media: UploadedMedia, mimetype: impl Into<String>) -> Self {
        Self {
            media,
            mimetype: mimetype.into(),
            title: None,
            file_name: None,
            caption: None,
            page_count: None,
            jpeg_thumbnail: None,
            thumbnail_height: None,
            thumbnail_width: None,
            remote_thumbnail: None,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }

    #[must_use]
    pub fn with_remote_thumbnail(mut self, thumbnail: RemoteMediaThumbnail) -> Self {
        self.remote_thumbnail = Some(thumbnail);
        self
    }

    #[cfg(feature = "image")]
    pub fn with_generated_jpeg_thumbnail(
        mut self,
        source_image: &[u8],
        options: crate::JpegThumbnailOptions,
    ) -> CoreResult<Self> {
        let thumbnail = crate::generate_jpeg_thumbnail(source_image, options)?;
        self.thumbnail_width = Some(thumbnail.width);
        self.thumbnail_height = Some(thumbnail.height);
        self.jpeg_thumbnail = Some(thumbnail.jpeg);
        Ok(self)
    }

    #[cfg(feature = "image")]
    pub fn with_generated_pdf_thumbnail(
        mut self,
        path: impl AsRef<std::path::Path>,
        options: crate::PdfThumbnailOptions,
    ) -> CoreResult<Self> {
        let thumbnail = crate::generate_pdf_thumbnail_from_file(path, options)?;
        self.thumbnail_width = Some(thumbnail.width);
        self.thumbnail_height = Some(thumbnail.height);
        self.jpeg_thumbnail = Some(thumbnail.jpeg);
        Ok(self)
    }
}

#[derive(Clone, PartialEq)]
pub struct StickerContent {
    pub media: UploadedMedia,
    pub mimetype: String,
    pub height: Option<u32>,
    pub width: Option<u32>,
    pub png_thumbnail: Option<Bytes>,
    pub is_animated: bool,
    pub context: MessageContext,
}

impl StickerContent {
    #[must_use]
    pub fn new(media: UploadedMedia, mimetype: impl Into<String>) -> Self {
        Self {
            media,
            mimetype: mimetype.into(),
            height: None,
            width: None,
            png_thumbnail: None,
            is_animated: false,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupInviteKind {
    Default,
    Parent,
}

#[derive(Clone, PartialEq)]
pub struct GroupInviteContent {
    pub group_jid: String,
    pub invite_code: String,
    pub invite_expiration: i64,
    pub group_name: String,
    pub jpeg_thumbnail: Option<Bytes>,
    pub caption: Option<String>,
    pub kind: GroupInviteKind,
    pub context: MessageContext,
}

impl GroupInviteContent {
    #[must_use]
    pub fn new(
        group_jid: impl Into<String>,
        invite_code: impl Into<String>,
        invite_expiration: i64,
        group_name: impl Into<String>,
    ) -> Self {
        Self {
            group_jid: group_jid.into(),
            invite_code: invite_code.into(),
            invite_expiration,
            group_name: group_name.into(),
            jpeg_thumbnail: None,
            caption: None,
            kind: GroupInviteKind::Default,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn parent_group(mut self) -> Self {
        self.kind = GroupInviteKind::Parent;
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct ProductSnapshotContent {
    pub product_id: String,
    pub title: String,
    pub description: Option<String>,
    pub currency_code: String,
    pub price_amount1000: i64,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub product_image: Option<ImageContent>,
    pub product_image_count: Option<u32>,
    pub first_image_id: Option<String>,
    pub sale_price_amount1000: Option<i64>,
    pub signed_url: Option<String>,
}

impl ProductSnapshotContent {
    #[must_use]
    pub fn new(
        product_id: impl Into<String>,
        title: impl Into<String>,
        currency_code: impl Into<String>,
        price_amount1000: i64,
    ) -> Self {
        Self {
            product_id: product_id.into(),
            title: title.into(),
            description: None,
            currency_code: currency_code.into(),
            price_amount1000,
            retailer_id: None,
            url: None,
            product_image: None,
            product_image_count: None,
            first_image_id: None,
            sale_price_amount1000: None,
            signed_url: None,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct CatalogSnapshotContent {
    pub title: Option<String>,
    pub description: Option<String>,
    pub catalog_image: Option<ImageContent>,
}

impl CatalogSnapshotContent {
    #[must_use]
    pub fn new() -> Self {
        Self {
            title: None,
            description: None,
            catalog_image: None,
        }
    }
}

impl Default for CatalogSnapshotContent {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, PartialEq)]
pub struct ProductContent {
    pub business_owner_jid: String,
    pub product: ProductSnapshotContent,
    pub catalog: Option<CatalogSnapshotContent>,
    pub body: Option<String>,
    pub footer: Option<String>,
    pub context: MessageContext,
}

impl ProductContent {
    #[must_use]
    pub fn new(business_owner_jid: impl Into<String>, product: ProductSnapshotContent) -> Self {
        Self {
            business_owner_jid: business_owner_jid.into(),
            product,
            catalog: None,
            body: None,
            footer: None,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct AlbumContent {
    pub expected_image_count: u32,
    pub expected_video_count: u32,
    pub context: MessageContext,
}

impl AlbumContent {
    #[must_use]
    pub fn new(expected_image_count: u32, expected_video_count: u32) -> Self {
        Self {
            expected_image_count,
            expected_video_count,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct RequestPhoneNumberContent {
    pub context: MessageContext,
}

impl RequestPhoneNumberContent {
    #[must_use]
    pub fn new() -> Self {
        Self {
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

impl Default for RequestPhoneNumberContent {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LimitSharingTrigger {
    Unknown,
    ChatSetting,
    BizSupportsFbHosting,
    UnknownGroup,
}

impl LimitSharingTrigger {
    #[must_use]
    pub const fn as_proto_i32(self) -> i32 {
        match self {
            Self::Unknown => limit_sharing::TriggerType::Unknown as i32,
            Self::ChatSetting => limit_sharing::TriggerType::ChatSetting as i32,
            Self::BizSupportsFbHosting => limit_sharing::TriggerType::BizSupportsFbHosting as i32,
            Self::UnknownGroup => limit_sharing::TriggerType::UnknownGroup as i32,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct LimitSharingContent {
    pub sharing_limited: bool,
    pub trigger: LimitSharingTrigger,
    pub setting_timestamp_ms: Option<i64>,
    pub initiated_by_me: bool,
}

impl LimitSharingContent {
    #[must_use]
    pub fn new(sharing_limited: bool) -> Self {
        Self {
            sharing_limited,
            trigger: LimitSharingTrigger::ChatSetting,
            setting_timestamp_ms: None,
            initiated_by_me: true,
        }
    }

    #[must_use]
    pub fn with_trigger(mut self, trigger: LimitSharingTrigger) -> Self {
        self.trigger = trigger;
        self
    }

    #[must_use]
    pub fn with_setting_timestamp_ms(mut self, timestamp_ms: i64) -> Self {
        self.setting_timestamp_ms = Some(timestamp_ms);
        self
    }

    #[must_use]
    pub fn initiated_by_me(mut self, value: bool) -> Self {
        self.initiated_by_me = value;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct ButtonReplyContent {
    pub selected_button_id: String,
    pub selected_display_text: String,
    pub context: MessageContext,
}

impl ButtonReplyContent {
    #[must_use]
    pub fn new(
        selected_button_id: impl Into<String>,
        selected_display_text: impl Into<String>,
    ) -> Self {
        Self {
            selected_button_id: selected_button_id.into(),
            selected_display_text: selected_display_text.into(),
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct TemplateButtonReplyContent {
    pub selected_id: String,
    pub selected_display_text: String,
    pub selected_index: Option<u32>,
    pub selected_carousel_card_index: Option<u32>,
    pub context: MessageContext,
}

impl TemplateButtonReplyContent {
    #[must_use]
    pub fn new(selected_id: impl Into<String>, selected_display_text: impl Into<String>) -> Self {
        Self {
            selected_id: selected_id.into(),
            selected_display_text: selected_display_text.into(),
            selected_index: None,
            selected_carousel_card_index: None,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_selected_index(mut self, index: u32) -> Self {
        self.selected_index = Some(index);
        self
    }

    #[must_use]
    pub fn with_selected_carousel_card_index(mut self, index: u32) -> Self {
        self.selected_carousel_card_index = Some(index);
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, PartialEq)]
pub struct ListReplyContent {
    pub title: String,
    pub selected_row_id: String,
    pub description: Option<String>,
    pub context: MessageContext,
}

impl ListReplyContent {
    #[must_use]
    pub fn new(title: impl Into<String>, selected_row_id: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            selected_row_id: selected_row_id.into(),
            description: None,
            context: MessageContext::default(),
        }
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = context;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderKeyDistributionContent {
    pub group_id: String,
    pub distribution: Bytes,
}

impl SenderKeyDistributionContent {
    #[must_use]
    pub fn new(group_id: impl Into<String>, distribution: impl Into<Bytes>) -> Self {
        Self {
            group_id: group_id.into(),
            distribution: distribution.into(),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum MessageContent {
    Text(Box<TextMessage>),
    Contact(Box<ContactContent>),
    Contacts(Box<ContactsContent>),
    Location(Box<LocationContent>),
    LiveLocation(Box<LiveLocationContent>),
    Reaction(Box<ReactionContent>),
    Poll(Box<PollContent>),
    Event(Box<EventContent>),
    PollUpdate(Box<PollUpdateContent>),
    EventResponse(Box<EventResponseContent>),
    Edit(Box<EditContent>),
    Delete(Box<DeleteContent>),
    Pin(Box<PinContent>),
    DisappearingMode(Box<DisappearingModeContent>),
    Image(Box<ImageContent>),
    Video(Box<VideoContent>),
    Ptv(Box<VideoContent>),
    Audio(Box<AudioContent>),
    Document(Box<DocumentContent>),
    Sticker(Box<StickerContent>),
    GroupInvite(Box<GroupInviteContent>),
    Product(Box<ProductContent>),
    Album(Box<AlbumContent>),
    RequestPhoneNumber(Box<RequestPhoneNumberContent>),
    SharePhoneNumber,
    LimitSharing(Box<LimitSharingContent>),
    ButtonReply(Box<ButtonReplyContent>),
    TemplateButtonReply(Box<TemplateButtonReplyContent>),
    ListReply(Box<ListReplyContent>),
    SenderKeyDistribution(Box<SenderKeyDistributionContent>),
    ViewOnce(Box<MessageContent>),
}

impl MessageContent {
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text(Box::new(TextMessage::new(text)))
    }

    #[must_use]
    pub fn text_message(text: TextMessage) -> Self {
        Self::Text(Box::new(text))
    }

    #[must_use]
    pub fn contact(contact: ContactContent) -> Self {
        Self::Contact(Box::new(contact))
    }

    #[must_use]
    pub fn contacts(contacts: ContactsContent) -> Self {
        Self::Contacts(Box::new(contacts))
    }

    #[must_use]
    pub fn location(location: LocationContent) -> Self {
        Self::Location(Box::new(location))
    }

    #[must_use]
    pub fn live_location(location: LiveLocationContent) -> Self {
        Self::LiveLocation(Box::new(location))
    }

    #[must_use]
    pub fn reaction(reaction: ReactionContent) -> Self {
        Self::Reaction(Box::new(reaction))
    }

    #[must_use]
    pub fn poll(poll: PollContent) -> Self {
        Self::Poll(Box::new(poll))
    }

    #[must_use]
    pub fn event(event: EventContent) -> Self {
        Self::Event(Box::new(event))
    }

    #[must_use]
    pub fn poll_update(update: PollUpdateContent) -> Self {
        Self::PollUpdate(Box::new(update))
    }

    #[must_use]
    pub fn event_response(response: EventResponseContent) -> Self {
        Self::EventResponse(Box::new(response))
    }

    #[must_use]
    pub fn edit(edit: EditContent) -> Self {
        Self::Edit(Box::new(edit))
    }

    #[must_use]
    pub fn delete(delete: DeleteContent) -> Self {
        Self::Delete(Box::new(delete))
    }

    #[must_use]
    pub fn pin(pin: PinContent) -> Self {
        Self::Pin(Box::new(pin))
    }

    #[must_use]
    pub fn disappearing_mode(content: DisappearingModeContent) -> Self {
        Self::DisappearingMode(Box::new(content))
    }

    #[must_use]
    pub fn image(image: ImageContent) -> Self {
        Self::Image(Box::new(image))
    }

    #[must_use]
    pub fn video(video: VideoContent) -> Self {
        Self::Video(Box::new(video))
    }

    #[must_use]
    pub fn ptv(video: VideoContent) -> Self {
        Self::Ptv(Box::new(video))
    }

    #[must_use]
    pub fn audio(audio: AudioContent) -> Self {
        Self::Audio(Box::new(audio))
    }

    #[must_use]
    pub fn document(document: DocumentContent) -> Self {
        Self::Document(Box::new(document))
    }

    #[must_use]
    pub fn sticker(sticker: StickerContent) -> Self {
        Self::Sticker(Box::new(sticker))
    }

    #[must_use]
    pub fn group_invite(invite: GroupInviteContent) -> Self {
        Self::GroupInvite(Box::new(invite))
    }

    #[must_use]
    pub fn product(product: ProductContent) -> Self {
        Self::Product(Box::new(product))
    }

    #[must_use]
    pub fn album(album: AlbumContent) -> Self {
        Self::Album(Box::new(album))
    }

    #[must_use]
    pub fn request_phone_number(content: RequestPhoneNumberContent) -> Self {
        Self::RequestPhoneNumber(Box::new(content))
    }

    #[must_use]
    pub fn share_phone_number() -> Self {
        Self::SharePhoneNumber
    }

    #[must_use]
    pub fn limit_sharing(content: LimitSharingContent) -> Self {
        Self::LimitSharing(Box::new(content))
    }

    #[must_use]
    pub fn button_reply(content: ButtonReplyContent) -> Self {
        Self::ButtonReply(Box::new(content))
    }

    #[must_use]
    pub fn template_button_reply(content: TemplateButtonReplyContent) -> Self {
        Self::TemplateButtonReply(Box::new(content))
    }

    #[must_use]
    pub fn list_reply(content: ListReplyContent) -> Self {
        Self::ListReply(Box::new(content))
    }

    #[must_use]
    pub fn sender_key_distribution(content: SenderKeyDistributionContent) -> Self {
        Self::SenderKeyDistribution(Box::new(content))
    }

    #[must_use]
    pub fn view_once(content: MessageContent) -> Self {
        Self::ViewOnce(Box::new(content))
    }

    pub fn into_proto(self) -> CoreResult<Message> {
        match self {
            Self::Text(text) => build_text_message(*text),
            Self::Contact(contact) => build_contact_message(*contact),
            Self::Contacts(contacts) => build_contacts_message(*contacts),
            Self::Location(location) => build_location_message(*location),
            Self::LiveLocation(location) => build_live_location_message(*location),
            Self::Reaction(reaction) => build_reaction_message(*reaction),
            Self::Poll(poll) => build_poll_message(*poll),
            Self::Event(event) => build_event_message(*event),
            Self::PollUpdate(update) => build_poll_update_message(*update),
            Self::EventResponse(response) => build_event_response_message(*response),
            Self::Edit(edit) => build_edit_message(*edit),
            Self::Delete(delete) => build_delete_message(*delete),
            Self::Pin(pin) => build_pin_message(*pin),
            Self::DisappearingMode(content) => build_disappearing_mode_message(*content),
            Self::Image(image) => build_image_message(*image),
            Self::Video(video) => build_video_message(*video),
            Self::Ptv(video) => build_ptv_message(*video),
            Self::Audio(audio) => build_audio_message(*audio),
            Self::Document(document) => build_document_message(*document),
            Self::Sticker(sticker) => build_sticker_message(*sticker),
            Self::GroupInvite(invite) => build_group_invite_message(*invite),
            Self::Product(product) => build_product_message(*product),
            Self::Album(album) => build_album_message(*album),
            Self::RequestPhoneNumber(content) => build_request_phone_number_message(*content),
            Self::SharePhoneNumber => build_share_phone_number_message(),
            Self::LimitSharing(content) => build_limit_sharing_message(*content),
            Self::ButtonReply(content) => build_button_reply_message(*content),
            Self::TemplateButtonReply(content) => build_template_button_reply_message(*content),
            Self::ListReply(content) => build_list_reply_message(*content),
            Self::SenderKeyDistribution(content) => build_sender_key_distribution_message(*content),
            Self::ViewOnce(content) => build_view_once_message(*content),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageCiphertextType {
    Message,
    PreKey,
    SenderKey,
}

impl MessageCiphertextType {
    #[must_use]
    pub fn as_stanza_type(self) -> &'static str {
        match self {
            Self::Message => "msg",
            Self::PreKey => "pkmsg",
            Self::SenderKey => "skmsg",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageEncryption {
    pub ciphertext_type: MessageCiphertextType,
    pub ciphertext: Bytes,
}

impl MessageEncryption {
    #[must_use]
    pub fn new(ciphertext_type: MessageCiphertextType, ciphertext: Bytes) -> Self {
        Self {
            ciphertext_type,
            ciphertext,
        }
    }
}

#[async_trait]
pub trait MessageEncryptor: Send + Sync {
    async fn encrypt_message(
        &self,
        recipient_jid: &str,
        plaintext: Bytes,
    ) -> CoreResult<MessageEncryption>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageRelayRecipient {
    pub jid: String,
    pub is_own_device: bool,
}

impl MessageRelayRecipient {
    #[must_use]
    pub fn new(jid: impl Into<String>) -> Self {
        Self {
            jid: jid.into(),
            is_own_device: false,
        }
    }

    #[must_use]
    pub fn own_device(jid: impl Into<String>) -> Self {
        Self {
            jid: jid.into(),
            is_own_device: true,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MessageRelayOptions {
    pub message_id: Option<String>,
    pub sender_jid: Option<String>,
    pub additional_attributes: BTreeMap<String, String>,
    pub additional_nodes: Vec<BinaryNode>,
    pub device_identity_node: Option<BinaryNode>,
    pub encryption_attributes: BTreeMap<String, String>,
}

impl MessageRelayOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    #[must_use]
    pub fn with_sender_jid(mut self, sender_jid: impl Into<String>) -> Self {
        self.sender_jid = Some(sender_jid.into());
        self
    }

    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_attributes.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_encryption_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.encryption_attributes.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_node(mut self, node: BinaryNode) -> Self {
        self.additional_nodes.push(node);
        self
    }

    #[must_use]
    pub fn with_device_identity_node(mut self, node: BinaryNode) -> Self {
        self.device_identity_node = Some(node);
        self
    }

    #[must_use]
    pub fn has_additional_node(&self, tag: &str) -> bool {
        self.additional_nodes.iter().any(|node| node.tag == tag)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageRelay {
    pub message_id: String,
    pub node: BinaryNode,
    pub recipient_count: usize,
    pub should_include_device_identity: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageReceiptType {
    Delivery,
    Read,
    ReadSelf,
    HistorySync,
    PeerMessage,
    Sender,
    Inactive,
    Played,
}

impl MessageReceiptType {
    #[must_use]
    pub fn as_wire_type(self) -> Option<&'static str> {
        match self {
            Self::Delivery => None,
            Self::Read => Some("read"),
            Self::ReadSelf => Some("read-self"),
            Self::HistorySync => Some("hist_sync"),
            Self::PeerMessage => Some("peer_msg"),
            Self::Sender => Some("sender"),
            Self::Inactive => Some("inactive"),
            Self::Played => Some("played"),
        }
    }

    #[must_use]
    pub fn requires_timestamp(self) -> bool {
        matches!(self, Self::Read | Self::ReadSelf)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageReceipt {
    pub remote_jid: String,
    pub participant: Option<String>,
    pub message_ids: Vec<String>,
}

impl MessageReceipt {
    #[must_use]
    pub fn new<I, T>(remote_jid: impl Into<String>, participant: Option<String>, ids: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self {
            remote_jid: remote_jid.into(),
            participant,
            message_ids: ids.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryPayload {
    pub ciphertext: Bytes,
    pub iv: Bytes,
}

impl MediaRetryPayload {
    #[must_use]
    pub fn new(ciphertext: Bytes, iv: Bytes) -> Self {
        Self { ciphertext, iv }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryError {
    pub code: u16,
    pub text: Option<String>,
    pub status_code: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryUpdate {
    pub key: MessageKey,
    pub media: Option<MediaRetryPayload>,
    pub error: Option<MediaRetryError>,
}

pub fn build_text_message(text: impl Into<TextMessage>) -> CoreResult<Message> {
    let text = text.into();
    if text.text.is_empty() {
        return Err(CoreError::Payload(
            "text message must not be empty".to_owned(),
        ));
    }

    let mut extended = ExtendedTextMessage {
        text: Some(text.text),
        context_info: context_info(text.context)?,
        text_argb: text.text_argb,
        background_argb: text.background_argb,
        font: text.font.map(TextFont::as_proto_i32),
        ..ExtendedTextMessage::default()
    };
    if let Some(preview) = text.link_preview {
        apply_link_preview(&mut extended, preview)?;
    }

    Ok(Message {
        extended_text_message: Some(Box::new(extended)),
        ..Message::default()
    })
}

pub fn build_contact_message(contact: ContactContent) -> CoreResult<Message> {
    validate_non_empty("contact display name", &contact.display_name)?;
    validate_non_empty("contact vCard", &contact.vcard)?;
    Ok(Message {
        contact_message: Some(Box::new(ContactMessage {
            display_name: Some(contact.display_name),
            vcard: Some(contact.vcard),
            context_info: context_info(contact.context)?,
        })),
        ..Message::default()
    })
}

pub fn build_contacts_message(contacts: ContactsContent) -> CoreResult<Message> {
    validate_non_empty("contacts display name", &contacts.display_name)?;
    if contacts.contacts.is_empty() {
        return Err(CoreError::Payload(
            "contacts message requires at least one contact".to_owned(),
        ));
    }
    let contact_nodes = contacts
        .contacts
        .into_iter()
        .map(|contact| {
            validate_non_empty("contact display name", &contact.display_name)?;
            validate_non_empty("contact vCard", &contact.vcard)?;
            Ok(ContactMessage {
                display_name: Some(contact.display_name),
                vcard: Some(contact.vcard),
                context_info: None,
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(Message {
        contacts_array_message: Some(Box::new(ContactsArrayMessage {
            display_name: Some(contacts.display_name),
            contacts: contact_nodes,
            context_info: context_info(contacts.context)?,
        })),
        ..Message::default()
    })
}

pub fn build_location_message(location: LocationContent) -> CoreResult<Message> {
    validate_coordinates(location.latitude, location.longitude)?;
    Ok(Message {
        location_message: Some(Box::new(location_proto(location)?)),
        ..Message::default()
    })
}

pub fn build_live_location_message(location: LiveLocationContent) -> CoreResult<Message> {
    validate_coordinates(location.latitude, location.longitude)?;
    if let Some(speed) = location.speed_in_mps
        && (!speed.is_finite() || speed < 0.0)
    {
        return Err(CoreError::Payload(
            "live location speed must be finite and non-negative".to_owned(),
        ));
    }
    Ok(Message {
        live_location_message: Some(Box::new(LiveLocationMessage {
            degrees_latitude: Some(location.latitude),
            degrees_longitude: Some(location.longitude),
            accuracy_in_meters: location.accuracy_in_meters,
            speed_in_mps: location.speed_in_mps,
            degrees_clockwise_from_magnetic_north: location.degrees_clockwise_from_magnetic_north,
            caption: location.caption,
            sequence_number: location.sequence_number,
            time_offset: location.time_offset,
            jpeg_thumbnail: None,
            context_info: context_info(location.context)?,
        })),
        ..Message::default()
    })
}

pub fn build_reaction_message(reaction: ReactionContent) -> CoreResult<Message> {
    validate_message_key(&reaction.key)?;
    Ok(Message {
        reaction_message: Some(ReactionMessage {
            key: Some(reaction.key),
            text: Some(reaction.text),
            grouping_key: reaction.grouping_key,
            sender_timestamp_ms: reaction.sender_timestamp_ms,
        }),
        ..Message::default()
    })
}

pub fn build_poll_message(poll: PollContent) -> CoreResult<Message> {
    validate_non_empty("poll name", &poll.name)?;
    if poll.options.len() < 2 {
        return Err(CoreError::Payload(
            "poll requires at least two options".to_owned(),
        ));
    }
    if poll.message_secret.len() != 32 {
        return Err(CoreError::Payload(
            "poll message secret must be 32 bytes".to_owned(),
        ));
    }
    let option_count = u32::try_from(poll.options.len())
        .map_err(|_| CoreError::Payload("poll has too many options".to_owned()))?;
    if poll.selectable_options_count > option_count {
        return Err(CoreError::Payload(
            "poll selectable option count exceeds option count".to_owned(),
        ));
    }
    let mut seen_options = BTreeSet::new();
    let options = poll
        .options
        .into_iter()
        .map(|option| {
            validate_non_empty("poll option", &option)?;
            if !seen_options.insert(option.clone()) {
                return Err(CoreError::Payload("poll options must be unique".to_owned()));
            }
            Ok(poll_creation_message::Option {
                option_name: Some(option),
                option_hash: None,
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    let poll_message = PollCreationMessage {
        enc_key: None,
        name: Some(poll.name),
        options,
        selectable_options_count: Some(poll.selectable_options_count),
        context_info: context_info(poll.context)?,
        poll_content_type: None,
        poll_type: None,
        correct_answer: None,
    };
    let mut message = Message {
        message_context_info: Some(MessageContextInfo {
            message_secret: Some(poll.message_secret),
            ..MessageContextInfo::default()
        }),
        ..Message::default()
    };
    if poll.to_announcement_group {
        message.poll_creation_message_v2 = Some(Box::new(poll_message));
    } else if poll.selectable_options_count == 1 {
        message.poll_creation_message_v3 = Some(Box::new(poll_message));
    } else {
        message.poll_creation_message = Some(Box::new(poll_message));
    }
    Ok(message)
}

pub fn build_event_message(event: EventContent) -> CoreResult<Message> {
    validate_non_empty("event name", &event.name)?;
    if event.message_secret.len() != 32 {
        return Err(CoreError::Payload(
            "event message secret must be 32 bytes".to_owned(),
        ));
    }
    if let Some(end_time) = event.end_time
        && end_time < event.start_time
    {
        return Err(CoreError::Payload(
            "event end time must not be before start time".to_owned(),
        ));
    }
    validate_optional_non_empty("event join link", event.join_link.as_deref())?;
    Ok(Message {
        event_message: Some(Box::new(EventMessage {
            context_info: context_info(event.context)?,
            is_canceled: Some(event.is_canceled),
            name: Some(event.name),
            description: event.description,
            location: event
                .location
                .map(location_proto)
                .transpose()?
                .map(Box::new),
            join_link: event.join_link,
            start_time: Some(event.start_time),
            end_time: event.end_time,
            extra_guests_allowed: event.extra_guests_allowed,
            is_schedule_call: Some(event.is_schedule_call),
            has_reminder: None,
            reminder_offset_sec: None,
        })),
        message_context_info: Some(MessageContextInfo {
            message_secret: Some(event.message_secret),
            ..MessageContextInfo::default()
        }),
        ..Message::default()
    })
}

#[cfg(feature = "noise")]
pub fn build_encrypted_poll_update_content(vote: PollVoteContent) -> CoreResult<PollUpdateContent> {
    let iv: [u8; POLL_EVENT_ENCRYPTION_IV_LEN] = rand::random();
    build_encrypted_poll_update_content_with_iv(vote, Bytes::copy_from_slice(&iv))
}

#[cfg(feature = "noise")]
pub fn build_encrypted_poll_update_content_with_iv(
    vote: PollVoteContent,
    iv: impl Into<Bytes>,
) -> CoreResult<PollUpdateContent> {
    validate_message_key(&vote.poll_creation_message_key)?;
    validate_poll_event_message_secret("poll message secret", &vote.poll_message_secret)?;
    let mut selected_hashes = BTreeSet::new();
    for hash in &vote.selected_option_hashes {
        validate_bytes_len("selected poll option hash", hash, 32)?;
        if !selected_hashes.insert(hash.as_ref()) {
            return Err(CoreError::Payload(
                "selected poll option hashes must be unique".to_owned(),
            ));
        }
    }
    let poll_message_id = vote
        .poll_creation_message_key
        .id
        .as_deref()
        .ok_or_else(|| CoreError::Payload("poll creation message key missing id".to_owned()))?
        .to_owned();
    let poll_creator_jid = normalize_crypto_jid("poll creator JID", &vote.poll_creator_jid)?;
    let voter_jid = normalize_crypto_jid("poll voter JID", &vote.voter_jid)?;
    let iv = iv.into();
    validate_bytes_len("encrypted poll vote iv", &iv, POLL_EVENT_ENCRYPTION_IV_LEN)?;
    let plaintext = wa_proto::proto::message::PollVoteMessage {
        selected_options: vote.selected_option_hashes,
    };
    let encrypted_payload = encrypt_poll_event_payload(
        &prost::Message::encode_to_vec(&plaintext),
        &vote.poll_message_secret,
        &poll_message_id,
        &poll_creator_jid,
        &voter_jid,
        POLL_VOTE_CRYPTO_LABEL,
        &iv,
    )?;
    let mut update = PollUpdateContent::new(vote.poll_creation_message_key, encrypted_payload, iv);
    update.sender_timestamp_ms = vote.sender_timestamp_ms;
    update.include_metadata = vote.include_metadata;
    Ok(update)
}

#[cfg(feature = "noise")]
pub fn build_encrypted_poll_update_message(vote: PollVoteContent) -> CoreResult<Message> {
    build_poll_update_message(build_encrypted_poll_update_content(vote)?)
}

#[cfg(feature = "noise")]
pub fn build_encrypted_poll_update_message_with_iv(
    vote: PollVoteContent,
    iv: impl Into<Bytes>,
) -> CoreResult<Message> {
    build_poll_update_message(build_encrypted_poll_update_content_with_iv(vote, iv)?)
}

pub fn build_poll_update_message(update: PollUpdateContent) -> CoreResult<Message> {
    validate_message_key(&update.poll_creation_message_key)?;
    validate_non_empty_bytes("encrypted poll vote payload", &update.encrypted_payload)?;
    validate_non_empty_bytes("encrypted poll vote iv", &update.encrypted_iv)?;
    Ok(Message {
        poll_update_message: Some(PollUpdateMessage {
            poll_creation_message_key: Some(update.poll_creation_message_key),
            vote: Some(PollEncValue {
                enc_payload: Some(update.encrypted_payload),
                enc_iv: Some(update.encrypted_iv),
            }),
            metadata: update
                .include_metadata
                .then_some(PollUpdateMessageMetadata {}),
            sender_timestamp_ms: update.sender_timestamp_ms,
        }),
        ..Message::default()
    })
}

#[cfg(feature = "noise")]
pub fn build_encrypted_event_response_content(
    response: EventResponsePayload,
) -> CoreResult<EventResponseContent> {
    let iv: [u8; POLL_EVENT_ENCRYPTION_IV_LEN] = rand::random();
    build_encrypted_event_response_content_with_iv(response, Bytes::copy_from_slice(&iv))
}

#[cfg(feature = "noise")]
pub fn build_encrypted_event_response_content_with_iv(
    response: EventResponsePayload,
    iv: impl Into<Bytes>,
) -> CoreResult<EventResponseContent> {
    validate_message_key(&response.event_creation_message_key)?;
    validate_poll_event_message_secret("event message secret", &response.event_message_secret)?;
    let event_message_id = response
        .event_creation_message_key
        .id
        .as_deref()
        .ok_or_else(|| CoreError::Payload("event creation message key missing id".to_owned()))?
        .to_owned();
    let event_creator_jid = normalize_crypto_jid("event creator JID", &response.event_creator_jid)?;
    let responder_jid = normalize_crypto_jid("event responder JID", &response.responder_jid)?;
    let iv = iv.into();
    validate_bytes_len(
        "encrypted event response iv",
        &iv,
        POLL_EVENT_ENCRYPTION_IV_LEN,
    )?;
    if let Some(extra_guest_count) = response.extra_guest_count
        && extra_guest_count < 0
    {
        return Err(CoreError::Payload(
            "event response extra guest count must not be negative".to_owned(),
        ));
    }
    let plaintext = wa_proto::proto::message::EventResponseMessage {
        response: Some(response.response.as_proto_i32()),
        timestamp_ms: response.timestamp_ms,
        extra_guest_count: response.extra_guest_count,
    };
    let encrypted_payload = encrypt_poll_event_payload(
        &prost::Message::encode_to_vec(&plaintext),
        &response.event_message_secret,
        &event_message_id,
        &event_creator_jid,
        &responder_jid,
        EVENT_RESPONSE_CRYPTO_LABEL,
        &iv,
    )?;
    Ok(EventResponseContent::new(
        response.event_creation_message_key,
        encrypted_payload,
        iv,
    ))
}

#[cfg(feature = "noise")]
pub fn build_encrypted_event_response_message(
    response: EventResponsePayload,
) -> CoreResult<Message> {
    build_event_response_message(build_encrypted_event_response_content(response)?)
}

#[cfg(feature = "noise")]
pub fn build_encrypted_event_response_message_with_iv(
    response: EventResponsePayload,
    iv: impl Into<Bytes>,
) -> CoreResult<Message> {
    build_event_response_message(build_encrypted_event_response_content_with_iv(
        response, iv,
    )?)
}

pub fn build_event_response_message(response: EventResponseContent) -> CoreResult<Message> {
    validate_message_key(&response.event_creation_message_key)?;
    validate_non_empty_bytes(
        "encrypted event response payload",
        &response.encrypted_payload,
    )?;
    validate_non_empty_bytes("encrypted event response iv", &response.encrypted_iv)?;
    Ok(Message {
        enc_event_response_message: Some(EncEventResponseMessage {
            event_creation_message_key: Some(response.event_creation_message_key),
            enc_payload: Some(response.encrypted_payload),
            enc_iv: Some(response.encrypted_iv),
        }),
        ..Message::default()
    })
}

#[cfg(feature = "noise")]
pub fn decrypt_poll_vote_message(
    encrypted_vote: &PollEncValue,
    poll_message_id: &str,
    poll_creator_jid: &str,
    voter_jid: &str,
    poll_message_secret: &[u8],
) -> CoreResult<wa_proto::proto::message::PollVoteMessage> {
    let enc_payload = encrypted_vote
        .enc_payload
        .as_ref()
        .ok_or_else(|| CoreError::Payload("encrypted poll vote missing payload".to_owned()))?;
    let enc_iv = encrypted_vote
        .enc_iv
        .as_ref()
        .ok_or_else(|| CoreError::Payload("encrypted poll vote missing iv".to_owned()))?;
    validate_non_empty("poll message id", poll_message_id)?;
    validate_poll_event_message_secret("poll message secret", poll_message_secret)?;
    validate_bytes_len(
        "encrypted poll vote iv",
        enc_iv,
        POLL_EVENT_ENCRYPTION_IV_LEN,
    )?;
    let poll_creator_jid = normalize_crypto_jid("poll creator JID", poll_creator_jid)?;
    let voter_jid = normalize_crypto_jid("poll voter JID", voter_jid)?;
    let decrypted = decrypt_poll_event_payload(
        enc_payload,
        poll_message_secret,
        poll_message_id,
        &poll_creator_jid,
        &voter_jid,
        POLL_VOTE_CRYPTO_LABEL,
        enc_iv,
    )?;
    <wa_proto::proto::message::PollVoteMessage as prost::Message>::decode(decrypted.as_slice())
        .map_err(CoreError::from)
}

#[cfg(feature = "noise")]
pub fn decrypt_event_response_message(
    encrypted_response: &EncEventResponseMessage,
    event_message_id: &str,
    event_creator_jid: &str,
    responder_jid: &str,
    event_message_secret: &[u8],
) -> CoreResult<wa_proto::proto::message::EventResponseMessage> {
    let enc_payload = encrypted_response
        .enc_payload
        .as_ref()
        .ok_or_else(|| CoreError::Payload("encrypted event response missing payload".to_owned()))?;
    let enc_iv = encrypted_response
        .enc_iv
        .as_ref()
        .ok_or_else(|| CoreError::Payload("encrypted event response missing iv".to_owned()))?;
    validate_non_empty("event message id", event_message_id)?;
    validate_poll_event_message_secret("event message secret", event_message_secret)?;
    validate_bytes_len(
        "encrypted event response iv",
        enc_iv,
        POLL_EVENT_ENCRYPTION_IV_LEN,
    )?;
    let event_creator_jid = normalize_crypto_jid("event creator JID", event_creator_jid)?;
    let responder_jid = normalize_crypto_jid("event responder JID", responder_jid)?;
    let decrypted = decrypt_poll_event_payload(
        enc_payload,
        event_message_secret,
        event_message_id,
        &event_creator_jid,
        &responder_jid,
        EVENT_RESPONSE_CRYPTO_LABEL,
        enc_iv,
    )?;
    <wa_proto::proto::message::EventResponseMessage as prost::Message>::decode(decrypted.as_slice())
        .map_err(CoreError::from)
}

pub fn build_edit_message(edit: EditContent) -> CoreResult<Message> {
    validate_message_key(&edit.key)?;
    Ok(Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            key: Some(edit.key),
            r#type: Some(protocol_message::Type::MessageEdit as i32),
            edited_message: Some(Box::new(edit.message)),
            timestamp_ms: edit.timestamp_ms,
            ..ProtocolMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_delete_message(delete: DeleteContent) -> CoreResult<Message> {
    validate_message_key(&delete.key)?;
    Ok(Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            key: Some(delete.key),
            r#type: Some(protocol_message::Type::Revoke as i32),
            ..ProtocolMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_placeholder_resend_request_message<I>(keys: I) -> CoreResult<Message>
where
    I: IntoIterator<Item = MessageKey>,
{
    let requests = keys
        .into_iter()
        .map(|key| {
            validate_message_key(&key)?;
            Ok(
                peer_data_operation_request_message::PlaceholderMessageResendRequest {
                    message_key: Some(key),
                },
            )
        })
        .collect::<CoreResult<Vec<_>>>()?;
    if requests.is_empty() {
        return Err(CoreError::Payload(
            "placeholder resend request requires at least one message key".to_owned(),
        ));
    }

    Ok(Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            r#type: Some(protocol_message::Type::PeerDataOperationRequestMessage as i32),
            peer_data_operation_request_message: Some(PeerDataOperationRequestMessage {
                peer_data_operation_request_type: Some(
                    PeerDataOperationRequestType::PlaceholderMessageResend as i32,
                ),
                placeholder_message_resend_request: requests,
                ..PeerDataOperationRequestMessage::default()
            }),
            ..ProtocolMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_pin_message(pin: PinContent) -> CoreResult<Message> {
    validate_message_key(&pin.key)?;
    let pin_type = match pin.action {
        PinAction::Pin => pin_in_chat_message::Type::PinForAll,
        PinAction::Unpin => pin_in_chat_message::Type::UnpinForAll,
    };
    Ok(Message {
        pin_in_chat_message: Some(PinInChatMessage {
            key: Some(pin.key),
            r#type: Some(pin_type as i32),
            sender_timestamp_ms: pin.sender_timestamp_ms,
        }),
        ..Message::default()
    })
}

pub fn build_disappearing_mode_message(content: DisappearingModeContent) -> CoreResult<Message> {
    if let Some(jid) = content.initiator_device_jid.as_deref()
        && jid_decode(jid).is_none()
    {
        return Err(CoreError::Payload(format!(
            "invalid initiator device JID for disappearing mode: {jid}"
        )));
    }
    let message = Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            r#type: Some(protocol_message::Type::EphemeralSetting as i32),
            ephemeral_expiration: Some(content.ephemeral_expiration),
            ephemeral_setting_timestamp: content.ephemeral_setting_timestamp,
            disappearing_mode: Some(DisappearingMode {
                initiator: Some(disappearing_mode::Initiator::InitiatedByMe as i32),
                trigger: Some(disappearing_mode::Trigger::ChatSetting as i32),
                initiator_device_jid: content.initiator_device_jid,
                initiated_by_me: Some(true),
            }),
            ..ProtocolMessage::default()
        })),
        ..Message::default()
    };
    Ok(Message {
        ephemeral_message: Some(Box::new(wrap_future_proof_message(message))),
        ..Message::default()
    })
}

pub fn build_view_once_message(content: MessageContent) -> CoreResult<Message> {
    let message = content.into_proto()?;
    Ok(Message {
        view_once_message: Some(Box::new(wrap_future_proof_message(message))),
        ..Message::default()
    })
}

fn wrap_future_proof_message(message: Message) -> FutureProofMessage {
    FutureProofMessage {
        message: Some(Box::new(message)),
    }
}

pub fn build_image_message(image: ImageContent) -> CoreResult<Message> {
    validate_uploaded_media(&image.media)?;
    validate_non_empty("image mimetype", &image.mimetype)?;
    Ok(Message {
        image_message: Some(Box::new(ImageMessage {
            url: image.media.url,
            mimetype: Some(image.mimetype),
            caption: image.caption,
            file_sha256: Some(image.media.file_sha256),
            file_length: Some(image.media.file_length),
            height: image.height,
            width: image.width,
            media_key: Some(image.media.media_key),
            file_enc_sha256: Some(image.media.file_enc_sha256),
            direct_path: image.media.direct_path,
            media_key_timestamp: image.media.media_key_timestamp,
            jpeg_thumbnail: image.jpeg_thumbnail,
            context_info: context_info(image.context)?,
            view_once: flag(image.view_once),
            ..ImageMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_video_message(video: VideoContent) -> CoreResult<Message> {
    Ok(Message {
        video_message: Some(Box::new(video_message_proto(video)?)),
        ..Message::default()
    })
}

pub fn build_ptv_message(video: VideoContent) -> CoreResult<Message> {
    Ok(Message {
        ptv_message: Some(Box::new(video_message_proto(video)?)),
        ..Message::default()
    })
}

fn video_message_proto(video: VideoContent) -> CoreResult<VideoMessage> {
    validate_uploaded_media(&video.media)?;
    validate_non_empty("video mimetype", &video.mimetype)?;
    let remote_thumbnail = video
        .remote_thumbnail
        .map(validate_remote_media_thumbnail)
        .transpose()?;
    Ok(VideoMessage {
        url: video.media.url,
        mimetype: Some(video.mimetype),
        file_sha256: Some(video.media.file_sha256),
        file_length: Some(video.media.file_length),
        seconds: video.seconds,
        media_key: Some(video.media.media_key),
        caption: video.caption,
        gif_playback: flag(video.gif_playback),
        height: video.height,
        width: video.width,
        file_enc_sha256: Some(video.media.file_enc_sha256),
        direct_path: video.media.direct_path,
        media_key_timestamp: video.media.media_key_timestamp,
        jpeg_thumbnail: video.jpeg_thumbnail,
        context_info: context_info(video.context)?,
        streaming_sidecar: video.streaming_sidecar,
        view_once: flag(video.view_once),
        thumbnail_direct_path: remote_thumbnail
            .as_ref()
            .map(|thumbnail| thumbnail.direct_path.clone()),
        thumbnail_sha256: remote_thumbnail
            .as_ref()
            .map(|thumbnail| thumbnail.sha256.clone()),
        thumbnail_enc_sha256: remote_thumbnail.map(|thumbnail| thumbnail.enc_sha256),
        ..VideoMessage::default()
    })
}

pub fn build_audio_message(audio: AudioContent) -> CoreResult<Message> {
    validate_uploaded_media(&audio.media)?;
    validate_non_empty("audio mimetype", &audio.mimetype)?;
    Ok(Message {
        audio_message: Some(Box::new(AudioMessage {
            url: audio.media.url,
            mimetype: Some(audio.mimetype),
            file_sha256: Some(audio.media.file_sha256),
            file_length: Some(audio.media.file_length),
            seconds: audio.seconds,
            ptt: flag(audio.ptt),
            media_key: Some(audio.media.media_key),
            file_enc_sha256: Some(audio.media.file_enc_sha256),
            direct_path: audio.media.direct_path,
            media_key_timestamp: audio.media.media_key_timestamp,
            context_info: context_info(audio.context)?,
            streaming_sidecar: audio.streaming_sidecar,
            waveform: audio.waveform,
            background_argb: audio.background_argb,
            ..AudioMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_document_message(document: DocumentContent) -> CoreResult<Message> {
    validate_uploaded_media(&document.media)?;
    validate_non_empty("document mimetype", &document.mimetype)?;
    let remote_thumbnail = document
        .remote_thumbnail
        .map(validate_remote_media_thumbnail)
        .transpose()?;
    Ok(Message {
        document_message: Some(Box::new(DocumentMessage {
            url: document.media.url,
            mimetype: Some(document.mimetype),
            title: document.title,
            file_sha256: Some(document.media.file_sha256),
            file_length: Some(document.media.file_length),
            page_count: document.page_count,
            media_key: Some(document.media.media_key),
            file_name: document.file_name,
            file_enc_sha256: Some(document.media.file_enc_sha256),
            direct_path: document.media.direct_path,
            media_key_timestamp: document.media.media_key_timestamp,
            jpeg_thumbnail: document.jpeg_thumbnail,
            thumbnail_direct_path: remote_thumbnail
                .as_ref()
                .map(|thumbnail| thumbnail.direct_path.clone()),
            thumbnail_sha256: remote_thumbnail
                .as_ref()
                .map(|thumbnail| thumbnail.sha256.clone()),
            thumbnail_enc_sha256: remote_thumbnail
                .as_ref()
                .map(|thumbnail| thumbnail.enc_sha256.clone()),
            thumbnail_height: document.thumbnail_height.or_else(|| {
                remote_thumbnail
                    .as_ref()
                    .and_then(|thumbnail| thumbnail.height)
            }),
            thumbnail_width: document.thumbnail_width.or_else(|| {
                remote_thumbnail
                    .as_ref()
                    .and_then(|thumbnail| thumbnail.width)
            }),
            context_info: context_info(document.context)?,
            caption: document.caption,
            ..DocumentMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_sticker_message(sticker: StickerContent) -> CoreResult<Message> {
    validate_uploaded_media(&sticker.media)?;
    validate_non_empty("sticker mimetype", &sticker.mimetype)?;
    Ok(Message {
        sticker_message: Some(Box::new(StickerMessage {
            url: sticker.media.url,
            file_sha256: Some(sticker.media.file_sha256),
            file_enc_sha256: Some(sticker.media.file_enc_sha256),
            media_key: Some(sticker.media.media_key),
            mimetype: Some(sticker.mimetype),
            height: sticker.height,
            width: sticker.width,
            direct_path: sticker.media.direct_path,
            file_length: Some(sticker.media.file_length),
            media_key_timestamp: sticker.media.media_key_timestamp,
            is_animated: flag(sticker.is_animated),
            png_thumbnail: sticker.png_thumbnail,
            context_info: context_info(sticker.context)?,
            ..StickerMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_group_invite_message(invite: GroupInviteContent) -> CoreResult<Message> {
    let decoded = jid_decode(&invite.group_jid).ok_or_else(|| {
        CoreError::Payload(format!(
            "invalid group JID for group invite: {}",
            invite.group_jid
        ))
    })?;
    if decoded.server != JidServer::GUs {
        return Err(CoreError::Payload(format!(
            "group invite JID must use group domain: {}",
            invite.group_jid
        )));
    }
    validate_non_empty("group invite code", &invite.invite_code)?;
    validate_non_empty("group name", &invite.group_name)?;
    if invite.invite_expiration < 0 {
        return Err(CoreError::Payload(
            "group invite expiration must not be negative".to_owned(),
        ));
    }

    let group_type = match invite.kind {
        GroupInviteKind::Default => group_invite_message::GroupType::Default,
        GroupInviteKind::Parent => group_invite_message::GroupType::Parent,
    };

    Ok(Message {
        group_invite_message: Some(Box::new(GroupInviteMessage {
            group_jid: Some(invite.group_jid),
            invite_code: Some(invite.invite_code),
            invite_expiration: Some(invite.invite_expiration),
            group_name: Some(invite.group_name),
            jpeg_thumbnail: invite.jpeg_thumbnail,
            caption: invite.caption,
            context_info: context_info(invite.context)?,
            group_type: Some(group_type as i32),
        })),
        ..Message::default()
    })
}

pub fn build_product_message(product: ProductContent) -> CoreResult<Message> {
    let owner = jid_decode(&product.business_owner_jid).ok_or_else(|| {
        CoreError::Payload(format!(
            "invalid business owner JID for product message: {}",
            product.business_owner_jid
        ))
    })?;
    if matches!(owner.server, JidServer::GUs | JidServer::Broadcast) {
        return Err(CoreError::Payload(format!(
            "business owner JID must be a user JID: {}",
            product.business_owner_jid
        )));
    }

    Ok(Message {
        product_message: Some(Box::new(ProductMessage {
            product: Some(Box::new(product_snapshot_proto(product.product)?)),
            business_owner_jid: Some(product.business_owner_jid),
            catalog: product
                .catalog
                .map(catalog_snapshot_proto)
                .transpose()?
                .map(Box::new),
            body: product.body,
            footer: product.footer,
            context_info: context_info(product.context)?,
        })),
        ..Message::default()
    })
}

pub fn build_album_message(album: AlbumContent) -> CoreResult<Message> {
    if album.expected_image_count == 0 && album.expected_video_count == 0 {
        return Err(CoreError::Payload(
            "album message must expect at least one image or video".to_owned(),
        ));
    }
    Ok(Message {
        album_message: Some(Box::new(AlbumMessage {
            expected_image_count: Some(album.expected_image_count),
            expected_video_count: Some(album.expected_video_count),
            context_info: context_info(album.context)?,
        })),
        ..Message::default()
    })
}

pub fn build_request_phone_number_message(
    content: RequestPhoneNumberContent,
) -> CoreResult<Message> {
    Ok(Message {
        request_phone_number_message: Some(Box::new(RequestPhoneNumberMessage {
            context_info: context_info(content.context)?,
        })),
        ..Message::default()
    })
}

pub fn build_share_phone_number_message() -> CoreResult<Message> {
    Ok(Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            r#type: Some(protocol_message::Type::SharePhoneNumber as i32),
            ..ProtocolMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_limit_sharing_message(content: LimitSharingContent) -> CoreResult<Message> {
    Ok(Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            r#type: Some(protocol_message::Type::LimitSharing as i32),
            limit_sharing: Some(LimitSharing {
                sharing_limited: Some(content.sharing_limited),
                trigger: Some(content.trigger.as_proto_i32()),
                limit_sharing_setting_timestamp: content.setting_timestamp_ms,
                initiated_by_me: Some(content.initiated_by_me),
            }),
            ..ProtocolMessage::default()
        })),
        ..Message::default()
    })
}

pub fn build_button_reply_message(content: ButtonReplyContent) -> CoreResult<Message> {
    validate_non_empty("selected button id", &content.selected_button_id)?;
    validate_non_empty(
        "selected button display text",
        &content.selected_display_text,
    )?;
    Ok(Message {
        buttons_response_message: Some(Box::new(ButtonsResponseMessage {
            selected_button_id: Some(content.selected_button_id),
            context_info: context_info(content.context)?,
            r#type: Some(buttons_response_message::Type::DisplayText as i32),
            response: Some(buttons_response_message::Response::SelectedDisplayText(
                content.selected_display_text,
            )),
        })),
        ..Message::default()
    })
}

pub fn build_template_button_reply_message(
    content: TemplateButtonReplyContent,
) -> CoreResult<Message> {
    validate_non_empty("selected template button id", &content.selected_id)?;
    validate_non_empty(
        "selected template button display text",
        &content.selected_display_text,
    )?;
    Ok(Message {
        template_button_reply_message: Some(Box::new(TemplateButtonReplyMessage {
            selected_id: Some(content.selected_id),
            selected_display_text: Some(content.selected_display_text),
            context_info: context_info(content.context)?,
            selected_index: content.selected_index,
            selected_carousel_card_index: content.selected_carousel_card_index,
        })),
        ..Message::default()
    })
}

pub fn build_list_reply_message(content: ListReplyContent) -> CoreResult<Message> {
    validate_non_empty("list reply title", &content.title)?;
    validate_non_empty("selected list row id", &content.selected_row_id)?;
    validate_optional_non_empty("list reply description", content.description.as_deref())?;
    Ok(Message {
        list_response_message: Some(Box::new(ListResponseMessage {
            title: Some(content.title),
            list_type: Some(list_response_message::ListType::SingleSelect as i32),
            single_select_reply: Some(list_response_message::SingleSelectReply {
                selected_row_id: Some(content.selected_row_id),
            }),
            context_info: context_info(content.context)?,
            description: content.description,
        })),
        ..Message::default()
    })
}

pub fn build_sender_key_distribution_message(
    content: SenderKeyDistributionContent,
) -> CoreResult<Message> {
    let decoded = jid_decode(&content.group_id).ok_or_else(|| {
        CoreError::Payload(format!(
            "invalid sender-key distribution group JID: {}",
            content.group_id
        ))
    })?;
    if decoded.server != JidServer::GUs {
        return Err(CoreError::Payload(format!(
            "sender-key distribution group must use group server: {}",
            content.group_id
        )));
    }
    if content.distribution.is_empty() {
        return Err(CoreError::Payload(
            "sender-key distribution payload must not be empty".to_owned(),
        ));
    }
    Ok(Message {
        sender_key_distribution_message: Some(ProtoSenderKeyDistributionMessage {
            group_id: Some(content.group_id),
            axolotl_sender_key_distribution_message: Some(content.distribution),
        }),
        ..Message::default()
    })
}

fn product_snapshot_proto(
    product: ProductSnapshotContent,
) -> CoreResult<product_message::ProductSnapshot> {
    validate_non_empty("product id", &product.product_id)?;
    validate_non_empty("product title", &product.title)?;
    validate_non_empty("product currency code", &product.currency_code)?;
    if product.price_amount1000 < 0 {
        return Err(CoreError::Payload(
            "product price must not be negative".to_owned(),
        ));
    }
    if let Some(sale_price) = product.sale_price_amount1000
        && sale_price < 0
    {
        return Err(CoreError::Payload(
            "product sale price must not be negative".to_owned(),
        ));
    }
    validate_optional_non_empty("product retailer id", product.retailer_id.as_deref())?;
    validate_optional_non_empty("product URL", product.url.as_deref())?;
    validate_optional_non_empty("product first image id", product.first_image_id.as_deref())?;
    validate_optional_non_empty("product signed URL", product.signed_url.as_deref())?;

    Ok(product_message::ProductSnapshot {
        product_image: product.product_image.map(image_message_proto).transpose()?,
        product_id: Some(product.product_id),
        title: Some(product.title),
        description: product.description,
        currency_code: Some(product.currency_code),
        price_amount1000: Some(product.price_amount1000),
        retailer_id: product.retailer_id,
        url: product.url,
        product_image_count: product.product_image_count,
        first_image_id: product.first_image_id,
        sale_price_amount1000: product.sale_price_amount1000,
        signed_url: product.signed_url,
    })
}

fn catalog_snapshot_proto(
    catalog: CatalogSnapshotContent,
) -> CoreResult<product_message::CatalogSnapshot> {
    validate_optional_non_empty("catalog title", catalog.title.as_deref())?;
    validate_optional_non_empty("catalog description", catalog.description.as_deref())?;
    Ok(product_message::CatalogSnapshot {
        catalog_image: catalog.catalog_image.map(image_message_proto).transpose()?,
        title: catalog.title,
        description: catalog.description,
    })
}

fn image_message_proto(image: ImageContent) -> CoreResult<Box<ImageMessage>> {
    build_image_message(image)?.image_message.ok_or_else(|| {
        CoreError::Payload("image content did not produce an image message".to_owned())
    })
}

fn apply_link_preview(
    extended: &mut ExtendedTextMessage,
    preview: LinkPreviewContent,
) -> CoreResult<()> {
    validate_non_empty("link preview matched text", &preview.matched_text)?;
    validate_non_empty("link preview title", &preview.title)?;
    validate_optional_non_empty("link preview description", preview.description.as_deref())?;
    if let Some(thumbnail) = preview.jpeg_thumbnail.as_ref()
        && thumbnail.is_empty()
    {
        return Err(CoreError::Payload(
            "link preview JPEG thumbnail must not be empty".to_owned(),
        ));
    }

    extended.matched_text = Some(preview.matched_text);
    extended.title = Some(preview.title);
    extended.description = preview.description;
    extended.jpeg_thumbnail = preview.jpeg_thumbnail;
    extended.preview_type = Some(extended_text_message::PreviewType::None as i32);

    if let Some(thumbnail) = preview.high_quality_thumbnail {
        apply_link_preview_thumbnail(extended, thumbnail)?;
    }
    Ok(())
}

fn apply_link_preview_thumbnail(
    extended: &mut ExtendedTextMessage,
    thumbnail: LinkPreviewThumbnail,
) -> CoreResult<()> {
    validate_non_empty("link preview thumbnail direct path", &thumbnail.direct_path)?;
    validate_bytes_len("link preview thumbnail media key", &thumbnail.media_key, 32)?;
    validate_bytes_len("link preview thumbnail SHA-256", &thumbnail.sha256, 32)?;
    validate_bytes_len(
        "encrypted link preview thumbnail SHA-256",
        &thumbnail.enc_sha256,
        32,
    )?;
    validate_optional_non_zero("link preview thumbnail width", thumbnail.width)?;
    validate_optional_non_zero("link preview thumbnail height", thumbnail.height)?;

    extended.thumbnail_direct_path = Some(thumbnail.direct_path);
    extended.media_key = Some(thumbnail.media_key);
    extended.media_key_timestamp = thumbnail.media_key_timestamp;
    extended.thumbnail_width = thumbnail.width;
    extended.thumbnail_height = thumbnail.height;
    extended.thumbnail_sha256 = Some(thumbnail.sha256);
    extended.thumbnail_enc_sha256 = Some(thumbnail.enc_sha256);
    Ok(())
}

fn context_info(context: MessageContext) -> CoreResult<Option<Box<ContextInfo>>> {
    if context.mentioned_jids.is_empty()
        && context.quoted.is_none()
        && context.forwarding_score.is_none()
        && !context.is_forwarded
        && context.expiration.is_none()
    {
        return Ok(None);
    }

    for jid in &context.mentioned_jids {
        if jid_decode(jid).is_none() {
            return Err(CoreError::Payload(format!(
                "invalid mentioned JID in message context: {jid}"
            )));
        }
    }

    let quoted = context.quoted.map(validate_quoted_message).transpose()?;
    Ok(Some(Box::new(ContextInfo {
        stanza_id: quoted.as_ref().map(|quoted| quoted.stanza_id.clone()),
        participant: quoted
            .as_ref()
            .and_then(|quoted| quoted.participant.clone()),
        quoted_message: quoted
            .as_ref()
            .map(|quoted| Box::new(quoted.message.clone())),
        remote_jid: quoted.map(|quoted| quoted.remote_jid),
        mentioned_jid: context.mentioned_jids,
        forwarding_score: context.forwarding_score,
        is_forwarded: if context.is_forwarded {
            Some(true)
        } else {
            None
        },
        expiration: context.expiration,
        ..ContextInfo::default()
    })))
}

fn validate_quoted_message(quoted: QuotedMessage) -> CoreResult<QuotedMessage> {
    if jid_decode(&quoted.remote_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid quoted remote JID: {}",
            quoted.remote_jid
        )));
    }
    if let Some(participant) = quoted.participant.as_deref()
        && jid_decode(participant).is_none()
    {
        return Err(CoreError::Payload(format!(
            "invalid quoted participant JID: {participant}"
        )));
    }
    validate_non_empty("quoted stanza id", &quoted.stanza_id)?;
    Ok(quoted)
}

fn location_proto(location: LocationContent) -> CoreResult<LocationMessage> {
    validate_coordinates(location.latitude, location.longitude)?;
    Ok(LocationMessage {
        degrees_latitude: Some(location.latitude),
        degrees_longitude: Some(location.longitude),
        name: location.name,
        address: location.address,
        url: location.url,
        is_live: None,
        accuracy_in_meters: None,
        speed_in_mps: None,
        degrees_clockwise_from_magnetic_north: None,
        comment: None,
        jpeg_thumbnail: None,
        context_info: context_info(location.context)?,
    })
}

fn validate_message_key(key: &MessageKey) -> CoreResult<()> {
    let remote_jid = key
        .remote_jid
        .as_deref()
        .ok_or_else(|| CoreError::Payload("message key missing remote JID".to_owned()))?;
    if jid_decode(remote_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid message key remote JID: {remote_jid}"
        )));
    }
    if key.id.as_deref().is_none_or(str::is_empty) {
        return Err(CoreError::Payload("message key missing id".to_owned()));
    }
    if let Some(participant) = key.participant.as_deref()
        && jid_decode(participant).is_none()
    {
        return Err(CoreError::Payload(format!(
            "invalid message key participant JID: {participant}"
        )));
    }
    Ok(())
}

fn validate_coordinates(latitude: f64, longitude: f64) -> CoreResult<()> {
    if !latitude.is_finite() || !(-90.0..=90.0).contains(&latitude) {
        return Err(CoreError::Payload(
            "latitude must be finite and between -90 and 90".to_owned(),
        ));
    }
    if !longitude.is_finite() || !(-180.0..=180.0).contains(&longitude) {
        return Err(CoreError::Payload(
            "longitude must be finite and between -180 and 180".to_owned(),
        ));
    }
    Ok(())
}

fn validate_uploaded_media(media: &UploadedMedia) -> CoreResult<()> {
    if media.url.as_deref().is_none_or(str::is_empty)
        && media.direct_path.as_deref().is_none_or(str::is_empty)
    {
        return Err(CoreError::Payload(
            "uploaded media requires a URL or direct path".to_owned(),
        ));
    }
    if let Some(url) = media.url.as_deref() {
        validate_non_empty("media URL", url)?;
    }
    if let Some(direct_path) = media.direct_path.as_deref() {
        validate_non_empty("media direct path", direct_path)?;
    }
    if media.file_length == 0 {
        return Err(CoreError::Payload(
            "uploaded media file length must be greater than zero".to_owned(),
        ));
    }
    validate_bytes_len("media key", &media.media_key, 32)?;
    validate_bytes_len("media file SHA-256", &media.file_sha256, 32)?;
    validate_bytes_len("encrypted media file SHA-256", &media.file_enc_sha256, 32)?;
    Ok(())
}

fn validate_remote_media_thumbnail(
    thumbnail: RemoteMediaThumbnail,
) -> CoreResult<RemoteMediaThumbnail> {
    validate_non_empty("remote media thumbnail direct path", &thumbnail.direct_path)?;
    validate_bytes_len("remote media thumbnail SHA-256", &thumbnail.sha256, 32)?;
    validate_bytes_len(
        "encrypted remote media thumbnail SHA-256",
        &thumbnail.enc_sha256,
        32,
    )?;
    validate_optional_non_zero("remote media thumbnail width", thumbnail.width)?;
    validate_optional_non_zero("remote media thumbnail height", thumbnail.height)?;
    Ok(thumbnail)
}

fn validate_media_retry_payload(payload: &MediaRetryPayload) -> CoreResult<()> {
    if payload.ciphertext.is_empty() {
        return Err(CoreError::Payload(
            "media retry ciphertext must not be empty".to_owned(),
        ));
    }
    validate_bytes_len("media retry iv", &payload.iv, 12)
}

fn validate_bytes_len(label: &str, value: &Bytes, expected: usize) -> CoreResult<()> {
    if value.len() != expected {
        return Err(CoreError::Payload(format!(
            "{label} must be {expected} bytes"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn validate_poll_event_message_secret(label: &str, value: &[u8]) -> CoreResult<()> {
    if value.len() != 32 {
        return Err(CoreError::Payload(format!("{label} must be 32 bytes")));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn normalize_crypto_jid(label: &str, jid: &str) -> CoreResult<String> {
    jid_normalized_user(jid).ok_or_else(|| CoreError::Payload(format!("invalid {label}: {jid}")))
}

#[cfg(feature = "noise")]
fn encrypt_poll_event_payload(
    plaintext: &[u8],
    message_secret: &[u8],
    message_id: &str,
    creator_jid: &str,
    actor_jid: &str,
    label: &str,
    iv: &[u8],
) -> CoreResult<Bytes> {
    let mut key =
        derive_poll_event_content_key(message_secret, message_id, creator_jid, actor_jid, label)?;
    let aad = poll_event_additional_data(message_id, actor_jid);
    let encrypted = wa_crypto::aes_256_gcm_encrypt(plaintext, &key, iv, &aad);
    key.zeroize();
    encrypted.map(Bytes::from).map_err(CoreError::Crypto)
}

#[cfg(feature = "noise")]
fn decrypt_poll_event_payload(
    encrypted_payload: &[u8],
    message_secret: &[u8],
    message_id: &str,
    creator_jid: &str,
    actor_jid: &str,
    label: &str,
    iv: &[u8],
) -> CoreResult<Vec<u8>> {
    let mut key =
        derive_poll_event_content_key(message_secret, message_id, creator_jid, actor_jid, label)?;
    let aad = poll_event_additional_data(message_id, actor_jid);
    let decrypted = wa_crypto::aes_256_gcm_decrypt(encrypted_payload, &key, iv, &aad);
    key.zeroize();
    decrypted.map_err(CoreError::Crypto)
}

#[cfg(feature = "noise")]
fn derive_poll_event_content_key(
    message_secret: &[u8],
    message_id: &str,
    creator_jid: &str,
    actor_jid: &str,
    label: &str,
) -> CoreResult<[u8; 32]> {
    validate_poll_event_message_secret("message secret", message_secret)?;
    validate_non_empty("message id", message_id)?;
    validate_non_empty("creator JID", creator_jid)?;
    validate_non_empty("actor JID", actor_jid)?;
    let zero_key = [0u8; 32];
    let mut key0 = wa_crypto::hmac_sha256(message_secret, &zero_key).map_err(CoreError::Crypto)?;
    let mut sign = Vec::with_capacity(
        message_id.len() + creator_jid.len() + actor_jid.len() + label.len() + 1,
    );
    sign.extend_from_slice(message_id.as_bytes());
    sign.extend_from_slice(creator_jid.as_bytes());
    sign.extend_from_slice(actor_jid.as_bytes());
    sign.extend_from_slice(label.as_bytes());
    sign.push(1);
    let derived = wa_crypto::hmac_sha256(&sign, &key0).map_err(CoreError::Crypto);
    key0.zeroize();
    sign.zeroize();
    derived
}

#[cfg(feature = "noise")]
fn poll_event_additional_data(message_id: &str, actor_jid: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(message_id.len() + actor_jid.len() + 1);
    aad.extend_from_slice(message_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(actor_jid.as_bytes());
    aad
}

fn validate_non_empty(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(CoreError::Payload(format!("{label} must not be empty")));
    }
    Ok(())
}

fn validate_non_empty_bytes(label: &str, value: &Bytes) -> CoreResult<()> {
    if value.is_empty() {
        return Err(CoreError::Payload(format!("{label} must not be empty")));
    }
    Ok(())
}

fn validate_optional_non_empty(label: &str, value: Option<&str>) -> CoreResult<()> {
    if let Some(value) = value {
        validate_non_empty(label, value)?;
    }
    Ok(())
}

fn validate_optional_non_zero(label: &str, value: Option<u32>) -> CoreResult<()> {
    if value == Some(0) {
        return Err(CoreError::Payload(format!(
            "{label} must be greater than zero"
        )));
    }
    Ok(())
}

fn flag(value: bool) -> Option<bool> {
    value.then_some(true)
}

fn media_retry_status_code(code: u16) -> u16 {
    match code {
        1 => 200,
        2 => 404,
        3 => 412,
        _ => 418,
    }
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return None;
    };
    children.iter().find(|child| child.tag == tag)
}

fn node_bytes(node: &BinaryNode) -> CoreResult<Bytes> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(value)) => Ok(value.clone()),
        Some(_) => Err(CoreError::Protocol(format!(
            "expected bytes content in {} node",
            node.tag
        ))),
        None => Err(CoreError::Protocol(format!(
            "missing bytes content in {} node",
            node.tag
        ))),
    }
}

pub fn build_receipt_node(
    receipt: &MessageReceipt,
    receipt_type: MessageReceiptType,
    timestamp: Option<u64>,
) -> CoreResult<BinaryNode> {
    if jid_decode(&receipt.remote_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid remote JID for receipt: {}",
            receipt.remote_jid
        )));
    }
    if let Some(participant) = receipt.participant.as_deref()
        && jid_decode(participant).is_none()
    {
        return Err(CoreError::Payload(format!(
            "invalid participant JID for receipt: {participant}"
        )));
    }
    if receipt.message_ids.is_empty() || receipt.message_ids.iter().any(|id| id.is_empty()) {
        return Err(CoreError::Payload(
            "receipt requires at least one non-empty message id".to_owned(),
        ));
    }

    let mut node = BinaryNode::new("receipt").with_attr("id", receipt.message_ids[0].clone());
    if receipt_type.requires_timestamp() {
        let timestamp = timestamp.ok_or_else(|| {
            CoreError::Payload("read receipts require an explicit timestamp".to_owned())
        })?;
        node = node.with_attr("t", timestamp.to_string());
    }

    if receipt_type == MessageReceiptType::Sender && is_user_jid(&receipt.remote_jid) {
        let participant = receipt.participant.as_deref().ok_or_else(|| {
            CoreError::Payload("sender receipt requires participant JID".to_owned())
        })?;
        node = node
            .with_attr("recipient", receipt.remote_jid.clone())
            .with_attr("to", participant);
    } else {
        node = node.with_attr("to", receipt.remote_jid.clone());
        if let Some(participant) = &receipt.participant {
            node = node.with_attr("participant", participant);
        }
    }

    if let Some(receipt_type) = receipt_type.as_wire_type() {
        node = node.with_attr("type", receipt_type);
    }

    if receipt.message_ids.len() > 1 {
        let items = receipt
            .message_ids
            .iter()
            .skip(1)
            .map(|id| BinaryNode::new("item").with_attr("id", id))
            .collect::<Vec<_>>();
        node = node.with_content(vec![BinaryNode::new("list").with_content(items)]);
    }

    Ok(node)
}

pub fn build_call_reject_node(
    from_jid: &str,
    call_from: &str,
    call_id: &str,
) -> CoreResult<BinaryNode> {
    if jid_decode(from_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid local JID for call reject: {from_jid}"
        )));
    }
    if jid_decode(call_from).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid caller JID for call reject: {call_from}"
        )));
    }
    if call_id.is_empty() {
        return Err(CoreError::Payload(
            "call reject requires non-empty call id".to_owned(),
        ));
    }

    Ok(BinaryNode::new("call")
        .with_attr("from", from_jid)
        .with_attr("to", call_from)
        .with_content(vec![
            BinaryNode::new("reject")
                .with_attr("call-id", call_id)
                .with_attr("call-creator", call_from)
                .with_attr("count", "0"),
        ]))
}

pub fn build_media_retry_request_node(
    key: &MessageKey,
    requester_jid: &str,
    payload: MediaRetryPayload,
) -> CoreResult<BinaryNode> {
    validate_message_key(key)?;
    validate_media_retry_payload(&payload)?;
    let id = key
        .id
        .clone()
        .ok_or_else(|| CoreError::Payload("media retry key missing id".to_owned()))?;
    let remote_jid = key
        .remote_jid
        .clone()
        .ok_or_else(|| CoreError::Payload("media retry key missing remote JID".to_owned()))?;
    let requester = jid_normalized_user(requester_jid).ok_or_else(|| {
        CoreError::Payload(format!(
            "invalid requester JID for media retry: {requester_jid}"
        ))
    })?;

    let encrypt = BinaryNode::new("encrypt").with_content(vec![
        BinaryNode::new("enc_p").with_content(payload.ciphertext),
        BinaryNode::new("enc_iv").with_content(payload.iv),
    ]);
    let mut retry = BinaryNode::new("rmr")
        .with_attr("jid", remote_jid)
        .with_attr("from_me", key.from_me.unwrap_or(false).to_string());
    if let Some(participant) = &key.participant {
        retry = retry.with_attr("participant", participant);
    }

    Ok(BinaryNode::new("receipt")
        .with_attr("id", id)
        .with_attr("to", requester)
        .with_attr("type", "server-error")
        .with_content(vec![encrypt, retry]))
}

#[cfg(feature = "noise")]
pub fn build_encrypted_media_retry_request_node(
    key: &MessageKey,
    requester_jid: &str,
    media_key: &[u8],
) -> CoreResult<BinaryNode> {
    validate_message_key(key)?;
    let id = key
        .id
        .as_deref()
        .ok_or_else(|| CoreError::Payload("media retry key missing id".to_owned()))?;
    let payload = wa_crypto::encrypt_media_retry_request(id, media_key)?;
    build_media_retry_request_node(
        key,
        requester_jid,
        MediaRetryPayload::new(payload.ciphertext, payload.iv),
    )
}

pub fn parse_media_retry_update(node: &BinaryNode) -> CoreResult<MediaRetryUpdate> {
    if !matches!(node.tag.as_str(), "receipt" | "notification") {
        return Err(CoreError::Protocol(format!(
            "media retry update must be a receipt or notification node, got {}",
            node.tag
        )));
    }
    let id = node
        .attrs
        .get("id")
        .cloned()
        .ok_or_else(|| CoreError::Protocol("media retry node missing id".to_owned()))?;
    validate_non_empty("media retry node id", &id)?;
    let retry = child_node(node, "rmr")
        .ok_or_else(|| CoreError::Protocol("media retry node missing rmr node".to_owned()))?;
    let remote_jid = retry
        .attrs
        .get("jid")
        .cloned()
        .ok_or_else(|| CoreError::Protocol("media retry rmr node missing jid".to_owned()))?;
    if jid_decode(&remote_jid).is_none() {
        return Err(CoreError::Protocol(format!(
            "invalid media retry remote JID: {remote_jid}"
        )));
    }
    let participant = retry.attrs.get("participant").cloned();
    if let Some(participant) = participant.as_deref()
        && jid_decode(participant).is_none()
    {
        return Err(CoreError::Protocol(format!(
            "invalid media retry participant JID: {participant}"
        )));
    }
    let from_me = retry
        .attrs
        .get("from_me")
        .is_some_and(|value| value == "true");
    let key = MessageKey {
        remote_jid: Some(remote_jid),
        from_me: Some(from_me),
        id: Some(id),
        participant,
    };

    if let Some(error) = child_node(node, "error") {
        let code = error
            .attrs
            .get("code")
            .ok_or_else(|| CoreError::Protocol("media retry error missing code".to_owned()))?
            .parse::<u16>()
            .map_err(|err| CoreError::Protocol(format!("invalid media retry error code: {err}")))?;
        return Ok(MediaRetryUpdate {
            key,
            media: None,
            error: Some(MediaRetryError {
                code,
                text: error.attrs.get("text").cloned(),
                status_code: media_retry_status_code(code),
            }),
        });
    }

    let encrypt = child_node(node, "encrypt")
        .ok_or_else(|| CoreError::Protocol("media retry node missing encrypt node".to_owned()))?;
    let payload = MediaRetryPayload {
        ciphertext: node_bytes(child_node(encrypt, "enc_p").ok_or_else(|| {
            CoreError::Protocol("media retry encrypt node missing enc_p".to_owned())
        })?)?,
        iv: node_bytes(child_node(encrypt, "enc_iv").ok_or_else(|| {
            CoreError::Protocol("media retry encrypt node missing enc_iv".to_owned())
        })?)?,
    };
    validate_media_retry_payload(&payload)?;

    Ok(MediaRetryUpdate {
        key,
        media: Some(payload),
        error: None,
    })
}

pub fn aggregate_receipts_from_message_keys(
    keys: &[MessageKey],
) -> CoreResult<Vec<MessageReceipt>> {
    let mut grouped = BTreeMap::<(String, Option<String>), Vec<String>>::new();
    for key in keys {
        if key.from_me.unwrap_or(false) {
            continue;
        }
        let remote_jid = key.remote_jid.clone().ok_or_else(|| {
            CoreError::Payload("message key missing remote JID for receipt".to_owned())
        })?;
        if jid_decode(&remote_jid).is_none() {
            return Err(CoreError::Payload(format!(
                "invalid remote JID for receipt: {remote_jid}"
            )));
        }
        let id = key
            .id
            .clone()
            .ok_or_else(|| CoreError::Payload("message key missing id for receipt".to_owned()))?;
        if id.is_empty() {
            return Err(CoreError::Payload(
                "message key id must not be empty for receipt".to_owned(),
            ));
        }
        if let Some(participant) = key.participant.as_deref()
            && jid_decode(participant).is_none()
        {
            return Err(CoreError::Payload(format!(
                "invalid participant JID for receipt: {participant}"
            )));
        }
        grouped
            .entry((remote_jid, key.participant.clone()))
            .or_default()
            .push(id);
    }

    Ok(grouped
        .into_iter()
        .map(|((remote_jid, participant), message_ids)| MessageReceipt {
            remote_jid,
            participant,
            message_ids,
        })
        .collect())
}

pub fn build_device_sent_message(destination_jid: &str, message: Message) -> CoreResult<Message> {
    if jid_decode(destination_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid destination JID for device-sent message: {destination_jid}"
        )));
    }
    Ok(Message {
        device_sent_message: Some(Box::new(wa_proto::proto::message::DeviceSentMessage {
            destination_jid: Some(destination_jid.to_owned()),
            message: Some(Box::new(message)),
            phash: None,
        })),
        ..Message::default()
    })
}

pub fn generate_participant_hash_v2<I, T>(participants: I) -> CoreResult<String>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut participants = participants
        .into_iter()
        .map(|participant| {
            let participant = participant.as_ref();
            if jid_decode(participant).is_none() {
                return Err(CoreError::Payload(format!(
                    "invalid participant JID for participant hash: {participant}"
                )));
            }
            Ok(participant.to_owned())
        })
        .collect::<CoreResult<Vec<_>>>()?;
    participants.sort();

    let mut hasher = Sha256::new();
    for participant in &participants {
        hasher.update(participant.as_bytes());
    }
    let digest = hasher.finalize();
    Ok(format!("2:{}", base64_prefix(&digest, 6)))
}

pub async fn build_direct_message_relay<E>(
    remote_jid: &str,
    message: Message,
    recipients: &[MessageRelayRecipient],
    encryptor: &E,
    options: MessageRelayOptions,
) -> CoreResult<MessageRelay>
where
    E: MessageEncryptor,
{
    if jid_decode(remote_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid remote JID for message relay: {remote_jid}"
        )));
    }
    if recipients.is_empty() {
        return Err(CoreError::Payload(
            "message relay requires at least one recipient device".to_owned(),
        ));
    }

    let MessageRelayOptions {
        message_id,
        sender_jid,
        additional_attributes,
        additional_nodes,
        device_identity_node,
        encryption_attributes,
    } = options;

    let message_id =
        message_id.unwrap_or_else(|| generate_message_id_v2_now(sender_jid.as_deref()));
    if message_id.is_empty() {
        return Err(CoreError::Payload(
            "message relay id must not be empty".to_owned(),
        ));
    }

    let mut should_include_device_identity = false;
    let mut participant_nodes = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        if jid_decode(&recipient.jid).is_none() {
            return Err(CoreError::Payload(format!(
                "invalid recipient JID for message relay: {}",
                recipient.jid
            )));
        }
        let message_to_encrypt = if recipient.is_own_device {
            build_device_sent_message(remote_jid, message.clone())?
        } else {
            message.clone()
        };
        let plaintext = encode_message(&message_to_encrypt)?;
        let encrypted = encryptor.encrypt_message(&recipient.jid, plaintext).await?;
        should_include_device_identity |=
            encrypted.ciphertext_type == MessageCiphertextType::PreKey;

        let mut enc_node = BinaryNode::new("enc")
            .with_attr("v", "2")
            .with_attr("type", encrypted.ciphertext_type.as_stanza_type())
            .with_content(encrypted.ciphertext);
        for (key, value) in &encryption_attributes {
            enc_node = enc_node.with_attr(key, value);
        }
        participant_nodes.push(
            BinaryNode::new("to")
                .with_attr("jid", recipient.jid.clone())
                .with_content(vec![enc_node]),
        );
    }

    let has_explicit_device_identity = additional_nodes
        .iter()
        .any(|node| node.tag == "device-identity");
    let mut content = vec![BinaryNode::new("participants").with_content(participant_nodes)];
    if should_include_device_identity
        && !has_explicit_device_identity
        && let Some(node) = device_identity_node
    {
        content.push(node);
    }
    content.extend(additional_nodes);

    let mut node = BinaryNode::new("message")
        .with_attr("id", message_id.clone())
        .with_attr("to", remote_jid)
        .with_attr("type", message_stanza_type(&message))
        .with_content(content);
    if !additional_attributes.contains_key("phash") {
        node = node.with_attr(
            "phash",
            generate_participant_hash_v2(
                recipients.iter().map(|recipient| recipient.jid.as_str()),
            )?,
        );
    }
    for (key, value) in additional_attributes {
        node = node.with_attr(key, value);
    }

    Ok(MessageRelay {
        message_id,
        node,
        recipient_count: recipients.len(),
        should_include_device_identity,
    })
}

pub async fn build_group_sender_key_message_relay<E>(
    group_jid: &str,
    message: Message,
    encryptor: &E,
    options: MessageRelayOptions,
) -> CoreResult<MessageRelay>
where
    E: MessageEncryptor,
{
    let decoded = jid_decode(group_jid).ok_or_else(|| {
        CoreError::Payload(format!(
            "invalid group JID for sender-key message relay: {group_jid}"
        ))
    })?;
    if decoded.server != JidServer::GUs {
        return Err(CoreError::Payload(format!(
            "sender-key message relay requires a group JID: {group_jid}"
        )));
    }

    let MessageRelayOptions {
        message_id,
        sender_jid,
        additional_attributes,
        additional_nodes,
        device_identity_node: _,
        encryption_attributes,
    } = options;

    let message_id =
        message_id.unwrap_or_else(|| generate_message_id_v2_now(sender_jid.as_deref()));
    if message_id.is_empty() {
        return Err(CoreError::Payload(
            "message relay id must not be empty".to_owned(),
        ));
    }

    let stanza_type = message_stanza_type(&message);
    let plaintext = encode_message(&message)?;
    let encrypted = encryptor.encrypt_message(group_jid, plaintext).await?;
    if encrypted.ciphertext_type != MessageCiphertextType::SenderKey {
        return Err(CoreError::Payload(format!(
            "group sender-key relay requires skmsg ciphertext, got {}",
            encrypted.ciphertext_type.as_stanza_type()
        )));
    }

    let mut enc_node = BinaryNode::new("enc")
        .with_attr("v", "2")
        .with_attr("type", encrypted.ciphertext_type.as_stanza_type())
        .with_content(encrypted.ciphertext);
    for (key, value) in &encryption_attributes {
        enc_node = enc_node.with_attr(key, value);
    }

    let mut content = vec![enc_node];
    content.extend(additional_nodes);
    let mut node = BinaryNode::new("message")
        .with_attr("id", message_id.clone())
        .with_attr("to", group_jid)
        .with_attr("type", stanza_type)
        .with_content(content);
    for (key, value) in additional_attributes {
        node = node.with_attr(key, value);
    }

    Ok(MessageRelay {
        message_id,
        node,
        recipient_count: 1,
        should_include_device_identity: false,
    })
}

#[must_use]
pub fn message_stanza_type(message: &Message) -> &'static str {
    let message = unwrapped_message_content(message);
    if message.reaction_message.is_some() || message.enc_reaction_message.is_some() {
        "reaction"
    } else if message.poll_creation_message.is_some()
        || message.poll_creation_message_v2.is_some()
        || message.poll_creation_message_v3.is_some()
        || message.poll_creation_message_v4.is_some()
        || message.poll_creation_message_v5.is_some()
        || message.poll_update_message.is_some()
    {
        "poll"
    } else if message.event_message.is_some() {
        "event"
    } else if message.image_message.is_some()
        || message.video_message.is_some()
        || message.ptv_message.is_some()
        || message.audio_message.is_some()
        || message.document_message.is_some()
        || message.sticker_message.is_some()
        || message.album_message.is_some()
    {
        "media"
    } else {
        "text"
    }
}

pub(crate) fn unwrapped_message_content(message: &Message) -> &Message {
    let mut current = message;
    for _ in 0..5 {
        let Some(inner) = future_proof_inner_message(current) else {
            break;
        };
        current = inner;
    }
    current
}

pub(crate) fn future_proof_inner_message(message: &Message) -> Option<&Message> {
    message
        .ephemeral_message
        .as_deref()
        .or(message.view_once_message.as_deref())
        .or(message.document_with_caption_message.as_deref())
        .or(message.view_once_message_v2.as_deref())
        .or(message.view_once_message_v2_extension.as_deref())
        .or(message.edited_message.as_deref())
        .or(message.group_mentioned_message.as_deref())
        .or(message.bot_invoke_message.as_deref())
        .or(message.lottie_sticker_message.as_deref())
        .or(message.event_cover_image.as_deref())
        .or(message.status_mention_message.as_deref())
        .or(message.poll_creation_option_image_message.as_deref())
        .or(message.associated_child_message.as_deref())
        .or(message.group_status_mention_message.as_deref())
        .or(message.poll_creation_message_v4.as_deref())
        .or(message.status_add_yours.as_deref())
        .or(message.group_status_message.as_deref())
        .or(message.limit_sharing_message.as_deref())
        .or(message.bot_task_message.as_deref())
        .or(message.question_message.as_deref())
        .or(message.group_status_message_v2.as_deref())
        .or(message.bot_forwarded_message.as_deref())
        .or(message.question_reply_message.as_deref())
        .and_then(|wrapper| wrapper.message.as_deref())
}

pub fn build_message_key(
    remote_jid: impl Into<String>,
    from_me: bool,
    id: impl Into<String>,
    participant: Option<String>,
) -> CoreResult<MessageKey> {
    let remote_jid = remote_jid.into();
    if jid_decode(&remote_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid remote JID for message key: {remote_jid}"
        )));
    }
    let id = id.into();
    if id.is_empty() {
        return Err(CoreError::Payload(
            "message id must not be empty".to_owned(),
        ));
    }
    if let Some(participant) = participant.as_deref()
        && jid_decode(participant).is_none()
    {
        return Err(CoreError::Payload(format!(
            "invalid participant JID for message key: {participant}"
        )));
    }

    Ok(MessageKey {
        remote_jid: Some(remote_jid),
        from_me: Some(from_me),
        id: Some(id),
        participant,
    })
}

#[must_use]
pub fn generate_message_id() -> String {
    let random: [u8; 18] = rand::random();
    format!("{MESSAGE_ID_PREFIX}{}", upper_hex(&random))
}

#[must_use]
pub fn generate_message_id_v2_now(user_jid: Option<&str>) -> String {
    let unix_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let random: [u8; 16] = rand::random();
    generate_message_id_v2(user_jid, unix_timestamp, &random)
}

#[must_use]
pub fn generate_message_id_v2(
    user_jid: Option<&str>,
    unix_timestamp: u64,
    random: &[u8; 16],
) -> String {
    let mut data = [0u8; 44];
    data[..8].copy_from_slice(&unix_timestamp.to_be_bytes());
    if let Some(user_jid) = user_jid
        && let Some(jid) = jid_decode(user_jid)
    {
        let user = jid.user.as_bytes();
        let user_len = user.len().min(20);
        data[8..8 + user_len].copy_from_slice(&user[..user_len]);
        let suffix = b"@c.us";
        let suffix_start = 8 + user_len;
        let suffix_len = suffix.len().min(28usize.saturating_sub(suffix_start));
        if suffix_len > 0 {
            data[suffix_start..suffix_start + suffix_len].copy_from_slice(&suffix[..suffix_len]);
        }
    }
    data[28..].copy_from_slice(random);

    let digest = Sha256::digest(data);
    format!("{MESSAGE_ID_PREFIX}{}", upper_hex(&digest[..9]))
}

pub fn encode_message(message: &Message) -> CoreResult<Bytes> {
    let mut out = Vec::new();
    prost::Message::encode(message, &mut out)
        .map_err(|err| CoreError::Payload(format!("failed to encode message: {err}")))?;
    Ok(Bytes::from(out))
}

fn upper_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn is_user_jid(jid: &str) -> bool {
    jid_decode(jid)
        .is_some_and(|jid| matches!(jid.server, JidServer::SWhatsAppNet | JidServer::Lid))
}

fn base64_prefix(input: &[u8], limit: usize) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(limit);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let indexes = [
            b0 >> 2,
            ((b0 & 0b0000_0011) << 4) | (b1 >> 4),
            ((b1 & 0b0000_1111) << 2) | (b2 >> 6),
            b2 & 0b0011_1111,
        ];
        let available = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for index in indexes.into_iter().take(available) {
            out.push(TABLE[usize::from(index)] as char);
            if out.len() == limit {
                return out;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use std::sync::{Arc, Mutex};
    use wa_binary::BinaryNodeContent;

    #[derive(Clone)]
    struct RecordingEncryptor {
        calls: Arc<Mutex<Vec<(String, Bytes)>>>,
        ciphertext_type: Option<MessageCiphertextType>,
    }

    impl RecordingEncryptor {
        fn sender_key() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                ciphertext_type: Some(MessageCiphertextType::SenderKey),
            }
        }
    }

    impl Default for RecordingEncryptor {
        fn default() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                ciphertext_type: None,
            }
        }
    }

    #[async_trait]
    impl MessageEncryptor for RecordingEncryptor {
        async fn encrypt_message(
            &self,
            recipient_jid: &str,
            plaintext: Bytes,
        ) -> CoreResult<MessageEncryption> {
            self.calls
                .lock()
                .unwrap()
                .push((recipient_jid.to_owned(), plaintext.clone()));
            let ciphertext_type = self.ciphertext_type.unwrap_or_else(|| {
                if recipient_jid.contains(":2@") {
                    MessageCiphertextType::PreKey
                } else {
                    MessageCiphertextType::Message
                }
            });
            Ok(MessageEncryption::new(ciphertext_type, plaintext))
        }
    }

    #[test]
    fn generated_message_ids_have_expected_shape() {
        let id = generate_message_id();
        assert_eq!(id.len(), 40);
        assert!(id.starts_with(MESSAGE_ID_PREFIX));
        assert!(id.chars().all(|ch| ch.is_ascii_hexdigit()));

        let id = generate_message_id_v2(Some("12345@s.whatsapp.net"), 1, &[7u8; 16]);
        assert_eq!(id.len(), 22);
        assert!(id.starts_with(MESSAGE_ID_PREFIX));
        assert_eq!(
            id,
            generate_message_id_v2(Some("12345@s.whatsapp.net"), 1, &[7u8; 16])
        );
        assert_ne!(
            id,
            generate_message_id_v2(Some("99999@s.whatsapp.net"), 1, &[7u8; 16])
        );
    }

    #[test]
    fn builds_text_message_proto() {
        let message = build_text_message("hello").unwrap();
        assert_eq!(
            message
                .extended_text_message
                .as_ref()
                .unwrap()
                .text
                .as_deref(),
            Some("hello")
        );
        assert!(message.conversation.is_none());

        let encoded = encode_message(&message).unwrap();
        assert_eq!(Message::decode(encoded).unwrap(), message);
        assert!(build_text_message("").is_err());
    }

    #[test]
    fn builds_text_message_with_style_metadata() {
        let message = build_text_message(
            TextMessage::new("styled")
                .with_text_argb(0xfff8f8f8)
                .with_background_argb(0xff123456)
                .with_font(TextFont::SystemBold),
        )
        .unwrap();

        let extended = message.extended_text_message.as_ref().unwrap();
        assert_eq!(extended.text.as_deref(), Some("styled"));
        assert_eq!(extended.text_argb, Some(0xfff8f8f8));
        assert_eq!(extended.background_argb, Some(0xff123456));
        assert_eq!(
            extended.font,
            Some(extended_text_message::FontType::SystemBold as i32)
        );

        let encoded = encode_message(&message).unwrap();
        assert_eq!(Message::decode(encoded).unwrap(), message);
    }

    #[test]
    fn builds_text_message_with_link_preview_metadata() {
        let thumbnail = LinkPreviewThumbnail::new(
            "/mms/thumb",
            Bytes::from(vec![1; 32]),
            Bytes::from(vec![2; 32]),
            Bytes::from(vec![3; 32]),
        )
        .with_media_key_timestamp(1_700_000_000)
        .with_dimensions(640, 360);
        let preview = LinkPreviewContent::new("https://example.invalid/post", "Example")
            .with_description("Preview text")
            .with_jpeg_thumbnail(Bytes::from_static(b"jpeg"))
            .with_high_quality_thumbnail(thumbnail);

        let message = build_text_message(
            TextMessage::new("See https://example.invalid/post").with_link_preview(preview),
        )
        .unwrap();
        let text = message.extended_text_message.unwrap();
        assert_eq!(
            text.matched_text.as_deref(),
            Some("https://example.invalid/post")
        );
        assert_eq!(text.title.as_deref(), Some("Example"));
        assert_eq!(text.description.as_deref(), Some("Preview text"));
        assert_eq!(text.jpeg_thumbnail, Some(Bytes::from_static(b"jpeg")));
        assert_eq!(
            text.preview_type,
            Some(extended_text_message::PreviewType::None as i32)
        );
        assert_eq!(text.thumbnail_direct_path.as_deref(), Some("/mms/thumb"));
        assert_eq!(text.media_key, Some(Bytes::from(vec![1; 32])));
        assert_eq!(text.thumbnail_sha256, Some(Bytes::from(vec![2; 32])));
        assert_eq!(text.thumbnail_enc_sha256, Some(Bytes::from(vec![3; 32])));
        assert_eq!(text.media_key_timestamp, Some(1_700_000_000));
        assert_eq!(text.thumbnail_width, Some(640));
        assert_eq!(text.thumbnail_height, Some(360));
    }

    #[test]
    fn rejects_invalid_link_preview_metadata() {
        assert!(
            build_text_message(
                TextMessage::new("x").with_link_preview(LinkPreviewContent::new("", "Example"))
            )
            .is_err()
        );
        assert!(
            build_text_message(TextMessage::new("x").with_link_preview(
                LinkPreviewContent::new("https://x", "Example").with_jpeg_thumbnail(Bytes::new())
            ))
            .is_err()
        );
        assert!(
            build_text_message(TextMessage::new("x").with_link_preview(
                LinkPreviewContent::new("https://x", "Example").with_high_quality_thumbnail(
                    LinkPreviewThumbnail::new(
                        "/thumb",
                        Bytes::from(vec![1; 31]),
                        Bytes::from(vec![2; 32]),
                        Bytes::from(vec![3; 32]),
                    )
                )
            ))
            .is_err()
        );
        assert!(
            build_text_message(
                TextMessage::new("x").with_link_preview(
                    LinkPreviewContent::new("https://x", "Example").with_high_quality_thumbnail(
                        LinkPreviewThumbnail::new(
                            "/thumb",
                            Bytes::from(vec![1; 32]),
                            Bytes::from(vec![2; 32]),
                            Bytes::from(vec![3; 32]),
                        )
                        .with_dimensions(0, 10)
                    )
                )
            )
            .is_err()
        );
    }

    #[test]
    fn message_content_converts_to_proto() {
        let message = MessageContent::text("hello").into_proto().unwrap();
        assert_eq!(
            message
                .extended_text_message
                .as_ref()
                .unwrap()
                .text
                .as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn builds_view_once_future_proof_wrapper() {
        let message = MessageContent::view_once(MessageContent::image(ImageContent::new(
            sample_uploaded_media(),
            "image/jpeg",
        )))
        .into_proto()
        .unwrap();

        assert!(message.image_message.is_none());
        let inner = message
            .view_once_message
            .as_ref()
            .and_then(|wrapper| wrapper.message.as_deref())
            .unwrap();
        assert!(inner.image_message.is_some());
        assert_eq!(message_stanza_type(&message), "media");

        let encoded = encode_message(&message).unwrap();
        assert_eq!(Message::decode(encoded).unwrap(), message);
    }

    #[test]
    fn message_stanza_type_unwraps_modern_future_proof_wrappers() {
        let lottie = Message {
            lottie_sticker_message: Some(Box::new(future_proof_message(Message {
                sticker_message: Some(Box::new(StickerMessage::default())),
                ..Message::default()
            }))),
            ..Message::default()
        };
        let status_mention = Message {
            status_mention_message: Some(Box::new(future_proof_message(Message {
                image_message: Some(Box::new(ImageMessage::default())),
                ..Message::default()
            }))),
            ..Message::default()
        };
        let poll_v4 = Message {
            poll_creation_message_v4: Some(Box::new(future_proof_message(Message {
                poll_creation_message: Some(Box::new(PollCreationMessage::default())),
                ..Message::default()
            }))),
            ..Message::default()
        };

        assert_eq!(message_stanza_type(&lottie), "media");
        assert_eq!(message_stanza_type(&status_mention), "media");
        assert_eq!(message_stanza_type(&poll_v4), "poll");
    }

    #[test]
    fn builds_album_phone_number_and_limit_sharing_messages() {
        let album =
            build_album_message(AlbumContent::new(2, 1).with_context(MessageContext::new()))
                .unwrap();
        let album_body = album.album_message.as_ref().unwrap();
        assert_eq!(album_body.expected_image_count, Some(2));
        assert_eq!(album_body.expected_video_count, Some(1));
        assert_eq!(message_stanza_type(&album), "media");
        assert!(build_album_message(AlbumContent::new(0, 0)).is_err());

        let request = build_request_phone_number_message(RequestPhoneNumberContent::new()).unwrap();
        assert!(request.request_phone_number_message.is_some());
        assert_eq!(message_stanza_type(&request), "text");

        let share = MessageContent::share_phone_number().into_proto().unwrap();
        let share_protocol = share.protocol_message.as_ref().unwrap();
        assert_eq!(
            share_protocol.r#type,
            Some(protocol_message::Type::SharePhoneNumber as i32)
        );

        let limit = MessageContent::limit_sharing(
            LimitSharingContent::new(true)
                .with_setting_timestamp_ms(1_700_000_001)
                .with_trigger(LimitSharingTrigger::ChatSetting),
        )
        .into_proto()
        .unwrap();
        let limit_protocol = limit.protocol_message.as_ref().unwrap();
        assert_eq!(
            limit_protocol.r#type,
            Some(protocol_message::Type::LimitSharing as i32)
        );
        let limit_sharing = limit_protocol.limit_sharing.as_ref().unwrap();
        assert_eq!(limit_sharing.sharing_limited, Some(true));
        assert_eq!(
            limit_sharing.trigger,
            Some(limit_sharing::TriggerType::ChatSetting as i32)
        );
        assert_eq!(
            limit_sharing.limit_sharing_setting_timestamp,
            Some(1_700_000_001)
        );
        assert_eq!(limit_sharing.initiated_by_me, Some(true));

        for message in [album, request, share, limit] {
            let encoded = encode_message(&message).unwrap();
            assert_eq!(Message::decode(encoded).unwrap(), message);
        }
    }

    #[test]
    fn builds_button_template_and_list_reply_messages() {
        let button =
            build_button_reply_message(ButtonReplyContent::new("button-1", "Open")).unwrap();
        let button_body = button.buttons_response_message.as_ref().unwrap();
        assert_eq!(button_body.selected_button_id.as_deref(), Some("button-1"));
        assert_eq!(
            button_body.r#type,
            Some(buttons_response_message::Type::DisplayText as i32)
        );
        assert_eq!(
            button_body.response,
            Some(buttons_response_message::Response::SelectedDisplayText(
                "Open".to_owned()
            ))
        );

        let template = MessageContent::template_button_reply(
            TemplateButtonReplyContent::new("tpl-1", "Choose")
                .with_selected_index(2)
                .with_selected_carousel_card_index(1),
        )
        .into_proto()
        .unwrap();
        let template_body = template.template_button_reply_message.as_ref().unwrap();
        assert_eq!(template_body.selected_id.as_deref(), Some("tpl-1"));
        assert_eq!(
            template_body.selected_display_text.as_deref(),
            Some("Choose")
        );
        assert_eq!(template_body.selected_index, Some(2));
        assert_eq!(template_body.selected_carousel_card_index, Some(1));

        let list = build_list_reply_message(
            ListReplyContent::new("Menu", "row-1").with_description("First row"),
        )
        .unwrap();
        let list_body = list.list_response_message.as_ref().unwrap();
        assert_eq!(list_body.title.as_deref(), Some("Menu"));
        assert_eq!(
            list_body.list_type,
            Some(list_response_message::ListType::SingleSelect as i32)
        );
        assert_eq!(
            list_body
                .single_select_reply
                .as_ref()
                .and_then(|reply| reply.selected_row_id.as_deref()),
            Some("row-1")
        );
        assert_eq!(list_body.description.as_deref(), Some("First row"));

        let sender_key_distribution = build_sender_key_distribution_message(
            SenderKeyDistributionContent::new("123@g.us", Bytes::from_static(b"sender-key")),
        )
        .unwrap();
        let sender_key_distribution_body = sender_key_distribution
            .sender_key_distribution_message
            .as_ref()
            .unwrap();
        assert_eq!(
            sender_key_distribution_body.group_id.as_deref(),
            Some("123@g.us")
        );
        assert_eq!(
            sender_key_distribution_body
                .axolotl_sender_key_distribution_message
                .as_deref(),
            Some(&b"sender-key"[..])
        );

        assert!(build_button_reply_message(ButtonReplyContent::new("", "Open")).is_err());
        assert!(
            build_template_button_reply_message(TemplateButtonReplyContent::new("tpl", ""))
                .is_err()
        );
        assert!(build_list_reply_message(ListReplyContent::new("Menu", "")).is_err());
        assert!(
            build_sender_key_distribution_message(SenderKeyDistributionContent::new(
                "123@s.whatsapp.net",
                Bytes::from_static(b"sender-key"),
            ))
            .is_err()
        );
        assert!(
            build_sender_key_distribution_message(SenderKeyDistributionContent::new(
                "123@g.us",
                Bytes::new(),
            ))
            .is_err()
        );

        for message in [button, template, list, sender_key_distribution] {
            assert_eq!(message_stanza_type(&message), "text");
            let encoded = encode_message(&message).unwrap();
            assert_eq!(Message::decode(encoded).unwrap(), message);
        }
    }

    #[test]
    fn builds_text_context_with_mentions_quote_and_forwarding() {
        let quoted = build_text_message("quoted").unwrap();
        let context = MessageContext::new()
            .with_mentions(["456@s.whatsapp.net", "789@s.whatsapp.net"])
            .with_quote(
                QuotedMessage::new("123@s.whatsapp.net", "quoted-1", quoted)
                    .with_participant("456@s.whatsapp.net"),
            )
            .forwarded(2)
            .with_expiration(60);

        let message =
            build_text_message(TextMessage::new("hello @456").with_context(context)).unwrap();
        let text = message.extended_text_message.unwrap();
        let context = text.context_info.unwrap();
        assert_eq!(context.mentioned_jid.len(), 2);
        assert_eq!(context.stanza_id.as_deref(), Some("quoted-1"));
        assert_eq!(context.remote_jid.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(context.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert_eq!(context.forwarding_score, Some(2));
        assert_eq!(context.is_forwarded, Some(true));
        assert_eq!(context.expiration, Some(60));
        assert!(context.quoted_message.is_some());
    }

    #[test]
    fn builds_contact_location_and_reaction_messages() {
        let contact =
            build_contact_message(ContactContent::new("Alice", "BEGIN:VCARD\nEND:VCARD")).unwrap();
        assert_eq!(
            contact
                .contact_message
                .as_ref()
                .unwrap()
                .display_name
                .as_deref(),
            Some("Alice")
        );

        let contacts = build_contacts_message(ContactsContent::new(
            "Team",
            [
                ContactContent::new("Alice", "BEGIN:VCARD\nEND:VCARD"),
                ContactContent::new("Bob", "BEGIN:VCARD\nEND:VCARD"),
            ],
        ))
        .unwrap();
        assert_eq!(contacts.contacts_array_message.unwrap().contacts.len(), 2);

        let location = build_location_message(
            LocationContent::new(-6.2, 106.8)
                .with_name("Jakarta")
                .with_address("Jakarta, Indonesia"),
        )
        .unwrap();
        assert_eq!(
            location.location_message.unwrap().name.as_deref(),
            Some("Jakarta")
        );

        let live = build_live_location_message(LiveLocationContent {
            accuracy_in_meters: Some(12),
            speed_in_mps: Some(1.5),
            caption: Some("moving".to_owned()),
            ..LiveLocationContent::new(-6.2, 106.8)
        })
        .unwrap();
        assert_eq!(
            live.live_location_message.unwrap().accuracy_in_meters,
            Some(12)
        );

        let key = build_message_key("123@s.whatsapp.net", false, "msg-1", None).unwrap();
        let reaction = build_reaction_message(ReactionContent::new(key, "+1")).unwrap();
        assert_eq!(
            reaction.reaction_message.unwrap().text.as_deref(),
            Some("+1")
        );
    }

    #[test]
    fn builds_uploaded_media_messages() {
        let mut image = ImageContent::new(sample_uploaded_media(), "image/jpeg");
        image.caption = Some("photo".to_owned());
        image.height = Some(720);
        image.width = Some(1280);
        image.jpeg_thumbnail = Some(Bytes::from_static(b"jpeg"));
        image.view_once = true;
        let image = build_image_message(image).unwrap();
        let image_body = image.image_message.as_ref().unwrap();
        assert_eq!(image_body.caption.as_deref(), Some("photo"));
        assert_eq!(image_body.view_once, Some(true));
        assert_eq!(image_body.media_key.as_ref().unwrap().len(), 32);
        assert_eq!(message_stanza_type(&image), "media");

        let mut video = VideoContent::new(sample_uploaded_media(), "video/mp4");
        video.caption = Some("clip".to_owned());
        video.seconds = Some(5);
        video = video.with_remote_thumbnail(RemoteMediaThumbnail::new(
            "/thumb/video",
            Bytes::from(vec![6; 32]),
            Bytes::from(vec![7; 32]),
        ));
        video.gif_playback = true;
        let video = build_video_message(video).unwrap();
        let video_body = video.video_message.unwrap();
        assert_eq!(video_body.gif_playback, Some(true));
        assert_eq!(
            video_body.thumbnail_direct_path.as_deref(),
            Some("/thumb/video")
        );
        assert_eq!(video_body.thumbnail_sha256, Some(Bytes::from(vec![6; 32])));
        assert_eq!(
            video_body.thumbnail_enc_sha256,
            Some(Bytes::from(vec![7; 32]))
        );

        let mut ptv = VideoContent::new(sample_uploaded_media(), "video/mp4");
        ptv.seconds = Some(7);
        ptv.height = Some(640);
        ptv.width = Some(640);
        let ptv = MessageContent::ptv(ptv).into_proto().unwrap();
        let ptv_body = ptv.ptv_message.as_ref().unwrap();
        assert_eq!(ptv_body.seconds, Some(7));
        assert_eq!(ptv_body.height, Some(640));
        assert_eq!(ptv_body.width, Some(640));
        assert_eq!(message_stanza_type(&ptv), "media");
        let encoded = encode_message(&ptv).unwrap();
        assert_eq!(Message::decode(encoded).unwrap(), ptv);

        let mut audio = AudioContent::new(sample_uploaded_media(), "audio/ogg; codecs=opus")
            .with_background_argb(0xff0a0b0c);
        audio.seconds = Some(3);
        audio.ptt = true;
        let audio = build_audio_message(audio).unwrap();
        let audio_body = audio.audio_message.unwrap();
        assert_eq!(audio_body.ptt, Some(true));
        assert_eq!(audio_body.background_argb, Some(0xff0a0b0c));

        let mut document = DocumentContent::new(sample_uploaded_media(), "application/pdf");
        document.title = Some("Report".to_owned());
        document.file_name = Some("report.pdf".to_owned());
        document.page_count = Some(2);
        document = document.with_remote_thumbnail(
            RemoteMediaThumbnail::new(
                "/thumb/document",
                Bytes::from(vec![8; 32]),
                Bytes::from(vec![9; 32]),
            )
            .with_dimensions(320, 180),
        );
        let document = build_document_message(document).unwrap();
        let document_body = document.document_message.unwrap();
        assert_eq!(document_body.title.as_deref(), Some("Report"));
        assert_eq!(document_body.page_count, Some(2));
        assert_eq!(
            document_body.thumbnail_direct_path.as_deref(),
            Some("/thumb/document")
        );
        assert_eq!(
            document_body.thumbnail_sha256,
            Some(Bytes::from(vec![8; 32]))
        );
        assert_eq!(
            document_body.thumbnail_enc_sha256,
            Some(Bytes::from(vec![9; 32]))
        );
        assert_eq!(document_body.thumbnail_width, Some(320));
        assert_eq!(document_body.thumbnail_height, Some(180));

        let mut sticker = StickerContent::new(sample_uploaded_media(), "image/webp");
        sticker.height = Some(512);
        sticker.width = Some(512);
        sticker.is_animated = true;
        let sticker = build_sticker_message(sticker).unwrap();
        assert_eq!(sticker.sticker_message.unwrap().is_animated, Some(true));

        let enum_message =
            MessageContent::image(ImageContent::new(sample_uploaded_media(), "image/jpeg"))
                .into_proto()
                .unwrap();
        assert!(enum_message.image_message.is_some());
    }

    #[test]
    fn rejects_invalid_remote_media_thumbnail_metadata() {
        let video = VideoContent::new(sample_uploaded_media(), "video/mp4").with_remote_thumbnail(
            RemoteMediaThumbnail::new("", Bytes::from(vec![1; 32]), Bytes::from(vec![2; 32])),
        );
        assert!(build_video_message(video).is_err());

        let document = DocumentContent::new(sample_uploaded_media(), "application/pdf")
            .with_remote_thumbnail(RemoteMediaThumbnail::new(
                "/thumb/document",
                Bytes::from(vec![1; 31]),
                Bytes::from(vec![2; 32]),
            ));
        assert!(build_document_message(document).is_err());

        let document = DocumentContent::new(sample_uploaded_media(), "application/pdf")
            .with_remote_thumbnail(
                RemoteMediaThumbnail::new(
                    "/thumb/document",
                    Bytes::from(vec![1; 32]),
                    Bytes::from(vec![2; 32]),
                )
                .with_dimensions(0, 180),
            );
        assert!(build_document_message(document).is_err());
    }

    #[cfg(feature = "image")]
    #[test]
    fn generated_image_thumbnail_sets_dimensions_and_proto_thumbnail_for_media() {
        use image::codecs::jpeg::JpegEncoder;
        use image::{Rgb, RgbImage};

        let source = RgbImage::from_fn(80, 40, |x, y| {
            Rgb([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8])
        });
        let mut source_bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut source_bytes, 90)
            .encode_image(&source)
            .unwrap();

        let content = ImageContent::new(sample_uploaded_media(), "image/jpeg")
            .with_generated_jpeg_thumbnail(&source_bytes, crate::JpegThumbnailOptions::default())
            .unwrap();
        assert_eq!(content.width, Some(80));
        assert_eq!(content.height, Some(40));
        let thumbnail = content.jpeg_thumbnail.clone().unwrap();
        assert!(thumbnail.starts_with(&[0xff, 0xd8]));

        let message = build_image_message(content).unwrap();
        let image = message.image_message.unwrap();
        assert_eq!(image.width, Some(80));
        assert_eq!(image.height, Some(40));
        assert_eq!(image.jpeg_thumbnail, Some(thumbnail));

        let video_content = VideoContent::new(sample_uploaded_media(), "video/mp4")
            .with_generated_jpeg_thumbnail(&source_bytes, crate::JpegThumbnailOptions::default())
            .unwrap();
        assert_eq!(video_content.width, Some(80));
        assert_eq!(video_content.height, Some(40));
        let video_thumbnail = video_content.jpeg_thumbnail.clone().unwrap();
        assert!(video_thumbnail.starts_with(&[0xff, 0xd8]));

        let video = build_video_message(video_content).unwrap();
        let video = video.video_message.unwrap();
        assert_eq!(video.width, Some(80));
        assert_eq!(video.height, Some(40));
        assert_eq!(video.jpeg_thumbnail, Some(video_thumbnail));

        let document_content = DocumentContent::new(sample_uploaded_media(), "application/pdf")
            .with_generated_jpeg_thumbnail(&source_bytes, crate::JpegThumbnailOptions::default())
            .unwrap();
        assert_eq!(document_content.thumbnail_width, Some(32));
        assert_eq!(document_content.thumbnail_height, Some(16));
        let document_thumbnail = document_content.jpeg_thumbnail.clone().unwrap();
        assert!(document_thumbnail.starts_with(&[0xff, 0xd8]));

        let document = build_document_message(document_content).unwrap();
        let document = document.document_message.unwrap();
        assert_eq!(document.thumbnail_width, Some(32));
        assert_eq!(document.thumbnail_height, Some(16));
        assert_eq!(document.jpeg_thumbnail, Some(document_thumbnail));
    }

    #[cfg(all(feature = "image", unix))]
    #[test]
    fn generated_pdf_thumbnail_sets_document_proto_thumbnail() {
        use image::codecs::jpeg::JpegEncoder;
        use image::{Rgb, RgbImage};
        use std::os::unix::fs::PermissionsExt as _;

        let dir = test_message_path("pdf-thumbnail");
        std::fs::create_dir_all(&dir).unwrap();
        let frame_path = dir.join("page.jpg");
        let log_path = dir.join("args.log");
        let renderer_path = dir.join("fake-pdftoppm");
        let pdf_path = dir.join("doc.pdf");
        let frame = RgbImage::from_fn(96, 48, |x, y| {
            Rgb([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8])
        });
        let mut frame_bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut frame_bytes, 90)
            .encode_image(&frame)
            .unwrap();
        std::fs::write(&frame_path, frame_bytes).unwrap();
        std::fs::write(&pdf_path, b"%PDF-1.7\n").unwrap();
        std::fs::write(
            &renderer_path,
            format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > {}\nout=\"\"\nfor arg do out=\"$arg\"; done\ncp {} \"$out.jpg\"\n",
                shell_quote(&log_path),
                shell_quote(&frame_path),
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&renderer_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&renderer_path, permissions).unwrap();

        let content = DocumentContent::new(sample_uploaded_media(), "application/pdf")
            .with_generated_pdf_thumbnail(
                &pdf_path,
                crate::PdfThumbnailOptions {
                    pdftoppm_path: renderer_path,
                    page: 1,
                    dpi: 72,
                    output: crate::JpegThumbnailOptions::default(),
                    temp_dir: Some(dir),
                },
            )
            .unwrap();
        assert_eq!(content.thumbnail_width, Some(32));
        assert_eq!(content.thumbnail_height, Some(16));
        let thumbnail = content.jpeg_thumbnail.clone().unwrap();
        assert!(thumbnail.starts_with(&[0xff, 0xd8]));

        let document = build_document_message(content).unwrap();
        let document = document.document_message.unwrap();
        assert_eq!(document.thumbnail_width, Some(32));
        assert_eq!(document.thumbnail_height, Some(16));
        assert_eq!(document.jpeg_thumbnail, Some(thumbnail));
    }

    #[test]
    fn builds_group_invite_message() {
        let mut invite =
            GroupInviteContent::new("123456@g.us", "invite-code", 1_700_000_000, "Group")
                .parent_group();
        invite.caption = Some("join".to_owned());
        invite.jpeg_thumbnail = Some(Bytes::from_static(b"thumb"));

        let message = build_group_invite_message(invite).unwrap();
        assert_eq!(message_stanza_type(&message), "text");
        let invite = message.group_invite_message.unwrap();
        assert_eq!(invite.group_jid.as_deref(), Some("123456@g.us"));
        assert_eq!(invite.invite_code.as_deref(), Some("invite-code"));
        assert_eq!(invite.group_name.as_deref(), Some("Group"));
        assert_eq!(
            invite.group_type,
            Some(group_invite_message::GroupType::Parent as i32)
        );

        let enum_message = MessageContent::group_invite(GroupInviteContent::new(
            "123456@g.us",
            "invite-code",
            1,
            "Group",
        ))
        .into_proto()
        .unwrap();
        assert!(enum_message.group_invite_message.is_some());
    }

    #[test]
    fn builds_product_message() {
        let mut snapshot = ProductSnapshotContent::new("sku-1", "Widget", "USD", 12_345_000);
        snapshot.description = Some("Useful widget".to_owned());
        snapshot.product_image = Some(ImageContent::new(sample_uploaded_media(), "image/jpeg"));
        snapshot.product_image_count = Some(1);

        let mut catalog = CatalogSnapshotContent::new();
        catalog.title = Some("Catalog".to_owned());
        catalog.catalog_image = Some(ImageContent::new(sample_uploaded_media(), "image/jpeg"));

        let mut product = ProductContent::new("12345@s.whatsapp.net", snapshot);
        product.catalog = Some(catalog);
        product.body = Some("Body".to_owned());
        product.footer = Some("Footer".to_owned());

        let message = build_product_message(product).unwrap();
        assert_eq!(message_stanza_type(&message), "text");
        let product = message.product_message.unwrap();
        assert_eq!(
            product.business_owner_jid.as_deref(),
            Some("12345@s.whatsapp.net")
        );
        assert_eq!(product.body.as_deref(), Some("Body"));
        let snapshot = product.product.unwrap();
        assert_eq!(snapshot.product_id.as_deref(), Some("sku-1"));
        assert_eq!(snapshot.title.as_deref(), Some("Widget"));
        assert_eq!(snapshot.price_amount1000, Some(12_345_000));
        assert!(snapshot.product_image.is_some());
        assert!(product.catalog.unwrap().catalog_image.is_some());

        let enum_message = MessageContent::product(ProductContent::new(
            "12345@s.whatsapp.net",
            ProductSnapshotContent::new("sku-2", "Other", "USD", 1_000),
        ))
        .into_proto()
        .unwrap();
        assert!(enum_message.product_message.is_some());
    }

    #[test]
    fn builds_poll_event_and_protocol_messages() {
        let poll = build_poll_message(PollContent::new(
            "Lunch?",
            ["Rice", "Noodles"],
            1,
            Bytes::from(vec![7u8; 32]),
        ))
        .unwrap();
        assert!(poll.poll_creation_message_v3.is_some());
        assert_eq!(
            poll.message_context_info
                .as_ref()
                .unwrap()
                .message_secret
                .as_ref()
                .unwrap()
                .len(),
            32
        );

        let event = build_event_message(EventContent {
            description: Some("Planning".to_owned()),
            end_time: Some(1010),
            location: Some(LocationContent::new(-6.2, 106.8).with_name("Office")),
            ..EventContent::new("Standup", 1000, Bytes::from(vec![9u8; 32]))
                .with_join_link("https://call.example.invalid/room")
        })
        .unwrap();
        let event_body = event.event_message.unwrap();
        assert_eq!(event_body.name.as_deref(), Some("Standup"));
        assert_eq!(
            event_body.join_link.as_deref(),
            Some("https://call.example.invalid/room")
        );

        let update_key = build_message_key(
            "123@g.us",
            false,
            "poll-1",
            Some("456@s.whatsapp.net".to_owned()),
        )
        .unwrap();
        let poll_update = build_poll_update_message(
            PollUpdateContent::new(
                update_key.clone(),
                Bytes::from_static(b"encrypted-vote"),
                Bytes::from_static(b"vote-iv"),
            )
            .with_sender_timestamp_ms(1_700_000_001),
        )
        .unwrap();
        let poll_update_body = poll_update.poll_update_message.as_ref().unwrap();
        assert_eq!(
            poll_update_body.poll_creation_message_key.as_ref(),
            Some(&update_key)
        );
        assert_eq!(poll_update_body.sender_timestamp_ms, Some(1_700_000_001));
        assert!(poll_update_body.metadata.is_some());
        let vote = poll_update_body.vote.as_ref().unwrap();
        assert_eq!(vote.enc_payload.as_deref(), Some(&b"encrypted-vote"[..]));
        assert_eq!(vote.enc_iv.as_deref(), Some(&b"vote-iv"[..]));
        assert_eq!(message_stanza_type(&poll_update), "poll");

        let response_key = build_message_key(
            "123@g.us",
            false,
            "event-1",
            Some("456@s.whatsapp.net".to_owned()),
        )
        .unwrap();
        let event_response = build_event_response_message(EventResponseContent::new(
            response_key.clone(),
            Bytes::from_static(b"encrypted-response"),
            Bytes::from_static(b"response-iv"),
        ))
        .unwrap();
        let event_response_body = event_response.enc_event_response_message.unwrap();
        assert_eq!(
            event_response_body.event_creation_message_key.as_ref(),
            Some(&response_key)
        );
        assert_eq!(
            event_response_body.enc_payload.as_deref(),
            Some(&b"encrypted-response"[..])
        );
        assert_eq!(
            event_response_body.enc_iv.as_deref(),
            Some(&b"response-iv"[..])
        );

        let placeholder_key =
            build_message_key("123@s.whatsapp.net", false, "missing-1", None).unwrap();
        let placeholder =
            build_placeholder_resend_request_message([placeholder_key.clone()]).unwrap();
        let protocol = placeholder.protocol_message.unwrap();
        assert_eq!(
            protocol.r#type,
            Some(protocol_message::Type::PeerDataOperationRequestMessage as i32)
        );
        let request = protocol.peer_data_operation_request_message.unwrap();
        assert_eq!(
            request.peer_data_operation_request_type,
            Some(PeerDataOperationRequestType::PlaceholderMessageResend as i32)
        );
        assert_eq!(request.placeholder_message_resend_request.len(), 1);
        assert_eq!(
            request.placeholder_message_resend_request[0].message_key,
            Some(placeholder_key)
        );
        assert!(build_placeholder_resend_request_message(Vec::<MessageKey>::new()).is_err());

        let key = build_message_key("123@s.whatsapp.net", true, "msg-1", None).unwrap();
        let edit = build_edit_message(EditContent {
            key: key.clone(),
            message: build_text_message("edited").unwrap(),
            timestamp_ms: Some(99),
        })
        .unwrap();
        let protocol = edit.protocol_message.unwrap();
        assert_eq!(
            protocol.r#type,
            Some(protocol_message::Type::MessageEdit as i32)
        );
        assert!(protocol.edited_message.is_some());

        let delete = build_delete_message(DeleteContent { key: key.clone() }).unwrap();
        assert_eq!(
            delete.protocol_message.unwrap().r#type,
            Some(protocol_message::Type::Revoke as i32)
        );

        let pin = build_pin_message(PinContent {
            key: key.clone(),
            action: PinAction::Pin,
            sender_timestamp_ms: Some(100),
        })
        .unwrap();
        assert_eq!(
            pin.pin_in_chat_message.unwrap().r#type,
            Some(pin_in_chat_message::Type::PinForAll as i32)
        );

        let disappearing =
            build_disappearing_mode_message(DisappearingModeContent::new(86_400)).unwrap();
        let inner = disappearing
            .ephemeral_message
            .as_ref()
            .and_then(|wrapper| wrapper.message.as_deref())
            .unwrap();
        let protocol = inner.protocol_message.as_ref().unwrap();
        assert_eq!(
            protocol.r#type,
            Some(protocol_message::Type::EphemeralSetting as i32)
        );
        assert_eq!(protocol.ephemeral_expiration, Some(86_400));
        assert!(protocol.disappearing_mode.is_some());
        assert_eq!(message_stanza_type(&disappearing), "text");
    }

    #[cfg(feature = "noise")]
    #[test]
    fn derives_and_decrypts_poll_vote_and_event_response_payloads() {
        let poll_key = build_message_key(
            "123@g.us",
            false,
            "poll-parent-1",
            Some("456@s.whatsapp.net".to_owned()),
        )
        .unwrap();
        let poll_secret = Bytes::from(vec![7u8; 32]);
        let poll_vote = PollVoteContent::from_option_names(
            poll_key.clone(),
            ["Rice"],
            poll_secret.clone(),
            "456@s.whatsapp.net",
            "789:1@s.whatsapp.net",
        )
        .unwrap()
        .with_sender_timestamp_ms(1_700_000_001);
        let poll_update = build_encrypted_poll_update_content_with_iv(
            poll_vote,
            Bytes::from_static(b"poll-vote-iv"),
        )
        .unwrap();
        assert_eq!(poll_update.encrypted_iv.as_ref(), b"poll-vote-iv");
        assert_eq!(poll_update.sender_timestamp_ms, Some(1_700_000_001));
        assert!(poll_update.include_metadata);
        let poll_message = build_poll_update_message(poll_update).unwrap();
        let poll_update = poll_message.poll_update_message.as_ref().unwrap();
        let vote = poll_update.vote.as_ref().unwrap();
        let selected_hash = Bytes::copy_from_slice(&Sha256::digest(b"Rice"));
        let plaintext_vote = wa_proto::proto::message::PollVoteMessage {
            selected_options: vec![selected_hash.clone()],
        }
        .encode_to_vec();
        assert_ne!(vote.enc_payload.as_deref(), Some(plaintext_vote.as_slice()));

        let decrypted_vote = decrypt_poll_vote_message(
            vote,
            "poll-parent-1",
            "456@s.whatsapp.net",
            "789@s.whatsapp.net",
            &poll_secret,
        )
        .unwrap();
        assert_eq!(decrypted_vote.selected_options.len(), 1);
        assert_eq!(decrypted_vote.selected_options[0], selected_hash);
        assert!(
            decrypt_poll_vote_message(
                vote,
                "poll-parent-1",
                "456@s.whatsapp.net",
                "790@s.whatsapp.net",
                &poll_secret,
            )
            .is_err()
        );

        let event_key = build_message_key(
            "123@g.us",
            false,
            "event-parent-1",
            Some("456@s.whatsapp.net".to_owned()),
        )
        .unwrap();
        let event_secret = Bytes::from(vec![9u8; 32]);
        let event_payload = EventResponsePayload::new(
            event_key.clone(),
            EventResponseKind::Going,
            event_secret.clone(),
            "456@s.whatsapp.net",
            "789:1@s.whatsapp.net",
        )
        .with_timestamp_ms(1_700_000_002)
        .with_extra_guest_count(2);
        let event_response = build_encrypted_event_response_content_with_iv(
            event_payload,
            Bytes::from_static(b"event-rsvpiv"),
        )
        .unwrap();
        assert_eq!(event_response.encrypted_iv.as_ref(), b"event-rsvpiv");
        let event_message = build_event_response_message(event_response).unwrap();
        let encrypted_event = event_message.enc_event_response_message.as_ref().unwrap();
        assert_eq!(
            encrypted_event.event_creation_message_key.as_ref(),
            Some(&event_key)
        );
        let decrypted_event = decrypt_event_response_message(
            encrypted_event,
            "event-parent-1",
            "456@s.whatsapp.net",
            "789@s.whatsapp.net",
            &event_secret,
        )
        .unwrap();
        assert_eq!(
            decrypted_event.response,
            Some(event_response_message::EventResponseType::Going as i32)
        );
        assert_eq!(decrypted_event.timestamp_ms, Some(1_700_000_002));
        assert_eq!(decrypted_event.extra_guest_count, Some(2));
        assert!(
            decrypt_event_response_message(
                encrypted_event,
                "event-parent-1",
                "456@s.whatsapp.net",
                "789@s.whatsapp.net",
                &[9u8; 31],
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_content_builder_inputs() {
        assert!(
            build_text_message(
                TextMessage::new("hello")
                    .with_context(MessageContext::new().with_mention("invalid"))
            )
            .is_err()
        );
        assert!(build_contact_message(ContactContent::new("", "vcard")).is_err());
        assert!(build_contacts_message(ContactsContent::new("Team", [])).is_err());
        assert!(build_location_message(LocationContent::new(91.0, 0.0)).is_err());
        assert!(
            build_live_location_message(LiveLocationContent {
                speed_in_mps: Some(-1.0),
                ..LiveLocationContent::new(0.0, 0.0)
            })
            .is_err()
        );
        assert!(build_reaction_message(ReactionContent::new(MessageKey::default(), "+1")).is_err());
        assert!(
            build_poll_message(PollContent::new(
                "Poll",
                ["Only one"],
                1,
                Bytes::from(vec![1u8; 32]),
            ))
            .is_err()
        );
        assert!(
            build_poll_message(PollContent::new(
                "Poll",
                ["A", "B"],
                3,
                Bytes::from(vec![1u8; 32]),
            ))
            .is_err()
        );
        let err = match build_poll_message(PollContent::new(
            "Poll",
            ["A", "A"],
            1,
            Bytes::from(vec![1u8; 32]),
        )) {
            Ok(_) => panic!("duplicate poll options should be rejected"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CoreError::Payload(message) if message == "poll options must be unique"
        ));
        assert!(
            build_event_message(EventContent {
                end_time: Some(9),
                ..EventContent::new("Event", 10, Bytes::from(vec![1u8; 32]))
            })
            .is_err()
        );
        assert!(
            build_event_message(
                EventContent::new("Event", 10, Bytes::from(vec![1u8; 32])).with_join_link("")
            )
            .is_err()
        );
        assert!(
            build_poll_update_message(PollUpdateContent::new(
                MessageKey::default(),
                Bytes::from_static(b"payload"),
                Bytes::from_static(b"iv")
            ))
            .is_err()
        );
        let key = build_message_key(
            "123@g.us",
            false,
            "poll-1",
            Some("456@s.whatsapp.net".to_owned()),
        )
        .unwrap();
        assert!(
            build_poll_update_message(PollUpdateContent::new(
                key.clone(),
                Bytes::new(),
                Bytes::from_static(b"iv")
            ))
            .is_err()
        );
        assert!(
            build_event_response_message(EventResponseContent::new(
                key,
                Bytes::from_static(b"payload"),
                Bytes::new()
            ))
            .is_err()
        );
        #[cfg(feature = "noise")]
        {
            let key = build_message_key(
                "123@g.us",
                false,
                "poll-1",
                Some("456@s.whatsapp.net".to_owned()),
            )
            .unwrap();
            assert!(
                build_encrypted_poll_update_content_with_iv(
                    PollVoteContent::new(
                        key.clone(),
                        [Bytes::from(vec![1u8; 31])],
                        Bytes::from(vec![1u8; 32]),
                        "456@s.whatsapp.net",
                        "789@s.whatsapp.net",
                    ),
                    Bytes::from_static(b"poll-vote-iv"),
                )
                .is_err()
            );
            assert!(
                build_encrypted_poll_update_content_with_iv(
                    PollVoteContent::new(
                        key.clone(),
                        [Bytes::from(vec![1u8; 32])],
                        Bytes::from(vec![1u8; 31]),
                        "456@s.whatsapp.net",
                        "789@s.whatsapp.net",
                    ),
                    Bytes::from_static(b"poll-vote-iv"),
                )
                .is_err()
            );
            let err = match build_encrypted_poll_update_content_with_iv(
                PollVoteContent::new(
                    key.clone(),
                    [Bytes::from(vec![1u8; 32]), Bytes::from(vec![1u8; 32])],
                    Bytes::from(vec![1u8; 32]),
                    "456@s.whatsapp.net",
                    "789@s.whatsapp.net",
                ),
                Bytes::from_static(b"poll-vote-iv"),
            ) {
                Ok(_) => panic!("duplicate selected poll option hashes should be rejected"),
                Err(err) => err,
            };
            assert!(matches!(
                err,
                CoreError::Payload(message)
                    if message == "selected poll option hashes must be unique"
            ));
            assert!(
                build_encrypted_event_response_content_with_iv(
                    EventResponsePayload::new(
                        key.clone(),
                        EventResponseKind::Going,
                        Bytes::from(vec![1u8; 32]),
                        "456@s.whatsapp.net",
                        "789@s.whatsapp.net",
                    ),
                    Bytes::from_static(b"short-iv"),
                )
                .is_err()
            );
            let err = match build_encrypted_event_response_content_with_iv(
                EventResponsePayload::new(
                    key,
                    EventResponseKind::Going,
                    Bytes::from(vec![1u8; 32]),
                    "456@s.whatsapp.net",
                    "789@s.whatsapp.net",
                )
                .with_extra_guest_count(-1),
                Bytes::from_static(b"event-rsvpiv"),
            ) {
                Ok(_) => panic!("negative extra guest count should be rejected"),
                Err(err) => err,
            };
            assert!(matches!(
                err,
                CoreError::Payload(message)
                    if message == "event response extra guest count must not be negative"
            ));
        }
        assert!(
            build_image_message(ImageContent::new(
                sample_uploaded_media_without_path(),
                "image/jpeg"
            ))
            .is_err()
        );
        assert!(
            build_image_message(ImageContent::new(
                UploadedMedia::new(
                    Bytes::from(vec![1u8; 31]),
                    Bytes::from(vec![2u8; 32]),
                    Bytes::from(vec![3u8; 32]),
                    10,
                )
                .with_direct_path("/media"),
                "image/jpeg",
            ))
            .is_err()
        );
        assert!(
            build_group_invite_message(GroupInviteContent::new(
                "123@s.whatsapp.net",
                "code",
                1,
                "Group",
            ))
            .is_err()
        );
        assert!(
            build_product_message(ProductContent::new(
                "123456@g.us",
                ProductSnapshotContent::new("sku", "Title", "USD", 1),
            ))
            .is_err()
        );
        assert!(
            build_product_message(ProductContent::new(
                "123@s.whatsapp.net",
                ProductSnapshotContent::new("sku", "Title", "USD", -1),
            ))
            .is_err()
        );
    }

    #[test]
    fn generates_sorted_participant_hash_v2() {
        let hash =
            generate_participant_hash_v2(["999:2@s.whatsapp.net", "123:1@s.whatsapp.net"]).unwrap();
        assert_eq!(hash, "2:305nmK");
        assert_eq!(
            hash,
            generate_participant_hash_v2(["123:1@s.whatsapp.net", "999:2@s.whatsapp.net",])
                .unwrap()
        );
        assert!(generate_participant_hash_v2(["invalid"]).is_err());
    }

    #[test]
    fn builds_validated_message_key() {
        let key = build_message_key(
            "123@s.whatsapp.net",
            true,
            "msg-1",
            Some("456@s.whatsapp.net".to_owned()),
        )
        .unwrap();

        assert_eq!(key.remote_jid.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(key.from_me, Some(true));
        assert_eq!(key.id.as_deref(), Some("msg-1"));
        assert_eq!(key.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert!(build_message_key("not-a-jid", true, "msg-1", None).is_err());
        assert!(build_message_key("123@s.whatsapp.net", true, "", None).is_err());
    }

    #[test]
    fn builds_receipt_nodes_with_list_and_timestamp() {
        let receipt = MessageReceipt::new(
            "123@s.whatsapp.net",
            Some("456@s.whatsapp.net".to_owned()),
            ["m1", "m2", "m3"],
        );
        let node = build_receipt_node(&receipt, MessageReceiptType::Read, Some(99)).unwrap();

        assert_eq!(node.tag, "receipt");
        assert_eq!(node.attrs["id"], "m1");
        assert_eq!(node.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(node.attrs["participant"], "456@s.whatsapp.net");
        assert_eq!(node.attrs["type"], "read");
        assert_eq!(node.attrs["t"], "99");
        let Some(BinaryNodeContent::Nodes(content)) = &node.content else {
            panic!("receipt should contain list node");
        };
        assert_eq!(content.len(), 1);
        assert_eq!(content[0].tag, "list");
        let Some(BinaryNodeContent::Nodes(items)) = &content[0].content else {
            panic!("list should contain item nodes");
        };
        assert_eq!(items[0].attrs["id"], "m2");
        assert_eq!(items[1].attrs["id"], "m3");
    }

    #[test]
    fn builds_sender_receipt_with_recipient_addressing() {
        let receipt = MessageReceipt::new(
            "123@s.whatsapp.net",
            Some("456:1@s.whatsapp.net".to_owned()),
            ["m1"],
        );
        let node = build_receipt_node(&receipt, MessageReceiptType::Sender, None).unwrap();

        assert_eq!(node.attrs["id"], "m1");
        assert_eq!(node.attrs["type"], "sender");
        assert_eq!(node.attrs["recipient"], "123@s.whatsapp.net");
        assert_eq!(node.attrs["to"], "456:1@s.whatsapp.net");
        assert!(!node.attrs.contains_key("participant"));
    }

    #[test]
    fn builds_call_reject_node() {
        let node =
            build_call_reject_node("999:2@s.whatsapp.net", "123@s.whatsapp.net", "call-1").unwrap();

        assert_eq!(node.tag, "call");
        assert_eq!(node.attrs["from"], "999:2@s.whatsapp.net");
        assert_eq!(node.attrs["to"], "123@s.whatsapp.net");
        let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
            panic!("call reject should contain reject child");
        };
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "reject");
        assert_eq!(children[0].attrs["call-id"], "call-1");
        assert_eq!(children[0].attrs["call-creator"], "123@s.whatsapp.net");
        assert_eq!(children[0].attrs["count"], "0");

        assert!(build_call_reject_node("invalid", "123@s.whatsapp.net", "call-1").is_err());
        assert!(build_call_reject_node("999@s.whatsapp.net", "invalid", "call-1").is_err());
        assert!(build_call_reject_node("999@s.whatsapp.net", "123@s.whatsapp.net", "").is_err());
    }

    #[test]
    fn builds_and_parses_media_retry_request_node() {
        let key = build_message_key(
            "123@s.whatsapp.net",
            false,
            "msg-1",
            Some("456:1@s.whatsapp.net".to_owned()),
        )
        .unwrap();
        let payload = MediaRetryPayload::new(
            Bytes::from_static(b"ciphertext"),
            Bytes::from([4u8; 12].to_vec()),
        );
        let node = build_media_retry_request_node(&key, "999:7@c.us", payload.clone()).unwrap();

        assert_eq!(node.tag, "receipt");
        assert_eq!(node.attrs["id"], "msg-1");
        assert_eq!(node.attrs["to"], "999@s.whatsapp.net");
        assert_eq!(node.attrs["type"], "server-error");
        let encrypt = child_node(&node, "encrypt").unwrap();
        assert_eq!(
            node_bytes(child_node(encrypt, "enc_p").unwrap()).unwrap(),
            payload.ciphertext
        );
        assert_eq!(
            node_bytes(child_node(encrypt, "enc_iv").unwrap()).unwrap(),
            payload.iv
        );
        let retry = child_node(&node, "rmr").unwrap();
        assert_eq!(retry.attrs["jid"], "123@s.whatsapp.net");
        assert_eq!(retry.attrs["from_me"], "false");
        assert_eq!(retry.attrs["participant"], "456:1@s.whatsapp.net");

        let update = parse_media_retry_update(&node).unwrap();
        assert_eq!(update.key, key);
        assert_eq!(update.media, Some(payload));
        assert_eq!(update.error, None);
    }

    #[test]
    fn parses_media_retry_error_update() {
        let node = BinaryNode::new("receipt")
            .with_attr("id", "msg-1")
            .with_content(vec![
                BinaryNode::new("rmr")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_attr("from_me", "true"),
                BinaryNode::new("error")
                    .with_attr("code", "2")
                    .with_attr("text", "missing"),
            ]);

        let update = parse_media_retry_update(&node).unwrap();
        assert_eq!(
            update.key,
            build_message_key("123@s.whatsapp.net", true, "msg-1", None).unwrap()
        );
        assert_eq!(update.media, None);
        assert_eq!(
            update.error,
            Some(MediaRetryError {
                code: 2,
                text: Some("missing".to_owned()),
                status_code: 404,
            })
        );
    }

    #[test]
    fn parses_media_retry_notification_update() {
        let node = BinaryNode::new("notification")
            .with_attr("id", "msg-2")
            .with_attr("type", "mediaretry")
            .with_content(vec![
                BinaryNode::new("rmr")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_attr("from_me", "false")
                    .with_attr("participant", "456@s.whatsapp.net"),
                BinaryNode::new("encrypt").with_content(vec![
                    BinaryNode::new("enc_p").with_content(Bytes::from_static(b"retry-payload")),
                    BinaryNode::new("enc_iv").with_content(Bytes::from(vec![7u8; 12])),
                ]),
            ]);

        let update = parse_media_retry_update(&node).unwrap();
        assert_eq!(
            update.key,
            build_message_key(
                "123@s.whatsapp.net",
                false,
                "msg-2",
                Some("456@s.whatsapp.net".to_owned())
            )
            .unwrap()
        );
        assert_eq!(
            update.media,
            Some(MediaRetryPayload::new(
                Bytes::from_static(b"retry-payload"),
                Bytes::from(vec![7u8; 12])
            ))
        );
        assert_eq!(update.error, None);
    }

    #[cfg(feature = "noise")]
    #[test]
    fn builds_encrypted_media_retry_request_node() {
        let key = build_message_key("123@s.whatsapp.net", false, "msg-1", None).unwrap();
        let node = build_encrypted_media_retry_request_node(&key, "999@s.whatsapp.net", &[8u8; 32])
            .unwrap();
        let update = parse_media_retry_update(&node).unwrap();
        let payload = update.media.unwrap();
        assert_eq!(payload.iv.len(), 12);
        assert!(!payload.ciphertext.is_empty());
        assert!(
            build_encrypted_media_retry_request_node(&key, "999@s.whatsapp.net", &[8u8; 31])
                .is_err()
        );
    }

    #[test]
    fn aggregates_receipts_from_message_keys() {
        let keys = vec![
            build_message_key(
                "123@s.whatsapp.net",
                false,
                "m1",
                Some("456@s.whatsapp.net".to_owned()),
            )
            .unwrap(),
            build_message_key(
                "123@s.whatsapp.net",
                false,
                "m2",
                Some("456@s.whatsapp.net".to_owned()),
            )
            .unwrap(),
            build_message_key("123@s.whatsapp.net", true, "own", None).unwrap(),
            build_message_key("999@s.whatsapp.net", false, "m3", None).unwrap(),
        ];

        let receipts = aggregate_receipts_from_message_keys(&keys).unwrap();
        assert_eq!(
            receipts,
            vec![
                MessageReceipt {
                    remote_jid: "123@s.whatsapp.net".to_owned(),
                    participant: Some("456@s.whatsapp.net".to_owned()),
                    message_ids: vec!["m1".to_owned(), "m2".to_owned()],
                },
                MessageReceipt {
                    remote_jid: "999@s.whatsapp.net".to_owned(),
                    participant: None,
                    message_ids: vec!["m3".to_owned()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn builds_direct_message_relay_with_participant_encryptions() {
        let message = build_text_message("hello").unwrap();
        let encryptor = RecordingEncryptor::default();
        let relay = build_direct_message_relay(
            "123@s.whatsapp.net",
            message.clone(),
            &[
                MessageRelayRecipient::new("123:1@s.whatsapp.net"),
                MessageRelayRecipient::own_device("999:2@s.whatsapp.net"),
            ],
            &encryptor,
            MessageRelayOptions::new()
                .with_message_id("msg-1")
                .with_sender_jid("999@s.whatsapp.net")
                .with_attribute("category", "peer")
                .with_encryption_attribute("decrypt-fail", "hide")
                .with_node(
                    BinaryNode::new("device-identity")
                        .with_content(Bytes::from_static(b"identity")),
                ),
        )
        .await
        .unwrap();

        assert_eq!(relay.message_id, "msg-1");
        assert_eq!(relay.recipient_count, 2);
        assert!(relay.should_include_device_identity);
        assert_eq!(relay.node.tag, "message");
        assert_eq!(relay.node.attrs["id"], "msg-1");
        assert_eq!(relay.node.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(relay.node.attrs["type"], "text");
        assert_eq!(relay.node.attrs["category"], "peer");
        assert_eq!(relay.node.attrs["phash"], "2:305nmK");

        let Some(BinaryNodeContent::Nodes(content)) = &relay.node.content else {
            panic!("relay node should contain child nodes");
        };
        assert_eq!(content.len(), 2);
        assert_eq!(content[0].tag, "participants");
        assert_eq!(content[1].tag, "device-identity");
        let Some(BinaryNodeContent::Nodes(participants)) = &content[0].content else {
            panic!("participants should contain device nodes");
        };
        assert_eq!(participants.len(), 2);
        assert_eq!(participants[0].attrs["jid"], "123:1@s.whatsapp.net");
        let enc = only_child(&participants[0]);
        assert_eq!(enc.attrs["v"], "2");
        assert_eq!(enc.attrs["type"], "msg");
        assert_eq!(enc.attrs["decrypt-fail"], "hide");
        let own_enc = only_child(&participants[1]);
        assert_eq!(own_enc.attrs["type"], "pkmsg");

        let calls = encryptor.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        let normal_plaintext = Message::decode(calls[0].1.clone()).unwrap();
        assert_eq!(normal_plaintext, message);
        let own_plaintext = Message::decode(calls[1].1.clone()).unwrap();
        let device_sent = own_plaintext.device_sent_message.unwrap();
        assert_eq!(
            device_sent.destination_jid.as_deref(),
            Some("123@s.whatsapp.net")
        );
        assert_eq!(*device_sent.message.unwrap(), message);
    }

    #[tokio::test]
    async fn direct_message_relay_adds_device_identity_for_pre_key_ciphertext() {
        let relay = build_direct_message_relay(
            "123@s.whatsapp.net",
            build_text_message("hello").unwrap(),
            &[MessageRelayRecipient::new("123:2@s.whatsapp.net")],
            &RecordingEncryptor::default(),
            MessageRelayOptions::new()
                .with_message_id("msg-1")
                .with_device_identity_node(
                    BinaryNode::new("device-identity")
                        .with_content(Bytes::from_static(b"stored-identity")),
                ),
        )
        .await
        .unwrap();

        assert!(relay.should_include_device_identity);
        let Some(BinaryNodeContent::Nodes(content)) = &relay.node.content else {
            panic!("relay node should contain child nodes");
        };
        assert_eq!(content.len(), 2);
        assert_eq!(content[0].tag, "participants");
        assert_eq!(content[1].tag, "device-identity");
        assert_eq!(
            content[1].content,
            Some(BinaryNodeContent::Bytes(Bytes::from_static(
                b"stored-identity"
            )))
        );
    }

    #[tokio::test]
    async fn direct_message_relay_does_not_duplicate_explicit_device_identity() {
        let relay = build_direct_message_relay(
            "123@s.whatsapp.net",
            build_text_message("hello").unwrap(),
            &[MessageRelayRecipient::new("123:2@s.whatsapp.net")],
            &RecordingEncryptor::default(),
            MessageRelayOptions::new()
                .with_message_id("msg-1")
                .with_device_identity_node(
                    BinaryNode::new("device-identity").with_content(Bytes::from_static(b"auto")),
                )
                .with_node(
                    BinaryNode::new("device-identity")
                        .with_content(Bytes::from_static(b"explicit")),
                ),
        )
        .await
        .unwrap();

        let Some(BinaryNodeContent::Nodes(content)) = &relay.node.content else {
            panic!("relay node should contain child nodes");
        };
        assert_eq!(content.len(), 2);
        assert_eq!(content[1].tag, "device-identity");
        assert_eq!(
            content[1].content,
            Some(BinaryNodeContent::Bytes(Bytes::from_static(b"explicit")))
        );
    }

    #[tokio::test]
    async fn direct_message_relay_allows_participant_hash_override() {
        let relay = build_direct_message_relay(
            "123@s.whatsapp.net",
            build_text_message("hello").unwrap(),
            &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
            &RecordingEncryptor::default(),
            MessageRelayOptions::new()
                .with_message_id("msg-1")
                .with_attribute("phash", "2:manual"),
        )
        .await
        .unwrap();

        assert_eq!(relay.node.attrs["phash"], "2:manual");
    }

    #[tokio::test]
    async fn builds_group_sender_key_message_relay_with_root_encryption() {
        let message = build_text_message("hello group").unwrap();
        let encryptor = RecordingEncryptor::sender_key();
        let relay = build_group_sender_key_message_relay(
            "123@g.us",
            message.clone(),
            &encryptor,
            MessageRelayOptions::new()
                .with_message_id("group-msg-1")
                .with_attribute("category", "peer")
                .with_encryption_attribute("decrypt-fail", "hide")
                .with_device_identity_node(
                    BinaryNode::new("device-identity").with_content(Bytes::from_static(b"ignore")),
                )
                .with_node(BinaryNode::new("meta").with_attr("source", "test")),
        )
        .await
        .unwrap();

        assert_eq!(relay.message_id, "group-msg-1");
        assert_eq!(relay.recipient_count, 1);
        assert!(!relay.should_include_device_identity);
        assert_eq!(relay.node.tag, "message");
        assert_eq!(relay.node.attrs["id"], "group-msg-1");
        assert_eq!(relay.node.attrs["to"], "123@g.us");
        assert_eq!(relay.node.attrs["type"], "text");
        assert_eq!(relay.node.attrs["category"], "peer");
        assert!(!relay.node.attrs.contains_key("phash"));

        let Some(BinaryNodeContent::Nodes(content)) = &relay.node.content else {
            panic!("relay node should contain child nodes");
        };
        assert_eq!(content.len(), 2);
        assert_eq!(content[0].tag, "enc");
        assert_eq!(content[0].attrs["v"], "2");
        assert_eq!(content[0].attrs["type"], "skmsg");
        assert_eq!(content[0].attrs["decrypt-fail"], "hide");
        assert_eq!(content[1].tag, "meta");
        assert_eq!(content[1].attrs["source"], "test");
        assert!(content.iter().all(|node| node.tag != "participants"));
        assert!(content.iter().all(|node| node.tag != "device-identity"));

        let calls = encryptor.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "123@g.us");
        let plaintext = Message::decode(calls[0].1.clone()).unwrap();
        assert_eq!(plaintext, message);
        assert_eq!(
            content[0].content,
            Some(BinaryNodeContent::Bytes(calls[0].1.clone()))
        );
    }

    #[tokio::test]
    async fn rejects_invalid_group_sender_key_message_relay_inputs() {
        let message = build_text_message("hello").unwrap();
        let sender_key_encryptor = RecordingEncryptor::sender_key();
        assert!(
            build_group_sender_key_message_relay(
                "123@s.whatsapp.net",
                message.clone(),
                &sender_key_encryptor,
                MessageRelayOptions::new(),
            )
            .await
            .is_err()
        );

        let message_encryptor = RecordingEncryptor::default();
        assert!(
            build_group_sender_key_message_relay(
                "123@g.us",
                message,
                &message_encryptor,
                MessageRelayOptions::new(),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_invalid_message_relay_inputs() {
        let message = build_text_message("hello").unwrap();
        let encryptor = RecordingEncryptor::default();
        assert!(
            build_direct_message_relay(
                "invalid",
                message.clone(),
                &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
                &encryptor,
                MessageRelayOptions::new(),
            )
            .await
            .is_err()
        );
        assert!(
            build_direct_message_relay(
                "123@s.whatsapp.net",
                message.clone(),
                &[],
                &encryptor,
                MessageRelayOptions::new(),
            )
            .await
            .is_err()
        );
        assert!(
            build_direct_message_relay(
                "123@s.whatsapp.net",
                message,
                &[MessageRelayRecipient::new("invalid")],
                &encryptor,
                MessageRelayOptions::new(),
            )
            .await
            .is_err()
        );
    }

    fn sample_uploaded_media() -> UploadedMedia {
        sample_uploaded_media_without_path()
            .with_url("https://media.example.invalid/file")
            .with_direct_path("/v/t62.7118-24/file")
            .with_media_key_timestamp(1_700_000_000)
    }

    fn sample_uploaded_media_without_path() -> UploadedMedia {
        UploadedMedia::new(
            Bytes::from(vec![1u8; 32]),
            Bytes::from(vec![2u8; 32]),
            Bytes::from(vec![3u8; 32]),
            1024,
        )
    }

    fn future_proof_message(message: Message) -> FutureProofMessage {
        FutureProofMessage {
            message: Some(Box::new(message)),
        }
    }

    #[cfg(all(feature = "image", unix))]
    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    #[cfg(all(feature = "image", unix))]
    fn test_message_path(label: &str) -> std::path::PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("wa-core-message-{label}-{suffix}"))
    }

    fn only_child(node: &BinaryNode) -> &BinaryNode {
        let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
            panic!("node should contain children");
        };
        assert_eq!(children.len(), 1);
        &children[0]
    }
}
