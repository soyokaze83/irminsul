//! High-level WhatsApp Web client facade.
//!
//! This crate wraps the protocol crates in an explicit `Client` API with typed
//! events, auth stores, connection validation, message helpers, media helpers,
//! and group/chat/account operations.
//!
//! WhatsApp Web is a private protocol and can change without notice. Treat live
//! usage as experimental, keep session material private, and use accounts you
//! control.
//!
//! ```no_run
//! use wa_client::prelude::*;
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let store = SqliteAuthStore::open(".wa/session.sqlite").await?;
//!     let client = Client::builder(store).connect().await?;
//!     let _events = client.subscribe();
//!
//!     let qr_payload = client.pairing_qr_data("reference-from-server");
//!     println!("QR payload bytes: {}", qr_payload.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! See `docs/api_transition_guide.md` and the examples in
//! `crates/wa-client/examples` for public workflow sketches.
#![forbid(unsafe_code)]

#[cfg(feature = "noise")]
use async_trait::async_trait;
#[cfg(feature = "noise")]
use bytes::Bytes;
#[cfg(feature = "noise")]
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "noise")]
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
#[cfg(feature = "noise")]
use wa_binary::{JidServer, jid_decode, jid_encode, jid_normalized_user};
#[cfg(feature = "noise")]
use wa_core::BinaryNodeContent;
#[cfg(feature = "noise")]
use wa_core::build_call_reject_node;
#[cfg(feature = "noise")]
use wa_core::{
    AccountJidKind, AppStatePatchBundle, AppStatePatchState, AuthCredentials, BlocklistAction,
    ChatMutationMessageRange, ChatMutationPatch, ConnectionValidation, ContactSyncAction,
    FrameSink, FrameStream, LabelEditMutation, LidPnMapping, LidPnMappingStore,
    LinkCodeCompanionRegistration, NoiseCertificateVerifier, PairingCodeRequest, PreKeyUpload,
    PresenceState, QuickReplyMutation, RetryReceiptSessionBundle, RetryResendPreparation,
    RetryResendTarget, RetrySessionAction, RetrySessionSnapshot, SignalRepository, SignedPreKey,
    SignedPreKeyRotation, StoreSignalRepository, USyncDeviceJid, USyncLidMapping,
    ValidatedConnection, XEdDsaNoiseCertificateVerifier, account_jid_kind,
    build_app_state_patch_bundle, build_archive_chat_patch, build_blocklist_update_query,
    build_chat_label_association_patch, build_chat_state_node, build_contact_patch,
    build_delete_chat_patch, build_device_identity_node, build_device_query,
    build_e2e_session_query, build_encrypted_media_retry_request_node,
    build_key_bundle_digest_query, build_label_edit_patch, build_lid_mapping_query,
    build_mark_chat_read_patch, build_message_label_association_patch, build_mute_chat_patch,
    build_pairing_code_request, build_pairing_qr_data, build_pin_chat_patch,
    build_placeholder_resend_request_message, build_pre_key_count_query,
    build_presence_update_node, build_push_name_patch, build_quick_reply_patch,
    build_signed_pre_key_rotation, build_star_message_patch, build_tc_token_issue_query,
    confirm_pre_key_upload, credentials_with_rotated_signed_pre_key, current_pre_key_status,
    encrypt_chat_mutation_patch, extract_device_jids, handle_link_code_companion_reg_notification,
    handle_pair_device_challenge, handle_pair_success, is_lid_signal_jid, lid_mappings_from_result,
    lid_user_jid, load_or_init_credentials, mapped_lid_session_jid, mark_tc_token_issued,
    normalize_account_jid, parse_e2e_sessions_node, parse_key_bundle_digest_response,
    parse_pre_key_count_response, parse_pre_key_upload_response,
    parse_signed_pre_key_rotation_response, placeholder_resend_request_from_web_message,
    pn_user_jid, prepare_pre_key_upload, privacy_token_notification_sender_lid,
    relay_recipients_from_device_jids, retry_receipt_session_bundle, save_credentials,
    store_tc_tokens_from_issue_result, store_tc_tokens_from_privacy_token_notification,
    validate_connection,
};
use wa_core::{
    AccountMutationKind, AppStateCollection, AppStateCollectionRequest, AppStateQueryKind,
    BinaryNode, Browser, BusinessCatalog, BusinessCatalogCollection, BusinessCatalogQuery,
    BusinessCollectionsQuery, BusinessOrderDetails, BusinessProduct, BusinessProductCreate,
    BusinessProductUpdate, BusinessProfile, BusinessProfileUpdate, ClientConfig,
    CommunityLinkedGroup, CommunityLinkedGroups, CommunityMutationKind, Connection,
    ConnectionState, CoreResult, DirtyBitType, Event, EventHub, GroupInviteV4,
    GroupJoinApprovalMode, GroupJoinRequest, GroupJoinRequestAction, GroupJoinRequestActionResult,
    GroupMemberAddMode, GroupMetadata, GroupMutationKind, GroupParticipantAction,
    GroupParticipantActionResult, GroupParticipantRole, GroupSettingUpdate, GroupUpdateEvent,
    MediaConnectionInfo, MediaRetryPayload, MessageCappingInfo, MessageContent, MessageEncryptor,
    MessageEvent, MessageKey, MessageReceipt, MessageReceiptType, MessageRelay,
    MessageRelayOptions, MessageRelayRecipient, NackReason, NewsletterAction,
    NewsletterLiveUpdateSubscription, NewsletterMetadata, NewsletterMetadataLookup,
    NewsletterMetadataUpdate, OnWhatsAppResult, PrivacyCategory, PrivacySettings, PrivacyValue,
    ProfilePictureType, ProtoMessage, QueryManager, ReachoutTimelockState, TextMessage,
    USyncBotProfile, USyncDisappearingModeResult, USyncQuery, USyncQueryResult, USyncStatusResult,
    aggregate_receipts_from_message_keys, bot_profiles_from_result,
    build_account_reachout_timelock_query, build_ack_node, build_app_state_patch_query,
    build_app_state_sync_query, build_blocklist_query, build_bot_profile_query,
    build_business_catalog_query, build_business_collections_query,
    build_business_cover_photo_delete_query, build_business_cover_photo_update_query,
    build_business_order_details_query, build_business_product_create_query,
    build_business_product_delete_query, build_business_product_update_query,
    build_business_profile_query, build_business_profile_update_query, build_clean_dirty_bits_node,
    build_community_accept_invite_query, build_community_accept_invite_v4_query,
    build_community_create_group_query, build_community_create_query,
    build_community_description_query, build_community_ephemeral_query,
    build_community_invite_code_query, build_community_invite_info_query,
    build_community_join_approval_mode_query, build_community_join_request_action_query,
    build_community_join_request_list_query, build_community_leave_query,
    build_community_link_group_query, build_community_linked_groups_query,
    build_community_member_add_mode_query, build_community_metadata_query,
    build_community_participants_query, build_community_participating_query,
    build_community_revoke_invite_query, build_community_revoke_invite_v4_query,
    build_community_setting_query, build_community_subject_query,
    build_community_unlink_group_query, build_default_disappearing_mode_query,
    build_direct_message_relay, build_disappearing_mode_query, build_group_accept_invite_query,
    build_group_accept_invite_v4_query, build_group_create_query, build_group_description_query,
    build_group_ephemeral_query, build_group_invite_code_query, build_group_invite_info_query,
    build_group_join_approval_mode_query, build_group_join_request_action_query,
    build_group_join_request_list_query, build_group_leave_query,
    build_group_member_add_mode_query, build_group_metadata_query, build_group_participants_query,
    build_group_participating_query, build_group_revoke_invite_query,
    build_group_revoke_invite_v4_query, build_group_sender_key_message_relay,
    build_group_setting_query, build_group_subject_query, build_media_connection_query,
    build_media_retry_request_node, build_message_capping_info_query, build_nack_node,
    build_newsletter_action_query, build_newsletter_admin_count_query,
    build_newsletter_change_owner_query, build_newsletter_create_query,
    build_newsletter_demote_query, build_newsletter_live_updates_query,
    build_newsletter_message_updates_query, build_newsletter_metadata_query,
    build_newsletter_metadata_update_query, build_newsletter_reaction_node,
    build_newsletter_subscribers_query, build_on_whatsapp_query, build_presence_subscribe_node,
    build_privacy_settings_query, build_privacy_update_query, build_profile_picture_remove_query,
    build_profile_picture_update_query, build_profile_picture_url_query,
    build_profile_status_update_query, build_receipt_node, build_status_query,
    disappearing_modes_from_result, generate_message_id, generate_message_id_v2_now,
    on_whatsapp_from_result, parse_account_mutation_result, parse_account_reachout_timelock_result,
    parse_app_state_query_result, parse_blocklist, parse_business_catalog,
    parse_business_collections, parse_business_mutation_result, parse_business_order_details,
    parse_business_product_create_result, parse_business_product_delete_result,
    parse_business_product_update_result, parse_business_profile,
    parse_community_accept_invite_result, parse_community_create_result_jid,
    parse_community_invite_code, parse_community_invite_info_result,
    parse_community_invite_v4_accept_result, parse_community_invite_v4_result,
    parse_community_join_request_action_result, parse_community_join_requests,
    parse_community_linked_groups, parse_community_metadata, parse_community_mutation_result,
    parse_community_participant_action_result, parse_community_participating_result,
    parse_dirty_notification_nodes, parse_group_accept_invite_result, parse_group_invite_code,
    parse_group_invite_v4_accept_result, parse_group_invite_v4_result,
    parse_group_join_request_action_result, parse_group_join_requests, parse_group_metadata,
    parse_group_mutation_result, parse_group_participant_action_result,
    parse_group_participating_result, parse_media_connection_info,
    parse_message_capping_info_result, parse_newsletter_action_result,
    parse_newsletter_admin_count_result, parse_newsletter_change_owner_result,
    parse_newsletter_create_result, parse_newsletter_demote_result,
    parse_newsletter_live_update_subscription, parse_newsletter_message_updates_result,
    parse_newsletter_metadata_result, parse_newsletter_metadata_update_result,
    parse_newsletter_reaction_result, parse_newsletter_subscriber_count_result,
    parse_privacy_settings, parse_profile_picture_url, statuses_from_result,
};
#[cfg(feature = "noise")]
use wa_core::{
    AudioContent, ContactContent, ContactsContent, DeleteContent, DisappearingModeContent,
    DocumentContent, EditContent, EventContent, EventResponseContent, EventResponsePayload,
    ImageContent, LiveLocationContent, LocationContent, PinContent, PollContent, PollUpdateContent,
    PollVoteContent, ReactionContent, StickerContent, VideoContent,
};
#[cfg(feature = "noise")]
use wa_store::SignalKeyStore;
use wa_store::{AuthStore, KeyNamespace, StoreError};

#[cfg(feature = "noise")]
const DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS: usize = 4;
#[cfg(feature = "noise")]
const DEFAULT_APP_STATE_SERVER_SYNC_RESYNC_ROUNDS: usize = 4;
#[cfg(feature = "noise")]
const MAX_IN_FLIGHT_TC_TOKEN_ISSUANCE: usize = 1024;
#[cfg(feature = "noise")]
const IDENTITY_CHANGE_DEBOUNCE_MS: u64 = 5_000;
#[cfg(feature = "noise")]
const MAX_IDENTITY_CHANGE_DEBOUNCE_JIDS: usize = 1024;
#[cfg(feature = "noise")]
const PENDING_MEDIA_RETRY_STORE_PAGE_SIZE: usize = 256;
#[cfg(feature = "noise")]
const MEDIA_RETRY_EVENT_STORE_PAGE_SIZE: usize = 256;

#[cfg(feature = "noise")]
struct PersistedMediaRetryStage {
    keys: Vec<wa_core::MessageEventKey>,
    malformed_stored_records: usize,
}

pub struct Client<S> {
    store: S,
    config: ClientConfig,
    events: EventHub,
    queries: QueryManager,
    #[cfg(feature = "noise")]
    credentials: AuthCredentials,
    #[cfg(feature = "noise")]
    media_retry: wa_core::MediaRetryCoordinator,
    #[cfg(feature = "noise")]
    message_retry: Arc<std::sync::Mutex<wa_core::MessageRetryManager>>,
    #[cfg(feature = "noise")]
    placeholder_resend: wa_core::PlaceholderResendTracker,
    #[cfg(feature = "noise")]
    tc_token_issuance: Arc<std::sync::Mutex<HashSet<String>>>,
    #[cfg(feature = "noise")]
    identity_change_debounce: Arc<std::sync::Mutex<HashMap<String, u64>>>,
    #[cfg(feature = "noise")]
    signal_mutation_locks: wa_core::SignalMutationLocks,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSenderKeyMessageRelay {
    pub distribution: MessageRelay,
    pub message: MessageRelay,
}

#[cfg(feature = "noise")]
#[derive(Clone)]
pub struct ClientSignalMessageCodec<S> {
    inner: wa_core::SignalMessageCodec<
        wa_core::StoreSignalRepository<S>,
        wa_core::StoreSignalSenderKeyProvider<S>,
    >,
}

#[cfg(feature = "noise")]
impl<S> ClientSignalMessageCodec<S> {
    #[must_use]
    pub fn new(
        inner: wa_core::SignalMessageCodec<
            wa_core::StoreSignalRepository<S>,
            wa_core::StoreSignalSenderKeyProvider<S>,
        >,
    ) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn inner(
        &self,
    ) -> &wa_core::SignalMessageCodec<
        wa_core::StoreSignalRepository<S>,
        wa_core::StoreSignalSenderKeyProvider<S>,
    > {
        &self.inner
    }
}

#[cfg(feature = "noise")]
#[async_trait]
impl<S> MessageEncryptor for ClientSignalMessageCodec<S>
where
    S: SignalKeyStore,
{
    async fn encrypt_message(
        &self,
        recipient_jid: &str,
        plaintext: Bytes,
    ) -> CoreResult<wa_core::MessageEncryption> {
        self.inner
            .encrypt_message(recipient_jid, wa_core::pad_random_max16(plaintext))
            .await
    }
}

#[cfg(feature = "noise")]
#[async_trait]
impl<S> wa_core::InboundMessageDecryptor for ClientSignalMessageCodec<S>
where
    S: SignalKeyStore,
{
    async fn decrypt_inbound_message(
        &self,
        payload: wa_core::InboundEncryptedPayload,
    ) -> CoreResult<Bytes> {
        wa_core::InboundMessageDecryptor::decrypt_inbound_message(&self.inner, payload).await
    }

    async fn process_sender_key_distribution(
        &self,
        author_jid: &str,
        message: &wa_core::ProtoSenderKeyDistributionMessage,
    ) -> CoreResult<()> {
        wa_core::InboundMessageDecryptor::process_sender_key_distribution(
            &self.inner,
            author_jid,
            message,
        )
        .await
    }
}

impl<S> Clone for Client<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            config: self.config.clone(),
            events: self.events.clone(),
            queries: self.queries.clone(),
            #[cfg(feature = "noise")]
            credentials: self.credentials.clone(),
            #[cfg(feature = "noise")]
            media_retry: self.media_retry.clone(),
            #[cfg(feature = "noise")]
            message_retry: Arc::clone(&self.message_retry),
            #[cfg(feature = "noise")]
            placeholder_resend: self.placeholder_resend.clone(),
            #[cfg(feature = "noise")]
            tc_token_issuance: Arc::clone(&self.tc_token_issuance),
            #[cfg(feature = "noise")]
            identity_change_debounce: Arc::clone(&self.identity_change_debounce),
            #[cfg(feature = "noise")]
            signal_mutation_locks: self.signal_mutation_locks.clone(),
        }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostAuthMaintenance {
    pub digest_validated: bool,
    pub pre_key_upload: Option<PreKeyUpload>,
    pub signed_pre_key_rotation: Option<SignedPreKey>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Copy, Debug)]
pub struct AppStateMutationUpload<'a> {
    pub previous_state: &'a AppStatePatchState,
    pub key_id: &'a [u8],
    pub key_data: &'a [u8],
}

#[cfg(feature = "noise")]
impl<'a> AppStateMutationUpload<'a> {
    #[must_use]
    pub fn new(
        previous_state: &'a AppStatePatchState,
        key_id: &'a [u8],
        key_data: &'a [u8],
    ) -> Self {
        Self {
            previous_state,
            key_id,
            key_data,
        }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, PartialEq)]
pub struct ChatMutationApplyOutcome {
    pub bundle: AppStatePatchBundle,
    pub batch: wa_core::EventBatch,
}

#[cfg(feature = "noise")]
#[derive(Clone, Copy, Debug)]
pub struct AppStateSyncRecoveryOptions<'a> {
    pub key_data: &'a [u8],
    pub is_initial_sync: bool,
    pub max_rounds: usize,
    pub fallback_host: Option<&'a str>,
}

#[cfg(feature = "noise")]
impl<'a> AppStateSyncRecoveryOptions<'a> {
    #[must_use]
    pub fn new(key_data: &'a [u8], max_rounds: usize) -> Self {
        Self {
            key_data,
            is_initial_sync: false,
            max_rounds,
            fallback_host: None,
        }
    }

    #[must_use]
    pub fn with_initial_sync(mut self, is_initial_sync: bool) -> Self {
        self.is_initial_sync = is_initial_sync;
        self
    }

    #[must_use]
    pub fn with_fallback_host(mut self, fallback_host: &'a str) -> Self {
        self.fallback_host = Some(fallback_host);
        self
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageLabelTarget<'a> {
    pub chat_jid: &'a str,
    pub label_id: &'a str,
    pub message_id: &'a str,
}

#[cfg(feature = "noise")]
impl<'a> MessageLabelTarget<'a> {
    #[must_use]
    pub fn new(chat_jid: &'a str, label_id: &'a str, message_id: &'a str) -> Self {
        Self {
            chat_jid,
            label_id,
            message_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupDirtyRefresh {
    pub groups: Vec<GroupMetadata>,
    pub clean: BinaryNode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityDirtyRefresh {
    pub communities: Vec<GroupMetadata>,
    pub clean: BinaryNode,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupSurfaceDirtyRefresh {
    groups: Option<GroupDirtyRefresh>,
    communities: Option<CommunityDirtyRefresh>,
}

#[cfg(feature = "noise")]
pub struct IncomingProcessor {
    handle: Option<tokio::task::JoinHandle<CoreResult<()>>>,
}

#[cfg(feature = "noise")]
pub struct PlaceholderResendCleanup {
    handle: Option<tokio::task::JoinHandle<CoreResult<()>>>,
}

#[cfg(feature = "noise")]
pub struct TcTokenPruneMaintenance {
    handle: Option<tokio::task::JoinHandle<CoreResult<()>>>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingMediaRetryProcessing {
    pub inbound: wa_core::InboundNodeProcessing,
    pub media_retry: wa_core::MediaRetryBatchOutcome,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingPlaceholderResendProcessing {
    pub inbound: wa_core::InboundNodeProcessing,
    pub placeholder_resend: Option<MessageRelay>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, PartialEq)]
pub struct IncomingPlaceholderRetryMediaProcessing {
    pub inbound: wa_core::InboundNodeProcessing,
    pub placeholder_resend: Option<MessageRelay>,
    pub retry_resend: Option<RetryResendOutcome>,
    pub media_retry: wa_core::MediaRetryBatchOutcome,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, PartialEq)]
pub struct IncomingOfflinePlaceholderRetryMediaProcessing {
    pub offline: wa_core::OfflineNodeProcessing,
    pub placeholder_resends: Vec<MessageRelay>,
    pub retry_resends: Vec<RetryResendOutcome>,
    pub media_retry: wa_core::MediaRetryBatchOutcome,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrySessionActionOutcome {
    pub action: RetrySessionAction,
    pub deleted_sessions: Vec<String>,
    pub refreshed_sessions: bool,
    pub injected_bundle: bool,
    pub injected_key_bundle: Option<RetryReceiptSessionBundle>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, PartialEq)]
pub struct RetryResendOutcome {
    pub receipt: wa_core::RetryReceipt,
    pub plan: wa_core::RetryReceiptPlan,
    pub preparation: RetryResendPreparation,
    pub session_action: RetrySessionActionOutcome,
    pub cleared_group_sender_key_memory: bool,
    pub sender_key_distribution_relays: Vec<MessageRelay>,
    pub relays: Vec<MessageRelay>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct RetryRecipientCacheEntry {
    remote_jid: String,
    target_key: String,
    recipients: Vec<MessageRelayRecipient>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcTokenIssueOutcome {
    pub storage_jid: String,
    pub issue_jid: String,
    pub timestamp_seconds: u64,
    pub stored_tokens: Vec<wa_core::TcTokenRecord>,
    pub sender_record: wa_core::TcTokenRecord,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyTokenNotificationOutcome {
    pub storage_jid: String,
    pub sender_lid: Option<String>,
    pub stored_tokens: Vec<wa_core::TcTokenRecord>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckErrorTcTokenRecoveryOutcome {
    pub ack_id: String,
    pub remote_jid: String,
    pub storage_jid: String,
    pub issue_jid: String,
    pub timestamp_seconds: u64,
    pub scheduled: bool,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct TcTokenIssuePlan {
    storage_jid: String,
    issue_jid: String,
    timestamp_seconds: u64,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityChangeOutcome {
    NoIdentityNode,
    InvalidNotification,
    SkippedCompanionDevice {
        device: u16,
    },
    SkippedSelfPrimary,
    Debounced,
    SkippedOffline,
    SkippedNoSession,
    SessionRefreshed {
        token_reissue_scheduled: bool,
    },
    SessionRefreshFailed {
        token_reissue_scheduled: bool,
        error: String,
    },
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceListNotificationOutcome {
    pub notification: wa_core::DeviceListNotification,
    pub device_jids: Vec<String>,
    pub deleted_sessions: Vec<String>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, PartialEq)]
pub struct ServerSyncNotificationOutcome {
    pub collections: Vec<AppStateCollection>,
    pub sync: wa_core::AppStateSyncApplyOutcome,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, PartialEq)]
pub struct IncomingRetryResendProcessing {
    pub inbound: wa_core::InboundNodeProcessing,
    pub retry_resend: Option<RetryResendOutcome>,
}

#[cfg(feature = "noise")]
struct ParsedRetryReceipt {
    receipt: wa_core::RetryReceipt,
    key_bundle: Option<RetryReceiptSessionBundle>,
}

#[cfg(feature = "noise")]
impl IncomingProcessor {
    pub fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }

    pub async fn join(mut self) -> CoreResult<()> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .await
            .map_err(|err| wa_core::CoreError::Task(err.to_string()))?
    }
}

#[cfg(feature = "noise")]
impl Drop for IncomingProcessor {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(feature = "noise")]
impl PlaceholderResendCleanup {
    pub fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }

    pub async fn join(mut self) -> CoreResult<()> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .await
            .map_err(|err| wa_core::CoreError::Task(err.to_string()))?
    }
}

#[cfg(feature = "noise")]
impl Drop for PlaceholderResendCleanup {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(feature = "noise")]
impl TcTokenPruneMaintenance {
    pub fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }

    pub async fn join(mut self) -> CoreResult<()> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .await
            .map_err(|err| wa_core::CoreError::Task(err.to_string()))?
    }
}

#[cfg(feature = "noise")]
impl Drop for TcTokenPruneMaintenance {
    fn drop(&mut self) {
        self.abort();
    }
}

impl<S> Client<S>
where
    S: AuthStore,
{
    #[must_use]
    pub fn builder(store: S) -> ClientBuilder<S> {
        ClientBuilder {
            store,
            config: ClientConfig::default(),
        }
    }

    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    #[must_use]
    pub fn query_manager(&self) -> &QueryManager {
        &self.queries
    }

    #[cfg(feature = "noise")]
    #[must_use]
    pub fn media_retry_coordinator(&self) -> &wa_core::MediaRetryCoordinator {
        &self.media_retry
    }

    #[cfg(feature = "noise")]
    pub fn message_retry_statistics(&self) -> CoreResult<wa_core::RetryStatistics> {
        Ok(self.message_retry_lock()?.statistics())
    }

    #[cfg(feature = "noise")]
    #[must_use]
    pub fn placeholder_resend_tracker(&self) -> wa_core::PlaceholderResendTracker {
        self.placeholder_resend.clone()
    }

    #[cfg(feature = "noise")]
    pub fn resolve_placeholder_resend(
        &self,
        message_id: &str,
    ) -> CoreResult<Option<wa_core::PlaceholderResendRecord>> {
        self.placeholder_resend.resolve(message_id)
    }

    #[cfg(feature = "noise")]
    pub fn resolve_placeholder_resend_events<'a, I>(&self, events: I) -> CoreResult<usize>
    where
        I: IntoIterator<Item = &'a MessageEvent>,
    {
        let mut resolved = 0;
        for event in events {
            if event.fields.get("kind").map(String::as_str) != Some("placeholder_resend") {
                continue;
            }
            if self.placeholder_resend.resolve(&event.key.id)?.is_some() {
                resolved += 1;
            }
        }
        Ok(resolved)
    }

    #[cfg(feature = "noise")]
    pub fn purge_expired_placeholder_resends(&self) -> CoreResult<usize> {
        self.placeholder_resend
            .purge_expired(current_unix_timestamp_ms())
    }

    #[cfg(feature = "noise")]
    pub fn spawn_placeholder_resend_cleanup(
        &self,
        interval: std::time::Duration,
    ) -> CoreResult<PlaceholderResendCleanup> {
        if interval.is_zero() {
            return Err(wa_core::CoreError::Payload(
                "placeholder resend cleanup interval must be non-zero".to_owned(),
            ));
        }
        let tracker = self.placeholder_resend.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                tracker.purge_expired(current_unix_timestamp_ms())?;
            }
        });
        Ok(PlaceholderResendCleanup {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    pub fn cache_recent_message_for_retry(
        &self,
        remote_jid: &str,
        message_id: &str,
        message: ProtoMessage,
        now_ms: u64,
    ) -> CoreResult<()> {
        self.message_retry_lock()?
            .add_recent_message(remote_jid, message_id, message, now_ms)
    }

    #[cfg(feature = "noise")]
    pub fn plan_retry_resend(
        &self,
        receipt: &wa_core::RetryReceipt,
        session: RetrySessionSnapshot,
        now_ms: u64,
    ) -> CoreResult<wa_core::RetryReceiptPlan> {
        let receipt = normalize_retry_receipt_signal_jids(receipt)?;
        self.message_retry_lock()?
            .plan_retry_resend(&receipt, session, now_ms)
    }

    #[cfg(feature = "noise")]
    pub fn prepare_retry_resends(
        &self,
        plan: &wa_core::RetryReceiptPlan,
        now_ms: u64,
    ) -> CoreResult<RetryResendPreparation> {
        self.message_retry_lock()?
            .prepare_retry_resends(plan, now_ms)
    }

    #[cfg(feature = "noise")]
    pub async fn retry_session_snapshot(
        &self,
        participant_jid: &str,
    ) -> CoreResult<RetrySessionSnapshot>
    where
        S: Clone,
    {
        if let Some(snapshot) = self.retry_session_snapshot_for_jid(participant_jid).await? {
            return Ok(snapshot);
        }

        let mappings = LidPnMappingStore::new(self.store.clone());
        let query_jid = self.session_query_jid(&mappings, participant_jid).await?;
        if query_jid != participant_jid
            && let Some(snapshot) = self.retry_session_snapshot_for_jid(&query_jid).await?
        {
            return Ok(snapshot);
        }

        Ok(RetrySessionSnapshot::missing())
    }

    #[cfg(feature = "noise")]
    async fn retry_session_snapshot_for_jid(
        &self,
        jid: &str,
    ) -> CoreResult<Option<RetrySessionSnapshot>>
    where
        S: Clone,
    {
        if let Some(info) = self
            .signal_provider_state_store()
            .load_session_info(jid)
            .await?
        {
            return Ok(Some(RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(info.registration_id),
                base_key: Some(info.base_key),
                signal_address: Some(info.address.to_string()),
            }));
        }

        if let Some(info) = self.signal_repository().get_session_info(jid).await? {
            return Ok(Some(RetrySessionSnapshot {
                has_session: true,
                registration_id: Some(info.registration_id),
                base_key: Some(info.base_key),
                signal_address: Some(info.address.to_string()),
            }));
        }

        Ok(None)
    }

    #[cfg(feature = "noise")]
    pub async fn apply_retry_session_action(
        &self,
        connection: &Connection,
        plan: &wa_core::RetryReceiptPlan,
        key_bundle: Option<RetryReceiptSessionBundle>,
    ) -> CoreResult<RetrySessionActionOutcome>
    where
        S: Clone,
    {
        let mut deleted_sessions = Vec::new();
        let mut refreshed_sessions = false;
        let mut injected_bundle = false;
        let mut injected_key_bundle = None;
        match &plan.session_action {
            RetrySessionAction::None => {}
            RetrySessionAction::InjectBundle => {
                if let Some(bundle) = key_bundle {
                    let injected_jid = bundle.session.jid.clone();
                    deleted_sessions = self
                        .retry_session_jids_for_participant(&plan.participant_jid)
                        .await?
                        .into_iter()
                        .filter(|jid| jid != &injected_jid)
                        .collect();
                    if !deleted_sessions.is_empty() {
                        self.signal_repository()
                            .delete_sessions(&deleted_sessions)
                            .await?;
                    }
                    self.signal_repository()
                        .inject_e2e_session(bundle.session.clone())
                        .await?;
                    injected_bundle = true;
                    injected_key_bundle = Some(bundle);
                } else {
                    deleted_sessions = self
                        .retry_session_jids_for_participant(&plan.participant_jid)
                        .await?;
                    if !deleted_sessions.is_empty() {
                        self.signal_repository()
                            .delete_sessions(&deleted_sessions)
                            .await?;
                    }
                    refreshed_sessions = self
                        .assert_sessions(connection, [plan.participant_jid.as_str()], true)
                        .await?;
                }
            }
            RetrySessionAction::Refresh { .. } => {
                refreshed_sessions = self
                    .assert_sessions(connection, [plan.participant_jid.as_str()], true)
                    .await?;
            }
            RetrySessionAction::DeleteAndRefresh { .. } => {
                deleted_sessions = self
                    .retry_session_jids_for_participant(&plan.participant_jid)
                    .await?;
                self.signal_repository()
                    .delete_sessions(&deleted_sessions)
                    .await?;
                refreshed_sessions = self
                    .assert_sessions(connection, [plan.participant_jid.as_str()], true)
                    .await?;
            }
        }
        Ok(RetrySessionActionOutcome {
            action: plan.session_action.clone(),
            deleted_sessions,
            refreshed_sessions,
            injected_bundle,
            injected_key_bundle,
        })
    }

    #[cfg(feature = "noise")]
    pub async fn handle_retry_receipt<E>(
        &self,
        connection: &Connection,
        receipt: &wa_core::RetryReceipt,
        encryptor: &E,
    ) -> CoreResult<RetryResendOutcome>
    where
        E: MessageEncryptor,
        S: Clone,
    {
        self.handle_retry_receipt_with_bundle(connection, receipt, None, encryptor)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn handle_retry_receipt_with_signal_provider(
        &self,
        connection: &Connection,
        receipt: &wa_core::RetryReceipt,
    ) -> CoreResult<RetryResendOutcome>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.handle_retry_receipt(connection, receipt, &codec).await
    }

    #[cfg(feature = "noise")]
    async fn handle_retry_receipt_with_bundle<E>(
        &self,
        connection: &Connection,
        receipt: &wa_core::RetryReceipt,
        key_bundle: Option<RetryReceiptSessionBundle>,
        encryptor: &E,
    ) -> CoreResult<RetryResendOutcome>
    where
        E: MessageEncryptor,
        S: Clone,
    {
        let now_ms = current_unix_timestamp_ms();
        let session = self
            .retry_session_snapshot(receipt.requester_jid()?)
            .await?;
        let plan = self.plan_retry_resend(receipt, session, now_ms)?;
        let session_action = self
            .apply_retry_session_action(connection, &plan, key_bundle)
            .await?;
        let preparation = self.prepare_retry_resends(&plan, current_unix_timestamp_ms())?;
        let cleared_group_sender_key_memory =
            self.clear_retry_group_sender_key_memory(&plan).await?;
        let retry_device_identity = session_action
            .injected_key_bundle
            .as_ref()
            .and_then(|bundle| bundle.device_identity.as_ref());
        let (sender_key_distribution_relays, cached_retry_recipients) = self
            .relay_retry_group_sender_key_distributions(
                connection,
                &preparation,
                encryptor,
                retry_device_identity,
            )
            .await?;
        let relays = self
            .execute_retry_resends_with_device_identity(
                connection,
                &preparation,
                encryptor,
                retry_device_identity,
                &cached_retry_recipients,
            )
            .await?;
        Ok(RetryResendOutcome {
            receipt: receipt.clone(),
            plan,
            preparation,
            session_action,
            cleared_group_sender_key_memory,
            sender_key_distribution_relays,
            relays,
        })
    }

    #[cfg(feature = "noise")]
    async fn clear_retry_group_sender_key_memory(
        &self,
        plan: &wa_core::RetryReceiptPlan,
    ) -> CoreResult<bool>
    where
        S: Clone,
    {
        if !plan.should_clear_group_sender_key {
            return Ok(false);
        }
        self.signal_repository()
            .clear_sender_key_memory(&plan.remote_jid)
            .await
    }

    #[cfg(feature = "noise")]
    async fn relay_retry_group_sender_key_distributions<E>(
        &self,
        connection: &Connection,
        preparation: &RetryResendPreparation,
        encryptor: &E,
        retry_device_identity: Option<&Bytes>,
    ) -> CoreResult<(Vec<MessageRelay>, Vec<RetryRecipientCacheEntry>)>
    where
        S: Clone,
        E: MessageEncryptor,
    {
        if !preparation.should_clear_group_sender_key || preparation.jobs.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut relays = Vec::new();
        let mut cached_recipients = Vec::new();
        for job in &preparation.jobs {
            let decoded = jid_decode(&job.remote_jid).ok_or_else(|| {
                wa_core::CoreError::Protocol(format!(
                    "invalid group retry JID for sender-key distribution: {}",
                    job.remote_jid
                ))
            })?;
            if decoded.server != wa_binary::JidServer::GUs {
                continue;
            }
            let target_key = retry_resend_target_key(&job.target);
            if cached_recipients
                .iter()
                .any(|entry: &RetryRecipientCacheEntry| {
                    entry.remote_jid == job.remote_jid && entry.target_key == target_key
                })
            {
                continue;
            }
            let recipients = self.retry_resend_recipients(connection, job).await?;
            let mut options = MessageRelayOptions::new();
            if let Some(identity) = retry_device_identity {
                options = retry_options_with_device_identity(options, identity)?;
            }
            let relay = self
                .relay_group_sender_key_distribution_to_devices(
                    connection,
                    &job.remote_jid,
                    &recipients,
                    encryptor,
                    options,
                )
                .await?;
            cached_recipients.push(RetryRecipientCacheEntry {
                remote_jid: job.remote_jid.clone(),
                target_key,
                recipients,
            });
            relays.push(relay);
        }
        Ok((relays, cached_recipients))
    }

    #[cfg(feature = "noise")]
    #[must_use]
    pub fn credentials(&self) -> &AuthCredentials {
        &self.credentials
    }

    #[cfg(feature = "noise")]
    #[must_use]
    pub fn signal_repository(&self) -> StoreSignalRepository<S>
    where
        S: Clone,
    {
        StoreSignalRepository::with_mutation_locks(
            self.store.clone(),
            self.signal_mutation_locks.clone(),
        )
    }

    #[cfg(feature = "noise")]
    #[must_use]
    pub fn signal_provider_state_store(&self) -> wa_core::SignalProviderStateStore<S>
    where
        S: Clone,
    {
        wa_core::SignalProviderStateStore::with_mutation_locks(
            self.store.clone(),
            self.signal_mutation_locks.clone(),
        )
    }

    #[cfg(feature = "noise")]
    pub fn signal_sender_key_provider(&self) -> CoreResult<wa_core::StoreSignalSenderKeyProvider<S>>
    where
        S: Clone,
    {
        self.signal_provider()
    }

    #[cfg(feature = "noise")]
    pub fn signal_provider(&self) -> CoreResult<wa_core::StoreSignalSenderKeyProvider<S>>
    where
        S: Clone,
    {
        let account_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol(
                "Signal provider requires authenticated account JID".to_owned(),
            )
        })?;
        wa_core::StoreSignalSenderKeyProvider::with_verifier_and_mutation_locks(
            self.store.clone(),
            XEdDsaNoiseCertificateVerifier,
            self.signal_mutation_locks.clone(),
        )
        .with_local_sender_jid(account_jid)
    }

    #[cfg(feature = "noise")]
    pub fn signal_message_codec(&self) -> CoreResult<ClientSignalMessageCodec<S>>
    where
        S: Clone,
    {
        Ok(ClientSignalMessageCodec::new(
            wa_core::SignalMessageCodec::new(self.signal_repository(), self.signal_provider()?),
        ))
    }

    #[cfg(feature = "noise")]
    pub fn connection_validation(&self) -> CoreResult<ConnectionValidation> {
        ConnectionValidation::from_credentials(self.config.clone(), &self.credentials)
    }

    #[cfg(feature = "noise")]
    fn message_retry_lock(
        &self,
    ) -> CoreResult<std::sync::MutexGuard<'_, wa_core::MessageRetryManager>> {
        self.message_retry
            .lock()
            .map_err(|_| wa_core::CoreError::Task("message retry manager lock poisoned".to_owned()))
    }

    #[cfg(feature = "noise")]
    fn try_begin_tc_token_issuance(&self, storage_jid: &str) -> CoreResult<bool> {
        let mut in_flight = self
            .tc_token_issuance
            .lock()
            .map_err(|_| wa_core::CoreError::Task("tctoken issuance lock poisoned".to_owned()))?;
        if in_flight.contains(storage_jid) || in_flight.len() >= MAX_IN_FLIGHT_TC_TOKEN_ISSUANCE {
            return Ok(false);
        }
        in_flight.insert(storage_jid.to_owned());
        Ok(true)
    }

    #[cfg(feature = "noise")]
    fn finish_tc_token_issuance(&self, storage_jid: &str) {
        if let Ok(mut in_flight) = self.tc_token_issuance.lock() {
            in_flight.remove(storage_jid);
        }
    }

    #[cfg(feature = "noise")]
    fn try_mark_identity_change_seen(&self, jid: &str, now_ms: u64) -> CoreResult<bool> {
        let mut debounce = self
            .identity_change_debounce
            .lock()
            .map_err(|_| wa_core::CoreError::Task("identity-change lock poisoned".to_owned()))?;
        debounce
            .retain(|_, seen_ms| now_ms.saturating_sub(*seen_ms) <= IDENTITY_CHANGE_DEBOUNCE_MS);
        if debounce.contains_key(jid) {
            return Ok(false);
        }
        if debounce.len() >= MAX_IDENTITY_CHANGE_DEBOUNCE_JIDS {
            let oldest = debounce
                .iter()
                .min_by_key(|(_, seen_ms)| **seen_ms)
                .map(|(jid, _)| jid.clone());
            if let Some(oldest) = oldest {
                debounce.remove(&oldest);
            }
        }
        debounce.insert(jid.to_owned(), now_ms);
        Ok(true)
    }

    #[cfg(feature = "noise")]
    pub async fn validate_transport<TSink, TStream, V>(
        &self,
        sink: TSink,
        stream: TStream,
        verifier: &V,
    ) -> CoreResult<ValidatedConnection>
    where
        TSink: FrameSink,
        TStream: FrameStream,
        V: NoiseCertificateVerifier,
    {
        validate_connection(
            sink,
            stream,
            self.connection_validation()?,
            self.events.clone(),
            self.queries.clone(),
            verifier,
            self.config.outbound_queue_capacity,
        )
        .await
    }

    #[cfg(all(feature = "noise", feature = "websocket"))]
    pub async fn connect_websocket(&self) -> CoreResult<ValidatedConnection> {
        let (sink, stream) =
            wa_core::connect_websocket_transport(self.config.websocket_url.as_str()).await?;
        self.validate_transport(sink, stream, &XEdDsaNoiseCertificateVerifier)
            .await
    }

    #[cfg(feature = "noise")]
    #[must_use]
    pub fn pairing_qr_data(&self, reference: &str) -> String {
        build_pairing_qr_data(reference, &self.credentials, &self.config.browser)
    }

    #[cfg(feature = "noise")]
    pub async fn prepare_pairing_code_request(
        &mut self,
        phone_number: &str,
        custom_pairing_code: Option<&str>,
    ) -> CoreResult<PairingCodeRequest> {
        let request = build_pairing_code_request(
            &self.credentials,
            &self.config.browser,
            phone_number,
            custom_pairing_code,
            self.queries.next_tag(),
        )?;
        self.credentials.pairing_code = Some(request.pairing_code.clone());
        self.credentials.account_jid = Some(request.account_jid.clone());
        save_credentials(&self.store, self.credentials.clone()).await?;
        self.events.emit(Event::CredentialsUpdated);
        Ok(request)
    }

    #[cfg(feature = "noise")]
    pub async fn send_pairing_code_request(
        &mut self,
        connection: &Connection,
        phone_number: &str,
        custom_pairing_code: Option<&str>,
    ) -> CoreResult<PairingCodeRequest> {
        let request = self
            .prepare_pairing_code_request(phone_number, custom_pairing_code)
            .await?;
        connection.send_node(&request.node).await?;
        Ok(request)
    }

    #[cfg(feature = "noise")]
    pub async fn respond_to_link_code_companion_reg_notification(
        &mut self,
        connection: &Connection,
        node: &BinaryNode,
    ) -> CoreResult<Option<LinkCodeCompanionRegistration>> {
        let Some(finish) = handle_link_code_companion_reg_notification(
            node,
            &self.credentials,
            self.queries.next_tag(),
        )?
        else {
            return Ok(None);
        };
        let response = connection.query_node(finish.reply.clone()).await?;
        if response.node.tag != "iq"
            || response.node.attrs.get("type").map(String::as_str) != Some("result")
        {
            return Err(wa_core::CoreError::Protocol(
                "link-code companion finish failed".to_owned(),
            ));
        }
        self.credentials = finish.credentials.clone();
        save_credentials(&self.store, self.credentials.clone()).await?;
        self.events.emit(Event::CredentialsUpdated);
        Ok(Some(finish))
    }

    #[cfg(feature = "noise")]
    pub async fn respond_to_pair_device_challenge(
        &self,
        connection: &Connection,
        stanza: &BinaryNode,
    ) -> CoreResult<Vec<String>> {
        let challenge =
            handle_pair_device_challenge(stanza, &self.credentials, &self.config.browser)?;
        connection.send_node(&challenge.ack).await?;
        for qr in &challenge.qr_codes {
            self.events.emit(Event::Qr(qr.clone()));
        }
        Ok(challenge.qr_codes)
    }

    #[cfg(feature = "noise")]
    pub async fn respond_to_pair_success(
        &mut self,
        connection: &Connection,
        stanza: &BinaryNode,
    ) -> CoreResult<()> {
        let success =
            handle_pair_success(stanza, &self.credentials, &XEdDsaNoiseCertificateVerifier)?;
        connection.send_node(&success.reply).await?;
        self.credentials = success.credentials;
        save_credentials(&self.store, self.credentials.clone()).await?;
        self.events.emit(Event::CredentialsUpdated);
        Ok(())
    }

    #[cfg(feature = "noise")]
    pub async fn query_available_pre_key_count(
        &self,
        connection: &Connection,
    ) -> CoreResult<usize> {
        let node = build_pre_key_count_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        parse_pre_key_count_response(&response.node)
    }

    #[cfg(feature = "noise")]
    pub async fn query_key_bundle_digest(&self, connection: &Connection) -> CoreResult<BinaryNode> {
        let node = build_key_bundle_digest_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        parse_key_bundle_digest_response(&response.node)?;
        Ok(response.node)
    }

    #[cfg(feature = "noise")]
    pub async fn validate_key_bundle_digest(&self, connection: &Connection) -> CoreResult<bool> {
        let node = build_key_bundle_digest_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        match parse_key_bundle_digest_response(&response.node) {
            Ok(()) => Ok(true),
            Err(wa_core::CoreError::Protocol(message))
                if message == "key-bundle digest response missing digest node" =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "noise")]
    pub async fn prepare_pre_key_upload(&mut self, count: usize) -> CoreResult<PreKeyUpload> {
        let upload = prepare_pre_key_upload(
            &self.store,
            &self.credentials,
            count,
            self.queries.next_tag(),
        )
        .await?;
        self.credentials = upload.credentials.clone();
        self.events.emit(Event::CredentialsUpdated);
        Ok(upload)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_pre_keys(
        &mut self,
        connection: &Connection,
        count: usize,
    ) -> CoreResult<PreKeyUpload> {
        let mut upload = self.prepare_pre_key_upload(count).await?;
        let response = connection.query_node(upload.node.clone()).await?;
        parse_pre_key_upload_response(&response.node)?;
        self.credentials =
            confirm_pre_key_upload(&self.store, &upload.credentials, &upload.pre_key_ids).await?;
        upload.credentials = self.credentials.clone();
        self.events.emit(Event::CredentialsUpdated);
        Ok(upload)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_pre_keys_if_required(
        &mut self,
        connection: &Connection,
    ) -> CoreResult<Option<PreKeyUpload>> {
        let server_count = self.query_available_pre_key_count(connection).await?;
        let upload_count = if server_count == 0 {
            wa_core::INITIAL_PRE_KEY_COUNT
        } else {
            wa_core::MIN_PRE_KEY_COUNT
        };
        let status = current_pre_key_status(&self.store, &self.credentials).await?;
        let low_server_count = server_count <= upload_count;
        let missing_current_pre_key = status.current_pre_key_id > 0 && !status.exists;

        if low_server_count || missing_current_pre_key {
            return self
                .upload_pre_keys(connection, upload_count)
                .await
                .map(Some);
        }

        Ok(None)
    }

    #[cfg(feature = "noise")]
    pub async fn rotate_signed_pre_key(
        &mut self,
        connection: &Connection,
    ) -> CoreResult<SignedPreKey> {
        let rotation = self.prepare_signed_pre_key_rotation()?;
        let response = connection.query_node(rotation.node).await?;
        parse_signed_pre_key_rotation_response(&response.node)?;
        self.credentials = credentials_with_rotated_signed_pre_key(
            &self.credentials,
            rotation.signed_pre_key.clone(),
        );
        save_credentials(&self.store, self.credentials.clone()).await?;
        self.events.emit(Event::CredentialsUpdated);
        Ok(rotation.signed_pre_key)
    }

    #[cfg(feature = "noise")]
    pub fn prepare_signed_pre_key_rotation(&self) -> CoreResult<SignedPreKeyRotation> {
        build_signed_pre_key_rotation(&self.credentials, self.queries.next_tag())
    }

    #[cfg(feature = "noise")]
    pub async fn run_post_auth_key_maintenance(
        &mut self,
        connection: &Connection,
    ) -> CoreResult<PostAuthMaintenance> {
        let digest_validated = self.validate_key_bundle_digest(connection).await?;
        let pre_key_upload = if digest_validated {
            self.upload_pre_keys_if_required(connection).await?
        } else {
            Some(
                self.upload_pre_keys(connection, wa_core::INITIAL_PRE_KEY_COUNT)
                    .await?,
            )
        };
        let signed_pre_key_rotation = if self.config.rotate_signed_pre_key_on_connect {
            Some(self.rotate_signed_pre_key(connection).await?)
        } else {
            None
        };

        Ok(PostAuthMaintenance {
            digest_validated,
            pre_key_upload,
            signed_pre_key_rotation,
        })
    }

    pub async fn execute_usync_query(
        &self,
        connection: &Connection,
        query: &USyncQuery,
    ) -> CoreResult<Option<USyncQueryResult>> {
        let response = connection
            .query_node(query.to_node(self.queries.next_tag())?)
            .await?;
        query.parse_result(&response.node)
    }

    pub async fn on_whatsapp<I, T>(
        &self,
        connection: &Connection,
        phone_numbers: I,
    ) -> CoreResult<Vec<OnWhatsAppResult>>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let Some(query) = build_on_whatsapp_query(phone_numbers)? else {
            return Ok(Vec::new());
        };
        let Some(result) = self.execute_usync_query(connection, &query).await? else {
            return Ok(Vec::new());
        };
        Ok(on_whatsapp_from_result(&result))
    }

    pub async fn fetch_statuses<I, T>(
        &self,
        connection: &Connection,
        jids: I,
    ) -> CoreResult<Vec<USyncStatusResult>>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let Some(query) = build_status_query(jids)? else {
            return Ok(Vec::new());
        };
        let Some(result) = self.execute_usync_query(connection, &query).await? else {
            return Ok(Vec::new());
        };
        Ok(statuses_from_result(&result))
    }

    pub async fn fetch_disappearing_modes<I, T>(
        &self,
        connection: &Connection,
        jids: I,
    ) -> CoreResult<Vec<USyncDisappearingModeResult>>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let Some(query) = build_disappearing_mode_query(jids)? else {
            return Ok(Vec::new());
        };
        let Some(result) = self.execute_usync_query(connection, &query).await? else {
            return Ok(Vec::new());
        };
        Ok(disappearing_modes_from_result(&result))
    }

    pub async fn fetch_bot_profiles<I, J, P>(
        &self,
        connection: &Connection,
        profiles: I,
    ) -> CoreResult<Vec<USyncBotProfile>>
    where
        I: IntoIterator<Item = (J, P)>,
        J: AsRef<str>,
        P: AsRef<str>,
    {
        let Some(query) = build_bot_profile_query(profiles)? else {
            return Ok(Vec::new());
        };
        let Some(result) = self.execute_usync_query(connection, &query).await? else {
            return Ok(Vec::new());
        };
        Ok(bot_profiles_from_result(&result))
    }

    pub async fn fetch_account_reachout_timelock(
        &self,
        connection: &Connection,
    ) -> CoreResult<ReachoutTimelockState> {
        let node = build_account_reachout_timelock_query(self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        let state = parse_account_reachout_timelock_result(&response.node)?;
        persist_reachout_timelock_state(&self.store, &state).await?;
        self.events
            .emit(Event::ReachoutTimelockUpdate(state.clone()));
        Ok(state)
    }

    pub async fn fetch_message_capping_info(
        &self,
        connection: &Connection,
    ) -> CoreResult<MessageCappingInfo> {
        let node = build_message_capping_info_query(self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        let info = parse_message_capping_info_result(&response.node)?;
        persist_message_capping_info(&self.store, &info).await?;
        self.events.emit(Event::MessageCappingUpdate(info.clone()));
        Ok(info)
    }

    pub async fn fetch_business_profile(
        &self,
        connection: &Connection,
        jid: &str,
    ) -> CoreResult<Option<BusinessProfile>> {
        let node = build_business_profile_query(jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_profile(&response.node)
    }

    pub async fn update_business_profile(
        &self,
        connection: &Connection,
        update: BusinessProfileUpdate,
    ) -> CoreResult<()> {
        let node = build_business_profile_update_query(update, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_mutation_result(&response.node)
    }

    pub async fn update_business_cover_photo(
        &self,
        connection: &Connection,
        upload: wa_core::BusinessCoverPhotoUpload,
    ) -> CoreResult<String> {
        let id = upload.id.clone();
        let node = build_business_cover_photo_update_query(upload, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_mutation_result(&response.node)?;
        Ok(id)
    }

    pub async fn remove_business_cover_photo(
        &self,
        connection: &Connection,
        id: &str,
    ) -> CoreResult<()> {
        let node = build_business_cover_photo_delete_query(id, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_mutation_result(&response.node)
    }

    pub async fn fetch_business_catalog(
        &self,
        connection: &Connection,
        query: BusinessCatalogQuery,
    ) -> CoreResult<BusinessCatalog> {
        let node = build_business_catalog_query(query, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_catalog(&response.node)
    }

    pub async fn fetch_business_collections(
        &self,
        connection: &Connection,
        query: BusinessCollectionsQuery,
    ) -> CoreResult<Vec<BusinessCatalogCollection>> {
        let node = build_business_collections_query(query, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_collections(&response.node)
    }

    pub async fn fetch_business_order_details(
        &self,
        connection: &Connection,
        order_id: &str,
        token_base64: &str,
    ) -> CoreResult<BusinessOrderDetails> {
        let node =
            build_business_order_details_query(order_id, token_base64, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_order_details(&response.node)
    }

    pub async fn create_business_product(
        &self,
        connection: &Connection,
        create: BusinessProductCreate,
    ) -> CoreResult<BusinessProduct> {
        let node = build_business_product_create_query(create, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_product_create_result(&response.node)
    }

    pub async fn update_business_product(
        &self,
        connection: &Connection,
        product_id: &str,
        update: BusinessProductUpdate,
    ) -> CoreResult<BusinessProduct> {
        let node =
            build_business_product_update_query(product_id, update, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_product_update_result(&response.node)
    }

    pub async fn delete_business_products<I, T>(
        &self,
        connection: &Connection,
        product_ids: I,
    ) -> CoreResult<u32>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let node = build_business_product_delete_query(product_ids, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_business_product_delete_result(&response.node)
    }

    #[cfg(feature = "noise")]
    pub async fn create_business_product_with_image_bytes<T, I, B>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        create: BusinessProductCreate,
        image_plaintexts: I,
        fallback_host: Option<&str>,
    ) -> CoreResult<BusinessProduct>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let images = self
            .upload_business_product_images_bytes(transfer, image_plaintexts, fallback_host)
            .await?;
        self.create_business_product(connection, create.with_images(images))
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn update_business_product_with_image_bytes<T, I, B>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        product_id: &str,
        update: BusinessProductUpdate,
        image_plaintexts: I,
        fallback_host: Option<&str>,
    ) -> CoreResult<BusinessProduct>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let images = self
            .upload_business_product_images_bytes(transfer, image_plaintexts, fallback_host)
            .await?;
        self.update_business_product(connection, product_id, update.with_images(images))
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn create_business_product_with_image_files<T, I, P>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        create: BusinessProductCreate,
        image_paths: I,
        fallback_host: Option<&str>,
    ) -> CoreResult<BusinessProduct>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = P>,
        P: AsRef<std::path::Path>,
    {
        let images = self
            .upload_business_product_image_files(transfer, image_paths, fallback_host)
            .await?;
        self.create_business_product(connection, create.with_images(images))
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn update_business_product_with_image_files<T, I, P>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        product_id: &str,
        update: BusinessProductUpdate,
        image_paths: I,
        fallback_host: Option<&str>,
    ) -> CoreResult<BusinessProduct>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = P>,
        P: AsRef<std::path::Path>,
    {
        let images = self
            .upload_business_product_image_files(transfer, image_paths, fallback_host)
            .await?;
        self.update_business_product(connection, product_id, update.with_images(images))
            .await
    }

    pub async fn fetch_privacy_settings(
        &self,
        connection: &Connection,
    ) -> CoreResult<PrivacySettings> {
        let node = build_privacy_settings_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        Ok(parse_privacy_settings(&response.node))
    }

    pub async fn update_privacy_setting(
        &self,
        connection: &Connection,
        category: PrivacyCategory,
        value: PrivacyValue,
    ) -> CoreResult<()> {
        let node = build_privacy_update_query(category, value, self.queries.next_tag());
        let response = connection.query_node(node).await?;
        parse_account_mutation_result(&response.node, AccountMutationKind::PrivacySetting)
    }

    pub async fn set_default_disappearing_mode(
        &self,
        connection: &Connection,
        duration_seconds: u32,
    ) -> CoreResult<()> {
        let node = build_default_disappearing_mode_query(duration_seconds, self.queries.next_tag());
        let response = connection.query_node(node).await?;
        parse_account_mutation_result(&response.node, AccountMutationKind::DefaultDisappearingMode)
    }

    pub async fn update_profile_status(
        &self,
        connection: &Connection,
        status: &str,
    ) -> CoreResult<()> {
        let node = build_profile_status_update_query(status, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_account_mutation_result(&response.node, AccountMutationKind::ProfileStatus)
    }

    pub async fn fetch_profile_picture_url(
        &self,
        connection: &Connection,
        target_jid: &str,
        picture_type: ProfilePictureType,
    ) -> CoreResult<Option<String>>
    where
        S: Clone,
    {
        let node =
            build_profile_picture_url_query(target_jid, picture_type, self.queries.next_tag())?;
        #[cfg(feature = "noise")]
        let node = self
            .node_with_tc_token_for_jid(target_jid, node, true)
            .await?;
        let response = connection.query_node(node).await?;
        Ok(parse_profile_picture_url(&response.node))
    }

    pub async fn update_profile_picture<I>(
        &self,
        connection: &Connection,
        target_jid: Option<&str>,
        image: I,
    ) -> CoreResult<()>
    where
        I: Into<Vec<u8>>,
    {
        let node =
            build_profile_picture_update_query(target_jid, image.into(), self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_account_mutation_result(&response.node, AccountMutationKind::ProfilePicture)
    }

    #[cfg(feature = "image")]
    pub async fn update_profile_picture_from_image(
        &self,
        connection: &Connection,
        target_jid: Option<&str>,
        image: &[u8],
        options: wa_core::ProfilePictureOptions,
    ) -> CoreResult<wa_core::GeneratedProfilePicture> {
        let profile = wa_core::generate_profile_picture(image, options)?;
        self.update_profile_picture(connection, target_jid, profile.image.clone())
            .await?;
        Ok(profile)
    }

    #[cfg(feature = "image")]
    pub fn generate_video_thumbnail_from_file(
        &self,
        path: impl AsRef<std::path::Path>,
        options: wa_core::VideoThumbnailOptions,
    ) -> CoreResult<wa_core::GeneratedJpegThumbnail> {
        wa_core::generate_video_thumbnail_from_file(path, options)
    }

    #[cfg(feature = "image")]
    pub fn generate_pdf_thumbnail_from_file(
        &self,
        path: impl AsRef<std::path::Path>,
        options: wa_core::PdfThumbnailOptions,
    ) -> CoreResult<wa_core::GeneratedJpegThumbnail> {
        wa_core::generate_pdf_thumbnail_from_file(path, options)
    }

    pub async fn remove_profile_picture(
        &self,
        connection: &Connection,
        target_jid: Option<&str>,
    ) -> CoreResult<()> {
        let node = build_profile_picture_remove_query(target_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_account_mutation_result(&response.node, AccountMutationKind::ProfilePicture)
    }

    pub async fn fetch_blocklist(&self, connection: &Connection) -> CoreResult<Vec<String>> {
        let node = build_blocklist_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        Ok(parse_blocklist(&response.node))
    }

    #[cfg(feature = "noise")]
    pub async fn update_block_status(
        &self,
        connection: &Connection,
        jid: &str,
        action: BlocklistAction,
    ) -> CoreResult<()>
    where
        S: Clone,
    {
        let normalized = normalize_account_jid(jid)?;
        let mapping_store = LidPnMappingStore::new(self.store.clone());
        let (lid_jid, pn_jid) = match account_jid_kind(&normalized)? {
            AccountJidKind::Lid => {
                let pn_jid = if action == BlocklistAction::Block {
                    let pn_user =
                        mapping_store
                            .pn_for_lid(&normalized)
                            .await?
                            .ok_or_else(|| {
                                wa_core::CoreError::Protocol(format!(
                                    "unable to resolve PN JID for LID: {normalized}"
                                ))
                            })?;
                    Some(pn_user_jid(pn_user)?)
                } else {
                    None
                };
                (normalized, pn_jid)
            }
            AccountJidKind::PhoneNumber => {
                let lid_user = mapping_store
                    .lid_for_pn(&normalized)
                    .await?
                    .ok_or_else(|| {
                        wa_core::CoreError::Protocol(format!(
                            "unable to resolve LID for PN JID: {normalized}"
                        ))
                    })?;
                let lid_jid = lid_user_jid(lid_user)?;
                let pn_jid = (action == BlocklistAction::Block).then_some(normalized);
                (lid_jid, pn_jid)
            }
            AccountJidKind::Other => {
                return Err(wa_core::CoreError::Protocol(format!(
                    "unsupported blocklist JID: {normalized}"
                )));
            }
        };
        let node = build_blocklist_update_query(
            &lid_jid,
            action,
            pn_jid.as_deref(),
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_account_mutation_result(&response.node, AccountMutationKind::Blocklist)
    }

    #[cfg(feature = "noise")]
    pub async fn send_presence_update(
        &self,
        connection: &Connection,
        state: PresenceState,
        to_jid: Option<&str>,
    ) -> CoreResult<BinaryNode> {
        let node = if state.is_online_presence() {
            let display_name = self.credentials.account_name.as_deref().ok_or_else(|| {
                wa_core::CoreError::Protocol(
                    "presence update requires stored account display name".to_owned(),
                )
            })?;
            build_presence_update_node(state, display_name)?
        } else {
            let to_jid = to_jid.ok_or_else(|| {
                wa_core::CoreError::Protocol("chat state update requires target JID".to_owned())
            })?;
            let own_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
                wa_core::CoreError::Protocol("chat state update requires account JID".to_owned())
            })?;
            build_chat_state_node(
                state,
                own_jid,
                self.credentials.account_lid.as_deref(),
                to_jid,
            )?
        };
        connection.send_node(&node).await?;
        Ok(node)
    }

    pub async fn subscribe_presence(
        &self,
        connection: &Connection,
        to_jid: &str,
    ) -> CoreResult<BinaryNode>
    where
        S: Clone,
    {
        let node = build_presence_subscribe_node(to_jid, self.queries.next_tag())?;
        #[cfg(feature = "noise")]
        let node = self.node_with_tc_token_for_jid(to_jid, node, true).await?;
        connection.send_node(&node).await?;
        Ok(node)
    }

    pub async fn clean_dirty_bits(
        &self,
        connection: &Connection,
        dirty_type: DirtyBitType,
        from_timestamp: Option<u64>,
    ) -> CoreResult<BinaryNode> {
        let node =
            build_clean_dirty_bits_node(dirty_type, from_timestamp, self.queries.next_tag())?;
        connection.send_node(&node).await?;
        Ok(node)
    }

    pub async fn refresh_dirty_groups(
        &self,
        connection: &Connection,
        from_timestamp: Option<u64>,
    ) -> CoreResult<GroupDirtyRefresh> {
        refresh_dirty_groups_with_queries(connection, &self.queries, from_timestamp).await
    }

    pub async fn process_group_dirty_node(
        &self,
        connection: &Connection,
        node: &BinaryNode,
    ) -> CoreResult<Option<GroupDirtyRefresh>> {
        let refresh =
            refresh_groups_for_dirty_node_with_queries(connection, &self.queries, node).await?;
        if let Some(refresh) = &refresh {
            emit_group_dirty_refresh_events(&self.events, refresh);
        }
        Ok(refresh)
    }

    pub async fn sync_app_state<I>(
        &self,
        connection: &Connection,
        collections: I,
    ) -> CoreResult<BinaryNode>
    where
        I: IntoIterator<Item = AppStateCollectionRequest>,
    {
        let node = build_app_state_sync_query(collections, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_app_state_query_result(&response.node, AppStateQueryKind::Sync)?;
        Ok(response.node)
    }

    pub async fn upload_app_state_patch_bytes<I>(
        &self,
        connection: &Connection,
        collection: AppStateCollection,
        previous_version: u64,
        encoded_patch: I,
    ) -> CoreResult<BinaryNode>
    where
        I: Into<Vec<u8>>,
    {
        let node = build_app_state_patch_query(
            collection,
            previous_version,
            encoded_patch.into(),
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_app_state_query_result(&response.node, AppStateQueryKind::PatchUpload)?;
        Ok(response.node)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_app_state_patch_bundle(
        &self,
        connection: &Connection,
        bundle: &AppStatePatchBundle,
    ) -> CoreResult<BinaryNode> {
        let node = build_app_state_patch_query(
            bundle.collection,
            bundle.previous_version,
            bundle.encoded_patch.clone(),
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_app_state_query_result(&response.node, AppStateQueryKind::PatchUpload)?;
        Ok(response.node)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_chat_mutation_patch(
        &self,
        connection: &Connection,
        patch: ChatMutationPatch,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let mutation = encrypt_chat_mutation_patch(&patch, upload.key_id, upload.key_data)?;
        let bundle = build_app_state_patch_bundle(
            patch.collection,
            upload.previous_state,
            upload.key_id,
            upload.key_data,
            [mutation],
        )?;
        self.upload_app_state_patch_bundle(connection, &bundle)
            .await?;
        Ok(bundle)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_chat_mutation_patch_and_apply(
        &self,
        connection: &Connection,
        patch: ChatMutationPatch,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let batch = wa_core::event_batch_from_chat_mutation_patch(&patch, false)?;
        let bundle = self
            .upload_chat_mutation_patch(connection, patch, upload)
            .await?;
        if !batch.is_empty() {
            let events = [Event::Batch(Box::new(batch.clone()))];
            persist_receive_events(&self.store, &events).await?;
        }
        wa_core::save_app_state_patch_state(&self.store, bundle.collection, &bundle.next_state)
            .await?;
        if !batch.is_empty() {
            self.events.emit_batch(batch.clone());
        }
        Ok(ChatMutationApplyOutcome { bundle, batch })
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_pinned(
        &self,
        connection: &Connection,
        chat_jid: &str,
        pinned: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_pin_chat_patch(chat_jid, pinned, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_pinned_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        pinned: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_pin_chat_patch(chat_jid, pinned, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_archived(
        &self,
        connection: &Connection,
        chat_jid: &str,
        archived: bool,
        message_range: Option<ChatMutationMessageRange>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch =
            build_archive_chat_patch(chat_jid, archived, message_range, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_archived_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        archived: bool,
        message_range: Option<ChatMutationMessageRange>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch =
            build_archive_chat_patch(chat_jid, archived, message_range, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_muted(
        &self,
        connection: &Connection,
        chat_jid: &str,
        mute_end_timestamp: Option<u64>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_mute_chat_patch(chat_jid, mute_end_timestamp, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_muted_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        mute_end_timestamp: Option<u64>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_mute_chat_patch(chat_jid, mute_end_timestamp, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_read(
        &self,
        connection: &Connection,
        chat_jid: &str,
        read: bool,
        message_range: Option<ChatMutationMessageRange>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_mark_chat_read_patch(chat_jid, read, message_range, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_read_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        read: bool,
        message_range: Option<ChatMutationMessageRange>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_mark_chat_read_patch(chat_jid, read, message_range, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn delete_chat(
        &self,
        connection: &Connection,
        chat_jid: &str,
        message_range: Option<ChatMutationMessageRange>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_delete_chat_patch(chat_jid, message_range, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn delete_chat_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        message_range: Option<ChatMutationMessageRange>,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_delete_chat_patch(chat_jid, message_range, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_message_starred(
        &self,
        connection: &Connection,
        key: MessageKey,
        starred: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_star_message_patch(key, starred, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_message_starred_and_apply(
        &self,
        connection: &Connection,
        key: MessageKey,
        starred: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_star_message_patch(key, starred, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn update_profile_name(
        &self,
        connection: &Connection,
        name: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_push_name_patch(name, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn update_profile_name_and_apply(
        &self,
        connection: &Connection,
        name: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_push_name_patch(name, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn update_contact(
        &self,
        connection: &Connection,
        chat_jid: &str,
        contact: ContactSyncAction,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_contact_patch(chat_jid, Some(contact), action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn update_contact_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        contact: ContactSyncAction,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_contact_patch(chat_jid, Some(contact), action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn remove_contact(
        &self,
        connection: &Connection,
        chat_jid: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_contact_patch(chat_jid, None, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn remove_contact_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_contact_patch(chat_jid, None, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn upsert_quick_reply(
        &self,
        connection: &Connection,
        quick_reply: QuickReplyMutation,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_quick_reply_patch(quick_reply, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn upsert_quick_reply_and_apply(
        &self,
        connection: &Connection,
        quick_reply: QuickReplyMutation,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_quick_reply_patch(quick_reply, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn delete_quick_reply(
        &self,
        connection: &Connection,
        quick_reply_id: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_quick_reply_patch(
            QuickReplyMutation::delete(quick_reply_id),
            action_timestamp_ms,
        )?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn delete_quick_reply_and_apply(
        &self,
        connection: &Connection,
        quick_reply_id: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_quick_reply_patch(
            QuickReplyMutation::delete(quick_reply_id),
            action_timestamp_ms,
        )?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn upsert_label(
        &self,
        connection: &Connection,
        label: LabelEditMutation,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_label_edit_patch(label, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn upsert_label_and_apply(
        &self,
        connection: &Connection,
        label: LabelEditMutation,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_label_edit_patch(label, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn delete_label(
        &self,
        connection: &Connection,
        label_id: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch =
            build_label_edit_patch(LabelEditMutation::delete(label_id), action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn delete_label_and_apply(
        &self,
        connection: &Connection,
        label_id: &str,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch =
            build_label_edit_patch(LabelEditMutation::delete(label_id), action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_label(
        &self,
        connection: &Connection,
        chat_jid: &str,
        label_id: &str,
        labeled: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch =
            build_chat_label_association_patch(chat_jid, label_id, labeled, action_timestamp_ms)?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_chat_label_and_apply(
        &self,
        connection: &Connection,
        chat_jid: &str,
        label_id: &str,
        labeled: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch =
            build_chat_label_association_patch(chat_jid, label_id, labeled, action_timestamp_ms)?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_message_label(
        &self,
        connection: &Connection,
        target: MessageLabelTarget<'_>,
        labeled: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<AppStatePatchBundle> {
        let patch = build_message_label_association_patch(
            target.chat_jid,
            target.label_id,
            target.message_id,
            labeled,
            action_timestamp_ms,
        )?;
        self.upload_chat_mutation_patch(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn set_message_label_and_apply(
        &self,
        connection: &Connection,
        target: MessageLabelTarget<'_>,
        labeled: bool,
        action_timestamp_ms: u64,
        upload: AppStateMutationUpload<'_>,
    ) -> CoreResult<ChatMutationApplyOutcome>
    where
        S: Clone,
    {
        let patch = build_message_label_association_patch(
            target.chat_jid,
            target.label_id,
            target.message_id,
            labeled,
            action_timestamp_ms,
        )?;
        self.upload_chat_mutation_patch_and_apply(connection, patch, upload)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn download_app_state_snapshot<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        collection: AppStateCollection,
        reference: &wa_core::ExternalBlobReference,
        key_data: &[u8],
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::DecodedAppStateSnapshot>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::download_and_decode_app_state_snapshot(
            transfer,
            collection,
            reference,
            key_data,
            fallback_host,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn load_app_state_patch_state(
        &self,
        collection: AppStateCollection,
    ) -> CoreResult<AppStatePatchState> {
        wa_core::load_app_state_patch_state(&self.store, collection).await
    }

    #[cfg(feature = "noise")]
    pub async fn save_app_state_patch_state(
        &self,
        collection: AppStateCollection,
        state: &AppStatePatchState,
    ) -> CoreResult<()> {
        wa_core::save_app_state_patch_state(&self.store, collection, state).await
    }

    #[cfg(feature = "noise")]
    pub async fn load_app_state_sync_key_data(&self, key_id: &[u8]) -> CoreResult<Option<Vec<u8>>> {
        Ok(wa_core::load_app_state_sync_key_data(&self.store, key_id)
            .await?
            .map(|key_data| key_data.to_vec()))
    }

    #[cfg(feature = "noise")]
    pub async fn save_app_state_sync_key_data(
        &self,
        key_id: &[u8],
        key_data: &[u8],
    ) -> CoreResult<()> {
        wa_core::save_app_state_sync_key_data(&self.store, key_id, key_data).await
    }

    #[cfg(feature = "noise")]
    pub async fn apply_decoded_app_state_patch(
        &self,
        patch: &wa_core::DecodedAppStatePatch,
        is_initial_sync: bool,
    ) -> CoreResult<wa_core::EventBatch> {
        let batch =
            wa_core::apply_decoded_app_state_patch_to_store(&self.store, patch, is_initial_sync)
                .await?;
        self.events.emit_batch(batch.clone());
        Ok(batch)
    }

    #[cfg(feature = "noise")]
    pub async fn apply_decoded_app_state_snapshot(
        &self,
        snapshot: &wa_core::DecodedAppStateSnapshot,
    ) -> CoreResult<wa_core::EventBatch> {
        let batch =
            wa_core::apply_decoded_app_state_snapshot_to_store(&self.store, snapshot).await?;
        self.events.emit_batch(batch.clone());
        Ok(batch)
    }

    #[cfg(feature = "noise")]
    pub async fn recover_app_state_snapshots<T, I>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        snapshots: I,
        key_data: &[u8],
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = wa_core::AppStatePendingSnapshot>,
    {
        let mut outcome = wa_core::AppStateSyncApplyOutcome::default();

        for pending in snapshots {
            let decoded = wa_core::download_and_decode_app_state_snapshot(
                transfer,
                pending.collection,
                &pending.reference,
                key_data,
                fallback_host,
            )
            .await?;
            let batch =
                wa_core::apply_decoded_app_state_snapshot_to_store(&self.store, &decoded).await?;
            let emitted_batches = usize::from(!batch.is_empty());
            if !batch.is_empty() {
                self.events.emit_batch(batch.clone());
                outcome.batches.push(batch);
            }
            outcome
                .collections
                .push(wa_core::AppStateCollectionSyncOutcome {
                    collection: decoded.collection,
                    response_version: Some(decoded.version),
                    final_version: decoded.version,
                    applied_patches: 0,
                    emitted_batches,
                    has_more_patches: false,
                    snapshot_pending: false,
                });
        }

        Ok(outcome)
    }

    #[cfg(feature = "noise")]
    pub async fn recover_app_state_snapshots_with_store_keys<T, I>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        snapshots: I,
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = wa_core::AppStatePendingSnapshot>,
    {
        let mut outcome = wa_core::AppStateSyncApplyOutcome::default();

        for pending in snapshots {
            match wa_core::download_and_decode_app_state_snapshot_with_store_key(
                &self.store,
                transfer,
                pending.collection,
                &pending.reference,
                fallback_host,
            )
            .await?
            {
                wa_core::AppStateStoreKeySnapshotDecode::Decoded(decoded) => {
                    let batch =
                        wa_core::apply_decoded_app_state_snapshot_to_store(&self.store, &decoded)
                            .await?;
                    wa_core::delete_app_state_blocked_collection(&self.store, decoded.collection)
                        .await?;
                    let emitted_batches = usize::from(!batch.is_empty());
                    if !batch.is_empty() {
                        self.events.emit_batch(batch.clone());
                        outcome.batches.push(batch);
                    }
                    outcome
                        .collections
                        .push(wa_core::AppStateCollectionSyncOutcome {
                            collection: decoded.collection,
                            response_version: Some(decoded.version),
                            final_version: decoded.version,
                            applied_patches: 0,
                            emitted_batches,
                            has_more_patches: false,
                            snapshot_pending: false,
                        });
                }
                wa_core::AppStateStoreKeySnapshotDecode::Blocked(blocked) => {
                    outcome
                        .collections
                        .push(wa_core::AppStateCollectionSyncOutcome {
                            collection: blocked.collection,
                            response_version: None,
                            final_version: blocked.previous_version,
                            applied_patches: 0,
                            emitted_batches: 0,
                            has_more_patches: false,
                            snapshot_pending: true,
                        });
                    outcome.blocked.push(blocked);
                }
            }
        }

        Ok(outcome)
    }

    #[cfg(feature = "noise")]
    pub async fn apply_app_state_sync_response(
        &self,
        response: &wa_core::AppStateSyncResponse,
        key_data: &[u8],
        is_initial_sync: bool,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome> {
        let outcome = wa_core::apply_app_state_sync_response_to_store(
            &self.store,
            response,
            key_data,
            is_initial_sync,
        )
        .await?;
        for batch in &outcome.batches {
            self.events.emit_batch(batch.clone());
        }
        Ok(outcome)
    }

    #[cfg(feature = "noise")]
    pub async fn apply_app_state_sync_response_with_store_keys(
        &self,
        response: &wa_core::AppStateSyncResponse,
        is_initial_sync: bool,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome> {
        let outcome = wa_core::apply_app_state_sync_response_with_store_keys(
            &self.store,
            response,
            is_initial_sync,
        )
        .await?;
        for batch in &outcome.batches {
            self.events.emit_batch(batch.clone());
        }
        Ok(outcome)
    }

    #[cfg(feature = "noise")]
    pub async fn sync_and_apply_app_state<I>(
        &self,
        connection: &Connection,
        collections: I,
        key_data: &[u8],
        is_initial_sync: bool,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        I: IntoIterator<Item = AppStateCollectionRequest>,
    {
        let node = self.sync_app_state(connection, collections).await?;
        let response = wa_core::parse_app_state_sync_response(&node)?.unwrap_or_default();
        self.apply_app_state_sync_response(&response, key_data, is_initial_sync)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn sync_and_apply_app_state_with_store_keys<I>(
        &self,
        connection: &Connection,
        collections: I,
        is_initial_sync: bool,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        I: IntoIterator<Item = AppStateCollectionRequest>,
    {
        let node = self.sync_app_state(connection, collections).await?;
        let response = wa_core::parse_app_state_sync_response(&node)?.unwrap_or_default();
        self.apply_app_state_sync_response_with_store_keys(&response, is_initial_sync)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn sync_and_apply_app_state_until_current<I>(
        &self,
        connection: &Connection,
        collections: I,
        key_data: &[u8],
        is_initial_sync: bool,
        max_rounds: usize,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        I: IntoIterator<Item = AppStateCollection>,
    {
        if max_rounds == 0 {
            return Err(wa_core::CoreError::Protocol(
                "app-state sync pagination requires at least one round".to_owned(),
            ));
        }

        let mut pending = collections.into_iter().collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }

        let mut combined = wa_core::AppStateSyncApplyOutcome::default();
        for _ in 0..max_rounds {
            let mut requests = Vec::with_capacity(pending.len());
            for collection in &pending {
                let state = self.load_app_state_patch_state(*collection).await?;
                requests.push(AppStateCollectionRequest::new(*collection, state.version()));
            }

            let round = self
                .sync_and_apply_app_state(connection, requests, key_data, is_initial_sync)
                .await?;
            pending = round
                .collections
                .iter()
                .filter(|collection| collection.has_more_patches && !collection.snapshot_pending)
                .map(|collection| collection.collection)
                .collect();
            combined.append(round);

            if pending.is_empty() {
                return Ok(combined);
            }
        }

        Err(wa_core::CoreError::Protocol(format!(
            "app-state sync pagination exceeded {max_rounds} rounds"
        )))
    }

    #[cfg(feature = "noise")]
    pub async fn sync_and_apply_app_state_until_current_with_store_keys<I>(
        &self,
        connection: &Connection,
        collections: I,
        is_initial_sync: bool,
        max_rounds: usize,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        I: IntoIterator<Item = AppStateCollection>,
    {
        if max_rounds == 0 {
            return Err(wa_core::CoreError::Protocol(
                "app-state sync pagination requires at least one round".to_owned(),
            ));
        }

        let mut pending = collections.into_iter().collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }

        let mut combined = wa_core::AppStateSyncApplyOutcome::default();
        for _ in 0..max_rounds {
            let mut requests = Vec::with_capacity(pending.len());
            for collection in &pending {
                let state = self.load_app_state_patch_state(*collection).await?;
                requests.push(AppStateCollectionRequest::new(*collection, state.version()));
            }

            let round = self
                .sync_and_apply_app_state_with_store_keys(connection, requests, is_initial_sync)
                .await?;
            pending = round
                .collections
                .iter()
                .filter(|collection| {
                    collection.has_more_patches
                        && !round
                            .blocked
                            .iter()
                            .any(|blocked| blocked.collection == collection.collection)
                })
                .map(|collection| collection.collection)
                .collect();
            combined.append(round);

            if pending.is_empty() {
                return Ok(combined);
            }
        }

        Err(wa_core::CoreError::Protocol(format!(
            "app-state sync pagination exceeded {max_rounds} rounds"
        )))
    }

    #[cfg(feature = "noise")]
    pub async fn handle_app_state_sync_key_share_events(
        &self,
        connection: &Connection,
        events: &[Event],
        is_initial_sync: bool,
        max_rounds: usize,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome> {
        handle_app_state_sync_key_share_events_with_store(
            &self.store,
            &self.queries,
            connection,
            Some(&self.events),
            events,
            is_initial_sync,
            max_rounds,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn sync_app_state_blocked_collections_with_store_keys(
        &self,
        connection: &Connection,
        is_initial_sync: bool,
        max_rounds: usize,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome> {
        let blocked =
            wa_core::load_app_state_blocked_collections_with_store_keys(&self.store).await?;
        if blocked.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }
        self.sync_and_apply_app_state_until_current_with_store_keys(
            connection,
            blocked.iter().map(|blocked| blocked.collection),
            is_initial_sync,
            max_rounds,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn sync_recover_app_state_blocked_collections_with_store_keys<T>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        is_initial_sync: bool,
        max_rounds: usize,
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        T: wa_core::MediaTransport,
    {
        let blocked =
            wa_core::load_app_state_blocked_collections_with_store_keys(&self.store).await?;
        if blocked.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }
        self.sync_recover_and_apply_app_state_until_current_with_store_keys(
            connection,
            transfer,
            blocked.iter().map(|blocked| blocked.collection),
            is_initial_sync,
            max_rounds,
            fallback_host,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn handle_app_state_sync_key_share_events_with_snapshot_recovery<T>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        events: &[Event],
        is_initial_sync: bool,
        max_rounds: usize,
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        T: wa_core::MediaTransport,
    {
        if max_rounds == 0 {
            return Err(wa_core::CoreError::Protocol(
                "app-state key-share snapshot recovery requires at least one round".to_owned(),
            ));
        }

        let keys = app_state_sync_key_share_items_from_events(events)?;
        if keys.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }

        let blocked = wa_core::save_app_state_sync_key_share(&self.store, keys).await?;
        let mut pending = blocked
            .iter()
            .map(|blocked| blocked.collection)
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }

        let mut combined = wa_core::AppStateSyncApplyOutcome::default();
        for _ in 0..max_rounds {
            let mut requests = Vec::with_capacity(pending.len());
            for collection in &pending {
                let state = self.load_app_state_patch_state(*collection).await?;
                requests.push(AppStateCollectionRequest::new(*collection, state.version()));
            }

            let mut round = self
                .sync_and_apply_app_state_with_store_keys(connection, requests, is_initial_sync)
                .await?;
            let snapshots = std::mem::take(&mut round.pending_snapshots);
            let blocked = round
                .blocked
                .iter()
                .map(|blocked| blocked.collection)
                .collect::<Vec<_>>();
            pending = round
                .collections
                .iter()
                .filter(|collection| {
                    collection.has_more_patches && !blocked.contains(&collection.collection)
                })
                .map(|collection| collection.collection)
                .collect();
            combined.append(round);

            if !snapshots.is_empty() {
                let recovered = self
                    .recover_app_state_snapshots_with_store_keys(transfer, snapshots, fallback_host)
                    .await?;
                let recovered_blocked = recovered
                    .blocked
                    .iter()
                    .map(|blocked| blocked.collection)
                    .collect::<Vec<_>>();
                pending.retain(|collection| !recovered_blocked.contains(collection));
                combined.append(recovered);
            }

            if pending.is_empty() {
                return Ok(combined);
            }
        }

        Err(wa_core::CoreError::Protocol(format!(
            "app-state key-share snapshot recovery exceeded {max_rounds} rounds"
        )))
    }

    #[cfg(feature = "noise")]
    pub async fn sync_recover_and_apply_app_state_until_current<T, I>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        collections: I,
        options: AppStateSyncRecoveryOptions<'_>,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = AppStateCollection>,
    {
        if options.max_rounds == 0 {
            return Err(wa_core::CoreError::Protocol(
                "app-state sync recovery requires at least one round".to_owned(),
            ));
        }

        let mut pending = collections.into_iter().collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }

        let mut combined = wa_core::AppStateSyncApplyOutcome::default();
        for _ in 0..options.max_rounds {
            let mut requests = Vec::with_capacity(pending.len());
            for collection in &pending {
                let state = self.load_app_state_patch_state(*collection).await?;
                requests.push(AppStateCollectionRequest::new(*collection, state.version()));
            }

            let mut round = self
                .sync_and_apply_app_state(
                    connection,
                    requests,
                    options.key_data,
                    options.is_initial_sync,
                )
                .await?;
            let snapshots = std::mem::take(&mut round.pending_snapshots);
            pending = round
                .collections
                .iter()
                .filter(|collection| collection.has_more_patches)
                .map(|collection| collection.collection)
                .collect();
            combined.append(round);

            if !snapshots.is_empty() {
                let recovered = self
                    .recover_app_state_snapshots(
                        transfer,
                        snapshots,
                        options.key_data,
                        options.fallback_host,
                    )
                    .await?;
                combined.append(recovered);
            }

            if pending.is_empty() {
                return Ok(combined);
            }
        }

        Err(wa_core::CoreError::Protocol(format!(
            "app-state sync recovery exceeded {} rounds",
            options.max_rounds
        )))
    }

    #[cfg(feature = "noise")]
    pub async fn sync_recover_and_apply_app_state_until_current_with_store_keys<T, I>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        collections: I,
        is_initial_sync: bool,
        max_rounds: usize,
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = AppStateCollection>,
    {
        if max_rounds == 0 {
            return Err(wa_core::CoreError::Protocol(
                "app-state store-key sync recovery requires at least one round".to_owned(),
            ));
        }

        let mut pending = collections.into_iter().collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok(wa_core::AppStateSyncApplyOutcome::default());
        }

        let mut combined = wa_core::AppStateSyncApplyOutcome::default();
        for _ in 0..max_rounds {
            let mut requests = Vec::with_capacity(pending.len());
            for collection in &pending {
                let state = self.load_app_state_patch_state(*collection).await?;
                requests.push(AppStateCollectionRequest::new(*collection, state.version()));
            }

            let mut round = self
                .sync_and_apply_app_state_with_store_keys(connection, requests, is_initial_sync)
                .await?;
            let snapshots = std::mem::take(&mut round.pending_snapshots);
            let blocked = round
                .blocked
                .iter()
                .map(|blocked| blocked.collection)
                .collect::<Vec<_>>();
            pending = round
                .collections
                .iter()
                .filter(|collection| {
                    collection.has_more_patches && !blocked.contains(&collection.collection)
                })
                .map(|collection| collection.collection)
                .collect();
            combined.append(round);

            if !snapshots.is_empty() {
                let recovered = self
                    .recover_app_state_snapshots_with_store_keys(transfer, snapshots, fallback_host)
                    .await?;
                let recovered_blocked = recovered
                    .blocked
                    .iter()
                    .map(|blocked| blocked.collection)
                    .collect::<Vec<_>>();
                pending.retain(|collection| !recovered_blocked.contains(collection));
                combined.append(recovered);
            }

            if pending.is_empty() {
                return Ok(combined);
            }
        }

        Err(wa_core::CoreError::Protocol(format!(
            "app-state store-key sync recovery exceeded {max_rounds} rounds"
        )))
    }

    pub async fn fetch_group_metadata(
        &self,
        connection: &Connection,
        group_jid: &str,
    ) -> CoreResult<GroupMetadata> {
        let node = build_group_metadata_query(group_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_metadata(&response.node)
    }

    pub async fn fetch_participating_groups(
        &self,
        connection: &Connection,
    ) -> CoreResult<Vec<GroupMetadata>> {
        let node = build_group_participating_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        parse_group_participating_result(&response.node)
    }

    pub async fn create_group<I, T>(
        &self,
        connection: &Connection,
        subject: &str,
        participants: I,
    ) -> CoreResult<GroupMetadata>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let creation_key = generate_message_id_v2_now(self.local_ack_jid());
        let node =
            build_group_create_query(subject, participants, creation_key, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_metadata(&response.node)
    }

    pub async fn leave_group(&self, connection: &Connection, group_jid: &str) -> CoreResult<()> {
        let node = build_group_leave_query(group_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_mutation_result(&response.node, GroupMutationKind::Leave)
    }

    pub async fn set_group_subject(
        &self,
        connection: &Connection,
        group_jid: &str,
        subject: &str,
    ) -> CoreResult<()> {
        let node = build_group_subject_query(group_jid, subject, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_mutation_result(&response.node, GroupMutationKind::Subject)
    }

    pub async fn set_group_description(
        &self,
        connection: &Connection,
        group_jid: &str,
        description: Option<&str>,
    ) -> CoreResult<()> {
        let metadata = self.fetch_group_metadata(connection, group_jid).await?;
        let new_description_id =
            description.map(|_| generate_message_id_v2_now(self.local_ack_jid()));
        let node = build_group_description_query(
            group_jid,
            description,
            metadata.description_id.as_deref(),
            new_description_id.as_deref(),
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_group_mutation_result(&response.node, GroupMutationKind::Description)
    }

    pub async fn update_group_participants<I, T>(
        &self,
        connection: &Connection,
        group_jid: &str,
        action: GroupParticipantAction,
        participants: I,
    ) -> CoreResult<GroupParticipantActionResult>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let node = build_group_participants_query(
            group_jid,
            action,
            participants,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_group_participant_action_result(&response.node, action)
    }

    pub async fn fetch_group_invite_code(
        &self,
        connection: &Connection,
        group_jid: &str,
    ) -> CoreResult<Option<String>> {
        let node = build_group_invite_code_query(group_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_invite_code(&response.node)
    }

    pub async fn revoke_group_invite(
        &self,
        connection: &Connection,
        group_jid: &str,
    ) -> CoreResult<Option<String>> {
        let node = build_group_revoke_invite_query(group_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_invite_code(&response.node)
    }

    pub async fn accept_group_invite(
        &self,
        connection: &Connection,
        code: &str,
    ) -> CoreResult<Option<String>> {
        let node = build_group_accept_invite_query(code, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_accept_invite_result(&response.node)
    }

    pub async fn revoke_group_invite_v4(
        &self,
        connection: &Connection,
        group_jid: &str,
        invited_jid: &str,
    ) -> CoreResult<bool> {
        let node =
            build_group_revoke_invite_v4_query(group_jid, invited_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_invite_v4_result(&response.node)
    }

    pub async fn accept_group_invite_v4(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
    ) -> CoreResult<Option<String>> {
        let node = build_group_accept_invite_v4_query(invite, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_invite_v4_accept_result(&response.node)
    }

    pub async fn accept_group_invite_v4_with_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
    ) -> CoreResult<Option<String>> {
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig::default());
        let accepted_jid = self
            .accept_group_invite_v4_with_buffered_message_events(
                connection,
                invite,
                invite_message_key,
                &mut buffer,
            )
            .await?;
        emit_buffered_events(&self.events, buffer.drain_events());
        Ok(accepted_jid)
    }

    pub async fn accept_group_invite_v4_with_buffered_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<Option<String>> {
        let accepted_jid = self.accept_group_invite_v4(connection, invite).await?;
        if accepted_jid.is_some() {
            self.buffer_invite_v4_accept_message_events(
                invite,
                invite_message_key,
                "group_invite_v4_accept",
                buffer,
            )
            .await?;
        }
        Ok(accepted_jid)
    }

    pub async fn fetch_group_invite_info(
        &self,
        connection: &Connection,
        code: &str,
    ) -> CoreResult<GroupMetadata> {
        let node = build_group_invite_info_query(code, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_metadata(&response.node)
    }

    pub async fn set_group_ephemeral(
        &self,
        connection: &Connection,
        group_jid: &str,
        duration_seconds: u32,
    ) -> CoreResult<()> {
        let node =
            build_group_ephemeral_query(group_jid, duration_seconds, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_mutation_result(&response.node, GroupMutationKind::Ephemeral)
    }

    pub async fn update_group_setting(
        &self,
        connection: &Connection,
        group_jid: &str,
        setting: GroupSettingUpdate,
    ) -> CoreResult<()> {
        let node = build_group_setting_query(group_jid, setting, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_mutation_result(&response.node, GroupMutationKind::Setting)
    }

    pub async fn set_group_member_add_mode(
        &self,
        connection: &Connection,
        group_jid: &str,
        mode: GroupMemberAddMode,
    ) -> CoreResult<()> {
        let node = build_group_member_add_mode_query(group_jid, mode, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_mutation_result(&response.node, GroupMutationKind::MemberAddMode)
    }

    pub async fn set_group_join_approval_mode(
        &self,
        connection: &Connection,
        group_jid: &str,
        mode: GroupJoinApprovalMode,
    ) -> CoreResult<()> {
        let node = build_group_join_approval_mode_query(group_jid, mode, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_mutation_result(&response.node, GroupMutationKind::JoinApprovalMode)
    }

    pub async fn fetch_group_join_requests(
        &self,
        connection: &Connection,
        group_jid: &str,
    ) -> CoreResult<Vec<GroupJoinRequest>> {
        let node = build_group_join_request_list_query(group_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_join_requests(&response.node)
    }

    pub async fn update_group_join_requests<I, T>(
        &self,
        connection: &Connection,
        group_jid: &str,
        action: GroupJoinRequestAction,
        participants: I,
    ) -> CoreResult<GroupJoinRequestActionResult>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let node = build_group_join_request_action_query(
            group_jid,
            participants,
            action,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_group_join_request_action_result(&response.node, action)
    }

    pub async fn fetch_community_metadata(
        &self,
        connection: &Connection,
        community_jid: &str,
    ) -> CoreResult<GroupMetadata> {
        let node = build_community_metadata_query(community_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_metadata(&response.node)
    }

    pub async fn fetch_participating_communities(
        &self,
        connection: &Connection,
    ) -> CoreResult<Vec<GroupMetadata>> {
        let node = build_community_participating_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        parse_community_participating_result(&response.node)
    }

    pub async fn refresh_dirty_communities(
        &self,
        connection: &Connection,
        from_timestamp: Option<u64>,
    ) -> CoreResult<CommunityDirtyRefresh> {
        refresh_dirty_communities_with_queries(connection, &self.queries, from_timestamp).await
    }

    pub async fn process_community_dirty_node(
        &self,
        connection: &Connection,
        node: &BinaryNode,
    ) -> CoreResult<Option<CommunityDirtyRefresh>> {
        let refresh =
            refresh_communities_for_dirty_node_with_queries(connection, &self.queries, node)
                .await?;
        if let Some(refresh) = &refresh {
            emit_community_dirty_refresh_events(&self.events, refresh);
        }
        Ok(refresh)
    }

    pub async fn create_community(
        &self,
        connection: &Connection,
        subject: &str,
        description: &str,
    ) -> CoreResult<GroupMetadata> {
        let description_id = generate_message_id().chars().take(12).collect::<String>();
        let node = build_community_create_query(
            subject,
            description,
            description_id,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        if let Some(jid) = parse_community_create_result_jid(&response.node)? {
            return self.fetch_group_metadata(connection, &jid).await;
        }
        parse_community_metadata(&response.node)
    }

    pub async fn create_community_group<I, T>(
        &self,
        connection: &Connection,
        subject: &str,
        participants: I,
        parent_community_jid: &str,
    ) -> CoreResult<GroupMetadata>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let creation_key = generate_message_id_v2_now(self.local_ack_jid());
        let node = build_community_create_group_query(
            subject,
            participants,
            parent_community_jid,
            creation_key,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        if let Some(jid) = parse_community_create_result_jid(&response.node)? {
            return self.fetch_group_metadata(connection, &jid).await;
        }
        parse_community_metadata(&response.node)
    }

    pub async fn leave_community(
        &self,
        connection: &Connection,
        community_id: &str,
    ) -> CoreResult<()> {
        let node = build_community_leave_query(community_id, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::Leave)
    }

    pub async fn set_community_subject(
        &self,
        connection: &Connection,
        community_jid: &str,
        subject: &str,
    ) -> CoreResult<()> {
        let node = build_community_subject_query(community_jid, subject, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::Subject)
    }

    pub async fn set_community_description(
        &self,
        connection: &Connection,
        community_jid: &str,
        description: Option<&str>,
    ) -> CoreResult<()> {
        let metadata = self
            .fetch_community_metadata(connection, community_jid)
            .await?;
        let new_description_id =
            description.map(|_| generate_message_id_v2_now(self.local_ack_jid()));
        let node = build_community_description_query(
            community_jid,
            description,
            metadata.description_id.as_deref(),
            new_description_id.as_deref(),
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::Description)
    }

    pub async fn link_community_group(
        &self,
        connection: &Connection,
        group_jid: &str,
        parent_community_jid: &str,
    ) -> CoreResult<()> {
        let node = build_community_link_group_query(
            group_jid,
            parent_community_jid,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::LinkGroup)
    }

    pub async fn unlink_community_group(
        &self,
        connection: &Connection,
        group_jid: &str,
        parent_community_jid: &str,
    ) -> CoreResult<()> {
        let node = build_community_unlink_group_query(
            group_jid,
            parent_community_jid,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::UnlinkGroup)
    }

    pub async fn fetch_community_linked_groups(
        &self,
        connection: &Connection,
        community_jid: &str,
    ) -> CoreResult<Vec<CommunityLinkedGroup>> {
        let node = build_community_linked_groups_query(community_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_linked_groups(&response.node)
    }

    pub async fn fetch_community_linked_groups_resolved(
        &self,
        connection: &Connection,
        jid: &str,
    ) -> CoreResult<CommunityLinkedGroups> {
        let metadata = self.fetch_group_metadata(connection, jid).await?;
        let (community_jid, is_community) = metadata
            .linked_parent
            .clone()
            .map_or((metadata.jid, true), |parent| (parent, false));
        let node = build_community_linked_groups_query(&community_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        Ok(CommunityLinkedGroups {
            community_jid,
            is_community,
            linked_groups: parse_community_linked_groups(&response.node)?,
        })
    }

    pub async fn update_community_participants<I, T>(
        &self,
        connection: &Connection,
        community_jid: &str,
        action: GroupParticipantAction,
        participants: I,
    ) -> CoreResult<GroupParticipantActionResult>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let node = build_community_participants_query(
            community_jid,
            action,
            participants,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_community_participant_action_result(&response.node, action)
    }

    pub async fn fetch_community_join_requests(
        &self,
        connection: &Connection,
        community_jid: &str,
    ) -> CoreResult<Vec<GroupJoinRequest>> {
        let node = build_community_join_request_list_query(community_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_join_requests(&response.node)
    }

    pub async fn update_community_join_requests<I, T>(
        &self,
        connection: &Connection,
        community_jid: &str,
        action: GroupJoinRequestAction,
        participants: I,
    ) -> CoreResult<GroupJoinRequestActionResult>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let node = build_community_join_request_action_query(
            community_jid,
            participants,
            action,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_community_join_request_action_result(&response.node, action)
    }

    pub async fn fetch_community_invite_code(
        &self,
        connection: &Connection,
        community_jid: &str,
    ) -> CoreResult<Option<String>> {
        let node = build_community_invite_code_query(community_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_invite_code(&response.node)
    }

    pub async fn revoke_community_invite(
        &self,
        connection: &Connection,
        community_jid: &str,
    ) -> CoreResult<Option<String>> {
        let node = build_community_revoke_invite_query(community_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_invite_code(&response.node)
    }

    pub async fn accept_community_invite(
        &self,
        connection: &Connection,
        code: &str,
    ) -> CoreResult<Option<String>> {
        let node = build_community_accept_invite_query(code, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_accept_invite_result(&response.node)
    }

    pub async fn fetch_community_invite_info(
        &self,
        connection: &Connection,
        code: &str,
    ) -> CoreResult<GroupMetadata> {
        let node = build_community_invite_info_query(code, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_invite_info_result(&response.node)
    }

    pub async fn revoke_community_invite_v4(
        &self,
        connection: &Connection,
        community_jid: &str,
        invited_jid: &str,
    ) -> CoreResult<bool> {
        let node = build_community_revoke_invite_v4_query(
            community_jid,
            invited_jid,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_community_invite_v4_result(&response.node)
    }

    pub async fn accept_community_invite_v4(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
    ) -> CoreResult<Option<String>> {
        let node = build_community_accept_invite_v4_query(invite, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_invite_v4_accept_result(&response.node)
    }

    pub async fn accept_community_invite_v4_with_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
    ) -> CoreResult<Option<String>> {
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig::default());
        let accepted_jid = self
            .accept_community_invite_v4_with_buffered_message_events(
                connection,
                invite,
                invite_message_key,
                &mut buffer,
            )
            .await?;
        emit_buffered_events(&self.events, buffer.drain_events());
        Ok(accepted_jid)
    }

    pub async fn accept_community_invite_v4_with_buffered_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<Option<String>> {
        let accepted_jid = self.accept_community_invite_v4(connection, invite).await?;
        if accepted_jid.is_some() {
            self.buffer_invite_v4_accept_message_events(
                invite,
                invite_message_key,
                "community_invite_v4_accept",
                buffer,
            )
            .await?;
        }
        Ok(accepted_jid)
    }

    pub async fn set_community_ephemeral(
        &self,
        connection: &Connection,
        community_jid: &str,
        duration_seconds: u32,
    ) -> CoreResult<()> {
        let node = build_community_ephemeral_query(
            community_jid,
            duration_seconds,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::Ephemeral)
    }

    pub async fn update_community_setting(
        &self,
        connection: &Connection,
        community_jid: &str,
        setting: GroupSettingUpdate,
    ) -> CoreResult<()> {
        let node = build_community_setting_query(community_jid, setting, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::Setting)
    }

    pub async fn set_community_member_add_mode(
        &self,
        connection: &Connection,
        community_jid: &str,
        mode: GroupMemberAddMode,
    ) -> CoreResult<()> {
        let node =
            build_community_member_add_mode_query(community_jid, mode, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::MemberAddMode)
    }

    pub async fn set_community_join_approval_mode(
        &self,
        connection: &Connection,
        community_jid: &str,
        mode: GroupJoinApprovalMode,
    ) -> CoreResult<()> {
        let node =
            build_community_join_approval_mode_query(community_jid, mode, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_mutation_result(&response.node, CommunityMutationKind::JoinApprovalMode)
    }

    pub async fn create_newsletter(
        &self,
        connection: &Connection,
        name: &str,
        description: Option<&str>,
    ) -> CoreResult<NewsletterMetadata> {
        let node = build_newsletter_create_query(name, description, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_create_result(&response.node)
    }

    pub async fn fetch_newsletter_metadata(
        &self,
        connection: &Connection,
        lookup: NewsletterMetadataLookup,
    ) -> CoreResult<Option<NewsletterMetadata>> {
        let node = build_newsletter_metadata_query(lookup, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_metadata_result(&response.node)
    }

    pub async fn update_newsletter_metadata(
        &self,
        connection: &Connection,
        jid: &str,
        update: NewsletterMetadataUpdate,
    ) -> CoreResult<()> {
        let node = build_newsletter_metadata_update_query(jid, update, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_metadata_update_result(&response.node)
    }

    pub async fn fetch_newsletter_subscriber_count(
        &self,
        connection: &Connection,
        jid: &str,
    ) -> CoreResult<u64> {
        let node = build_newsletter_subscribers_query(jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_subscriber_count_result(&response.node)
    }

    pub async fn fetch_newsletter_admin_count(
        &self,
        connection: &Connection,
        jid: &str,
    ) -> CoreResult<u64> {
        let node = build_newsletter_admin_count_query(jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_admin_count_result(&response.node)
    }

    pub async fn follow_newsletter(&self, connection: &Connection, jid: &str) -> CoreResult<()> {
        self.execute_newsletter_action(connection, jid, NewsletterAction::Follow)
            .await
    }

    pub async fn unfollow_newsletter(&self, connection: &Connection, jid: &str) -> CoreResult<()> {
        self.execute_newsletter_action(connection, jid, NewsletterAction::Unfollow)
            .await
    }

    pub async fn mute_newsletter(&self, connection: &Connection, jid: &str) -> CoreResult<()> {
        self.execute_newsletter_action(connection, jid, NewsletterAction::Mute)
            .await
    }

    pub async fn unmute_newsletter(&self, connection: &Connection, jid: &str) -> CoreResult<()> {
        self.execute_newsletter_action(connection, jid, NewsletterAction::Unmute)
            .await
    }

    pub async fn delete_newsletter(&self, connection: &Connection, jid: &str) -> CoreResult<()> {
        self.execute_newsletter_action(connection, jid, NewsletterAction::Delete)
            .await
    }

    pub async fn execute_newsletter_action(
        &self,
        connection: &Connection,
        jid: &str,
        action: NewsletterAction,
    ) -> CoreResult<()> {
        let node = build_newsletter_action_query(jid, action, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_action_result(&response.node, action)
    }

    pub async fn change_newsletter_owner(
        &self,
        connection: &Connection,
        jid: &str,
        new_owner_jid: &str,
    ) -> CoreResult<()> {
        let node =
            build_newsletter_change_owner_query(jid, new_owner_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_change_owner_result(&response.node)
    }

    pub async fn demote_newsletter_admin(
        &self,
        connection: &Connection,
        jid: &str,
        user_jid: &str,
    ) -> CoreResult<()> {
        let node = build_newsletter_demote_query(jid, user_jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_demote_result(&response.node)
    }

    pub async fn fetch_newsletter_messages(
        &self,
        connection: &Connection,
        jid: &str,
        count: u32,
        since: Option<u64>,
        after: Option<u64>,
    ) -> CoreResult<Vec<MessageEvent>> {
        let node = build_newsletter_message_updates_query(
            jid,
            count,
            since,
            after,
            self.queries.next_tag(),
        )?;
        let response = connection.query_node(node).await?;
        parse_newsletter_message_updates_result(&response.node, jid)
    }

    pub async fn subscribe_newsletter_live_updates(
        &self,
        connection: &Connection,
        jid: &str,
    ) -> CoreResult<Option<NewsletterLiveUpdateSubscription>> {
        let node = build_newsletter_live_updates_query(jid, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        Ok(parse_newsletter_live_update_subscription(&response.node))
    }

    pub async fn react_to_newsletter_message(
        &self,
        connection: &Connection,
        jid: &str,
        server_id: &str,
        reaction: Option<&str>,
    ) -> CoreResult<()> {
        let node =
            build_newsletter_reaction_node(jid, server_id, reaction, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_newsletter_reaction_result(&response.node)
    }

    pub async fn relay_message_to_devices<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        content: MessageContent,
        recipients: &[MessageRelayRecipient],
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
    {
        let message = content.into_proto()?;
        self.relay_proto_message_to_devices(
            connection, remote_jid, message, recipients, encryptor, options,
        )
        .await
    }

    pub async fn relay_proto_message_to_devices<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        message: ProtoMessage,
        recipients: &[MessageRelayRecipient],
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
    {
        #[cfg(feature = "noise")]
        let retry_message = message.clone();
        let options = self.message_relay_options_with_sender(options)?;
        let relay =
            build_direct_message_relay(remote_jid, message, recipients, encryptor, options).await?;
        connection.send_node(&relay.node).await?;
        #[cfg(feature = "noise")]
        self.cache_recent_message_for_retry(
            remote_jid,
            &relay.message_id,
            retry_message,
            current_unix_timestamp_ms(),
        )?;
        Ok(relay)
    }

    pub async fn relay_group_sender_key_message<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        content: MessageContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
    {
        let message = content.into_proto()?;
        self.relay_group_sender_key_proto_message(
            connection, group_jid, message, encryptor, options,
        )
        .await
    }

    pub async fn relay_group_sender_key_proto_message<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        message: ProtoMessage,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
    {
        #[cfg(feature = "noise")]
        let retry_message = message.clone();
        let options = self.message_relay_options_with_sender(options)?;
        #[cfg(feature = "noise")]
        let options = {
            let options = Self::message_relay_options_with_generated_id(options)?;
            Self::message_relay_options_with_reporting(group_jid, &message, options)?
        };
        let relay =
            build_group_sender_key_message_relay(group_jid, message, encryptor, options).await?;
        connection.send_node(&relay.node).await?;
        #[cfg(feature = "noise")]
        self.cache_recent_message_for_retry(
            group_jid,
            &relay.message_id,
            retry_message,
            current_unix_timestamp_ms(),
        )?;
        Ok(relay)
    }

    #[cfg(feature = "noise")]
    pub async fn relay_group_sender_key_distribution_to_devices<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        recipients: &[MessageRelayRecipient],
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone,
        E: MessageEncryptor,
    {
        let distribution = self
            .signal_sender_key_provider()?
            .load_or_create_sender_key_distribution(group_jid)
            .await?;
        let message = wa_core::build_sender_key_distribution_message(
            wa_core::SenderKeyDistributionContent::new(group_jid, distribution.distribution_bytes),
        )?;
        self.relay_proto_message_to_devices(
            connection, group_jid, message, recipients, encryptor, options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_group_sender_key_distribution_to_devices_with_signal_provider(
        &self,
        connection: &Connection,
        group_jid: &str,
        recipients: &[MessageRelayRecipient],
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.relay_group_sender_key_distribution_to_devices(
            connection, group_jid, recipients, &codec, options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_group_sender_key_message_with_distribution<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        content: MessageContent,
        device_encryptor: &E,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
        E: MessageEncryptor,
    {
        let message = content.into_proto()?;
        self.relay_group_sender_key_proto_message_with_distribution(
            connection,
            group_jid,
            message,
            device_encryptor,
            distribution_options,
            message_options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_group_sender_key_proto_message_with_distribution<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        message: ProtoMessage,
        device_encryptor: &E,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
        E: MessageEncryptor,
    {
        let sender_key_codec = self.signal_message_codec()?;
        self.relay_group_sender_key_proto_message_with_encryptors(
            connection,
            group_jid,
            message,
            device_encryptor,
            &sender_key_codec,
            (distribution_options, message_options),
        )
        .await
    }

    #[cfg(feature = "noise")]
    async fn relay_group_sender_key_proto_message_with_encryptors<D, G>(
        &self,
        connection: &Connection,
        group_jid: &str,
        message: ProtoMessage,
        device_encryptor: &D,
        sender_key_encryptor: &G,
        options: (MessageRelayOptions, MessageRelayOptions),
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
        D: MessageEncryptor,
        G: MessageEncryptor,
    {
        let (distribution_options, message_options) = options;
        let recipients = self
            .group_sender_key_distribution_recipients(connection, group_jid)
            .await?;
        let recipient_jids = recipients
            .iter()
            .map(|recipient| recipient.jid.as_str())
            .collect::<Vec<_>>();
        self.assert_sessions(connection, recipient_jids, false)
            .await?;
        let distribution = self
            .relay_group_sender_key_distribution_to_devices(
                connection,
                group_jid,
                &recipients,
                device_encryptor,
                distribution_options,
            )
            .await?;
        let message = self
            .relay_group_sender_key_proto_message(
                connection,
                group_jid,
                message,
                sender_key_encryptor,
                message_options,
            )
            .await?;
        Ok(GroupSenderKeyMessageRelay {
            distribution,
            message,
        })
    }

    #[cfg(feature = "noise")]
    pub async fn relay_group_sender_key_message_with_signal_provider(
        &self,
        connection: &Connection,
        group_jid: &str,
        content: MessageContent,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
    {
        let message = content.into_proto()?;
        self.relay_group_sender_key_proto_message_with_signal_provider(
            connection,
            group_jid,
            message,
            distribution_options,
            message_options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_group_sender_key_proto_message_with_signal_provider(
        &self,
        connection: &Connection,
        group_jid: &str,
        message: ProtoMessage,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.relay_group_sender_key_proto_message_with_distribution(
            connection,
            group_jid,
            message,
            &codec,
            distribution_options,
            message_options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    async fn group_sender_key_distribution_recipients(
        &self,
        connection: &Connection,
        group_jid: &str,
    ) -> CoreResult<Vec<MessageRelayRecipient>>
    where
        S: Clone,
    {
        let my_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("group sender-key send requires account JID".to_owned())
        })?;
        let my_lid = self.credentials.account_lid.clone();
        let metadata = self.fetch_group_metadata(connection, group_jid).await?;
        let mut lookup_jids = Vec::with_capacity(metadata.participants.len() * 3 + 2);
        for participant in &metadata.participants {
            push_unique_normalized_account_jid(&mut lookup_jids, &participant.jid)?;
            if let Some(phone_number) = participant.phone_number.as_deref() {
                push_unique_normalized_account_jid(&mut lookup_jids, phone_number)?;
            }
            if let Some(lid) = participant.lid.as_deref() {
                push_unique_normalized_account_jid(&mut lookup_jids, lid)?;
            }
        }
        push_unique_jid(&mut lookup_jids, &my_jid);
        if let Some(lid) = my_lid.as_deref() {
            push_unique_jid(&mut lookup_jids, lid);
        }
        let devices = self
            .fetch_device_jids(connection, &lookup_jids, false)
            .await?;
        let recipients = relay_recipients_from_device_jids(&devices, &my_jid, my_lid.as_deref())?;
        if recipients.is_empty() {
            return Err(wa_core::CoreError::Protocol(
                "group sender-key distribution requires at least one recipient device".to_owned(),
            ));
        }
        Ok(recipients)
    }

    #[cfg(feature = "noise")]
    async fn status_message_recipients(
        &self,
        connection: &Connection,
        status_jids: &[String],
    ) -> CoreResult<Vec<MessageRelayRecipient>>
    where
        S: Clone,
    {
        let my_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("status send requires account JID".to_owned())
        })?;
        let my_lid = self.credentials.account_lid.clone();
        let mut lookup_jids = Vec::with_capacity(status_jids.len() + 2);
        for jid in status_jids {
            let jid = normalize_status_target_jid(jid)?;
            push_unique_jid(&mut lookup_jids, &jid);
        }
        push_unique_jid(&mut lookup_jids, &my_jid);
        if let Some(lid) = my_lid.as_deref() {
            push_unique_jid(&mut lookup_jids, lid);
        }
        let devices = self
            .fetch_device_jids(connection, &lookup_jids, false)
            .await?;
        let recipients = relay_recipients_from_device_jids(&devices, &my_jid, my_lid.as_deref())?;
        if recipients.is_empty() {
            return Err(wa_core::CoreError::Protocol(
                "status send requires at least one recipient device".to_owned(),
            ));
        }
        Ok(recipients)
    }

    #[cfg(feature = "noise")]
    fn message_relay_options_with_sender(
        &self,
        mut options: MessageRelayOptions,
    ) -> CoreResult<MessageRelayOptions> {
        if options.sender_jid.is_none() {
            options.sender_jid = self.credentials.account_jid.clone();
        }
        if options.device_identity_node.is_none()
            && !options.has_additional_node("device-identity")
            && let Some(node) = build_device_identity_node(&self.credentials)?
        {
            options = options.with_device_identity_node(node);
        }
        Ok(options)
    }

    #[cfg(not(feature = "noise"))]
    fn message_relay_options_with_sender(
        &self,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelayOptions> {
        Ok(options)
    }

    pub async fn send_text_to_devices<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        text: impl Into<String>,
        recipients: &[MessageRelayRecipient],
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
    {
        self.relay_message_to_devices(
            connection,
            remote_jid,
            MessageContent::text_message(TextMessage::new(text)),
            recipients,
            encryptor,
            options,
        )
        .await
    }

    pub async fn send_group_sender_key_message<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        content: impl Into<MessageContent>,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
    {
        self.relay_group_sender_key_message(
            connection,
            group_jid,
            content.into(),
            encryptor,
            options,
        )
        .await
    }

    pub async fn send_group_sender_key_text<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        text: impl Into<String>,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
    {
        self.relay_group_sender_key_message(
            connection,
            group_jid,
            MessageContent::text_message(TextMessage::new(text)),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_group_sender_key_message_with_distribution<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        content: impl Into<MessageContent>,
        device_encryptor: &E,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
        E: MessageEncryptor,
    {
        self.relay_group_sender_key_message_with_distribution(
            connection,
            group_jid,
            content.into(),
            device_encryptor,
            distribution_options,
            message_options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_group_sender_key_text_with_distribution<E>(
        &self,
        connection: &Connection,
        group_jid: &str,
        text: impl Into<String>,
        device_encryptor: &E,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
        E: MessageEncryptor,
    {
        self.relay_group_sender_key_message_with_distribution(
            connection,
            group_jid,
            MessageContent::text_message(TextMessage::new(text)),
            device_encryptor,
            distribution_options,
            message_options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_group_sender_key_message_with_signal_provider(
        &self,
        connection: &Connection,
        group_jid: &str,
        content: impl Into<MessageContent>,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_group_sender_key_message_with_signal_provider(
            connection,
            group_jid,
            content.into(),
            distribution_options,
            message_options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_group_sender_key_text_with_signal_provider(
        &self,
        connection: &Connection,
        group_jid: &str,
        text: impl Into<String>,
        distribution_options: MessageRelayOptions,
        message_options: MessageRelayOptions,
    ) -> CoreResult<GroupSenderKeyMessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_group_sender_key_message_with_signal_provider(
            connection,
            group_jid,
            MessageContent::text_message(TextMessage::new(text)),
            distribution_options,
            message_options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn assert_sessions<I, T>(
        &self,
        connection: &Connection,
        jids: I,
        force_identity_refresh: bool,
    ) -> CoreResult<bool>
    where
        S: Clone,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let repository = self.signal_repository();
        let provider_state = self.signal_provider_state_store();
        let mut unique_jids = Vec::<String>::new();
        for jid in jids {
            let jid = normalize_signal_session_jid(jid.as_ref())?;
            push_unique_jid(&mut unique_jids, &jid);
        }

        let mut missing = Vec::new();
        let mappings = LidPnMappingStore::new(self.store.clone());
        for jid in unique_jids {
            if !force_identity_refresh {
                let validation = repository.validate_session(&jid).await?;
                if validation.exists {
                    continue;
                }
                let provider_validation = provider_state.validate_session_record(&jid).await?;
                if provider_validation.exists {
                    continue;
                }
                let query_jid = self.session_query_jid(&mappings, &jid).await?;
                if query_jid != jid {
                    if let Some(info) = repository.get_session_info(&query_jid).await? {
                        repository
                            .inject_e2e_session(wa_core::SessionInjection {
                                jid: jid.clone(),
                                session: info.session,
                            })
                            .await?;
                        continue;
                    }
                    let provider_validation =
                        provider_state.validate_session_record(&query_jid).await?;
                    if provider_validation.exists
                        && let (Some(session), Some(identity)) = (
                            provider_state.load_session_record(&query_jid).await?,
                            provider_state.load_identity_record(&query_jid).await?,
                        )
                    {
                        provider_state
                            .store_session_and_identity_records(&jid, &session, &identity)
                            .await?;
                        continue;
                    }
                }
            }
            missing.push(jid);
        }

        if missing.is_empty() {
            return Ok(false);
        }

        let mut query_jids = Vec::with_capacity(missing.len());
        let mut query_aliases = Vec::new();
        for jid in &missing {
            let query_jid = self.session_query_jid(&mappings, jid).await?;
            if query_jid != *jid {
                query_aliases.push((query_jid.clone(), jid.clone()));
            }
            push_unique_jid(&mut query_jids, &query_jid);
        }
        let Some(query) =
            build_e2e_session_query(&query_jids, force_identity_refresh, self.queries.next_tag())?
        else {
            return Ok(false);
        };
        let response = connection.query_node(query).await?;
        for injection in parse_e2e_sessions_node(&response.node)? {
            let alias_jids = query_aliases
                .iter()
                .filter_map(|(query_jid, original_jid)| {
                    (query_jid == &injection.jid).then_some(original_jid.clone())
                })
                .collect::<Vec<_>>();
            repository.inject_e2e_session(injection.clone()).await?;
            for alias_jid in alias_jids {
                let mut alias_injection = injection.clone();
                alias_injection.jid = alias_jid;
                repository.inject_e2e_session(alias_injection).await?;
            }
        }
        Ok(true)
    }

    #[cfg(feature = "noise")]
    pub async fn relay_message<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        content: MessageContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        let message = content.into_proto()?;
        self.relay_proto_message(connection, remote_jid, message, encryptor, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_message_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        content: MessageContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.relay_message(connection, remote_jid, content, &codec, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_message<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        content: impl Into<MessageContent>,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(connection, remote_jid, content.into(), encryptor, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_message_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        content: impl Into<MessageContent>,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(connection, remote_jid, content.into(), options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_status_message<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        content: MessageContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        let message = content.into_proto()?;
        self.relay_status_proto_message(connection, status_jids, message, encryptor, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_status_proto_message<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        message: ProtoMessage,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        let status_jids = status_jids
            .into_iter()
            .map(|jid| jid.as_ref().to_owned())
            .collect::<Vec<_>>();
        if status_jids.is_empty() {
            return Err(wa_core::CoreError::Payload(
                "status send requires at least one target JID".to_owned(),
            ));
        }
        let recipients = self
            .status_message_recipients(connection, &status_jids)
            .await?;
        let recipient_jids = recipients
            .iter()
            .map(|recipient| recipient.jid.as_str())
            .collect::<Vec<_>>();
        self.assert_sessions(connection, recipient_jids, false)
            .await?;
        let options = self.message_relay_options_with_sender(options)?;
        let options = Self::message_relay_options_with_generated_id(options)?;
        let options = Self::message_relay_options_with_reporting(
            wa_core::STATUS_BROADCAST_JID,
            &message,
            options,
        )?;
        self.relay_proto_message_to_devices(
            connection,
            wa_core::STATUS_BROADCAST_JID,
            message,
            &recipients,
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_status_message_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        content: MessageContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        let message = content.into_proto()?;
        self.relay_status_proto_message_with_signal_provider(
            connection,
            status_jids,
            message,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_message<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        content: impl Into<MessageContent>,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(connection, status_jids, content.into(), encryptor, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_message_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        content: impl Into<MessageContent>,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            content.into(),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_status_proto_message_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        message: ProtoMessage,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        let codec = self.signal_message_codec()?;
        self.relay_status_proto_message(connection, status_jids, message, &codec, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn relay_proto_message<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        message: ProtoMessage,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        let remote_jid = normalize_account_jid(remote_jid)?;
        let my_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("message send requires account JID".to_owned())
        })?;
        let my_lid = self.credentials.account_lid.clone();
        let mut lookup_jids = Vec::with_capacity(3);
        push_unique_jid(&mut lookup_jids, &remote_jid);
        push_unique_jid(&mut lookup_jids, &my_jid);
        if let Some(lid) = my_lid.as_deref() {
            push_unique_jid(&mut lookup_jids, lid);
        }

        let devices = self
            .fetch_device_jids(connection, &lookup_jids, false)
            .await?;
        let recipients = relay_recipients_from_device_jids(&devices, &my_jid, my_lid.as_deref())?;
        if recipients.is_empty() {
            return Err(wa_core::CoreError::Protocol(
                "message send requires at least one recipient device".to_owned(),
            ));
        }
        let recipient_jids = recipients
            .iter()
            .map(|recipient| recipient.jid.as_str())
            .collect::<Vec<_>>();
        self.assert_sessions(connection, recipient_jids, false)
            .await?;
        let options = self.message_relay_options_with_sender(options)?;
        let options = Self::message_relay_options_with_generated_id(options)?;
        let options = Self::message_relay_options_with_reporting(&remote_jid, &message, options)?;
        let options = self
            .message_relay_options_with_tc_token(&remote_jid, options)
            .await?;
        let issue_plan = self
            .tc_token_issue_after_send_plan(&remote_jid, &message, &options)
            .await?;
        let relay = self
            .relay_proto_message_to_devices(
                connection,
                &remote_jid,
                message,
                &recipients,
                encryptor,
                options,
            )
            .await?;
        if let Some(plan) = issue_plan {
            self.spawn_tc_token_issue_after_send(connection, plan)?;
        }
        Ok(relay)
    }

    #[cfg(feature = "noise")]
    pub async fn relay_proto_message_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        message: ProtoMessage,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.relay_proto_message(connection, remote_jid, message, &codec, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn request_placeholder_resend<E, I>(
        &self,
        connection: &Connection,
        keys: I,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = MessageKey>,
        S: Clone + 'static,
    {
        let account_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol(
                "placeholder resend request requires account JID".to_owned(),
            )
        })?;
        let remote_jid = normalize_account_jid(account_jid)?;
        let incoming_keys = keys;
        let mut keys = Vec::<MessageKey>::new();
        for key in incoming_keys {
            let message_id = key
                .id
                .as_deref()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    wa_core::CoreError::Payload(
                        "placeholder resend message key missing id".to_owned(),
                    )
                })?
                .to_owned();
            if let Some(existing) = keys
                .iter()
                .find(|existing| existing.id.as_deref() == Some(message_id.as_str()))
            {
                if existing != &key {
                    return Err(wa_core::CoreError::Payload(format!(
                        "placeholder resend duplicate message id {message_id} has conflicting keys"
                    )));
                }
                continue;
            }
            keys.push(key);
        }
        let message = build_placeholder_resend_request_message(keys.clone())?;
        let now_ms = current_unix_timestamp_ms();
        let mut recorded_ids: Vec<String> = Vec::with_capacity(keys.len());
        for key in &keys {
            let message_id = key
                .id
                .as_deref()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    wa_core::CoreError::Payload(
                        "placeholder resend message key missing id".to_owned(),
                    )
                })?;
            if !self.placeholder_resend.begin_request(message_id, now_ms)? {
                for recorded_id in recorded_ids {
                    let _ = self.placeholder_resend.resolve(&recorded_id);
                }
                return Err(wa_core::CoreError::Protocol(format!(
                    "placeholder resend already pending for message id {message_id}"
                )));
            }
            recorded_ids.push(message_id.to_owned());
        }
        let mut options = options
            .with_attribute("category", "peer")
            .with_attribute("push_priority", "high_force");
        if !options.has_additional_node("meta") {
            options = options.with_node(BinaryNode::new("meta").with_attr("appdata", "default"));
        }
        let relay = self
            .relay_proto_message(connection, &remote_jid, message, encryptor, options)
            .await;
        if relay.is_err() {
            for recorded_id in recorded_ids {
                let _ = self.placeholder_resend.resolve(&recorded_id);
            }
        }
        relay
    }

    #[cfg(feature = "noise")]
    pub async fn request_placeholder_resend_with_signal_provider<I>(
        &self,
        connection: &Connection,
        keys: I,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = MessageKey>,
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.request_placeholder_resend(connection, keys, &codec, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn request_placeholder_resend_for_web_message<E>(
        &self,
        connection: &Connection,
        message: &wa_core::WebMessageInfo,
        category: Option<&str>,
        unavailable_type: Option<&str>,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<Option<MessageRelay>>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        let Some(request) = placeholder_resend_request_from_web_message(
            message,
            category,
            unavailable_type,
            current_unix_timestamp(),
        )?
        else {
            return Ok(None);
        };
        let message_id = request.key.id.as_deref().ok_or_else(|| {
            wa_core::CoreError::Payload("placeholder resend message key missing id".to_owned())
        })?;
        if self
            .placeholder_resend
            .contains(message_id, current_unix_timestamp_ms())?
        {
            return Ok(None);
        }
        let relay = self
            .request_placeholder_resend(connection, [request.key], encryptor, options)
            .await?;
        Ok(Some(relay))
    }

    #[cfg(feature = "noise")]
    pub async fn request_placeholder_resend_for_web_message_with_signal_provider(
        &self,
        connection: &Connection,
        message: &wa_core::WebMessageInfo,
        category: Option<&str>,
        unavailable_type: Option<&str>,
        options: MessageRelayOptions,
    ) -> CoreResult<Option<MessageRelay>>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.request_placeholder_resend_for_web_message(
            connection,
            message,
            category,
            unavailable_type,
            &codec,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn execute_retry_resends<E>(
        &self,
        connection: &Connection,
        preparation: &RetryResendPreparation,
        encryptor: &E,
    ) -> CoreResult<Vec<MessageRelay>>
    where
        E: MessageEncryptor,
        S: Clone,
    {
        self.execute_retry_resends_with_device_identity(
            connection,
            preparation,
            encryptor,
            None,
            &[],
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn execute_retry_resends_with_signal_provider(
        &self,
        connection: &Connection,
        preparation: &RetryResendPreparation,
    ) -> CoreResult<Vec<MessageRelay>>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.execute_retry_resends(connection, preparation, &codec)
            .await
    }

    #[cfg(feature = "noise")]
    async fn execute_retry_resends_with_device_identity<E>(
        &self,
        connection: &Connection,
        preparation: &RetryResendPreparation,
        encryptor: &E,
        retry_device_identity: Option<&Bytes>,
        cached_recipients: &[RetryRecipientCacheEntry],
    ) -> CoreResult<Vec<MessageRelay>>
    where
        E: MessageEncryptor,
        S: Clone,
    {
        let mut relays = Vec::with_capacity(preparation.jobs.len());
        for job in &preparation.jobs {
            let target_key = retry_resend_target_key(&job.target);
            let recipients = cached_recipients
                .iter()
                .find(|entry| entry.remote_jid == job.remote_jid && entry.target_key == target_key)
                .map(|entry| entry.recipients.clone());
            let recipients = match recipients {
                Some(recipients) => recipients,
                None => self.retry_resend_recipients(connection, job).await?,
            };
            let options = self.retry_resend_options(&job.message_id, retry_device_identity)?;
            let relay = self
                .relay_proto_message_to_devices(
                    connection,
                    &job.remote_jid,
                    job.message.clone(),
                    &recipients,
                    encryptor,
                    options,
                )
                .await?;
            self.message_retry_lock()?
                .mark_retry_success(&job.message_id);
            relays.push(relay);
        }
        Ok(relays)
    }

    #[cfg(feature = "noise")]
    async fn retry_resend_recipients(
        &self,
        connection: &Connection,
        job: &wa_core::RetryResendJob,
    ) -> CoreResult<Vec<MessageRelayRecipient>>
    where
        S: Clone,
    {
        match &job.target {
            RetryResendTarget::Participant { jid, .. } => {
                self.assert_sessions(connection, [jid.as_str()], false)
                    .await?;
                Ok(vec![MessageRelayRecipient::new(jid.clone())])
            }
            RetryResendTarget::AllDevices => {
                let my_jid = self.credentials.account_jid.clone().ok_or_else(|| {
                    wa_core::CoreError::Protocol("retry resend requires account JID".to_owned())
                })?;
                let my_lid = self.credentials.account_lid.clone();
                let mut lookup_jids = Vec::with_capacity(3);
                push_unique_normalized_account_jid(&mut lookup_jids, &job.requester_jid)?;
                push_unique_jid(&mut lookup_jids, &my_jid);
                if let Some(lid) = my_lid.as_deref() {
                    push_unique_jid(&mut lookup_jids, lid);
                }

                let devices = self
                    .fetch_device_jids(connection, &lookup_jids, false)
                    .await?;
                let recipients =
                    relay_recipients_from_device_jids(&devices, &my_jid, my_lid.as_deref())?;
                if recipients.is_empty() {
                    return Err(wa_core::CoreError::Protocol(
                        "retry resend requires at least one recipient device".to_owned(),
                    ));
                }
                let recipient_jids = recipients
                    .iter()
                    .map(|recipient| recipient.jid.as_str())
                    .collect::<Vec<_>>();
                self.assert_sessions(connection, recipient_jids, false)
                    .await?;
                Ok(recipients)
            }
        }
    }

    #[cfg(feature = "noise")]
    fn retry_resend_options(
        &self,
        message_id: &str,
        retry_device_identity: Option<&Bytes>,
    ) -> CoreResult<MessageRelayOptions>
    where
        S: Clone,
    {
        let mut options = MessageRelayOptions::new().with_message_id(message_id.to_owned());
        if let Some(identity) = retry_device_identity {
            options = retry_options_with_device_identity(options, identity)?;
        }
        let options = self.message_relay_options_with_sender(options)?;
        Self::message_relay_options_with_generated_id(options)
    }

    #[cfg(feature = "noise")]
    fn message_relay_options_with_reporting(
        remote_jid: &str,
        message: &ProtoMessage,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelayOptions> {
        if options.has_additional_node("reporting")
            || options
                .additional_attributes
                .get("category")
                .is_some_and(|value| value == "peer")
        {
            return Ok(options);
        }

        let Some(message_id) = options.message_id.as_deref() else {
            return Ok(options);
        };
        let key = MessageKey {
            remote_jid: Some(remote_jid.to_owned()),
            from_me: Some(true),
            id: Some(message_id.to_owned()),
            participant: None,
        };
        let Some(node) = wa_core::build_reporting_token_node(message, &key)? else {
            return Ok(options);
        };
        Ok(options.with_node(node))
    }

    #[cfg(feature = "noise")]
    fn message_relay_options_with_generated_id(
        mut options: MessageRelayOptions,
    ) -> CoreResult<MessageRelayOptions> {
        let message_id = options
            .message_id
            .clone()
            .unwrap_or_else(|| generate_message_id_v2_now(options.sender_jid.as_deref()));
        if message_id.is_empty() {
            return Err(wa_core::CoreError::Payload(
                "message relay id must not be empty".to_owned(),
            ));
        }
        options.message_id = Some(message_id);
        Ok(options)
    }

    #[cfg(feature = "noise")]
    async fn message_relay_options_with_tc_token(
        &self,
        remote_jid: &str,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelayOptions>
    where
        S: Clone,
    {
        if options.has_additional_node("tctoken")
            || options
                .additional_attributes
                .get("category")
                .is_some_and(|value| value == "peer")
            || !wa_core::is_regular_tc_token_jid(remote_jid)
        {
            return Ok(options);
        }

        if self.is_own_token_target_resolved(remote_jid).await? {
            return Ok(options);
        }
        let storage_jid = self.tc_token_storage_jid(remote_jid).await?;
        if !wa_core::is_regular_tc_token_jid(&storage_jid) {
            return Ok(options);
        }
        let Some(node) = wa_core::load_tc_token_node_for_send(
            &self.store,
            &storage_jid,
            current_unix_timestamp(),
        )
        .await?
        else {
            return Ok(options);
        };
        Ok(options.with_node(node))
    }

    #[cfg(feature = "noise")]
    async fn node_with_tc_token_for_jid(
        &self,
        target_jid: &str,
        node: BinaryNode,
        skip_self: bool,
    ) -> CoreResult<BinaryNode>
    where
        S: Clone,
    {
        let normalized_target = normalize_account_jid(target_jid)?;
        if has_child_node(&node, "tctoken") || !wa_core::is_regular_tc_token_jid(&normalized_target)
        {
            return Ok(node);
        }
        if skip_self
            && self
                .is_own_token_target_resolved(&normalized_target)
                .await?
        {
            return Ok(node);
        }

        let storage_jid = self.tc_token_storage_jid(&normalized_target).await?;
        let Some(token_node) = wa_core::load_tc_token_node_for_send(
            &self.store,
            &storage_jid,
            current_unix_timestamp(),
        )
        .await?
        else {
            return Ok(node);
        };
        Ok(binary_node_with_child(node, token_node))
    }

    #[cfg(feature = "noise")]
    fn is_own_token_target(&self, normalized_target: &str) -> bool {
        self.credentials
            .account_jid
            .as_deref()
            .and_then(jid_normalized_user)
            .is_some_and(|own| own == normalized_target)
            || self
                .credentials
                .account_lid
                .as_deref()
                .and_then(jid_normalized_user)
                .is_some_and(|own| own == normalized_target)
    }

    #[cfg(feature = "noise")]
    async fn is_own_token_target_resolved(&self, jid: &str) -> CoreResult<bool>
    where
        S: Clone,
    {
        let normalized = normalize_account_jid(jid)?;
        if self.is_own_token_target(&normalized) {
            return Ok(true);
        }

        let mapping = LidPnMappingStore::new(self.store.clone());
        match account_jid_kind(&normalized)? {
            AccountJidKind::PhoneNumber => {
                if let Some(lid_user) = mapping.lid_for_pn(&normalized).await? {
                    return Ok(self.is_own_token_target(&lid_user_jid(lid_user)?));
                }
            }
            AccountJidKind::Lid => {
                if let Some(pn_user) = mapping.pn_for_lid(&normalized).await? {
                    return Ok(self.is_own_token_target(&pn_user_jid(pn_user)?));
                }
            }
            _ => {}
        }
        Ok(false)
    }

    #[cfg(feature = "noise")]
    pub async fn handle_privacy_token_notification(
        &self,
        node: &BinaryNode,
    ) -> CoreResult<Option<PrivacyTokenNotificationOutcome>>
    where
        S: Clone,
    {
        let Ok(notification) = wa_core::parse_inbound_notification(node) else {
            return Ok(None);
        };
        if notification.notification_type.as_deref() != Some("privacy_token")
            || !has_child_node(node, "tokens")
        {
            return Ok(None);
        }

        let sender_lid = privacy_token_notification_sender_lid(node);
        let storage_jid = match &sender_lid {
            Some(sender_lid) => sender_lid.clone(),
            None => {
                let from = jid_normalized_user(&notification.from)
                    .unwrap_or_else(|| notification.from.clone());
                self.tc_token_storage_jid(&from).await?
            }
        };
        if self.is_own_token_target_resolved(&storage_jid).await? {
            return Ok(None);
        }
        let stored_tokens =
            store_tc_tokens_from_privacy_token_notification(&self.store, node, Some(&storage_jid))
                .await?;
        Ok(Some(PrivacyTokenNotificationOutcome {
            storage_jid,
            sender_lid,
            stored_tokens,
        }))
    }

    #[cfg(feature = "noise")]
    pub async fn handle_ack_error_tc_token_recovery(
        &self,
        connection: &Connection,
        node: &BinaryNode,
    ) -> CoreResult<Option<AckErrorTcTokenRecoveryOutcome>>
    where
        S: Clone + 'static,
    {
        let Ok(ack) = wa_core::parse_inbound_ack(node) else {
            return Ok(None);
        };
        if ack.class != "message" || ack.error_code != Some(wa_core::ACK_ERROR_ACCOUNT_RESTRICTED) {
            return Ok(None);
        }
        let Some(plan) = self
            .tc_token_ack_error_recovery_plan(&ack, current_unix_timestamp())
            .await?
        else {
            return Ok(None);
        };
        let scheduled = self.spawn_tc_token_issue(connection, plan.clone())?;
        Ok(Some(AckErrorTcTokenRecoveryOutcome {
            ack_id: ack.id,
            remote_jid: ack.from.unwrap_or_default(),
            storage_jid: plan.storage_jid,
            issue_jid: plan.issue_jid,
            timestamp_seconds: plan.timestamp_seconds,
            scheduled,
        }))
    }

    #[cfg(feature = "noise")]
    async fn handle_incoming_node_side_effects(
        &self,
        connection: &Connection,
        node: &BinaryNode,
    ) -> CoreResult<()>
    where
        S: Clone + 'static,
    {
        for side_effect_node in incoming_side_effect_nodes(node) {
            let _ = self
                .handle_ack_error_tc_token_recovery(connection, side_effect_node)
                .await?;
            let _ = self
                .handle_server_sync_notification(connection, side_effect_node)
                .await?;
            let _ = self
                .handle_privacy_token_notification(side_effect_node)
                .await?;
            let _ = self
                .handle_device_list_notification(side_effect_node)
                .await?;
            let _ = self
                .handle_identity_change_notification(connection, side_effect_node)
                .await?;
        }
        Ok(())
    }

    #[cfg(feature = "noise")]
    async fn handle_incoming_node_side_effects_with_app_state_snapshot_recovery<T>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        node: &BinaryNode,
    ) -> CoreResult<()>
    where
        S: Clone + 'static,
        T: wa_core::MediaTransport,
    {
        for side_effect_node in incoming_side_effect_nodes(node) {
            let _ = self
                .handle_ack_error_tc_token_recovery(connection, side_effect_node)
                .await?;
            let _ = self
                .handle_server_sync_notification_with_snapshot_recovery(
                    connection,
                    transfer,
                    side_effect_node,
                    None,
                )
                .await?;
            let _ = self
                .handle_privacy_token_notification(side_effect_node)
                .await?;
            let _ = self
                .handle_device_list_notification(side_effect_node)
                .await?;
            let _ = self
                .handle_identity_change_notification(connection, side_effect_node)
                .await?;
        }
        Ok(())
    }

    #[cfg(feature = "noise")]
    pub async fn issue_tc_token(
        &self,
        connection: &Connection,
        jid: &str,
    ) -> CoreResult<Option<TcTokenIssueOutcome>>
    where
        S: Clone,
    {
        self.issue_tc_token_with_options(connection, jid, false, current_unix_timestamp())
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn issue_tc_token_with_options(
        &self,
        connection: &Connection,
        jid: &str,
        issue_to_lid: bool,
        timestamp_seconds: u64,
    ) -> CoreResult<Option<TcTokenIssueOutcome>>
    where
        S: Clone,
    {
        if self.is_own_token_target_resolved(jid).await? {
            return Ok(None);
        }
        let storage_jid = self.tc_token_storage_jid(jid).await?;
        let issue_jid = self.tc_token_issue_jid(jid, issue_to_lid).await?;
        self.issue_resolved_tc_token(connection, storage_jid, issue_jid, timestamp_seconds)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn prune_expired_tc_tokens(&self) -> CoreResult<wa_core::TcTokenPruneOutcome> {
        self.prune_expired_tc_tokens_with_batch_size(wa_core::DEFAULT_TC_TOKEN_PRUNE_BATCH_SIZE)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn prune_expired_tc_tokens_with_batch_size(
        &self,
        batch_size: usize,
    ) -> CoreResult<wa_core::TcTokenPruneOutcome> {
        wa_core::prune_expired_tc_tokens(&self.store, current_unix_timestamp(), batch_size).await
    }

    #[cfg(feature = "noise")]
    pub fn spawn_tc_token_prune_on_connection_open(
        &self,
        interval: std::time::Duration,
        batch_size: usize,
    ) -> CoreResult<TcTokenPruneMaintenance>
    where
        S: Clone + 'static,
    {
        if interval.is_zero() {
            return Err(wa_core::CoreError::Payload(
                "tctoken prune interval must be non-zero".to_owned(),
            ));
        }
        if batch_size == 0 {
            return Err(wa_core::CoreError::Payload(
                "tctoken prune batch size must be non-zero".to_owned(),
            ));
        }
        let mut events = self.events.subscribe();
        let store = self.store.clone();
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        let handle = tokio::spawn(async move {
            let mut last_prune_ms = None::<u64>;
            loop {
                match events.recv().await {
                    Ok(Event::ConnectionUpdate(ConnectionState::Open)) => {
                        let now_ms = current_unix_timestamp_ms();
                        if last_prune_ms
                            .is_some_and(|last| now_ms.saturating_sub(last) < interval_ms)
                        {
                            continue;
                        }
                        wa_core::prune_expired_tc_tokens(
                            &store,
                            current_unix_timestamp(),
                            batch_size,
                        )
                        .await?;
                        last_prune_ms = Some(now_ms);
                    }
                    Ok(Event::ConnectionUpdate(ConnectionState::Closed)) => return Ok(()),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(wa_core::CoreError::Protocol(format!(
                            "tctoken prune maintenance lagged by {skipped} events"
                        )));
                    }
                }
            }
        });
        Ok(TcTokenPruneMaintenance {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    async fn issue_resolved_tc_token(
        &self,
        connection: &Connection,
        storage_jid: String,
        issue_jid: String,
        timestamp_seconds: u64,
    ) -> CoreResult<Option<TcTokenIssueOutcome>> {
        if !wa_core::is_regular_tc_token_jid(&storage_jid) {
            return Ok(None);
        }
        let Some(node) = build_tc_token_issue_query(
            [issue_jid.as_str()],
            timestamp_seconds,
            self.queries.next_tag(),
        )?
        else {
            return Ok(None);
        };
        let response = connection.query_node(node).await?;
        let stored_tokens =
            store_tc_tokens_from_issue_result(&self.store, &response.node, Some(&storage_jid))
                .await?;
        let sender_record =
            mark_tc_token_issued(&self.store, &storage_jid, timestamp_seconds).await?;
        Ok(Some(TcTokenIssueOutcome {
            storage_jid,
            issue_jid,
            timestamp_seconds,
            stored_tokens,
            sender_record,
        }))
    }

    #[cfg(feature = "noise")]
    async fn tc_token_issue_after_send_plan(
        &self,
        remote_jid: &str,
        message: &ProtoMessage,
        options: &MessageRelayOptions,
    ) -> CoreResult<Option<TcTokenIssuePlan>>
    where
        S: Clone,
    {
        if message.protocol_message.is_some()
            || options
                .additional_attributes
                .get("category")
                .is_some_and(|value| value == "peer")
        {
            return Ok(None);
        }
        if self.is_own_token_target_resolved(remote_jid).await? {
            return Ok(None);
        }
        let storage_jid = self.tc_token_storage_jid(remote_jid).await?;
        if !wa_core::is_regular_tc_token_jid(&storage_jid) {
            return Ok(None);
        }
        let now = current_unix_timestamp();
        let existing = wa_core::load_tc_token(&self.store, &storage_jid).await?;
        if !wa_core::should_send_new_tc_token(
            existing
                .as_ref()
                .and_then(|record| record.sender_timestamp_seconds),
            now,
        ) {
            return Ok(None);
        }
        let issue_jid = self.tc_token_issue_jid(remote_jid, false).await?;
        if !wa_core::is_regular_tc_token_jid(&issue_jid) {
            return Ok(None);
        }
        Ok(Some(TcTokenIssuePlan {
            storage_jid,
            issue_jid,
            timestamp_seconds: now,
        }))
    }

    #[cfg(feature = "noise")]
    async fn tc_token_ack_error_recovery_plan(
        &self,
        ack: &wa_core::InboundAck,
        now_seconds: u64,
    ) -> CoreResult<Option<TcTokenIssuePlan>>
    where
        S: Clone,
    {
        let Some(remote_jid) = ack.from.as_deref() else {
            return Ok(None);
        };
        if self.is_own_token_target_resolved(remote_jid).await? {
            return Ok(None);
        }
        let storage_jid = self.tc_token_storage_jid(remote_jid).await?;
        if !wa_core::is_regular_tc_token_jid(&storage_jid) {
            return Ok(None);
        }
        let issue_jid = self
            .tc_token_issue_jid(remote_jid, self.config.lid_trusted_token_issue_to_lid)
            .await?;
        if !wa_core::is_regular_tc_token_jid(&issue_jid) {
            return Ok(None);
        }
        Ok(Some(TcTokenIssuePlan {
            storage_jid,
            issue_jid,
            timestamp_seconds: now_seconds,
        }))
    }

    #[cfg(feature = "noise")]
    fn spawn_tc_token_issue_after_send(
        &self,
        connection: &Connection,
        plan: TcTokenIssuePlan,
    ) -> CoreResult<bool>
    where
        S: Clone + 'static,
    {
        self.spawn_tc_token_issue(connection, plan)
    }

    #[cfg(feature = "noise")]
    fn spawn_tc_token_issue(
        &self,
        connection: &Connection,
        plan: TcTokenIssuePlan,
    ) -> CoreResult<bool>
    where
        S: Clone + 'static,
    {
        if !self.try_begin_tc_token_issuance(&plan.storage_jid)? {
            return Ok(false);
        }
        let client = self.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            let storage_jid = plan.storage_jid.clone();
            let _ = client
                .issue_resolved_tc_token(
                    &connection,
                    plan.storage_jid,
                    plan.issue_jid,
                    plan.timestamp_seconds,
                )
                .await;
            client.finish_tc_token_issuance(&storage_jid);
        });
        Ok(true)
    }

    #[cfg(feature = "noise")]
    pub async fn handle_identity_change_notification(
        &self,
        connection: &Connection,
        node: &BinaryNode,
    ) -> CoreResult<IdentityChangeOutcome>
    where
        S: Clone + 'static,
    {
        if node.tag != "notification"
            || node.attrs.get("type").map(String::as_str) != Some("encrypt")
        {
            return Ok(IdentityChangeOutcome::InvalidNotification);
        }
        let Some(from) = node.attrs.get("from").filter(|from| !from.is_empty()) else {
            return Ok(IdentityChangeOutcome::InvalidNotification);
        };
        if !has_child_node(node, "identity") {
            return Ok(IdentityChangeOutcome::NoIdentityNode);
        }
        if let Some(device) = jid_decode(from).and_then(|jid| jid.device)
            && device != 0
        {
            return Ok(IdentityChangeOutcome::SkippedCompanionDevice { device });
        }
        if self
            .credentials
            .account_jid
            .as_deref()
            .is_some_and(|own| same_jid_user(from, own))
            || self
                .credentials
                .account_lid
                .as_deref()
                .is_some_and(|own| same_jid_user(from, own))
        {
            return Ok(IdentityChangeOutcome::SkippedSelfPrimary);
        }

        let normalized_from = jid_normalized_user(from)
            .unwrap_or_else(|| normalize_account_jid(from).unwrap_or_else(|_| from.clone()));
        if !self.try_mark_identity_change_seen(&normalized_from, current_unix_timestamp_ms())? {
            return Ok(IdentityChangeOutcome::Debounced);
        }

        let validation = self
            .signal_repository()
            .validate_session(&normalized_from)
            .await?;
        if !validation.exists {
            return Ok(IdentityChangeOutcome::SkippedNoSession);
        }
        if node
            .attrs
            .get("offline")
            .is_some_and(|value| !value.is_empty())
        {
            return Ok(IdentityChangeOutcome::SkippedOffline);
        }

        let token_reissue_scheduled = self
            .schedule_tc_token_reissue_after_identity_change(connection, &normalized_from)
            .await?;
        tokio::task::yield_now().await;

        match self
            .assert_sessions(connection, [normalized_from.as_str()], true)
            .await
        {
            Ok(_) => Ok(IdentityChangeOutcome::SessionRefreshed {
                token_reissue_scheduled,
            }),
            Err(error) => Ok(IdentityChangeOutcome::SessionRefreshFailed {
                token_reissue_scheduled,
                error: error.to_string(),
            }),
        }
    }

    #[cfg(feature = "noise")]
    pub async fn handle_device_list_notification(
        &self,
        node: &BinaryNode,
    ) -> CoreResult<Option<DeviceListNotificationOutcome>>
    where
        S: Clone,
    {
        let Ok(notification) = wa_core::parse_inbound_notification(node) else {
            return Ok(None);
        };
        let Some(notification) = wa_core::device_list_notification_from_node(node, &notification)
        else {
            return Ok(None);
        };
        let device_jids = notification.device_jids();
        let deleted_sessions = if notification.action == "remove" {
            self.signal_repository()
                .delete_sessions(&device_jids)
                .await?;
            device_jids.clone()
        } else {
            Vec::new()
        };
        Ok(Some(DeviceListNotificationOutcome {
            notification,
            device_jids,
            deleted_sessions,
        }))
    }

    #[cfg(feature = "noise")]
    pub async fn handle_server_sync_notification(
        &self,
        connection: &Connection,
        node: &BinaryNode,
    ) -> CoreResult<Option<ServerSyncNotificationOutcome>>
    where
        S: Clone,
    {
        let Ok(notification) = wa_core::parse_inbound_notification(node) else {
            return Ok(None);
        };
        let collections =
            wa_core::server_sync_collections_from_notification_node(node, &notification)?;
        if collections.is_empty() {
            return Ok(None);
        }
        let sync = self
            .sync_and_apply_app_state_until_current_with_store_keys(
                connection,
                collections.iter().copied(),
                false,
                DEFAULT_APP_STATE_SERVER_SYNC_RESYNC_ROUNDS,
            )
            .await?;
        Ok(Some(ServerSyncNotificationOutcome { collections, sync }))
    }

    #[cfg(feature = "noise")]
    pub async fn handle_server_sync_notification_with_snapshot_recovery<T>(
        &self,
        connection: &Connection,
        transfer: &wa_core::MediaTransfer<T>,
        node: &BinaryNode,
        fallback_host: Option<&str>,
    ) -> CoreResult<Option<ServerSyncNotificationOutcome>>
    where
        S: Clone,
        T: wa_core::MediaTransport,
    {
        let Ok(notification) = wa_core::parse_inbound_notification(node) else {
            return Ok(None);
        };
        let collections =
            wa_core::server_sync_collections_from_notification_node(node, &notification)?;
        if collections.is_empty() {
            return Ok(None);
        }
        let sync = self
            .sync_recover_and_apply_app_state_until_current_with_store_keys(
                connection,
                transfer,
                collections.iter().copied(),
                false,
                DEFAULT_APP_STATE_SERVER_SYNC_RESYNC_ROUNDS,
                fallback_host,
            )
            .await?;
        Ok(Some(ServerSyncNotificationOutcome { collections, sync }))
    }

    #[cfg(feature = "noise")]
    async fn schedule_tc_token_reissue_after_identity_change(
        &self,
        connection: &Connection,
        jid: &str,
    ) -> CoreResult<bool>
    where
        S: Clone + 'static,
    {
        let Some(plan) = self
            .tc_token_reissue_after_identity_change_plan(jid, current_unix_timestamp())
            .await?
        else {
            return Ok(false);
        };
        self.spawn_tc_token_issue(connection, plan)
    }

    #[cfg(feature = "noise")]
    async fn tc_token_reissue_after_identity_change_plan(
        &self,
        jid: &str,
        now_seconds: u64,
    ) -> CoreResult<Option<TcTokenIssuePlan>>
    where
        S: Clone,
    {
        if self.is_own_token_target_resolved(jid).await? {
            return Ok(None);
        }
        let storage_jid = self.tc_token_storage_jid(jid).await?;
        if !wa_core::is_regular_tc_token_jid(&storage_jid) {
            return Ok(None);
        }
        let Some(record) = wa_core::load_tc_token(&self.store, &storage_jid).await? else {
            return Ok(None);
        };
        let Some(sender_timestamp_seconds) = record.sender_timestamp_seconds else {
            return Ok(None);
        };
        if wa_core::is_tc_token_expired(Some(sender_timestamp_seconds), now_seconds) {
            return Ok(None);
        }
        let issue_jid = self.tc_token_issue_jid(jid, false).await?;
        if !wa_core::is_regular_tc_token_jid(&issue_jid) {
            return Ok(None);
        }
        Ok(Some(TcTokenIssuePlan {
            storage_jid,
            issue_jid,
            timestamp_seconds: sender_timestamp_seconds,
        }))
    }

    #[cfg(feature = "noise")]
    async fn tc_token_storage_jid(&self, jid: &str) -> CoreResult<String>
    where
        S: Clone,
    {
        let normalized = normalize_account_jid(jid)?;
        if !matches!(account_jid_kind(&normalized)?, AccountJidKind::PhoneNumber) {
            return Ok(normalized);
        }
        let mapping = LidPnMappingStore::new(self.store.clone());
        if let Some(lid_user) = mapping.lid_for_pn(&normalized).await? {
            return lid_user_jid(lid_user);
        }
        Ok(normalized)
    }

    #[cfg(feature = "noise")]
    async fn tc_token_issue_jid(&self, jid: &str, issue_to_lid: bool) -> CoreResult<String>
    where
        S: Clone,
    {
        let normalized = normalize_account_jid(jid)?;
        let mapping = LidPnMappingStore::new(self.store.clone());
        match (issue_to_lid, account_jid_kind(&normalized)?) {
            (true, AccountJidKind::PhoneNumber) => match mapping.lid_for_pn(&normalized).await? {
                Some(lid_user) => lid_user_jid(lid_user),
                None => Ok(normalized),
            },
            (false, AccountJidKind::Lid) => match mapping.pn_for_lid(&normalized).await? {
                Some(pn_user) => pn_user_jid(pn_user),
                None => Ok(normalized),
            },
            _ => Ok(normalized),
        }
    }

    #[cfg(feature = "noise")]
    pub async fn send_text<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        text: impl Into<String>,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::text_message(TextMessage::new(text)),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_text_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        text: impl Into<String>,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::text_message(TextMessage::new(text)),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_contact<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        contact: ContactContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::contact(contact),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_contact_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        contact: ContactContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::contact(contact),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_contacts<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        contacts: ContactsContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::contacts(contacts),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_contacts_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        contacts: ContactsContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::contacts(contacts),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_location<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        location: LocationContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::location(location),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_location_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        location: LocationContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::location(location),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_live_location<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        location: LiveLocationContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::live_location(location),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_live_location_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        location: LiveLocationContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::live_location(location),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_image<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        image: ImageContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::image(image),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_image_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        image: ImageContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::image(image),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_view_once_image<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut image: ImageContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        image.view_once = true;
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::view_once(MessageContent::image(image)),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_view_once_image_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut image: ImageContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        image.view_once = true;
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::view_once(MessageContent::image(image)),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_video<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        video: VideoContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::video(video),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_video_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        video: VideoContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::video(video),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_view_once_video<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut video: VideoContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        video.view_once = true;
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::view_once(MessageContent::video(video)),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_view_once_video_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut video: VideoContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        video.view_once = true;
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::view_once(MessageContent::video(video)),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_gif<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut video: VideoContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        video.gif_playback = true;
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::video(video),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_gif_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut video: VideoContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        video.gif_playback = true;
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::video(video),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_ptv<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        video: VideoContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::ptv(video),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_ptv_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        video: VideoContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::ptv(video),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_audio<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        audio: AudioContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::audio(audio),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_audio_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        audio: AudioContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::audio(audio),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_ptt<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut audio: AudioContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        audio.ptt = true;
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::audio(audio),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_ptt_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        mut audio: AudioContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        audio.ptt = true;
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::audio(audio),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_document<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        document: DocumentContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::document(document),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_document_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        document: DocumentContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::document(document),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_sticker<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        sticker: StickerContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::sticker(sticker),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_sticker_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        sticker: StickerContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::sticker(sticker),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_poll<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        poll: PollContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::poll(poll),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_poll_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        poll: PollContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::poll(poll),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_event<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        event: EventContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::event(event),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_event_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        event: EventContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::event(event),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_poll_update<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        update: PollUpdateContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::poll_update(update),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_poll_update_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        update: PollUpdateContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::poll_update(update),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_poll_vote<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        vote: PollVoteContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        let update = wa_core::build_encrypted_poll_update_content(vote)?;
        self.send_poll_update(connection, remote_jid, update, encryptor, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_poll_vote_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        vote: PollVoteContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        let update = wa_core::build_encrypted_poll_update_content(vote)?;
        self.send_poll_update_with_signal_provider(connection, remote_jid, update, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_event_response<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        response: EventResponseContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::event_response(response),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_event_response_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        response: EventResponseContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::event_response(response),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_event_response_payload<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        response: EventResponsePayload,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        let response = wa_core::build_encrypted_event_response_content(response)?;
        self.send_event_response(connection, remote_jid, response, encryptor, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_event_response_payload_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        response: EventResponsePayload,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        let response = wa_core::build_encrypted_event_response_content(response)?;
        self.send_event_response_with_signal_provider(connection, remote_jid, response, options)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_reaction<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        reaction: ReactionContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::reaction(reaction),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_reaction_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        reaction: ReactionContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::reaction(reaction),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_edit<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        edit: EditContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::edit(edit),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_edit_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        edit: EditContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::edit(edit),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_delete<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        delete: DeleteContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::delete(delete),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_delete_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        delete: DeleteContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::delete(delete),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_pin<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        pin: PinContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::pin(pin),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_pin_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        pin: PinContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::pin(pin),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_disappearing_mode<E>(
        &self,
        connection: &Connection,
        remote_jid: &str,
        content: DisappearingModeContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        self.relay_message(
            connection,
            remote_jid,
            MessageContent::disappearing_mode(content),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_disappearing_mode_with_signal_provider(
        &self,
        connection: &Connection,
        remote_jid: &str,
        content: DisappearingModeContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        S: Clone + 'static,
    {
        self.relay_message_with_signal_provider(
            connection,
            remote_jid,
            MessageContent::disappearing_mode(content),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_text<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        text: impl Into<String>,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::text_message(TextMessage::new(text)),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_text_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        text: impl Into<String>,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::text_message(TextMessage::new(text)),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_poll<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        poll: PollContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::poll(poll),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_poll_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        poll: PollContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::poll(poll),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_image<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        image: ImageContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::image(image),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_image_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        image: ImageContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::image(image),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_video<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        video: VideoContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::video(video),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_video_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        video: VideoContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::video(video),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_document<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        document: DocumentContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::document(document),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_document_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        document: DocumentContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::document(document),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_audio<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        audio: AudioContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::audio(audio),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_audio_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        audio: AudioContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::audio(audio),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_sticker<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        sticker: StickerContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::sticker(sticker),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_sticker_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        sticker: StickerContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::sticker(sticker),
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_event<E, I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        event: EventContent,
        encryptor: &E,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        E: MessageEncryptor,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message(
            connection,
            status_jids,
            MessageContent::event(event),
            encryptor,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn send_status_event_with_signal_provider<I, T>(
        &self,
        connection: &Connection,
        status_jids: I,
        event: EventContent,
        options: MessageRelayOptions,
    ) -> CoreResult<MessageRelay>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
        S: Clone,
    {
        self.relay_status_message_with_signal_provider(
            connection,
            status_jids,
            MessageContent::event(event),
            options,
        )
        .await
    }

    pub async fn send_receipt(
        &self,
        connection: &Connection,
        receipt: &MessageReceipt,
        receipt_type: MessageReceiptType,
        timestamp: Option<u64>,
    ) -> CoreResult<()> {
        let timestamp = receipt_timestamp(receipt_type, timestamp);
        let node = build_receipt_node(receipt, receipt_type, timestamp)?;
        connection.send_node(&node).await
    }

    pub async fn send_ack(
        &self,
        connection: &Connection,
        received: &BinaryNode,
        error_code: Option<u16>,
    ) -> CoreResult<BinaryNode> {
        let node = build_ack_node(received, self.local_ack_jid(), error_code)?;
        connection.send_node(&node).await?;
        Ok(node)
    }

    pub async fn send_nack(
        &self,
        connection: &Connection,
        received: &BinaryNode,
        reason: NackReason,
    ) -> CoreResult<BinaryNode> {
        let node = build_nack_node(received, self.local_ack_jid(), reason)?;
        connection.send_node(&node).await?;
        Ok(node)
    }

    #[cfg(feature = "noise")]
    pub async fn reject_call(
        &self,
        connection: &Connection,
        call_id: &str,
        call_from: &str,
    ) -> CoreResult<BinaryNode> {
        let from_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("call reject requires account JID".to_owned())
        })?;
        let node = build_call_reject_node(from_jid, call_from, call_id)?;
        let response = connection.query_node(node).await?;
        Ok(response.node)
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node<D>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        decryptor: &D,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<wa_core::InboundNodeProcessing>
    where
        D: wa_core::InboundMessageDecryptor,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let result = wa_core::process_inbound_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            self.local_ack_jid(),
            decryptor,
            buffer,
        )
        .await?;

        if let Some(response) = &result.response {
            connection.send_node(response).await?;
        }
        let mut events = buffer.drain_events();
        enrich_poll_event_update_events_from_store(&self.store, &mut events).await?;
        enrich_call_events_from_store(&self.store, &mut events).await?;
        append_derived_message_events(&mut events)?;
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        self.handle_incoming_node_side_effects(connection, node)
            .await?;
        emit_buffered_events(&self.events, events);
        Ok(result)
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_signal_provider(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<wa_core::InboundNodeProcessing>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.process_incoming_node(connection, node, &codec, buffer)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_placeholder_resend<D, E>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        decryptor: &D,
        encryptor: &E,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<IncomingPlaceholderResendProcessing>
    where
        D: wa_core::InboundMessageDecryptor,
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let placeholder = wa_core::placeholder_unavailable_message_from_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            current_unix_timestamp(),
        )?;
        let result = wa_core::process_inbound_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            self.local_ack_jid(),
            decryptor,
            buffer,
        )
        .await?;

        if let Some(response) = &result.response {
            connection.send_node(response).await?;
        }
        let mut events = buffer.drain_events();
        enrich_poll_event_update_events_from_store(&self.store, &mut events).await?;
        enrich_call_events_from_store(&self.store, &mut events).await?;
        append_derived_message_events(&mut events)?;
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        self.handle_incoming_node_side_effects(connection, node)
            .await?;
        emit_buffered_events(&self.events, events);

        let placeholder_resend = if let Some(placeholder) = placeholder {
            self.request_placeholder_resend_for_web_message(
                connection,
                &placeholder.web_message,
                placeholder.category.as_deref(),
                placeholder.unavailable_type.as_deref(),
                encryptor,
                MessageRelayOptions::new(),
            )
            .await?
        } else {
            None
        };

        Ok(IncomingPlaceholderResendProcessing {
            inbound: result,
            placeholder_resend,
        })
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_placeholder_resend_with_signal_provider(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<IncomingPlaceholderResendProcessing>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.process_incoming_node_with_placeholder_resend(connection, node, &codec, &codec, buffer)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_retry_resend<D, E>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        decryptor: &D,
        encryptor: &E,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<IncomingRetryResendProcessing>
    where
        D: wa_core::InboundMessageDecryptor,
        E: MessageEncryptor,
        S: Clone + 'static,
    {
        let inbound = self
            .process_incoming_node(connection, node, decryptor, buffer)
            .await?;
        let retry_resend = if let Some(parsed) = parse_retry_receipt_with_bundle(node)? {
            Some(
                self.handle_retry_receipt_with_bundle(
                    connection,
                    &parsed.receipt,
                    parsed.key_bundle,
                    encryptor,
                )
                .await?,
            )
        } else {
            None
        };

        Ok(IncomingRetryResendProcessing {
            inbound,
            retry_resend,
        })
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_retry_resend_with_signal_provider(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<IncomingRetryResendProcessing>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.process_incoming_node_with_retry_resend(connection, node, &codec, &codec, buffer)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_media_retry<D, T>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        decryptor: &D,
        buffer: &mut wa_core::EventBuffer,
        transfer: &wa_core::MediaTransfer<T>,
    ) -> CoreResult<IncomingMediaRetryProcessing>
    where
        D: wa_core::InboundMessageDecryptor,
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let result = wa_core::process_inbound_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            self.local_ack_jid(),
            decryptor,
            buffer,
        )
        .await?;

        if let Some(response) = &result.response {
            connection.send_node(response).await?;
        }

        let mut events = buffer.drain_events();
        enrich_poll_event_update_events_from_store(&self.store, &mut events).await?;
        enrich_call_events_from_store(&self.store, &mut events).await?;
        append_derived_message_events(&mut events)?;
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        self.handle_incoming_node_side_effects_with_app_state_snapshot_recovery(
            connection, transfer, node,
        )
        .await?;
        let media_retry = self
            .handle_persisted_media_retry_events(transfer, &events)
            .await?;
        emit_buffered_events(&self.events, events);

        Ok(IncomingMediaRetryProcessing {
            inbound: result,
            media_retry,
        })
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_media_retry_with_signal_provider<T>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        buffer: &mut wa_core::EventBuffer,
        transfer: &wa_core::MediaTransfer<T>,
    ) -> CoreResult<IncomingMediaRetryProcessing>
    where
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.process_incoming_node_with_media_retry(connection, node, &codec, buffer, transfer)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_placeholder_retry_and_media_retry<D, E, T>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        decryptor: &D,
        encryptor: &E,
        buffer: &mut wa_core::EventBuffer,
        transfer: &wa_core::MediaTransfer<T>,
    ) -> CoreResult<IncomingPlaceholderRetryMediaProcessing>
    where
        D: wa_core::InboundMessageDecryptor,
        E: MessageEncryptor,
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let placeholder = wa_core::placeholder_unavailable_message_from_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            current_unix_timestamp(),
        )?;
        let retry_receipt = parse_retry_receipt_with_bundle(node)?;
        let result = wa_core::process_inbound_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            self.local_ack_jid(),
            decryptor,
            buffer,
        )
        .await?;

        if let Some(response) = &result.response {
            connection.send_node(response).await?;
        }

        let mut events = buffer.drain_events();
        enrich_poll_event_update_events_from_store(&self.store, &mut events).await?;
        enrich_call_events_from_store(&self.store, &mut events).await?;
        append_derived_message_events(&mut events)?;
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        self.handle_incoming_node_side_effects_with_app_state_snapshot_recovery(
            connection, transfer, node,
        )
        .await?;
        let media_retry = self
            .handle_persisted_media_retry_events(transfer, &events)
            .await?;
        emit_buffered_events(&self.events, events);

        let placeholder_resend = if let Some(placeholder) = placeholder {
            self.request_placeholder_resend_for_web_message(
                connection,
                &placeholder.web_message,
                placeholder.category.as_deref(),
                placeholder.unavailable_type.as_deref(),
                encryptor,
                MessageRelayOptions::new(),
            )
            .await?
        } else {
            None
        };
        let retry_resend = if let Some(parsed) = retry_receipt {
            Some(
                self.handle_retry_receipt_with_bundle(
                    connection,
                    &parsed.receipt,
                    parsed.key_bundle,
                    encryptor,
                )
                .await?,
            )
        } else {
            None
        };

        Ok(IncomingPlaceholderRetryMediaProcessing {
            inbound: result,
            placeholder_resend,
            retry_resend,
            media_retry,
        })
    }

    #[cfg(feature = "noise")]
    pub async fn process_incoming_node_with_placeholder_retry_and_media_retry_with_signal_provider<
        T,
    >(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        buffer: &mut wa_core::EventBuffer,
        transfer: &wa_core::MediaTransfer<T>,
    ) -> CoreResult<IncomingPlaceholderRetryMediaProcessing>
    where
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.process_incoming_node_with_placeholder_retry_and_media_retry(
            connection, node, &codec, &codec, buffer, transfer,
        )
        .await
    }

    pub async fn process_offline_node<D>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        decryptor: &D,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<wa_core::OfflineNodeProcessing>
    where
        D: wa_core::InboundMessageDecryptor,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let result = wa_core::process_offline_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            self.local_ack_jid(),
            decryptor,
            buffer,
            wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
        )
        .await?;

        for child in &result.results {
            if let Some(response) = &child.response {
                connection.send_node(response).await?;
            }
        }

        let mut events = buffer.drain_events();
        enrich_poll_event_update_events_from_store(&self.store, &mut events).await?;
        enrich_call_events_from_store(&self.store, &mut events).await?;
        append_derived_message_events(&mut events)?;
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        self.handle_incoming_node_side_effects(connection, node)
            .await?;
        emit_buffered_events(&self.events, events);
        Ok(result)
    }

    #[cfg(feature = "noise")]
    pub async fn process_offline_node_with_signal_provider(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<wa_core::OfflineNodeProcessing>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.process_offline_node(connection, node, &codec, buffer)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn process_offline_node_with_placeholder_retry_and_media_retry<D, E, T>(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        decryptor: &D,
        encryptor: &E,
        buffer: &mut wa_core::EventBuffer,
        transfer: &wa_core::MediaTransfer<T>,
    ) -> CoreResult<IncomingOfflinePlaceholderRetryMediaProcessing>
    where
        D: wa_core::InboundMessageDecryptor,
        E: MessageEncryptor,
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let placeholders = placeholder_unavailable_messages_from_raw_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            current_unix_timestamp(),
        )?;
        let retry_receipts = retry_receipts_from_raw_node(node)?;
        let result = wa_core::process_offline_node(
            node,
            own_jid,
            self.credentials.account_lid.as_deref(),
            self.local_ack_jid(),
            decryptor,
            buffer,
            wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
        )
        .await?;

        for child in &result.results {
            if let Some(response) = &child.response {
                connection.send_node(response).await?;
            }
        }

        let mut events = buffer.drain_events();
        enrich_poll_event_update_events_from_store(&self.store, &mut events).await?;
        enrich_call_events_from_store(&self.store, &mut events).await?;
        append_derived_message_events(&mut events)?;
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        self.handle_incoming_node_side_effects_with_app_state_snapshot_recovery(
            connection, transfer, node,
        )
        .await?;
        let media_retry = self
            .handle_persisted_media_retry_events(transfer, &events)
            .await?;
        emit_buffered_events(&self.events, events);

        let mut placeholder_resends = Vec::new();
        for placeholder in placeholders {
            if let Some(relay) = self
                .request_placeholder_resend_for_web_message(
                    connection,
                    &placeholder.web_message,
                    placeholder.category.as_deref(),
                    placeholder.unavailable_type.as_deref(),
                    encryptor,
                    MessageRelayOptions::new(),
                )
                .await?
            {
                placeholder_resends.push(relay);
            }
        }

        let mut retry_resends = Vec::new();
        for parsed in retry_receipts {
            retry_resends.push(
                self.handle_retry_receipt_with_bundle(
                    connection,
                    &parsed.receipt,
                    parsed.key_bundle,
                    encryptor,
                )
                .await?,
            );
        }

        Ok(IncomingOfflinePlaceholderRetryMediaProcessing {
            offline: result,
            placeholder_resends,
            retry_resends,
            media_retry,
        })
    }

    #[cfg(feature = "noise")]
    pub async fn process_offline_node_with_placeholder_retry_and_media_retry_with_signal_provider<
        T,
    >(
        &self,
        connection: &Connection,
        node: &BinaryNode,
        buffer: &mut wa_core::EventBuffer,
        transfer: &wa_core::MediaTransfer<T>,
    ) -> CoreResult<IncomingOfflinePlaceholderRetryMediaProcessing>
    where
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.process_offline_node_with_placeholder_retry_and_media_retry(
            connection, node, &codec, &codec, buffer, transfer,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor<D>(
        &self,
        connection: Connection,
        decryptor: D,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        D: wa_core::InboundMessageDecryptor + 'static,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let own_lid = self.credentials.account_lid.clone();
        let local_ack_jid = self.local_ack_jid().map(ToOwned::to_owned);
        let mut events = self.events.subscribe();
        let event_hub = self.events.clone();
        let queries = self.queries.clone();
        let store = self.store.clone();
        let placeholder_resend = self.placeholder_resend.clone();
        let client = self.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = wa_core::EventBuffer::new(buffer_config);
            loop {
                match events.recv().await {
                    Ok(Event::RawNode(node)) => {
                        if let Some(refresh) = refresh_group_surfaces_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_group_surface_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }
                        if node.tag == "offline" {
                            let result = wa_core::process_offline_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                                wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
                            )
                            .await?;
                            for child in &result.results {
                                if let Some(response) = &child.response {
                                    connection.send_node(response).await?;
                                }
                            }
                        } else {
                            let result = wa_core::process_inbound_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                            )
                            .await?;
                            if let Some(response) = &result.response {
                                connection.send_node(response).await?;
                            }
                        }
                        let mut events = buffer.drain_events();
                        enrich_poll_event_update_events_from_store(&store, &mut events).await?;
                        enrich_call_events_from_store(&store, &mut events).await?;
                        append_derived_message_events(&mut events)?;
                        persist_receive_events(&store, &events).await?;
                        resolve_placeholder_resend_events_in_batches(&placeholder_resend, &events)?;
                        handle_app_state_sync_key_share_events_with_store(
                            &store,
                            &queries,
                            &connection,
                            Some(&event_hub),
                            &events,
                            false,
                            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
                        )
                        .await?;
                        client
                            .handle_incoming_node_side_effects(&connection, &node)
                            .await?;
                        emit_buffered_events(&event_hub, events);
                    }
                    Ok(Event::ConnectionUpdate(ConnectionState::Closed)) => return Ok(()),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(wa_core::CoreError::Protocol(format!(
                            "incoming processor lagged by {skipped} events"
                        )));
                    }
                }
            }
        });

        Ok(IncomingProcessor {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_signal_provider(
        &self,
        connection: Connection,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.spawn_incoming_processor(connection, codec, buffer_config)
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_placeholder_resend<D, E>(
        &self,
        connection: Connection,
        decryptor: D,
        encryptor: E,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        D: wa_core::InboundMessageDecryptor + 'static,
        E: MessageEncryptor + 'static,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let own_lid = self.credentials.account_lid.clone();
        let local_ack_jid = self.local_ack_jid().map(ToOwned::to_owned);
        let mut events = self.events.subscribe();
        let event_hub = self.events.clone();
        let queries = self.queries.clone();
        let store = self.store.clone();
        let placeholder_resend = self.placeholder_resend.clone();
        let client = self.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = wa_core::EventBuffer::new(buffer_config);
            loop {
                match events.recv().await {
                    Ok(Event::RawNode(node)) => {
                        if let Some(refresh) = refresh_group_surfaces_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_group_surface_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }

                        if node.tag == "offline" {
                            let result = wa_core::process_offline_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                                wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
                            )
                            .await?;
                            for child in &result.results {
                                if let Some(response) = &child.response {
                                    connection.send_node(response).await?;
                                }
                            }
                        } else {
                            let result = wa_core::process_inbound_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                            )
                            .await?;
                            if let Some(response) = &result.response {
                                connection.send_node(response).await?;
                            }
                        }
                        let placeholders = placeholder_unavailable_messages_from_raw_node(
                            &node,
                            &own_jid,
                            own_lid.as_deref(),
                            current_unix_timestamp(),
                        )?;
                        let mut events = buffer.drain_events();
                        enrich_poll_event_update_events_from_store(&store, &mut events).await?;
                        enrich_call_events_from_store(&store, &mut events).await?;
                        append_derived_message_events(&mut events)?;
                        persist_receive_events(&store, &events).await?;
                        resolve_placeholder_resend_events_in_batches(&placeholder_resend, &events)?;
                        handle_app_state_sync_key_share_events_with_store(
                            &store,
                            &queries,
                            &connection,
                            Some(&event_hub),
                            &events,
                            false,
                            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
                        )
                        .await?;
                        client
                            .handle_incoming_node_side_effects(&connection, &node)
                            .await?;
                        emit_buffered_events(&event_hub, events);

                        for placeholder in placeholders {
                            client
                                .request_placeholder_resend_for_web_message(
                                    &connection,
                                    &placeholder.web_message,
                                    placeholder.category.as_deref(),
                                    placeholder.unavailable_type.as_deref(),
                                    &encryptor,
                                    MessageRelayOptions::new(),
                                )
                                .await?;
                        }
                    }
                    Ok(Event::ConnectionUpdate(ConnectionState::Closed)) => return Ok(()),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(wa_core::CoreError::Protocol(format!(
                            "incoming processor lagged by {skipped} events"
                        )));
                    }
                }
            }
        });

        Ok(IncomingProcessor {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_placeholder_resend_with_signal_provider(
        &self,
        connection: Connection,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.spawn_incoming_processor_with_placeholder_resend(
            connection,
            codec.clone(),
            codec,
            buffer_config,
        )
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_retry_resend<D, E>(
        &self,
        connection: Connection,
        decryptor: D,
        encryptor: E,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        D: wa_core::InboundMessageDecryptor + 'static,
        E: MessageEncryptor + 'static,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let own_lid = self.credentials.account_lid.clone();
        let local_ack_jid = self.local_ack_jid().map(ToOwned::to_owned);
        let mut events = self.events.subscribe();
        let event_hub = self.events.clone();
        let queries = self.queries.clone();
        let store = self.store.clone();
        let placeholder_resend = self.placeholder_resend.clone();
        let client = self.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = wa_core::EventBuffer::new(buffer_config);
            loop {
                match events.recv().await {
                    Ok(Event::RawNode(node)) => {
                        if let Some(refresh) = refresh_group_surfaces_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_group_surface_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }

                        if node.tag == "offline" {
                            let result = wa_core::process_offline_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                                wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
                            )
                            .await?;
                            for child in &result.results {
                                if let Some(response) = &child.response {
                                    connection.send_node(response).await?;
                                }
                            }
                        } else {
                            let result = wa_core::process_inbound_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                            )
                            .await?;
                            if let Some(response) = &result.response {
                                connection.send_node(response).await?;
                            }
                        }
                        let retry_receipts = retry_receipts_from_raw_node(&node)?;
                        let mut events = buffer.drain_events();
                        enrich_poll_event_update_events_from_store(&store, &mut events).await?;
                        enrich_call_events_from_store(&store, &mut events).await?;
                        append_derived_message_events(&mut events)?;
                        persist_receive_events(&store, &events).await?;
                        resolve_placeholder_resend_events_in_batches(&placeholder_resend, &events)?;
                        handle_app_state_sync_key_share_events_with_store(
                            &store,
                            &queries,
                            &connection,
                            Some(&event_hub),
                            &events,
                            false,
                            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
                        )
                        .await?;
                        client
                            .handle_incoming_node_side_effects(&connection, &node)
                            .await?;
                        emit_buffered_events(&event_hub, events);

                        for receipt in retry_receipts {
                            client
                                .handle_retry_receipt_with_bundle(
                                    &connection,
                                    &receipt.receipt,
                                    receipt.key_bundle,
                                    &encryptor,
                                )
                                .await?;
                        }
                    }
                    Ok(Event::ConnectionUpdate(ConnectionState::Closed)) => return Ok(()),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(wa_core::CoreError::Protocol(format!(
                            "incoming processor lagged by {skipped} events"
                        )));
                    }
                }
            }
        });

        Ok(IncomingProcessor {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_retry_resend_with_signal_provider(
        &self,
        connection: Connection,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.spawn_incoming_processor_with_retry_resend(
            connection,
            codec.clone(),
            codec,
            buffer_config,
        )
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_placeholder_and_retry_resend<D, E>(
        &self,
        connection: Connection,
        decryptor: D,
        encryptor: E,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        D: wa_core::InboundMessageDecryptor + 'static,
        E: MessageEncryptor + 'static,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let own_lid = self.credentials.account_lid.clone();
        let local_ack_jid = self.local_ack_jid().map(ToOwned::to_owned);
        let mut events = self.events.subscribe();
        let event_hub = self.events.clone();
        let queries = self.queries.clone();
        let store = self.store.clone();
        let placeholder_resend = self.placeholder_resend.clone();
        let client = self.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = wa_core::EventBuffer::new(buffer_config);
            loop {
                match events.recv().await {
                    Ok(Event::RawNode(node)) => {
                        if let Some(refresh) = refresh_group_surfaces_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_group_surface_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }

                        if node.tag == "offline" {
                            let result = wa_core::process_offline_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                                wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
                            )
                            .await?;
                            for child in &result.results {
                                if let Some(response) = &child.response {
                                    connection.send_node(response).await?;
                                }
                            }
                        } else {
                            let result = wa_core::process_inbound_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                            )
                            .await?;
                            if let Some(response) = &result.response {
                                connection.send_node(response).await?;
                            }
                        }
                        let placeholders = placeholder_unavailable_messages_from_raw_node(
                            &node,
                            &own_jid,
                            own_lid.as_deref(),
                            current_unix_timestamp(),
                        )?;
                        let retry_receipts = retry_receipts_from_raw_node(&node)?;
                        let mut events = buffer.drain_events();
                        enrich_poll_event_update_events_from_store(&store, &mut events).await?;
                        enrich_call_events_from_store(&store, &mut events).await?;
                        append_derived_message_events(&mut events)?;
                        persist_receive_events(&store, &events).await?;
                        resolve_placeholder_resend_events_in_batches(&placeholder_resend, &events)?;
                        handle_app_state_sync_key_share_events_with_store(
                            &store,
                            &queries,
                            &connection,
                            Some(&event_hub),
                            &events,
                            false,
                            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
                        )
                        .await?;
                        client
                            .handle_incoming_node_side_effects(&connection, &node)
                            .await?;
                        emit_buffered_events(&event_hub, events);

                        for placeholder in placeholders {
                            client
                                .request_placeholder_resend_for_web_message(
                                    &connection,
                                    &placeholder.web_message,
                                    placeholder.category.as_deref(),
                                    placeholder.unavailable_type.as_deref(),
                                    &encryptor,
                                    MessageRelayOptions::new(),
                                )
                                .await?;
                        }
                        for receipt in retry_receipts {
                            client
                                .handle_retry_receipt_with_bundle(
                                    &connection,
                                    &receipt.receipt,
                                    receipt.key_bundle,
                                    &encryptor,
                                )
                                .await?;
                        }
                    }
                    Ok(Event::ConnectionUpdate(ConnectionState::Closed)) => return Ok(()),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(wa_core::CoreError::Protocol(format!(
                            "incoming processor lagged by {skipped} events"
                        )));
                    }
                }
            }
        });

        Ok(IncomingProcessor {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_placeholder_and_retry_resend_with_signal_provider(
        &self,
        connection: Connection,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.spawn_incoming_processor_with_placeholder_and_retry_resend(
            connection,
            codec.clone(),
            codec,
            buffer_config,
        )
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_placeholder_retry_and_media_retry<D, E, T>(
        &self,
        connection: Connection,
        decryptor: D,
        encryptor: E,
        transfer: wa_core::MediaTransfer<T>,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        D: wa_core::InboundMessageDecryptor + 'static,
        E: MessageEncryptor + 'static,
        T: wa_core::MediaTransport + 'static,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let own_lid = self.credentials.account_lid.clone();
        let local_ack_jid = self.local_ack_jid().map(ToOwned::to_owned);
        let mut events = self.events.subscribe();
        let event_hub = self.events.clone();
        let queries = self.queries.clone();
        let store = self.store.clone();
        let placeholder_resend = self.placeholder_resend.clone();
        let client = self.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = wa_core::EventBuffer::new(buffer_config);
            let startup_media_retry = client.handle_stored_media_retry_events(&transfer).await?;
            if !startup_media_retry.is_empty() {
                event_hub.emit(Event::MediaRetryProcessed(startup_media_retry));
            }
            loop {
                match events.recv().await {
                    Ok(Event::RawNode(node)) => {
                        if let Some(refresh) = refresh_group_surfaces_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_group_surface_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }

                        if node.tag == "offline" {
                            let result = wa_core::process_offline_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                                wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
                            )
                            .await?;
                            for child in &result.results {
                                if let Some(response) = &child.response {
                                    connection.send_node(response).await?;
                                }
                            }
                        } else {
                            let result = wa_core::process_inbound_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                            )
                            .await?;
                            if let Some(response) = &result.response {
                                connection.send_node(response).await?;
                            }
                        }
                        let placeholders = placeholder_unavailable_messages_from_raw_node(
                            &node,
                            &own_jid,
                            own_lid.as_deref(),
                            current_unix_timestamp(),
                        )?;
                        let retry_receipts = retry_receipts_from_raw_node(&node)?;
                        let mut events = buffer.drain_events();
                        enrich_poll_event_update_events_from_store(&store, &mut events).await?;
                        enrich_call_events_from_store(&store, &mut events).await?;
                        append_derived_message_events(&mut events)?;
                        persist_receive_events(&store, &events).await?;
                        resolve_placeholder_resend_events_in_batches(&placeholder_resend, &events)?;
                        handle_app_state_sync_key_share_events_with_store(
                            &store,
                            &queries,
                            &connection,
                            Some(&event_hub),
                            &events,
                            false,
                            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
                        )
                        .await?;
                        client
                            .handle_incoming_node_side_effects_with_app_state_snapshot_recovery(
                                &connection,
                                &transfer,
                                &node,
                            )
                            .await?;
                        let media_retry = client
                            .handle_persisted_media_retry_events(&transfer, &events)
                            .await?;
                        emit_buffered_events(&event_hub, events);
                        if !media_retry.is_empty() {
                            event_hub.emit(Event::MediaRetryProcessed(media_retry));
                        }

                        for placeholder in placeholders {
                            client
                                .request_placeholder_resend_for_web_message(
                                    &connection,
                                    &placeholder.web_message,
                                    placeholder.category.as_deref(),
                                    placeholder.unavailable_type.as_deref(),
                                    &encryptor,
                                    MessageRelayOptions::new(),
                                )
                                .await?;
                        }
                        for receipt in retry_receipts {
                            client
                                .handle_retry_receipt_with_bundle(
                                    &connection,
                                    &receipt.receipt,
                                    receipt.key_bundle,
                                    &encryptor,
                                )
                                .await?;
                        }
                    }
                    Ok(Event::ConnectionUpdate(ConnectionState::Closed)) => return Ok(()),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(wa_core::CoreError::Protocol(format!(
                            "incoming processor lagged by {skipped} events"
                        )));
                    }
                }
            }
        });

        Ok(IncomingProcessor {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_placeholder_retry_and_media_retry_with_signal_provider<T>(
        &self,
        connection: Connection,
        transfer: wa_core::MediaTransfer<T>,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        T: wa_core::MediaTransport + 'static,
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.spawn_incoming_processor_with_placeholder_retry_and_media_retry(
            connection,
            codec.clone(),
            codec,
            transfer,
            buffer_config,
        )
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_media_retry<D, T>(
        &self,
        connection: Connection,
        decryptor: D,
        transfer: wa_core::MediaTransfer<T>,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        D: wa_core::InboundMessageDecryptor + 'static,
        T: wa_core::MediaTransport + 'static,
        S: Clone + 'static,
    {
        let own_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("incoming processing requires account JID".to_owned())
        })?;
        let own_lid = self.credentials.account_lid.clone();
        let local_ack_jid = self.local_ack_jid().map(ToOwned::to_owned);
        let mut events = self.events.subscribe();
        let event_hub = self.events.clone();
        let queries = self.queries.clone();
        let store = self.store.clone();
        let placeholder_resend = self.placeholder_resend.clone();
        let client = self.clone();
        let handle = tokio::spawn(async move {
            let mut buffer = wa_core::EventBuffer::new(buffer_config);
            let startup_media_retry = client.handle_stored_media_retry_events(&transfer).await?;
            if !startup_media_retry.is_empty() {
                event_hub.emit(Event::MediaRetryProcessed(startup_media_retry));
            }
            loop {
                match events.recv().await {
                    Ok(Event::RawNode(node)) => {
                        if let Some(refresh) = refresh_group_surfaces_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_group_surface_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }

                        if node.tag == "offline" {
                            let result = wa_core::process_offline_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                                wa_core::DEFAULT_OFFLINE_NODE_YIELD_EVERY,
                            )
                            .await?;
                            for child in &result.results {
                                if let Some(response) = &child.response {
                                    connection.send_node(response).await?;
                                }
                            }
                        } else {
                            let result = wa_core::process_inbound_node(
                                &node,
                                &own_jid,
                                own_lid.as_deref(),
                                local_ack_jid.as_deref(),
                                &decryptor,
                                &mut buffer,
                            )
                            .await?;
                            if let Some(response) = &result.response {
                                connection.send_node(response).await?;
                            }
                        }
                        let mut events = buffer.drain_events();
                        enrich_poll_event_update_events_from_store(&store, &mut events).await?;
                        enrich_call_events_from_store(&store, &mut events).await?;
                        append_derived_message_events(&mut events)?;
                        persist_receive_events(&store, &events).await?;
                        resolve_placeholder_resend_events_in_batches(&placeholder_resend, &events)?;
                        handle_app_state_sync_key_share_events_with_store(
                            &store,
                            &queries,
                            &connection,
                            Some(&event_hub),
                            &events,
                            false,
                            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
                        )
                        .await?;
                        client
                            .handle_incoming_node_side_effects_with_app_state_snapshot_recovery(
                                &connection,
                                &transfer,
                                &node,
                            )
                            .await?;
                        let media_retry = client
                            .handle_persisted_media_retry_events(&transfer, &events)
                            .await?;
                        emit_buffered_events(&event_hub, events);
                        if !media_retry.is_empty() {
                            event_hub.emit(Event::MediaRetryProcessed(media_retry));
                        }
                    }
                    Ok(Event::ConnectionUpdate(ConnectionState::Closed)) => return Ok(()),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(wa_core::CoreError::Protocol(format!(
                            "incoming processor lagged by {skipped} events"
                        )));
                    }
                }
            }
        });

        Ok(IncomingProcessor {
            handle: Some(handle),
        })
    }

    #[cfg(feature = "noise")]
    pub fn spawn_incoming_processor_with_media_retry_with_signal_provider<T>(
        &self,
        connection: Connection,
        transfer: wa_core::MediaTransfer<T>,
        buffer_config: wa_core::EventBufferConfig,
    ) -> CoreResult<IncomingProcessor>
    where
        T: wa_core::MediaTransport + 'static,
        S: Clone + 'static,
    {
        let codec = self.signal_message_codec()?;
        self.spawn_incoming_processor_with_media_retry(connection, codec, transfer, buffer_config)
    }

    pub async fn fetch_media_connection_info(
        &self,
        connection: &Connection,
    ) -> CoreResult<MediaConnectionInfo> {
        let node = build_media_connection_query(self.queries.next_tag());
        let response = connection.query_node(node).await?;
        parse_media_connection_info(&response.node)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_media_bytes<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        plaintext: &[u8],
        kind: wa_core::MediaKind,
    ) -> CoreResult<wa_core::UploadedMedia>
    where
        T: wa_core::MediaTransport,
    {
        transfer.upload_bytes(plaintext, kind).await
    }

    #[cfg(feature = "noise")]
    pub async fn upload_media_bytes_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        plaintext: &[u8],
        kind: wa_core::MediaKind,
        cache: &C,
    ) -> CoreResult<wa_core::UploadedMedia>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        transfer.upload_bytes_cached(plaintext, kind, cache).await
    }

    #[cfg(feature = "noise")]
    pub async fn upload_media_file<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        path: impl AsRef<std::path::Path>,
        kind: wa_core::MediaKind,
    ) -> CoreResult<wa_core::UploadedMedia>
    where
        T: wa_core::MediaTransport,
    {
        transfer.upload_file(path, kind).await
    }

    #[cfg(feature = "noise")]
    pub async fn upload_media_file_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        path: impl AsRef<std::path::Path>,
        kind: wa_core::MediaKind,
        cache: &C,
    ) -> CoreResult<wa_core::UploadedMedia>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        transfer.upload_file_cached(path, kind, cache).await
    }

    #[cfg(feature = "noise")]
    pub async fn upload_video_remote_thumbnail<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        parent_media: &wa_core::UploadedMedia,
        jpeg_thumbnail: &[u8],
    ) -> CoreResult<wa_core::RemoteMediaThumbnail>
    where
        T: wa_core::MediaTransport,
    {
        transfer
            .upload_video_remote_thumbnail(parent_media, jpeg_thumbnail)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn upload_document_remote_thumbnail<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        parent_media: &wa_core::UploadedMedia,
        jpeg_thumbnail: &[u8],
        dimensions: Option<(u32, u32)>,
    ) -> CoreResult<wa_core::RemoteMediaThumbnail>
    where
        T: wa_core::MediaTransport,
    {
        transfer
            .upload_document_remote_thumbnail(parent_media, jpeg_thumbnail, dimensions)
            .await
    }

    #[cfg(all(feature = "noise", feature = "image"))]
    pub async fn upload_generated_video_remote_thumbnail_file<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        parent_media: &wa_core::UploadedMedia,
        path: impl AsRef<std::path::Path>,
        options: wa_core::VideoThumbnailOptions,
    ) -> CoreResult<wa_core::GeneratedRemoteMediaThumbnailUpload>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::upload_generated_video_remote_thumbnail_file(transfer, parent_media, path, options)
            .await
    }

    #[cfg(all(feature = "noise", feature = "image"))]
    pub async fn upload_generated_document_remote_thumbnail_file<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        parent_media: &wa_core::UploadedMedia,
        path: impl AsRef<std::path::Path>,
        options: wa_core::PdfThumbnailOptions,
    ) -> CoreResult<wa_core::GeneratedRemoteMediaThumbnailUpload>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::upload_generated_document_remote_thumbnail_file(
            transfer,
            parent_media,
            path,
            options,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_image_bytes<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        plaintext: &[u8],
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::BusinessProductImage>
    where
        T: wa_core::MediaTransport,
    {
        let media = transfer
            .upload_bytes(plaintext, wa_core::MediaKind::ProductCatalogImage)
            .await?;
        wa_core::business_product_image_from_uploaded_media(&media, fallback_host)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_image_bytes_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        plaintext: &[u8],
        fallback_host: Option<&str>,
        cache: &C,
    ) -> CoreResult<wa_core::BusinessProductImage>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        let media = transfer
            .upload_bytes_cached(plaintext, wa_core::MediaKind::ProductCatalogImage, cache)
            .await?;
        wa_core::business_product_image_from_uploaded_media(&media, fallback_host)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_image_file<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        path: impl AsRef<std::path::Path>,
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::BusinessProductImage>
    where
        T: wa_core::MediaTransport,
    {
        let media = transfer
            .upload_file(path, wa_core::MediaKind::ProductCatalogImage)
            .await?;
        wa_core::business_product_image_from_uploaded_media(&media, fallback_host)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_image_file_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        path: impl AsRef<std::path::Path>,
        fallback_host: Option<&str>,
        cache: &C,
    ) -> CoreResult<wa_core::BusinessProductImage>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        let media = transfer
            .upload_file_cached(path, wa_core::MediaKind::ProductCatalogImage, cache)
            .await?;
        wa_core::business_product_image_from_uploaded_media(&media, fallback_host)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_images_bytes<T, I, B>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        plaintexts: I,
        fallback_host: Option<&str>,
    ) -> CoreResult<Vec<wa_core::BusinessProductImage>>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut images = Vec::new();
        for plaintext in plaintexts {
            images.push(
                self.upload_business_product_image_bytes(
                    transfer,
                    plaintext.as_ref(),
                    fallback_host,
                )
                .await?,
            );
        }
        Ok(images)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_images_bytes_cached<T, C, I, B>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        plaintexts: I,
        fallback_host: Option<&str>,
        cache: &C,
    ) -> CoreResult<Vec<wa_core::BusinessProductImage>>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut images = Vec::new();
        for plaintext in plaintexts {
            images.push(
                self.upload_business_product_image_bytes_cached(
                    transfer,
                    plaintext.as_ref(),
                    fallback_host,
                    cache,
                )
                .await?,
            );
        }
        Ok(images)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_image_files<T, I, P>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        paths: I,
        fallback_host: Option<&str>,
    ) -> CoreResult<Vec<wa_core::BusinessProductImage>>
    where
        T: wa_core::MediaTransport,
        I: IntoIterator<Item = P>,
        P: AsRef<std::path::Path>,
    {
        let mut images = Vec::new();
        for path in paths {
            images.push(
                self.upload_business_product_image_file(transfer, path, fallback_host)
                    .await?,
            );
        }
        Ok(images)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_product_image_files_cached<T, C, I, P>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        paths: I,
        fallback_host: Option<&str>,
        cache: &C,
    ) -> CoreResult<Vec<wa_core::BusinessProductImage>>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
        I: IntoIterator<Item = P>,
        P: AsRef<std::path::Path>,
    {
        let mut images = Vec::new();
        for path in paths {
            images.push(
                self.upload_business_product_image_file_cached(
                    transfer,
                    path,
                    fallback_host,
                    cache,
                )
                .await?,
            );
        }
        Ok(images)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_cover_photo_bytes<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        plaintext: &[u8],
    ) -> CoreResult<wa_core::BusinessCoverPhotoUpload>
    where
        T: wa_core::MediaTransport,
    {
        let upload = transfer
            .upload_bytes_with_location(plaintext, wa_core::MediaKind::BusinessCoverPhoto)
            .await?;
        wa_core::business_cover_photo_upload_from_location(&upload.location)
    }

    #[cfg(feature = "noise")]
    pub async fn upload_business_cover_photo_file<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        path: impl AsRef<std::path::Path>,
    ) -> CoreResult<wa_core::BusinessCoverPhotoUpload>
    where
        T: wa_core::MediaTransport,
    {
        let upload = transfer
            .upload_file_with_location(path, wa_core::MediaKind::BusinessCoverPhoto)
            .await?;
        wa_core::business_cover_photo_upload_from_location(&upload.location)
    }

    #[cfg(feature = "link-preview")]
    pub async fn fetch_link_preview(
        &self,
        url: &str,
        options: wa_core::LinkPreviewFetchOptions,
    ) -> CoreResult<wa_core::FetchedLinkPreview> {
        wa_core::fetch_link_preview(url, options).await
    }

    #[cfg(feature = "link-preview")]
    pub async fn upload_link_preview_thumbnail_bytes<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        jpeg_thumbnail: &[u8],
        dimensions: Option<(u32, u32)>,
    ) -> CoreResult<wa_core::LinkPreviewThumbnail>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::upload_link_preview_thumbnail(transfer, jpeg_thumbnail, dimensions).await
    }

    #[cfg(feature = "link-preview")]
    pub async fn upload_link_preview_thumbnail_bytes_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        jpeg_thumbnail: &[u8],
        dimensions: Option<(u32, u32)>,
        cache: &C,
    ) -> CoreResult<wa_core::LinkPreviewThumbnail>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        wa_core::upload_link_preview_thumbnail_cached(transfer, jpeg_thumbnail, dimensions, cache)
            .await
    }

    #[cfg(feature = "link-preview")]
    pub async fn upload_link_preview_thumbnail_file<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        path: impl AsRef<std::path::Path>,
        dimensions: Option<(u32, u32)>,
    ) -> CoreResult<wa_core::LinkPreviewThumbnail>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::upload_link_preview_thumbnail_file(transfer, path, dimensions).await
    }

    #[cfg(feature = "link-preview")]
    pub async fn upload_link_preview_thumbnail_file_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        path: impl AsRef<std::path::Path>,
        dimensions: Option<(u32, u32)>,
        cache: &C,
    ) -> CoreResult<wa_core::LinkPreviewThumbnail>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        wa_core::upload_link_preview_thumbnail_file_cached(transfer, path, dimensions, cache).await
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    pub async fn upload_generated_link_preview_thumbnail<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        input: &[u8],
        options: wa_core::LinkPreviewImageOptions,
    ) -> CoreResult<wa_core::GeneratedLinkPreviewThumbnailUpload>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::upload_generated_link_preview_thumbnail(transfer, input, options).await
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    pub async fn upload_generated_link_preview_thumbnail_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        input: &[u8],
        options: wa_core::LinkPreviewImageOptions,
        cache: &C,
    ) -> CoreResult<wa_core::GeneratedLinkPreviewThumbnailUpload>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        wa_core::upload_generated_link_preview_thumbnail_cached(transfer, input, options, cache)
            .await
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    pub async fn fetch_link_preview_with_thumbnail<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        url: &str,
        options: wa_core::LinkPreviewThumbnailFetchOptions,
    ) -> CoreResult<wa_core::FetchedLinkPreviewWithThumbnail>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::fetch_link_preview_with_thumbnail(transfer, url, options).await
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    pub async fn fetch_link_preview_with_thumbnail_cached<T, C>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        url: &str,
        options: wa_core::LinkPreviewThumbnailFetchOptions,
        cache: &C,
    ) -> CoreResult<wa_core::FetchedLinkPreviewWithThumbnail>
    where
        T: wa_core::MediaTransport,
        C: wa_core::MediaUploadCache,
    {
        wa_core::fetch_link_preview_with_thumbnail_cached(transfer, url, options, cache).await
    }

    #[cfg(feature = "noise")]
    pub async fn download_media_bytes<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        media: &wa_core::UploadedMedia,
        kind: wa_core::MediaKind,
        fallback_host: Option<&str>,
    ) -> CoreResult<Vec<u8>>
    where
        T: wa_core::MediaTransport,
    {
        transfer.download_bytes(media, kind, fallback_host).await
    }

    #[cfg(feature = "noise")]
    pub fn apply_media_retry_event(
        &self,
        retry: &wa_core::MediaRetryEvent,
        media: &wa_core::UploadedMedia,
    ) -> CoreResult<wa_core::MediaRetryApplication> {
        wa_core::apply_media_retry_event(retry, media)
    }

    #[cfg(feature = "noise")]
    pub async fn download_media_bytes_after_retry<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        media: &wa_core::UploadedMedia,
        kind: wa_core::MediaKind,
        retry: &wa_core::MediaRetryEvent,
        fallback_host: Option<&str>,
    ) -> CoreResult<wa_core::MediaRetryDownload>
    where
        T: wa_core::MediaTransport,
    {
        transfer
            .download_bytes_after_retry(media, kind, retry, fallback_host)
            .await
    }

    #[cfg(feature = "noise")]
    pub fn register_pending_media_retry(
        &self,
        key: wa_core::MessageEventKey,
        pending: wa_core::PendingMediaRetry,
    ) -> CoreResult<()> {
        self.media_retry.register(key, pending)
    }

    #[cfg(feature = "noise")]
    pub async fn register_pending_media_retry_persisted(
        &self,
        key: wa_core::MessageEventKey,
        pending: wa_core::PendingMediaRetry,
    ) -> CoreResult<()> {
        let entry = wa_core::MediaRetryPendingEntry::new(key, pending);
        let store_key = wa_core::pending_media_retry_store_key(&entry.key);
        let encoded = wa_core::encode_stored_pending_media_retry(&entry)?;
        self.store
            .set(KeyNamespace::PendingMediaRetry, &store_key, &encoded)
            .await?;
        self.media_retry.register(entry.key, entry.pending)
    }

    #[cfg(feature = "noise")]
    pub async fn load_pending_media_retry_from_store(
        &self,
        key: &wa_core::MessageEventKey,
    ) -> CoreResult<Option<wa_core::PendingMediaRetry>> {
        let store_key = wa_core::pending_media_retry_store_key(key);
        let Some(value) = self
            .store
            .get(KeyNamespace::PendingMediaRetry, &store_key)
            .await?
        else {
            return Ok(None);
        };
        let entry = wa_core::decode_stored_pending_media_retry(&value)?;
        if entry.key != *key {
            return Err(wa_core::CoreError::Protocol(
                "stored pending media retry key mismatch".to_owned(),
            ));
        }
        Ok(Some(entry.pending))
    }

    #[cfg(feature = "noise")]
    pub async fn restore_pending_media_retries_from_store(&self) -> CoreResult<usize> {
        let mut after = None;
        let mut restored = 0;
        loop {
            let keys = self
                .store
                .list_keys(
                    KeyNamespace::PendingMediaRetry,
                    after.as_deref(),
                    PENDING_MEDIA_RETRY_STORE_PAGE_SIZE,
                )
                .await?;
            if keys.is_empty() {
                break;
            }

            for key in &keys {
                if let Some(value) = self.store.get(KeyNamespace::PendingMediaRetry, key).await? {
                    let entry = wa_core::decode_stored_pending_media_retry(&value)?;
                    if wa_core::pending_media_retry_store_key(&entry.key) != *key {
                        return Err(wa_core::CoreError::Protocol(
                            "stored pending media retry key mismatch".to_owned(),
                        ));
                    }
                    self.media_retry.register(entry.key, entry.pending)?;
                    restored += 1;
                }
            }

            if keys.len() < PENDING_MEDIA_RETRY_STORE_PAGE_SIZE {
                break;
            }
            after = keys.last().cloned();
        }
        Ok(restored)
    }

    #[cfg(feature = "noise")]
    pub async fn delete_pending_media_retry_from_store(
        &self,
        key: &wa_core::MessageEventKey,
    ) -> CoreResult<()> {
        let store_key = wa_core::pending_media_retry_store_key(key);
        self.store
            .delete(KeyNamespace::PendingMediaRetry, &store_key)
            .await?;
        Ok(())
    }

    #[cfg(feature = "noise")]
    async fn load_media_retry_event_from_store_key(
        &self,
        store_key: &str,
    ) -> CoreResult<Option<wa_core::MediaRetryEvent>> {
        let Some(value) = self
            .store
            .get(KeyNamespace::MediaRetryEvent, store_key)
            .await?
        else {
            return Ok(None);
        };
        let retry = wa_core::decode_stored_media_retry_event(&value)?;
        if wa_core::media_retry_event_store_key(&retry) != store_key {
            return Err(wa_core::CoreError::Protocol(
                "stored media retry event key mismatch".to_owned(),
            ));
        }
        Ok(Some(retry))
    }

    #[cfg(feature = "noise")]
    async fn delete_media_retry_event_from_store_key(&self, store_key: &str) -> CoreResult<()> {
        self.store
            .delete(KeyNamespace::MediaRetryEvent, store_key)
            .await?;
        Ok(())
    }

    #[cfg(feature = "noise")]
    pub fn register_pending_media_retry_with(
        &self,
        coordinator: &wa_core::MediaRetryCoordinator,
        key: wa_core::MessageEventKey,
        pending: wa_core::PendingMediaRetry,
    ) -> CoreResult<()> {
        coordinator.register(key, pending)
    }

    #[cfg(feature = "noise")]
    pub async fn download_pending_media_after_retry<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        retry: &wa_core::MediaRetryEvent,
    ) -> CoreResult<wa_core::MediaRetryDownload>
    where
        T: wa_core::MediaTransport,
    {
        self.media_retry.download_after_retry(transfer, retry).await
    }

    #[cfg(feature = "noise")]
    pub async fn download_persisted_pending_media_after_retry<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        retry: &wa_core::MediaRetryEvent,
    ) -> CoreResult<wa_core::MediaRetryDownload>
    where
        T: wa_core::MediaTransport,
    {
        if self.media_retry.pending(&retry.key)?.is_none()
            && let Some(pending) = self.load_pending_media_retry_from_store(&retry.key).await?
        {
            self.media_retry.register(retry.key.clone(), pending)?;
        }

        let download = self
            .media_retry
            .download_after_retry(transfer, retry)
            .await?;
        self.delete_pending_media_retry_from_store(&retry.key)
            .await?;
        Ok(download)
    }

    #[cfg(feature = "noise")]
    pub async fn download_pending_media_after_retry_with<T>(
        &self,
        coordinator: &wa_core::MediaRetryCoordinator,
        transfer: &wa_core::MediaTransfer<T>,
        retry: &wa_core::MediaRetryEvent,
    ) -> CoreResult<wa_core::MediaRetryDownload>
    where
        T: wa_core::MediaTransport,
    {
        coordinator.download_after_retry(transfer, retry).await
    }

    #[cfg(feature = "noise")]
    pub async fn handle_media_retry_batch<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        batch: &wa_core::EventBatch,
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        self.media_retry.handle_event_batch(transfer, batch).await
    }

    #[cfg(feature = "noise")]
    async fn handle_media_retry_slice<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        retries: &[wa_core::MediaRetryEvent],
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        self.media_retry
            .handle_retry_events(transfer, retries)
            .await
    }

    #[cfg(feature = "noise")]
    async fn stage_persisted_media_retry_batch(
        &self,
        batch: &wa_core::EventBatch,
    ) -> CoreResult<PersistedMediaRetryStage> {
        let mut staged = Vec::new();
        let mut malformed_stored_records = 0;
        for retry in &batch.media_retry {
            if self.media_retry.pending(&retry.key)?.is_none() {
                match self.load_pending_media_retry_from_store(&retry.key).await {
                    Ok(Some(pending)) => {
                        self.media_retry.register(retry.key.clone(), pending)?;
                    }
                    Ok(None) => {}
                    Err(err) if is_malformed_media_retry_store_record(&err) => {
                        self.delete_pending_media_retry_from_store(&retry.key)
                            .await?;
                        malformed_stored_records += 1;
                    }
                    Err(err) => return Err(err),
                }
            }
            if self.media_retry.pending(&retry.key)?.is_some() && !staged.contains(&retry.key) {
                staged.push(retry.key.clone());
            }
        }
        Ok(PersistedMediaRetryStage {
            keys: staged,
            malformed_stored_records,
        })
    }

    #[cfg(feature = "noise")]
    async fn delete_completed_persisted_media_retries(
        &self,
        keys: &[wa_core::MessageEventKey],
    ) -> CoreResult<()> {
        for key in keys {
            if self.media_retry.pending(key)?.is_none() {
                self.delete_pending_media_retry_from_store(key).await?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "noise")]
    async fn delete_completed_persisted_media_retry_events(
        &self,
        records: &[(String, wa_core::MessageEventKey)],
        staged: &[wa_core::MessageEventKey],
    ) -> CoreResult<()> {
        for (store_key, event_key) in records {
            if staged.contains(event_key) && self.media_retry.pending(event_key)?.is_none() {
                self.delete_media_retry_event_from_store_key(store_key)
                    .await?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "noise")]
    pub async fn handle_persisted_media_retry_batch<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        batch: &wa_core::EventBatch,
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        let staged = self.stage_persisted_media_retry_batch(batch).await?;
        let records = batch
            .media_retry
            .iter()
            .map(|retry| {
                (
                    wa_core::media_retry_event_store_key(retry),
                    retry.key.clone(),
                )
            })
            .collect::<Vec<_>>();
        let mut outcome = self.handle_media_retry_batch(transfer, batch).await?;
        outcome.malformed_stored_records += staged.malformed_stored_records;
        self.delete_completed_persisted_media_retries(&staged.keys)
            .await?;
        self.delete_completed_persisted_media_retry_events(&records, &staged.keys)
            .await?;
        Ok(outcome)
    }

    #[cfg(feature = "noise")]
    async fn handle_persisted_media_retry_slice<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        retries: &[wa_core::MediaRetryEvent],
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        let batch = wa_core::EventBatch {
            media_retry: retries.to_vec(),
            ..wa_core::EventBatch::default()
        };
        self.handle_persisted_media_retry_batch(transfer, &batch)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn handle_stored_media_retry_events<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        let mut after = None;
        let mut merged = wa_core::MediaRetryBatchOutcome::default();
        loop {
            let store_keys = self
                .store
                .list_keys(
                    KeyNamespace::MediaRetryEvent,
                    after.as_deref(),
                    MEDIA_RETRY_EVENT_STORE_PAGE_SIZE,
                )
                .await?;
            if store_keys.is_empty() {
                break;
            }

            let mut retries = Vec::new();
            let mut records = Vec::new();
            for store_key in &store_keys {
                match self.load_media_retry_event_from_store_key(store_key).await {
                    Ok(Some(retry)) => {
                        records.push((store_key.clone(), retry.key.clone()));
                        retries.push(retry);
                    }
                    Ok(None) => {}
                    Err(err) if is_malformed_media_retry_store_record(&err) => {
                        self.delete_media_retry_event_from_store_key(store_key)
                            .await?;
                        merged.malformed_stored_records += 1;
                    }
                    Err(err) => return Err(err),
                }
            }

            if !retries.is_empty() {
                let batch = wa_core::EventBatch {
                    media_retry: retries,
                    ..wa_core::EventBatch::default()
                };
                let staged = self.stage_persisted_media_retry_batch(&batch).await?;
                let outcome = self.handle_media_retry_batch(transfer, &batch).await?;
                self.delete_completed_persisted_media_retries(&staged.keys)
                    .await?;
                self.delete_completed_persisted_media_retry_events(&records, &staged.keys)
                    .await?;
                merged.downloads.extend(outcome.downloads);
                merged.errors.extend(outcome.errors);
                merged.ignored_without_pending += outcome.ignored_without_pending;
                merged.malformed_stored_records +=
                    staged.malformed_stored_records + outcome.malformed_stored_records;
            }

            if store_keys.len() < MEDIA_RETRY_EVENT_STORE_PAGE_SIZE {
                break;
            }
            after = store_keys.last().cloned();
        }
        Ok(merged)
    }

    #[cfg(feature = "noise")]
    pub async fn handle_media_retry_events<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        events: &[Event],
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        let mut merged = wa_core::MediaRetryBatchOutcome::default();
        for event in events {
            let outcome = match event {
                Event::Batch(batch) => self.handle_media_retry_batch(transfer, batch).await?,
                Event::MediaRetry(retries) => {
                    self.handle_media_retry_slice(transfer, retries).await?
                }
                _ => continue,
            };
            merged.downloads.extend(outcome.downloads);
            merged.errors.extend(outcome.errors);
            merged.ignored_without_pending += outcome.ignored_without_pending;
            merged.malformed_stored_records += outcome.malformed_stored_records;
        }
        Ok(merged)
    }

    #[cfg(feature = "noise")]
    pub async fn handle_persisted_media_retry_events<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        events: &[Event],
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        let mut merged = wa_core::MediaRetryBatchOutcome::default();
        for event in events {
            let outcome = match event {
                Event::Batch(batch) => {
                    self.handle_persisted_media_retry_batch(transfer, batch)
                        .await?
                }
                Event::MediaRetry(retries) => {
                    self.handle_persisted_media_retry_slice(transfer, retries)
                        .await?
                }
                _ => continue,
            };
            merged.downloads.extend(outcome.downloads);
            merged.errors.extend(outcome.errors);
            merged.ignored_without_pending += outcome.ignored_without_pending;
            merged.malformed_stored_records += outcome.malformed_stored_records;
        }
        Ok(merged)
    }

    #[cfg(feature = "noise")]
    pub async fn handle_media_retry_batch_with<T>(
        &self,
        coordinator: &wa_core::MediaRetryCoordinator,
        transfer: &wa_core::MediaTransfer<T>,
        batch: &wa_core::EventBatch,
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        coordinator.handle_event_batch(transfer, batch).await
    }

    #[cfg(feature = "noise")]
    pub async fn download_media_to_file<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        media: &wa_core::UploadedMedia,
        kind: wa_core::MediaKind,
        fallback_host: Option<&str>,
        path: impl AsRef<std::path::Path>,
    ) -> CoreResult<u64>
    where
        T: wa_core::MediaTransport,
    {
        transfer
            .download_to_file(media, kind, fallback_host, path)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn download_history_sync<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        notification: &wa_core::HistorySyncNotification,
        fallback_host: Option<&str>,
        config: wa_core::HistorySyncDecodeConfig,
    ) -> CoreResult<wa_core::HistorySync>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::download_history_sync(transfer, notification, fallback_host, config).await
    }

    #[cfg(feature = "noise")]
    pub async fn download_and_process_history_sync<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        notification: &wa_core::HistorySyncNotification,
        fallback_host: Option<&str>,
        decode_config: wa_core::HistorySyncDecodeConfig,
        process_config: wa_core::HistorySyncProcessConfig,
    ) -> CoreResult<wa_core::ProcessedHistorySync>
    where
        T: wa_core::MediaTransport,
    {
        wa_core::download_and_process_history_sync(
            transfer,
            notification,
            fallback_host,
            decode_config,
            process_config,
        )
        .await
    }

    #[cfg(feature = "noise")]
    pub async fn process_inline_and_emit_history_sync(
        &self,
        notification: &wa_core::HistorySyncNotification,
        decode_config: wa_core::HistorySyncDecodeConfig,
        process_config: wa_core::HistorySyncProcessConfig,
    ) -> CoreResult<Option<wa_core::ProcessedHistorySync>>
    where
        S: Clone + 'static,
    {
        let Some(processed) = wa_core::process_inline_history_sync_notification(
            notification,
            decode_config,
            process_config,
        )?
        else {
            return Ok(None);
        };
        self.process_history_sync_result(processed).await.map(Some)
    }

    #[cfg(feature = "noise")]
    pub async fn process_history_sync_result(
        &self,
        processed: wa_core::ProcessedHistorySync,
    ) -> CoreResult<wa_core::ProcessedHistorySync>
    where
        S: Clone + 'static,
    {
        let mut events = Vec::new();
        if !processed.lid_pn_mappings.is_empty() {
            events.push(Event::LidMappingUpdate(
                processed
                    .lid_pn_mappings
                    .iter()
                    .map(|mapping| {
                        wa_core::LidMappingEvent::new(
                            mapping.lid_jid.clone(),
                            mapping.pn_jid.clone(),
                        )
                    })
                    .collect(),
            ));
        }
        if !processed.batch.is_empty() {
            events.push(Event::Batch(Box::new(processed.batch.clone())));
        }
        if let Some(mode) = processed.default_disappearing_mode.clone() {
            events.push(Event::DefaultDisappearingModeUpdate(mode));
        }

        enrich_call_events_from_store(&self.store, &mut events).await?;
        append_derived_message_events(&mut events)?;
        persist_receive_events(&self.store, &events).await?;
        emit_buffered_events(&self.events, events);
        Ok(processed)
    }

    #[cfg(feature = "noise")]
    pub async fn download_process_and_emit_history_sync<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        notification: &wa_core::HistorySyncNotification,
        fallback_host: Option<&str>,
        decode_config: wa_core::HistorySyncDecodeConfig,
        process_config: wa_core::HistorySyncProcessConfig,
    ) -> CoreResult<wa_core::ProcessedHistorySync>
    where
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let processed = wa_core::download_and_process_history_sync(
            transfer,
            notification,
            fallback_host,
            decode_config,
            process_config,
        )
        .await?;
        self.process_history_sync_result(processed).await
    }

    #[cfg(feature = "noise")]
    pub async fn process_inline_and_emit_history_sync_events(
        &self,
        events: &[Event],
        decode_config: wa_core::HistorySyncDecodeConfig,
        process_config: wa_core::HistorySyncProcessConfig,
    ) -> CoreResult<Vec<wa_core::ProcessedHistorySync>>
    where
        S: Clone + 'static,
    {
        let notifications = history_sync_notifications_from_events(events)?;
        let mut processed = Vec::new();
        for notification in notifications {
            if let Some(result) = self
                .process_inline_and_emit_history_sync(&notification, decode_config, process_config)
                .await?
            {
                processed.push(result);
            }
        }
        Ok(processed)
    }

    #[cfg(feature = "noise")]
    pub async fn download_process_and_emit_history_sync_events<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        events: &[Event],
        fallback_host: Option<&str>,
        decode_config: wa_core::HistorySyncDecodeConfig,
        process_config: wa_core::HistorySyncProcessConfig,
    ) -> CoreResult<Vec<wa_core::ProcessedHistorySync>>
    where
        T: wa_core::MediaTransport,
        S: Clone + 'static,
    {
        let notifications = history_sync_notifications_from_events(events)?;
        let mut processed = Vec::with_capacity(notifications.len());
        for notification in notifications {
            processed.push(
                self.download_process_and_emit_history_sync(
                    transfer,
                    &notification,
                    fallback_host,
                    decode_config,
                    process_config,
                )
                .await?,
            );
        }
        Ok(processed)
    }

    pub async fn send_media_retry_request_with_payload(
        &self,
        connection: &Connection,
        key: &MessageKey,
        requester_jid: &str,
        payload: MediaRetryPayload,
    ) -> CoreResult<BinaryNode> {
        let node = build_media_retry_request_node(key, requester_jid, payload)?;
        connection.send_node(&node).await?;
        Ok(node)
    }

    #[cfg(feature = "noise")]
    pub async fn send_media_retry_request(
        &self,
        connection: &Connection,
        key: &MessageKey,
        media_key: &[u8],
    ) -> CoreResult<BinaryNode> {
        let requester_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Payload(
                "registered account JID is required for media retry request".to_owned(),
            )
        })?;
        let node = build_encrypted_media_retry_request_node(key, requester_jid, media_key)?;
        connection.send_node(&node).await?;
        Ok(node)
    }

    pub async fn send_receipts(
        &self,
        connection: &Connection,
        keys: &[MessageKey],
        receipt_type: MessageReceiptType,
        timestamp: Option<u64>,
    ) -> CoreResult<Vec<MessageReceipt>> {
        let receipts = aggregate_receipts_from_message_keys(keys)?;
        for receipt in &receipts {
            self.send_receipt(connection, receipt, receipt_type, timestamp)
                .await?;
        }
        Ok(receipts)
    }

    pub async fn read_messages(
        &self,
        connection: &Connection,
        keys: &[MessageKey],
        send_read_receipts: bool,
        timestamp: Option<u64>,
    ) -> CoreResult<Vec<MessageReceipt>> {
        let receipt_type = if send_read_receipts {
            MessageReceiptType::Read
        } else {
            MessageReceiptType::ReadSelf
        };
        self.send_receipts(connection, keys, receipt_type, timestamp)
            .await
    }

    #[cfg(feature = "noise")]
    pub async fn fetch_lid_mappings<I, T>(
        &self,
        connection: &Connection,
        jids: I,
    ) -> CoreResult<Vec<USyncLidMapping>>
    where
        S: Clone,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let Some(query) = build_lid_mapping_query(jids)? else {
            return Ok(Vec::new());
        };
        let Some(result) = self.execute_usync_query(connection, &query).await? else {
            return Ok(Vec::new());
        };
        let mappings = lid_mappings_from_result(&result);
        let store_mappings = mappings
            .iter()
            .map(|mapping| LidPnMapping {
                pn: mapping.pn.clone(),
                lid: mapping.lid.clone(),
            })
            .collect::<Vec<_>>();
        LidPnMappingStore::new(self.store.clone())
            .store_mappings(store_mappings)
            .await?;
        Ok(mappings)
    }

    #[cfg(feature = "noise")]
    fn local_ack_jid(&self) -> Option<&str> {
        self.credentials.account_jid.as_deref()
    }

    #[cfg(not(feature = "noise"))]
    fn local_ack_jid(&self) -> Option<&str> {
        None
    }

    async fn buffer_invite_v4_accept_message_events(
        &self,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
        source: &'static str,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<()> {
        let batch = invite_v4_accept_message_batch(
            invite,
            invite_message_key,
            self.local_ack_jid(),
            source,
        );
        persist_message_event_batch(&self.store, &batch).await?;
        buffer.push(Event::Batch(Box::new(batch)))
    }

    #[cfg(feature = "noise")]
    pub async fn fetch_device_jids<I, T>(
        &self,
        connection: &Connection,
        jids: I,
        exclude_zero_devices: bool,
    ) -> CoreResult<Vec<USyncDeviceJid>>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let Some(query) = build_device_query(jids)? else {
            return Ok(Vec::new());
        };
        let Some(result) = self.execute_usync_query(connection, &query).await? else {
            return Ok(Vec::new());
        };
        let my_jid = self.credentials.account_jid.as_deref().ok_or_else(|| {
            wa_core::CoreError::Protocol("device lookup requires account JID".to_owned())
        })?;
        extract_device_jids(
            &result,
            my_jid,
            self.credentials.account_lid.as_deref(),
            exclude_zero_devices,
        )
    }

    #[cfg(feature = "noise")]
    async fn session_query_jids(&self, jids: &[String]) -> CoreResult<Vec<String>>
    where
        S: Clone,
    {
        let mappings = LidPnMappingStore::new(self.store.clone());
        let mut out = Vec::with_capacity(jids.len());
        for jid in jids {
            let query_jid = self.session_query_jid(&mappings, jid).await?;
            push_unique_jid(&mut out, &query_jid);
        }
        Ok(out)
    }

    #[cfg(feature = "noise")]
    async fn session_query_jid(
        &self,
        mappings: &LidPnMappingStore<S>,
        jid: &str,
    ) -> CoreResult<String>
    where
        S: Clone,
    {
        if is_lid_signal_jid(jid)? {
            Ok(jid.to_owned())
        } else if let Some(lid_user) = mappings.lid_for_pn(jid).await? {
            mapped_lid_session_jid(jid, &lid_user)
        } else {
            Ok(jid.to_owned())
        }
    }

    #[cfg(feature = "noise")]
    async fn retry_session_jids_for_participant(
        &self,
        participant_jid: &str,
    ) -> CoreResult<Vec<String>>
    where
        S: Clone,
    {
        let participant_jid = normalize_signal_session_jid(participant_jid)?;
        let mut jids = vec![participant_jid.to_owned()];
        let mappings = LidPnMappingStore::new(self.store.clone());
        if is_lid_signal_jid(&participant_jid)?
            && let Some(pn_user) = mappings.pn_for_lid(&participant_jid).await?
        {
            let decoded = jid_decode(&participant_jid).ok_or_else(|| {
                wa_core::CoreError::Protocol(format!(
                    "invalid retry participant JID: {participant_jid}"
                ))
            })?;
            let server = if decoded.server == JidServer::HostedLid {
                JidServer::Hosted
            } else {
                JidServer::SWhatsAppNet
            };
            let pn_jid = jid_encode(
                pn_user,
                server,
                decoded.device.filter(|device| *device != 0),
                None,
            );
            push_unique_jid(&mut jids, &pn_jid);
        }
        for query_jid in self
            .session_query_jids(std::slice::from_ref(&participant_jid))
            .await?
        {
            push_unique_jid(&mut jids, &query_jid);
        }
        Ok(jids)
    }
}

fn receipt_timestamp(receipt_type: MessageReceiptType, timestamp: Option<u64>) -> Option<u64> {
    if receipt_type.requires_timestamp() {
        Some(timestamp.unwrap_or_else(current_unix_timestamp))
    } else {
        timestamp
    }
}

#[cfg(feature = "noise")]
fn has_child_node(node: &BinaryNode, tag: &str) -> bool {
    matches!(
        &node.content,
        Some(BinaryNodeContent::Nodes(children)) if children.iter().any(|child| child.tag == tag)
    )
}

#[cfg(feature = "noise")]
fn binary_node_with_child(mut node: BinaryNode, child: BinaryNode) -> BinaryNode {
    match node.content.take() {
        Some(BinaryNodeContent::Nodes(mut children)) => {
            children.push(child);
            node.content = Some(BinaryNodeContent::Nodes(children));
        }
        None => {
            node.content = Some(BinaryNodeContent::Nodes(vec![child]));
        }
        Some(content) => {
            node.content = Some(content);
        }
    }
    node
}

#[cfg(feature = "noise")]
fn same_jid_user(left: &str, right: &str) -> bool {
    jid_decode(left)
        .zip(jid_decode(right))
        .is_some_and(|(left, right)| left.user == right.user)
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(feature = "noise")]
fn current_unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn invite_v4_accept_message_batch(
    invite: &GroupInviteV4,
    invite_message_key: Option<wa_core::MessageEventKey>,
    local_jid: Option<&str>,
    source: &'static str,
) -> wa_core::EventBatch {
    let mut batch = wa_core::EventBatch {
        messages_upsert: vec![invite_v4_accept_stub_event(invite, local_jid, source)],
        ..wa_core::EventBatch::default()
    };
    if let Some(key) = invite_message_key {
        batch
            .messages_update
            .push(expired_invite_v4_update(key, &invite.group_jid, source));
    }
    batch
}

async fn persist_message_event_batch<S>(store: &S, batch: &wa_core::EventBatch) -> CoreResult<()>
where
    S: AuthStore,
{
    let mut upserts = batch.messages_upsert.clone();
    if let Some(history) = &batch.history {
        upserts.extend(history.messages.clone());
    }

    if batch.messages_upsert.is_empty()
        && batch.messages_update.is_empty()
        && batch.messages_delete.is_empty()
        && upserts.is_empty()
    {
        return Ok(());
    }

    let updates = batch.messages_update.clone();
    let deletes = batch.messages_delete.clone();

    store
        .transaction("persist-message-event-batch", move |tx| {
            for message in upserts {
                let key = wa_core::message_event_store_key(&message.key);
                let mut message = message;
                if let Some(existing_update) = tx.get(KeyNamespace::MessageUpdate, &key)? {
                    let update = decode_store_record(wa_core::decode_stored_message_update(
                        &existing_update,
                    ))?;
                    #[cfg(feature = "noise")]
                    let update = {
                        let mut update = update;
                        if let Some(secret) = decode_store_record(
                            wa_core::poll_event_message_secret_from_event(&message),
                        )? && let Some(update_event_key) = poll_event_update_source_key(&update)
                        {
                            let update_store_key =
                                wa_core::message_event_store_key(&update_event_key);
                            if let Some(existing_update_event) =
                                tx.get(KeyNamespace::MessageEvent, &update_store_key)?
                            {
                                let update_event = decode_store_record(
                                    wa_core::decode_stored_message_event(&existing_update_event),
                                )?;
                                let mut secrets = wa_core::PollEventMessageSecrets::new();
                                secrets.insert(message.key.clone(), secret);
                                if let Some(enriched) = decode_store_record(
                                    message_updates_from_stored_event_with_poll_event_secrets(
                                        &update_event,
                                        &secrets,
                                    ),
                                )?
                                .and_then(|updates| {
                                    updates
                                        .into_iter()
                                        .find(|candidate| candidate.key == message.key)
                                }) {
                                    update.fields.extend(enriched.fields);
                                    if enriched.timestamp.is_some() {
                                        update.timestamp = enriched.timestamp;
                                    }
                                }
                            }
                        }
                        update
                    };
                    merge_persisted_message_update(&mut message, update);
                }
                let encoded = encode_store_record(wa_core::encode_stored_message_event(&message))?;
                tx.set(KeyNamespace::MessageEvent, &key, &encoded)?;
                tx.delete(KeyNamespace::MessageUpdate, &key)?;
            }

            for update in updates {
                let key = wa_core::message_event_store_key(&update.key);
                if let Some(existing) = tx.get(KeyNamespace::MessageEvent, &key)? {
                    let mut message =
                        decode_store_record(wa_core::decode_stored_message_event(&existing))?;
                    merge_persisted_message_update(&mut message, update);
                    let encoded =
                        encode_store_record(wa_core::encode_stored_message_event(&message))?;
                    tx.set(KeyNamespace::MessageEvent, &key, &encoded)?;
                    tx.delete(KeyNamespace::MessageUpdate, &key)?;
                } else {
                    let encoded =
                        encode_store_record(wa_core::encode_stored_message_update(&update))?;
                    tx.set(KeyNamespace::MessageUpdate, &key, &encoded)?;
                }
            }

            for key in deletes {
                let key = wa_core::message_event_store_key(&key);
                tx.delete(KeyNamespace::MessageEvent, &key)?;
                tx.delete(KeyNamespace::MessageUpdate, &key)?;
            }

            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn enrich_poll_event_update_events_from_store<S>(
    store: &S,
    events: &mut [Event],
) -> CoreResult<()>
where
    S: AuthStore,
{
    for event in events {
        if let Event::Batch(batch) = event {
            enrich_poll_event_update_batch_from_store(store, batch).await?;
        }
    }
    Ok(())
}

#[cfg(feature = "noise")]
async fn enrich_poll_event_update_batch_from_store<S>(
    store: &S,
    batch: &mut wa_core::EventBatch,
) -> CoreResult<()>
where
    S: AuthStore,
{
    if batch.messages_update.is_empty() || batch.messages_upsert.is_empty() {
        return Ok(());
    }

    let mut secret_keys = Vec::new();
    for update in &batch.messages_update {
        if matches!(
            update.fields.get("source").map(String::as_str),
            Some("poll_update_message" | "enc_event_response_message")
        ) {
            secret_keys.push(update.key.clone());
        }
    }
    if secret_keys.is_empty() {
        return Ok(());
    }

    let mut secrets = wa_core::PollEventMessageSecrets::new();
    for key in secret_keys {
        if secrets.contains_key(&key) {
            continue;
        }
        if let Some(secret) = load_poll_event_secret_from_store(store, &key).await? {
            secrets.insert(key, secret);
        }
    }
    if secrets.is_empty() {
        return Ok(());
    }

    for event in &batch.messages_upsert {
        let Some(enriched) =
            message_updates_from_stored_event_with_poll_event_secrets(event, &secrets)?
        else {
            continue;
        };
        for enriched_update in enriched {
            if let Some(update) = batch
                .messages_update
                .iter_mut()
                .find(|update| update.key == enriched_update.key)
            {
                update.fields.extend(enriched_update.fields);
                if enriched_update.timestamp.is_some() {
                    update.timestamp = enriched_update.timestamp;
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "noise")]
async fn load_poll_event_secret_from_store<S>(
    store: &S,
    key: &wa_core::MessageEventKey,
) -> CoreResult<Option<wa_core::PollEventMessageSecret>>
where
    S: AuthStore,
{
    let store_key = wa_core::message_event_store_key(key);
    let Some(stored) = store.get(KeyNamespace::MessageEvent, &store_key).await? else {
        return Ok(None);
    };
    let event = wa_core::decode_stored_message_event(&stored)?;
    wa_core::poll_event_message_secret_from_event(&event)
}

#[cfg(feature = "noise")]
fn message_updates_from_stored_event_with_poll_event_secrets(
    event: &wa_core::MessageEvent,
    secrets: &wa_core::PollEventMessageSecrets,
) -> CoreResult<Option<Vec<wa_core::MessageUpdate>>> {
    let Some(payload) = event.payload.as_ref() else {
        return Ok(None);
    };
    let message = <wa_core::ProtoMessage as prost::Message>::decode(payload.as_ref())?;
    let from_me = event
        .fields
        .get("from_me")
        .is_some_and(|value| value == "true");
    let author = event
        .fields
        .get("author")
        .cloned()
        .or_else(|| event.key.participant.clone())
        .unwrap_or_else(|| event.key.remote_jid.clone());
    let sender = event
        .fields
        .get("sender")
        .cloned()
        .unwrap_or_else(|| event.key.remote_jid.clone());
    let decoded = wa_core::DecodedInboundMessage {
        info: wa_core::InboundMessageInfo {
            key: MessageKey {
                remote_jid: Some(event.key.remote_jid.clone()),
                from_me: Some(from_me),
                id: Some(event.key.id.clone()),
                participant: event.key.participant.clone(),
            },
            kind: inbound_message_kind_from_field(event.fields.get("kind").map(String::as_str)),
            author,
            sender,
            category: event.fields.get("category").cloned(),
            push_name: event.fields.get("push_name").cloned(),
            timestamp: event.timestamp,
            addressing: wa_core::AddressingContext {
                mode: wa_core::AddressingMode::PhoneNumber,
                sender_alt: None,
                recipient_alt: None,
            },
        },
        payloads: vec![wa_core::DecodedInboundPayload {
            kind: wa_core::InboundPayloadKind::Plaintext,
            message: message.clone(),
            device_sent_unwrapped: event
                .fields
                .get("device_sent_unwrapped")
                .is_some_and(|value| value == "true"),
            sender_key_distribution_count: event
                .fields
                .get("sender_key_distribution_count")
                .and_then(|value| value.parse().ok())
                .unwrap_or_default(),
        }],
    };
    let updates = wa_core::message_updates_from_decoded_message_with_poll_event_secrets(
        &decoded, &message, secrets,
    )?
    .into_iter()
    .filter(|update| {
        matches!(
            update.fields.get("source").map(String::as_str),
            Some("poll_update_message" | "enc_event_response_message")
        )
    })
    .collect::<Vec<_>>();
    Ok((!updates.is_empty()).then_some(updates))
}

#[cfg(feature = "noise")]
fn inbound_message_kind_from_field(kind: Option<&str>) -> wa_core::InboundMessageKind {
    match kind {
        Some("group") => wa_core::InboundMessageKind::Group,
        Some("peer_broadcast") => wa_core::InboundMessageKind::PeerBroadcast,
        Some("other_broadcast") => wa_core::InboundMessageKind::OtherBroadcast,
        Some("direct_peer_status") => wa_core::InboundMessageKind::DirectPeerStatus,
        Some("other_status") => wa_core::InboundMessageKind::OtherStatus,
        Some("newsletter") => wa_core::InboundMessageKind::Newsletter,
        Some("chat") | None | Some(_) => wa_core::InboundMessageKind::Chat,
    }
}

#[cfg(feature = "noise")]
fn poll_event_update_source_key(
    update: &wa_core::MessageUpdate,
) -> Option<wa_core::MessageEventKey> {
    let remote_jid = update.fields.get("update_message_remote_jid")?.to_owned();
    let id = update.fields.get("update_message_id")?.to_owned();
    let participant = update
        .fields
        .get("update_message_participant")
        .filter(|participant| !participant.is_empty())
        .cloned();
    Some(wa_core::MessageEventKey::new(remote_jid, id, participant))
}

#[cfg(feature = "noise")]
async fn persist_state_event_batch<S>(store: &S, batch: &wa_core::EventBatch) -> CoreResult<()>
where
    S: AuthStore,
{
    let mut chat_upserts = batch.chats_upsert.clone();
    let mut contact_upserts = batch.contacts_upsert.clone();
    if let Some(history) = &batch.history {
        chat_upserts.extend(history.chats.clone());
        contact_upserts.extend(history.contacts.clone());
    }

    if chat_upserts.is_empty()
        && batch.chats_update.is_empty()
        && batch.chats_delete.is_empty()
        && contact_upserts.is_empty()
        && batch.contacts_update.is_empty()
        && batch.contacts_delete.is_empty()
        && batch.groups_update.is_empty()
        && batch.business_notifications.is_empty()
    {
        return Ok(());
    }

    let chat_updates = batch.chats_update.clone();
    let chat_deletes = batch.chats_delete.clone();
    let contact_updates = batch.contacts_update.clone();
    let contact_deletes = batch.contacts_delete.clone();
    let group_updates = batch.groups_update.clone();
    let business_notifications = batch.business_notifications.clone();

    store
        .transaction("persist-state-event-batch", move |tx| {
            for chat in chat_upserts {
                let encoded = encode_store_record(wa_core::encode_stored_chat_event(&chat))?;
                tx.set(KeyNamespace::ChatEvent, &chat.jid, &encoded)?;
            }
            for chat in chat_updates {
                if let Some(existing) = tx.get(KeyNamespace::ChatEvent, &chat.jid)? {
                    let mut stored =
                        decode_store_record(wa_core::decode_stored_chat_event(&existing))?;
                    merge_persisted_chat_event(&mut stored, chat);
                    let encoded = encode_store_record(wa_core::encode_stored_chat_event(&stored))?;
                    tx.set(KeyNamespace::ChatEvent, &stored.jid, &encoded)?;
                } else {
                    let encoded = encode_store_record(wa_core::encode_stored_chat_event(&chat))?;
                    tx.set(KeyNamespace::ChatEvent, &chat.jid, &encoded)?;
                }
            }
            for jid in chat_deletes {
                tx.delete(KeyNamespace::ChatEvent, &jid)?;
            }

            for contact in contact_upserts {
                let encoded = encode_store_record(wa_core::encode_stored_contact_event(&contact))?;
                tx.set(KeyNamespace::ContactEvent, &contact.jid, &encoded)?;
            }
            for contact in contact_updates {
                if let Some(existing) = tx.get(KeyNamespace::ContactEvent, &contact.jid)? {
                    let mut stored =
                        decode_store_record(wa_core::decode_stored_contact_event(&existing))?;
                    merge_persisted_contact_event(&mut stored, contact);
                    let encoded =
                        encode_store_record(wa_core::encode_stored_contact_event(&stored))?;
                    tx.set(KeyNamespace::ContactEvent, &stored.jid, &encoded)?;
                } else {
                    let encoded =
                        encode_store_record(wa_core::encode_stored_contact_event(&contact))?;
                    tx.set(KeyNamespace::ContactEvent, &contact.jid, &encoded)?;
                }
            }
            for jid in contact_deletes {
                tx.delete(KeyNamespace::ContactEvent, &jid)?;
            }

            for group in group_updates {
                if let Some(existing) = tx.get(KeyNamespace::GroupEvent, &group.jid)? {
                    let mut stored =
                        decode_store_record(wa_core::decode_stored_group_event(&existing))?;
                    merge_persisted_group_event(&mut stored, group);
                    let encoded = encode_store_record(wa_core::encode_stored_group_event(&stored))?;
                    tx.set(KeyNamespace::GroupEvent, &stored.jid, &encoded)?;
                } else {
                    let encoded = encode_store_record(wa_core::encode_stored_group_event(&group))?;
                    tx.set(KeyNamespace::GroupEvent, &group.jid, &encoded)?;
                }
            }

            for notification in business_notifications {
                let key = wa_core::business_notification_event_store_key(&notification);
                if let Some(existing) = tx.get(KeyNamespace::BusinessNotificationEvent, &key)? {
                    let mut stored = decode_store_record(
                        wa_core::decode_stored_business_notification_event(&existing),
                    )?;
                    merge_persisted_business_notification_event(&mut stored, notification);
                    let encoded = encode_store_record(
                        wa_core::encode_stored_business_notification_event(&stored),
                    )?;
                    tx.set(KeyNamespace::BusinessNotificationEvent, &key, &encoded)?;
                } else {
                    let encoded = encode_store_record(
                        wa_core::encode_stored_business_notification_event(&notification),
                    )?;
                    tx.set(KeyNamespace::BusinessNotificationEvent, &key, &encoded)?;
                }
            }

            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_interaction_event_batch<S>(
    store: &S,
    batch: &wa_core::EventBatch,
) -> CoreResult<()>
where
    S: AuthStore,
{
    if batch.receipts_update.is_empty()
        && batch.reactions_update.is_empty()
        && batch.calls_update.is_empty()
        && batch.presence_update.is_empty()
    {
        return Ok(());
    }

    let receipts = batch.receipts_update.clone();
    let reactions = batch.reactions_update.clone();
    let calls = batch.calls_update.clone();
    let presence_updates = batch.presence_update.clone();

    store
        .transaction("persist-interaction-event-batch", move |tx| {
            for receipt in receipts {
                let key = wa_core::receipt_event_store_key(&receipt);
                let encoded = encode_store_record(wa_core::encode_stored_receipt_event(&receipt))?;
                tx.set(KeyNamespace::ReceiptEvent, &key, &encoded)?;
            }

            for reaction in reactions {
                let key = wa_core::reaction_event_store_key(&reaction);
                let encoded =
                    encode_store_record(wa_core::encode_stored_reaction_event(&reaction))?;
                tx.set(KeyNamespace::ReactionEvent, &key, &encoded)?;
            }

            for call in calls {
                let key = wa_core::call_event_store_key(&call);
                let encoded = encode_store_record(wa_core::encode_stored_call_event(&call))?;
                tx.set(KeyNamespace::CallEvent, &key, &encoded)?;
                if call.event_type == "offer"
                    && let Some(cache_key) = call_offer_cache_key(&call)
                {
                    tx.set(KeyNamespace::CallEvent, &cache_key, &encoded)?;
                }
                if is_call_terminal_event(&call.event_type)
                    && let Some(cache_key) = call_offer_cache_key(&call)
                {
                    tx.delete(KeyNamespace::CallEvent, &cache_key)?;
                }
            }

            for presence in presence_updates {
                let key = wa_core::presence_event_store_key(&presence);
                let encoded =
                    encode_store_record(wa_core::encode_stored_presence_event(&presence))?;
                tx.set(KeyNamespace::PresenceEvent, &key, &encoded)?;
            }

            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn enrich_call_events_from_store<S>(store: &S, events: &mut [Event]) -> CoreResult<()>
where
    S: AuthStore,
{
    let mut local_offers = HashMap::<String, wa_core::CallEvent>::new();
    for event in events {
        match event {
            Event::Batch(batch) => {
                enrich_call_event_list_from_store(
                    store,
                    &mut batch.calls_update,
                    &mut local_offers,
                )
                .await?;
            }
            Event::CallsUpdate(calls) => {
                enrich_call_event_list_from_store(store, calls, &mut local_offers).await?;
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn append_derived_message_events(events: &mut Vec<Event>) -> CoreResult<()> {
    let mut existing_message_keys = HashSet::<String>::new();
    for event in events.iter() {
        match event {
            Event::Batch(batch) => {
                for message in &batch.messages_upsert {
                    existing_message_keys.insert(wa_core::message_event_store_key(&message.key));
                }
            }
            Event::MessagesUpsert(messages) => {
                for message in messages {
                    existing_message_keys.insert(wa_core::message_event_store_key(&message.key));
                }
            }
            _ => {}
        }
    }

    let mut messages = Vec::new();
    let mut generated_message_indices = HashMap::<String, usize>::new();
    for event in events.iter() {
        let mut generated = match event {
            Event::Batch(batch) => {
                let mut generated =
                    wa_core::call_message_events_from_call_events(&batch.calls_update)?;
                generated.extend(wa_core::group_message_events_from_group_update_events(
                    &batch.groups_update,
                )?);
                generated
            }
            Event::CallsUpdate(calls) => wa_core::call_message_events_from_call_events(calls)?,
            Event::GroupsUpdate(groups) => {
                wa_core::group_message_events_from_group_update_events(groups)?
            }
            _ => Vec::new(),
        };
        for message in generated.drain(..) {
            let key = wa_core::message_event_store_key(&message.key);
            if existing_message_keys.contains(&key) {
                continue;
            }
            if let Some(index) = generated_message_indices.get(&key).copied() {
                if should_replace_generated_message(&messages[index], &message) {
                    messages[index] = message;
                }
            } else {
                generated_message_indices.insert(key, messages.len());
                messages.push(message);
            }
        }
    }

    if !messages.is_empty() {
        events.push(Event::Batch(Box::new(wa_core::EventBatch {
            messages_upsert: messages,
            ..wa_core::EventBatch::default()
        })));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn should_replace_generated_message(existing: &MessageEvent, candidate: &MessageEvent) -> bool {
    if !matches!(
        (
            existing.fields.get("source").map(String::as_str),
            candidate.fields.get("source").map(String::as_str),
        ),
        (Some("call_event"), Some("call_event"))
    ) {
        return false;
    }

    let existing_status = existing.fields.get("call_status").map(String::as_str);
    let candidate_status = candidate.fields.get("call_status").map(String::as_str);
    if candidate_status == Some("timeout") && existing_status != Some("timeout") {
        return true;
    }
    if existing_status == Some("timeout") && candidate_status != Some("timeout") {
        return false;
    }

    matches!(
        (existing.timestamp, candidate.timestamp),
        (Some(existing_timestamp), Some(candidate_timestamp))
            if candidate_timestamp > existing_timestamp
    )
}

#[cfg(feature = "noise")]
async fn enrich_call_event_list_from_store<S>(
    store: &S,
    calls: &mut [wa_core::CallEvent],
    local_offers: &mut HashMap<String, wa_core::CallEvent>,
) -> CoreResult<()>
where
    S: AuthStore,
{
    for call in calls {
        let Some(cache_key) = call_offer_cache_key(call) else {
            continue;
        };
        if call.event_type == "offer" {
            local_offers.insert(cache_key, call.clone());
            continue;
        }

        let offer = match local_offers.get(&cache_key) {
            Some(offer) => Some(offer.clone()),
            None => match store.get(KeyNamespace::CallEvent, &cache_key).await? {
                Some(value) => {
                    let offer = decode_store_record(wa_core::decode_stored_call_event(&value))?;
                    local_offers.insert(cache_key.clone(), offer.clone());
                    Some(offer)
                }
                None => None,
            },
        };
        if let Some(offer) = offer {
            inherit_call_offer_metadata(call, &offer);
        }
        if is_call_terminal_event(&call.event_type) {
            local_offers.remove(&cache_key);
        }
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn inherit_call_offer_metadata(call: &mut wa_core::CallEvent, offer: &wa_core::CallEvent) {
    for key in ["is_video", "is_group", "caller_pn"] {
        if !call.fields.contains_key(key)
            && let Some(value) = offer.fields.get(key).filter(|value| !value.is_empty())
        {
            call.fields.insert(key.to_owned(), value.clone());
        }
    }
}

#[cfg(feature = "noise")]
fn call_offer_cache_key(call: &wa_core::CallEvent) -> Option<String> {
    let call_id = call.call_id.as_deref().filter(|value| !value.is_empty())?;
    Some(format!("offer-cache|{}|{}", call.from, call_id))
}

#[cfg(feature = "noise")]
fn is_call_terminal_event(event_type: &str) -> bool {
    matches!(event_type, "reject" | "accept" | "timeout" | "terminate")
}

#[cfg(feature = "noise")]
async fn persist_utility_event_batch<S>(store: &S, batch: &wa_core::EventBatch) -> CoreResult<()>
where
    S: AuthStore,
{
    if batch.labels_edit.is_empty()
        && batch.labels_association.is_empty()
        && batch.quick_replies_update.is_empty()
    {
        return Ok(());
    }

    let labels = batch.labels_edit.clone();
    let associations = batch.labels_association.clone();
    let quick_replies = batch.quick_replies_update.clone();

    store
        .transaction("persist-utility-event-batch", move |tx| {
            for label in labels {
                if let Some(existing) = tx.get(KeyNamespace::LabelEvent, &label.id)? {
                    let mut stored =
                        decode_store_record(wa_core::decode_stored_label_event(&existing))?;
                    merge_persisted_label_event(&mut stored, label);
                    let encoded = encode_store_record(wa_core::encode_stored_label_event(&stored))?;
                    tx.set(KeyNamespace::LabelEvent, &stored.id, &encoded)?;
                } else {
                    let encoded = encode_store_record(wa_core::encode_stored_label_event(&label))?;
                    tx.set(KeyNamespace::LabelEvent, &label.id, &encoded)?;
                }
            }

            for association in associations {
                let key = wa_core::label_association_store_key(&association);
                let encoded = encode_store_record(wa_core::encode_stored_label_association_event(
                    &association,
                ))?;
                tx.set(KeyNamespace::LabelAssociation, &key, &encoded)?;
            }

            for quick_reply in quick_replies {
                if let Some(existing) = tx.get(KeyNamespace::QuickReplyEvent, &quick_reply.id)? {
                    let mut stored =
                        decode_store_record(wa_core::decode_stored_quick_reply_event(&existing))?;
                    merge_persisted_quick_reply_event(&mut stored, quick_reply);
                    let encoded =
                        encode_store_record(wa_core::encode_stored_quick_reply_event(&stored))?;
                    tx.set(KeyNamespace::QuickReplyEvent, &stored.id, &encoded)?;
                } else {
                    let encoded = encode_store_record(wa_core::encode_stored_quick_reply_event(
                        &quick_reply,
                    ))?;
                    tx.set(KeyNamespace::QuickReplyEvent, &quick_reply.id, &encoded)?;
                }
            }

            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_media_retry_event_batch<S>(
    store: &S,
    batch: &wa_core::EventBatch,
) -> CoreResult<()>
where
    S: AuthStore,
{
    if batch.media_retry.is_empty() {
        return Ok(());
    }

    let retries = batch.media_retry.clone();

    store
        .transaction("persist-media-retry-event-batch", move |tx| {
            for retry in retries {
                let key = wa_core::media_retry_event_store_key(&retry);
                let encoded =
                    encode_store_record(wa_core::encode_stored_media_retry_event(&retry))?;
                tx.set(KeyNamespace::MediaRetryEvent, &key, &encoded)?;
            }

            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_recent_sticker_event_batch<S>(
    store: &S,
    batch: &wa_core::EventBatch,
) -> CoreResult<()>
where
    S: AuthStore,
{
    if batch.recent_stickers.is_empty() {
        return Ok(());
    }

    let stickers = batch.recent_stickers.clone();

    store
        .transaction("persist-recent-sticker-event-batch", move |tx| {
            for sticker in stickers {
                let key = wa_core::recent_sticker_event_store_key(&sticker);
                if let Some(existing) = tx.get(KeyNamespace::RecentStickerEvent, &key)? {
                    let mut stored = decode_store_record(
                        wa_core::decode_stored_recent_sticker_event(&existing),
                    )?;
                    merge_persisted_recent_sticker_event(&mut stored, sticker);
                    let encoded =
                        encode_store_record(wa_core::encode_stored_recent_sticker_event(&stored))?;
                    tx.set(KeyNamespace::RecentStickerEvent, &key, &encoded)?;
                } else {
                    let encoded =
                        encode_store_record(wa_core::encode_stored_recent_sticker_event(&sticker))?;
                    tx.set(KeyNamespace::RecentStickerEvent, &key, &encoded)?;
                }
            }

            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_account_settings_event_batch<S>(
    store: &S,
    batch: &wa_core::EventBatch,
) -> CoreResult<()>
where
    S: AuthStore,
{
    if batch.account_settings.is_empty() {
        return Ok(());
    }

    persist_account_settings_events(store, batch.account_settings.clone()).await
}

#[cfg(feature = "noise")]
async fn persist_account_settings_events<S>(
    store: &S,
    settings: Vec<wa_core::AccountSettingsEvent>,
) -> CoreResult<()>
where
    S: AuthStore,
{
    if settings.is_empty() {
        return Ok(());
    }

    store
        .transaction("persist-account-settings-events", move |tx| {
            for setting in settings {
                let key = wa_core::account_settings_event_store_key(&setting);
                if let Some(existing) = tx.get(KeyNamespace::AccountSettingsEvent, &key)? {
                    let mut stored = decode_store_record(
                        wa_core::decode_stored_account_settings_event(&existing),
                    )?;
                    merge_persisted_account_settings_event(&mut stored, setting);
                    let encoded = encode_store_record(
                        wa_core::encode_stored_account_settings_event(&stored),
                    )?;
                    tx.set(KeyNamespace::AccountSettingsEvent, &key, &encoded)?;
                } else {
                    let encoded = encode_store_record(
                        wa_core::encode_stored_account_settings_event(&setting),
                    )?;
                    tx.set(KeyNamespace::AccountSettingsEvent, &key, &encoded)?;
                }
            }

            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_newsletter_events<S>(store: &S, events: &[Event]) -> CoreResult<()>
where
    S: AuthStore,
{
    let mut reactions = Vec::new();
    let mut views = Vec::new();
    let mut participants = Vec::new();
    let mut settings = Vec::new();

    for event in events {
        match event {
            Event::NewsletterReactionUpdate(updates) => reactions.extend(updates.clone()),
            Event::NewsletterViewUpdate(updates) => views.extend(updates.clone()),
            Event::NewsletterParticipantsUpdate(updates) => participants.extend(updates.clone()),
            Event::NewsletterSettingsUpdate(updates) => settings.extend(updates.clone()),
            _ => {}
        }
    }

    if reactions.is_empty() && views.is_empty() && participants.is_empty() && settings.is_empty() {
        return Ok(());
    }

    store
        .transaction("persist-newsletter-events", move |tx| {
            for reaction in reactions {
                let key = wa_core::newsletter_reaction_event_store_key(&reaction);
                let encoded = encode_store_record(
                    wa_core::encode_stored_newsletter_reaction_event(&reaction),
                )?;
                tx.set(KeyNamespace::NewsletterReactionEvent, &key, &encoded)?;
            }
            for view in views {
                let key = wa_core::newsletter_view_event_store_key(&view);
                let encoded =
                    encode_store_record(wa_core::encode_stored_newsletter_view_event(&view))?;
                tx.set(KeyNamespace::NewsletterViewEvent, &key, &encoded)?;
            }
            for participant in participants {
                let key = wa_core::newsletter_participant_update_event_store_key(&participant);
                let encoded = encode_store_record(
                    wa_core::encode_stored_newsletter_participant_update_event(&participant),
                )?;
                tx.set(KeyNamespace::NewsletterParticipantEvent, &key, &encoded)?;
            }
            for settings_update in settings {
                let key = wa_core::newsletter_settings_update_event_store_key(&settings_update);
                if let Some(existing) = tx.get(KeyNamespace::NewsletterSettingsEvent, &key)? {
                    let mut stored = decode_store_record(
                        wa_core::decode_stored_newsletter_settings_update_event(&existing),
                    )?;
                    merge_persisted_newsletter_settings_event(&mut stored, settings_update);
                    let encoded = encode_store_record(
                        wa_core::encode_stored_newsletter_settings_update_event(&stored),
                    )?;
                    tx.set(KeyNamespace::NewsletterSettingsEvent, &key, &encoded)?;
                } else {
                    let encoded = encode_store_record(
                        wa_core::encode_stored_newsletter_settings_update_event(&settings_update),
                    )?;
                    tx.set(KeyNamespace::NewsletterSettingsEvent, &key, &encoded)?;
                }
            }

            Ok(())
        })
        .await?;
    Ok(())
}

async fn persist_reachout_timelock_state<S>(
    store: &S,
    state: &wa_core::ReachoutTimelockState,
) -> CoreResult<()>
where
    S: AuthStore,
{
    let encoded = wa_core::encode_stored_reachout_timelock_state(state)?;
    store
        .set(
            KeyNamespace::AccountReachoutTimelock,
            wa_core::reachout_timelock_store_key(),
            &encoded,
        )
        .await?;
    Ok(())
}

async fn persist_message_capping_info<S>(
    store: &S,
    info: &wa_core::MessageCappingInfo,
) -> CoreResult<()>
where
    S: AuthStore,
{
    let encoded = wa_core::encode_stored_message_capping_info(info)?;
    store
        .set(
            KeyNamespace::MessageCappingInfo,
            wa_core::message_capping_info_store_key(),
            &encoded,
        )
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_default_disappearing_mode<S>(
    store: &S,
    mode: &wa_core::DefaultDisappearingMode,
) -> CoreResult<()>
where
    S: AuthStore,
{
    let encoded = wa_core::encode_stored_default_disappearing_mode(mode)?;
    store
        .set(
            KeyNamespace::DefaultDisappearingMode,
            wa_core::default_disappearing_mode_store_key(),
            &encoded,
        )
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_account_state_events<S>(store: &S, events: &[Event]) -> CoreResult<()>
where
    S: AuthStore,
{
    let mut reachout = None;
    let mut capping = None;
    let mut default_disappearing_mode = None;
    for event in events {
        match event {
            Event::ReachoutTimelockUpdate(state) => reachout = Some(state.clone()),
            Event::MessageCappingUpdate(info) => capping = Some(info.clone()),
            Event::DefaultDisappearingModeUpdate(mode) => {
                default_disappearing_mode = Some(mode.clone());
            }
            _ => {}
        }
    }
    if let Some(state) = reachout {
        persist_reachout_timelock_state(store, &state).await?;
    }
    if let Some(info) = capping {
        persist_message_capping_info(store, &info).await?;
    }
    if let Some(mode) = default_disappearing_mode {
        persist_default_disappearing_mode(store, &mode).await?;
    }
    Ok(())
}

#[cfg(feature = "noise")]
async fn persist_receive_events<S>(store: &S, events: &[Event]) -> CoreResult<()>
where
    S: AuthStore + Clone,
{
    let events = if events.iter().any(|event| match event {
        Event::Batch(batch) => !batch.calls_update.is_empty() || !batch.groups_update.is_empty(),
        Event::CallsUpdate(calls) => !calls.is_empty(),
        Event::GroupsUpdate(groups) => !groups.is_empty(),
        _ => false,
    }) {
        let mut enriched_events = events.to_vec();
        enrich_call_events_from_store(store, &mut enriched_events).await?;
        append_derived_message_events(&mut enriched_events)?;
        Cow::Owned(enriched_events)
    } else {
        Cow::Borrowed(events)
    };
    let events = events.as_ref();

    persist_lid_mapping_events(store, events).await?;
    persist_newsletter_events(store, events).await?;
    persist_account_state_events(store, events).await?;
    for event in events {
        match event {
            Event::Batch(batch) => {
                persist_message_event_batch(store, batch).await?;
                persist_state_event_batch(store, batch).await?;
                persist_interaction_event_batch(store, batch).await?;
                persist_utility_event_batch(store, batch).await?;
                persist_media_retry_event_batch(store, batch).await?;
                persist_recent_sticker_event_batch(store, batch).await?;
                persist_account_settings_event_batch(store, batch).await?;
            }
            Event::HistorySet(history) => {
                let batch = wa_core::EventBatch {
                    history: Some(history.clone()),
                    ..wa_core::EventBatch::default()
                };
                persist_message_event_batch(store, &batch).await?;
                persist_state_event_batch(store, &batch).await?;
            }
            Event::MessagesUpsert(messages) => {
                persist_message_event_batch(
                    store,
                    &wa_core::EventBatch {
                        messages_upsert: messages.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::MessagesUpdate(updates) => {
                persist_message_event_batch(
                    store,
                    &wa_core::EventBatch {
                        messages_update: updates.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::MessagesDelete(keys) => {
                persist_message_event_batch(
                    store,
                    &wa_core::EventBatch {
                        messages_delete: keys.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ChatsUpsert(chats) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        chats_upsert: chats.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ChatsUpdate(chats) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        chats_update: chats.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ChatsDelete(jids) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        chats_delete: jids.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ContactsUpsert(contacts) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        contacts_upsert: contacts.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ContactsUpdate(contacts) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        contacts_update: contacts.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ContactsDelete(jids) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        contacts_delete: jids.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::GroupsUpdate(groups) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        groups_update: groups.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ReceiptsUpdate(receipts) => {
                persist_interaction_event_batch(
                    store,
                    &wa_core::EventBatch {
                        receipts_update: receipts.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::ReactionsUpdate(reactions) => {
                persist_interaction_event_batch(
                    store,
                    &wa_core::EventBatch {
                        reactions_update: reactions.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::CallsUpdate(calls) => {
                persist_interaction_event_batch(
                    store,
                    &wa_core::EventBatch {
                        calls_update: calls.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::PresenceUpdate(updates) => {
                persist_interaction_event_batch(
                    store,
                    &wa_core::EventBatch {
                        presence_update: updates.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::LabelsEdit(labels) => {
                persist_utility_event_batch(
                    store,
                    &wa_core::EventBatch {
                        labels_edit: labels.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::LabelsAssociation(associations) => {
                persist_utility_event_batch(
                    store,
                    &wa_core::EventBatch {
                        labels_association: associations.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::QuickRepliesUpdate(quick_replies) => {
                persist_utility_event_batch(
                    store,
                    &wa_core::EventBatch {
                        quick_replies_update: quick_replies.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::MediaRetry(retries) => {
                persist_media_retry_event_batch(
                    store,
                    &wa_core::EventBatch {
                        media_retry: retries.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            Event::AccountSettingsUpdate(settings) => {
                persist_account_settings_events(store, settings.clone()).await?;
            }
            Event::BusinessNotificationUpdate(notifications) => {
                persist_state_event_batch(
                    store,
                    &wa_core::EventBatch {
                        business_notifications: notifications.clone(),
                        ..wa_core::EventBatch::default()
                    },
                )
                .await?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn merge_persisted_message_update(
    message: &mut wa_core::MessageEvent,
    update: wa_core::MessageUpdate,
) {
    for (key, value) in update.fields {
        message.fields.insert(key, value);
    }
    if update.timestamp.is_some() {
        message.timestamp = update.timestamp;
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_chat_event(chat: &mut wa_core::ChatEvent, update: wa_core::ChatEvent) {
    for (key, value) in update.fields {
        chat.fields.insert(key, value);
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_contact_event(
    contact: &mut wa_core::ContactEvent,
    update: wa_core::ContactEvent,
) {
    for (key, value) in update.fields {
        contact.fields.insert(key, value);
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_recent_sticker_event(
    sticker: &mut wa_core::RecentStickerEvent,
    update: wa_core::RecentStickerEvent,
) {
    for (key, value) in update.fields {
        sticker.fields.insert(key, value);
    }
    if update.file_sha256.is_some() {
        sticker.file_sha256 = update.file_sha256;
    }
    if update.file_enc_sha256.is_some() {
        sticker.file_enc_sha256 = update.file_enc_sha256;
    }
    if update.media_key.is_some() {
        sticker.media_key = update.media_key;
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_account_settings_event(
    settings: &mut wa_core::AccountSettingsEvent,
    update: wa_core::AccountSettingsEvent,
) {
    for (key, value) in update.fields {
        settings.fields.insert(key, value);
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_group_event(
    group: &mut wa_core::GroupUpdateEvent,
    update: wa_core::GroupUpdateEvent,
) {
    for (key, value) in update.fields {
        group.fields.insert(key, value);
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_business_notification_event(
    notification: &mut wa_core::BusinessNotificationEvent,
    update: wa_core::BusinessNotificationEvent,
) {
    for (key, value) in update.fields {
        notification.fields.insert(key, value);
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_label_event(label: &mut wa_core::LabelEvent, update: wa_core::LabelEvent) {
    for (key, value) in update.fields {
        label.fields.insert(key, value);
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_quick_reply_event(
    quick_reply: &mut wa_core::QuickReplyEvent,
    update: wa_core::QuickReplyEvent,
) {
    for (key, value) in update.fields {
        quick_reply.fields.insert(key, value);
    }
}

#[cfg(feature = "noise")]
fn merge_persisted_newsletter_settings_event(
    settings: &mut wa_core::NewsletterSettingsUpdateEvent,
    update: wa_core::NewsletterSettingsUpdateEvent,
) {
    for (key, value) in update.fields {
        settings.fields.insert(key, value);
    }
}

fn encode_store_record(value: CoreResult<Vec<u8>>) -> wa_store::StoreResult<Vec<u8>> {
    value.map_err(store_invalid_data)
}

fn decode_store_record<T>(value: CoreResult<T>) -> wa_store::StoreResult<T> {
    value.map_err(store_invalid_data)
}

fn store_invalid_data(error: wa_core::CoreError) -> StoreError {
    StoreError::InvalidData(error.to_string())
}

#[cfg(feature = "noise")]
fn is_malformed_media_retry_store_record(error: &wa_core::CoreError) -> bool {
    matches!(
        error,
        wa_core::CoreError::Protocol(_) | wa_core::CoreError::Payload(_)
    )
}

fn expired_invite_v4_update(
    key: wa_core::MessageEventKey,
    group_jid: &str,
    source: &'static str,
) -> wa_core::MessageUpdate {
    wa_core::MessageUpdate::new(key)
        .with_field("source", source)
        .with_field("message_type", "group_invite")
        .with_field("invite_status", "accepted")
        .with_field("group_jid", group_jid)
        .with_field("invite_code", "")
        .with_field("invite_expiration", "0")
}

fn invite_v4_accept_stub_event(
    invite: &GroupInviteV4,
    local_jid: Option<&str>,
    source: &'static str,
) -> wa_core::MessageEvent {
    let mut event = wa_core::MessageEvent::new(wa_core::MessageEventKey::new(
        invite.group_jid.clone(),
        generate_message_id_v2_now(local_jid),
        Some(invite.inviter_jid.clone()),
    ))
    .with_timestamp(current_unix_timestamp())
    .with_field("source", source)
    .with_field("kind", "notify")
    .with_field("stub_type", "group_participant_add")
    .with_field("participant", invite.inviter_jid.clone())
    .with_field("group_jid", invite.group_jid.clone());
    if let Some(local_jid) = local_jid {
        event = event.with_field("added_jid", local_jid.to_owned());
    }
    event
}

async fn refresh_dirty_groups_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    from_timestamp: Option<u64>,
) -> CoreResult<GroupDirtyRefresh> {
    let groups = fetch_dirty_groups_with_queries(connection, queries).await?;
    let clean = clean_group_dirty_bit_with_queries(connection, queries, from_timestamp).await?;
    Ok(GroupDirtyRefresh { groups, clean })
}

async fn fetch_dirty_groups_with_queries(
    connection: &Connection,
    queries: &QueryManager,
) -> CoreResult<Vec<GroupMetadata>> {
    let node = build_group_participating_query(queries.next_tag());
    let response = connection.query_node(node).await?;
    parse_group_participating_result(&response.node)
}

async fn clean_group_dirty_bit_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    from_timestamp: Option<u64>,
) -> CoreResult<BinaryNode> {
    let clean =
        build_clean_dirty_bits_node(DirtyBitType::Groups, from_timestamp, queries.next_tag())?;
    connection.send_node(&clean).await?;
    Ok(clean)
}

async fn refresh_groups_for_dirty_node_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    node: &BinaryNode,
) -> CoreResult<Option<GroupDirtyRefresh>> {
    let dirties = parse_dirty_notification_nodes(node)?;
    if dirties.is_empty() {
        return Ok(None);
    };
    let Some(timestamp) =
        latest_dirty_timestamp_for(&dirties, |dirty| dirty.dirty_type == "groups")
    else {
        return Ok(None);
    };
    Ok(Some(
        refresh_dirty_groups_with_queries(connection, queries, timestamp).await?,
    ))
}

#[cfg(feature = "noise")]
async fn refresh_group_surfaces_for_dirty_node_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    node: &BinaryNode,
) -> CoreResult<Option<GroupSurfaceDirtyRefresh>> {
    let dirties = parse_dirty_notification_nodes(node)?;
    if dirties.is_empty() {
        return Ok(None);
    };
    let refresh_groups = dirties.iter().any(|dirty| dirty.dirty_type == "groups");
    let refresh_communities = dirties
        .iter()
        .any(|dirty| dirty.dirty_type == "groups" || dirty.dirty_type == "communities");
    if !refresh_groups && !refresh_communities {
        return Ok(None);
    }

    let groups = if refresh_groups {
        Some(fetch_dirty_groups_with_queries(connection, queries).await?)
    } else {
        None
    };
    let communities = if refresh_communities {
        Some(fetch_dirty_communities_with_queries(connection, queries).await?)
    } else {
        None
    };
    let clean_timestamp = latest_dirty_timestamp_for(&dirties, |dirty| {
        dirty.dirty_type == "groups" || dirty.dirty_type == "communities"
    })
    .flatten();
    let clean = clean_group_dirty_bit_with_queries(connection, queries, clean_timestamp).await?;
    Ok(Some(GroupSurfaceDirtyRefresh {
        groups: groups.map(|groups| GroupDirtyRefresh {
            groups,
            clean: clean.clone(),
        }),
        communities: communities.map(|communities| CommunityDirtyRefresh { communities, clean }),
    }))
}

fn latest_dirty_timestamp_for<F>(
    dirties: &[wa_core::DirtyNotification],
    mut predicate: F,
) -> Option<Option<u64>>
where
    F: FnMut(&wa_core::DirtyNotification) -> bool,
{
    let mut found = false;
    let mut timestamp = None;
    for dirty in dirties {
        if !predicate(dirty) {
            continue;
        }
        found = true;
        if let Some(value) = dirty.timestamp {
            timestamp = Some(timestamp.map_or(value, |current: u64| current.max(value)));
        }
    }
    found.then_some(timestamp)
}

#[cfg(feature = "noise")]
fn emit_group_surface_dirty_refresh_events(events: &EventHub, refresh: &GroupSurfaceDirtyRefresh) {
    if let Some(groups) = &refresh.groups {
        emit_group_dirty_refresh_events(events, groups);
    }
    if let Some(communities) = &refresh.communities {
        emit_community_dirty_refresh_events(events, communities);
    }
}

fn emit_group_dirty_refresh_events(events: &EventHub, refresh: &GroupDirtyRefresh) {
    let updates = refresh
        .groups
        .iter()
        .map(group_metadata_update_event)
        .collect::<Vec<_>>();
    if !updates.is_empty() {
        events.emit(Event::GroupsUpdate(updates));
    }
}

fn group_metadata_update_event(metadata: &GroupMetadata) -> GroupUpdateEvent {
    let mut event = GroupUpdateEvent::new(metadata.jid.clone())
        .with_field("source", "group_dirty_refresh")
        .with_field("announce", metadata.announce.to_string())
        .with_field("restrict", metadata.restrict.to_string())
        .with_field(
            "join_approval_mode",
            metadata.join_approval_mode.to_string(),
        )
        .with_field(
            "member_add_mode_all",
            metadata.member_add_mode_all.to_string(),
        );
    if let Some(subject) = &metadata.subject {
        event = event.with_field("subject", subject.clone());
    }
    if let Some(description_id) = &metadata.description_id {
        event = event.with_field("description_id", description_id.clone());
    }
    if let Some(linked_parent) = &metadata.linked_parent {
        event = event.with_field("linked_parent", linked_parent.clone());
    }
    if let Some(size) = metadata.size {
        event = event.with_field("size", size.to_string());
    }
    if let Some(duration) = metadata.ephemeral_duration {
        event = event.with_field("ephemeral_duration", duration.to_string());
    }
    add_group_participant_snapshot_fields(event, metadata)
}

fn add_group_participant_snapshot_fields(
    mut event: GroupUpdateEvent,
    metadata: &GroupMetadata,
) -> GroupUpdateEvent {
    if metadata.participants.is_empty() {
        return event;
    }

    let participants = metadata
        .participants
        .iter()
        .map(|participant| participant.jid.as_str())
        .collect::<Vec<_>>();
    event = event
        .with_field("participants", participants.join(","))
        .with_field("participants_count", participants.len().to_string());

    let admins = metadata
        .participants
        .iter()
        .filter(|participant| participant.role == GroupParticipantRole::Admin)
        .map(|participant| participant.jid.as_str())
        .collect::<Vec<_>>();
    if !admins.is_empty() {
        event = event
            .with_field("participants_admins", admins.join(","))
            .with_field("participants_admins_count", admins.len().to_string());
    }

    let superadmins = metadata
        .participants
        .iter()
        .filter(|participant| participant.role == GroupParticipantRole::SuperAdmin)
        .map(|participant| participant.jid.as_str())
        .collect::<Vec<_>>();
    if !superadmins.is_empty() {
        event = event
            .with_field("participants_superadmins", superadmins.join(","))
            .with_field(
                "participants_superadmins_count",
                superadmins.len().to_string(),
            );
    }

    event
}

async fn refresh_dirty_communities_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    from_timestamp: Option<u64>,
) -> CoreResult<CommunityDirtyRefresh> {
    let communities = fetch_dirty_communities_with_queries(connection, queries).await?;
    let clean = clean_group_dirty_bit_with_queries(connection, queries, from_timestamp).await?;
    Ok(CommunityDirtyRefresh { communities, clean })
}

async fn fetch_dirty_communities_with_queries(
    connection: &Connection,
    queries: &QueryManager,
) -> CoreResult<Vec<GroupMetadata>> {
    let node = build_community_participating_query(queries.next_tag());
    let response = connection.query_node(node).await?;
    parse_community_participating_result(&response.node)
}

async fn refresh_communities_for_dirty_node_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    node: &BinaryNode,
) -> CoreResult<Option<CommunityDirtyRefresh>> {
    let dirties = parse_dirty_notification_nodes(node)?;
    if dirties.is_empty() {
        return Ok(None);
    };
    let Some(timestamp) =
        latest_dirty_timestamp_for(&dirties, |dirty| dirty.dirty_type == "communities")
    else {
        return Ok(None);
    };
    Ok(Some(
        refresh_dirty_communities_with_queries(connection, queries, timestamp).await?,
    ))
}

fn emit_community_dirty_refresh_events(events: &EventHub, refresh: &CommunityDirtyRefresh) {
    let updates = refresh
        .communities
        .iter()
        .map(community_metadata_update_event)
        .collect::<Vec<_>>();
    if !updates.is_empty() {
        events.emit(Event::GroupsUpdate(updates));
    }
}

fn community_metadata_update_event(metadata: &GroupMetadata) -> GroupUpdateEvent {
    let mut event = GroupUpdateEvent::new(metadata.jid.clone())
        .with_field("source", "community_dirty_refresh")
        .with_field("is_community", metadata.is_community.to_string())
        .with_field(
            "is_community_announce",
            metadata.is_community_announce.to_string(),
        );
    if let Some(subject) = &metadata.subject {
        event = event.with_field("subject", subject.clone());
    }
    if let Some(description_id) = &metadata.description_id {
        event = event.with_field("description_id", description_id.clone());
    }
    if let Some(linked_parent) = &metadata.linked_parent {
        event = event.with_field("linked_parent", linked_parent.clone());
    }
    if let Some(size) = metadata.size {
        event = event.with_field("size", size.to_string());
    }
    add_group_participant_snapshot_fields(event, metadata)
}

#[cfg(feature = "noise")]
fn push_unique_jid(jids: &mut Vec<String>, jid: &str) {
    if !jids.iter().any(|existing| existing == jid) {
        jids.push(jid.to_owned());
    }
}

#[cfg(feature = "noise")]
fn push_unique_normalized_account_jid(jids: &mut Vec<String>, jid: &str) -> CoreResult<()> {
    let jid = normalize_account_jid(jid)?;
    push_unique_jid(jids, &jid);
    Ok(())
}

#[cfg(feature = "noise")]
fn normalize_signal_session_jid(jid: &str) -> CoreResult<String> {
    let decoded = jid_decode(jid).ok_or_else(|| {
        wa_core::CoreError::Protocol(format!("invalid Signal session JID: {jid}"))
    })?;
    if decoded.user.is_empty() {
        return Err(wa_core::CoreError::Protocol(format!(
            "Signal session JID user must not be empty: {jid}"
        )));
    }
    if decoded.server != JidServer::CUs {
        return Ok(jid.to_owned());
    }
    Ok(jid_encode(
        decoded.user,
        JidServer::SWhatsAppNet,
        decoded.device.filter(|device| *device != 0),
        decoded.agent,
    ))
}

#[cfg(feature = "noise")]
fn normalize_retry_receipt_signal_jids(
    receipt: &wa_core::RetryReceipt,
) -> CoreResult<wa_core::RetryReceipt> {
    let mut receipt = receipt.clone();
    if let Some(jid) = receipt.from_jid.as_deref() {
        receipt.from_jid = Some(normalize_signal_session_jid(jid)?);
    }
    if let Some(jid) = receipt.participant.as_deref() {
        receipt.participant = Some(normalize_signal_session_jid(jid)?);
    }
    if let Some(jid) = receipt.to_jid.as_deref() {
        receipt.to_jid = Some(normalize_signal_session_jid(jid)?);
    }
    if let Some(jid) = receipt.recipient.as_deref() {
        receipt.recipient = Some(normalize_signal_session_jid(jid)?);
    }
    if let Some(jid) = receipt.chat_jid.as_deref() {
        receipt.chat_jid = Some(normalize_signal_session_jid(jid)?);
    }
    Ok(receipt)
}

#[cfg(feature = "noise")]
fn normalize_status_target_jid(jid: &str) -> CoreResult<String> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| wa_core::CoreError::Payload(format!("invalid status target JID: {jid}")))?;
    let has_device_suffix = jid
        .split_once('@')
        .is_some_and(|(user, _)| user.contains(':'));
    let is_user_server = matches!(
        decoded.server,
        JidServer::CUs
            | JidServer::SWhatsAppNet
            | JidServer::Lid
            | JidServer::Hosted
            | JidServer::HostedLid
    );
    if decoded.user.is_empty() || has_device_suffix || !is_user_server {
        return Err(wa_core::CoreError::Payload(format!(
            "status target must be a user JID: {jid}"
        )));
    }
    let server = match decoded.server {
        JidServer::CUs => JidServer::SWhatsAppNet,
        server => server,
    };
    Ok(jid_encode(decoded.user, server, None, None))
}

#[cfg(feature = "noise")]
fn retry_resend_target_key(target: &RetryResendTarget) -> String {
    match target {
        RetryResendTarget::AllDevices => "all-devices".to_owned(),
        RetryResendTarget::Participant { jid, count } => format!("participant:{jid}:{count}"),
    }
}

#[cfg(feature = "noise")]
fn retry_options_with_device_identity(
    options: MessageRelayOptions,
    identity: &Bytes,
) -> CoreResult<MessageRelayOptions> {
    if identity.is_empty() {
        return Err(wa_core::CoreError::Protocol(
            "retry key-bundle device identity must not be empty".to_owned(),
        ));
    }
    Ok(options.with_device_identity_node(
        BinaryNode::new("device-identity").with_content(identity.clone()),
    ))
}

#[cfg(feature = "noise")]
async fn persist_lid_mapping_events<S>(store: &S, events: &[Event]) -> CoreResult<()>
where
    S: AuthStore + Clone,
{
    let mut mappings = Vec::new();
    for event in events {
        let Event::LidMappingUpdate(event_mappings) = event else {
            continue;
        };
        mappings.extend(event_mappings.iter().map(|mapping| LidPnMapping {
            pn: mapping.pn_jid.clone(),
            lid: mapping.lid_jid.clone(),
        }));
    }
    if mappings.is_empty() {
        return Ok(());
    }
    LidPnMappingStore::new(store.clone())
        .store_mappings(mappings)
        .await
}

#[cfg(feature = "noise")]
fn app_state_sync_key_share_items_from_events(
    events: &[Event],
) -> CoreResult<Vec<wa_core::AppStateSyncKeyShareItem>> {
    let mut keys = Vec::new();
    for event in events {
        match event {
            Event::MessagesUpsert(messages) => {
                for message in messages {
                    keys.extend(wa_core::app_state_sync_key_share_from_message_event(
                        message,
                    )?);
                }
            }
            Event::Batch(batch) => {
                for message in &batch.messages_upsert {
                    keys.extend(wa_core::app_state_sync_key_share_from_message_event(
                        message,
                    )?);
                }
            }
            _ => {}
        }
    }
    Ok(keys)
}

#[cfg(feature = "noise")]
fn history_sync_notifications_from_events(
    events: &[Event],
) -> CoreResult<Vec<wa_core::HistorySyncNotification>> {
    let mut notifications = Vec::new();
    for event in events {
        match event {
            Event::MessagesUpsert(messages) => {
                for message in messages {
                    push_unique_history_sync_notifications(
                        &mut notifications,
                        wa_core::history_sync_notifications_from_message_event(message)?,
                    );
                }
            }
            Event::Batch(batch) => {
                for message in &batch.messages_upsert {
                    push_unique_history_sync_notifications(
                        &mut notifications,
                        wa_core::history_sync_notifications_from_message_event(message)?,
                    );
                }
            }
            _ => {}
        }
    }
    Ok(notifications)
}

#[cfg(feature = "noise")]
fn push_unique_history_sync_notifications(
    notifications: &mut Vec<wa_core::HistorySyncNotification>,
    incoming: Vec<wa_core::HistorySyncNotification>,
) {
    for notification in incoming {
        if !notifications
            .iter()
            .any(|existing| existing == &notification)
        {
            notifications.push(notification);
        }
    }
}

#[cfg(feature = "noise")]
async fn handle_app_state_sync_key_share_events_with_store<S>(
    store: &S,
    queries: &QueryManager,
    connection: &Connection,
    hub: Option<&EventHub>,
    events: &[Event],
    is_initial_sync: bool,
    max_rounds: usize,
) -> CoreResult<wa_core::AppStateSyncApplyOutcome>
where
    S: AuthStore,
{
    if max_rounds == 0 {
        return Err(wa_core::CoreError::Protocol(
            "app-state key-share resync requires at least one round".to_owned(),
        ));
    }

    let keys = app_state_sync_key_share_items_from_events(events)?;
    if keys.is_empty() {
        return Ok(wa_core::AppStateSyncApplyOutcome::default());
    }

    let blocked = wa_core::save_app_state_sync_key_share(store, keys).await?;
    let mut pending = blocked
        .iter()
        .map(|blocked| blocked.collection)
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(wa_core::AppStateSyncApplyOutcome::default());
    }

    let mut combined = wa_core::AppStateSyncApplyOutcome::default();
    for _ in 0..max_rounds {
        let mut requests = Vec::with_capacity(pending.len());
        for collection in &pending {
            let state = wa_core::load_app_state_patch_state(store, *collection).await?;
            requests.push(AppStateCollectionRequest::new(*collection, state.version()));
        }

        let node = build_app_state_sync_query(requests, queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_app_state_query_result(&response.node, AppStateQueryKind::Sync)?;
        let sync = wa_core::parse_app_state_sync_response(&response.node)?.unwrap_or_default();
        let round =
            wa_core::apply_app_state_sync_response_with_store_keys(store, &sync, is_initial_sync)
                .await?;
        if let Some(hub) = hub {
            for batch in &round.batches {
                hub.emit_batch(batch.clone());
            }
        }
        pending = round
            .collections
            .iter()
            .filter(|collection| {
                collection.has_more_patches
                    && !round
                        .blocked
                        .iter()
                        .any(|blocked| blocked.collection == collection.collection)
            })
            .map(|collection| collection.collection)
            .collect();
        combined.append(round);

        if pending.is_empty() {
            return Ok(combined);
        }
    }

    Err(wa_core::CoreError::Protocol(format!(
        "app-state key-share resync exceeded {max_rounds} rounds"
    )))
}

fn emit_buffered_events(hub: &EventHub, events: Vec<Event>) {
    for event in events {
        hub.emit(event);
    }
}

#[cfg(feature = "noise")]
fn placeholder_unavailable_messages_from_raw_node(
    node: &BinaryNode,
    own_jid: &str,
    own_lid: Option<&str>,
    now_secs: u64,
) -> CoreResult<Vec<wa_core::PlaceholderUnavailableMessage>> {
    let mut placeholders = Vec::new();
    if node.tag == "offline" {
        if let Some(BinaryNodeContent::Nodes(children)) = &node.content {
            for child in children {
                if let Some(placeholder) = wa_core::placeholder_unavailable_message_from_node(
                    child, own_jid, own_lid, now_secs,
                )? {
                    placeholders.push(placeholder);
                }
            }
        }
        return Ok(placeholders);
    }

    if let Some(placeholder) =
        wa_core::placeholder_unavailable_message_from_node(node, own_jid, own_lid, now_secs)?
    {
        placeholders.push(placeholder);
    }
    Ok(placeholders)
}

#[cfg(feature = "noise")]
fn retry_receipts_from_raw_node(node: &BinaryNode) -> CoreResult<Vec<ParsedRetryReceipt>> {
    let mut receipts = Vec::new();
    if node.tag == "offline" {
        if let Some(BinaryNodeContent::Nodes(children)) = &node.content {
            for child in children {
                if let Some(receipt) = parse_retry_receipt_with_bundle(child)? {
                    receipts.push(receipt);
                }
            }
        }
        return Ok(receipts);
    }

    if let Some(receipt) = parse_retry_receipt_with_bundle(node)? {
        receipts.push(receipt);
    }
    Ok(receipts)
}

#[cfg(feature = "noise")]
fn incoming_side_effect_nodes(node: &BinaryNode) -> Vec<&BinaryNode> {
    if node.tag == "offline"
        && let Some(BinaryNodeContent::Nodes(children)) = &node.content
    {
        return children.iter().collect();
    }
    vec![node]
}

#[cfg(feature = "noise")]
fn parse_retry_receipt_with_bundle(node: &BinaryNode) -> CoreResult<Option<ParsedRetryReceipt>> {
    let Some(receipt) = wa_core::parse_retry_receipt(node)? else {
        return Ok(None);
    };
    let requester_jid = normalize_signal_session_jid(receipt.requester_jid()?)?;
    let key_bundle = retry_receipt_session_bundle(node, &requester_jid)?;
    Ok(Some(ParsedRetryReceipt {
        receipt,
        key_bundle,
    }))
}

#[cfg(feature = "noise")]
fn resolve_placeholder_resend_events_in_batches(
    tracker: &wa_core::PlaceholderResendTracker,
    events: &[Event],
) -> CoreResult<usize> {
    let mut resolved = 0;
    for event in events {
        let Event::Batch(batch) = event else {
            continue;
        };
        for message in &batch.messages_upsert {
            if message.fields.get("kind").map(String::as_str) != Some("placeholder_resend") {
                continue;
            }
            if tracker.resolve(&message.key.id)?.is_some() {
                resolved += 1;
            }
        }
    }
    Ok(resolved)
}

pub struct ClientBuilder<S> {
    store: S,
    config: ClientConfig,
}

impl<S> ClientBuilder<S>
where
    S: AuthStore,
{
    #[must_use]
    pub fn browser(mut self, browser: Browser) -> Self {
        self.config.browser = browser;
        self
    }

    #[must_use]
    pub fn config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    pub async fn connect(self) -> CoreResult<Client<S>> {
        let events = EventHub::new(1024);
        let queries = QueryManager::new(self.config.default_query_timeout);
        events.emit(Event::ConnectionUpdate(ConnectionState::Connecting));
        #[cfg(feature = "noise")]
        let credentials = {
            let load = load_or_init_credentials(&self.store).await?;
            if load.initialized {
                events.emit(Event::CredentialsUpdated);
            }
            load.credentials
        };
        Ok(Client {
            store: self.store,
            config: self.config,
            events,
            queries,
            #[cfg(feature = "noise")]
            credentials,
            #[cfg(feature = "noise")]
            media_retry: wa_core::MediaRetryCoordinator::default(),
            #[cfg(feature = "noise")]
            message_retry: Arc::new(std::sync::Mutex::new(
                wa_core::MessageRetryManager::default(),
            )),
            #[cfg(feature = "noise")]
            placeholder_resend: wa_core::PlaceholderResendTracker::default(),
            #[cfg(feature = "noise")]
            tc_token_issuance: Arc::new(std::sync::Mutex::new(HashSet::new())),
            #[cfg(feature = "noise")]
            identity_change_debounce: Arc::new(std::sync::Mutex::new(HashMap::new())),
            #[cfg(feature = "noise")]
            signal_mutation_locks: wa_core::SignalMutationLocks::default(),
        })
    }
}

pub mod prelude {
    #[cfg(feature = "noise")]
    pub use super::{
        AckErrorTcTokenRecoveryOutcome, AppStateMutationUpload, AppStateSyncRecoveryOptions,
        ChatMutationApplyOutcome, DeviceListNotificationOutcome, GroupSenderKeyMessageRelay,
        IdentityChangeOutcome, IncomingMediaRetryProcessing,
        IncomingOfflinePlaceholderRetryMediaProcessing, IncomingPlaceholderResendProcessing,
        IncomingPlaceholderRetryMediaProcessing, IncomingProcessor, IncomingRetryResendProcessing,
        MessageLabelTarget, PlaceholderResendCleanup, PostAuthMaintenance,
        PrivacyTokenNotificationOutcome, RetryResendOutcome, RetrySessionActionOutcome,
        ServerSyncNotificationOutcome, TcTokenPruneMaintenance,
    };
    pub use super::{Client, ClientBuilder, CommunityDirtyRefresh, GroupDirtyRefresh};
    pub use wa_core::{
        ACK_ERROR_ACCOUNT_RESTRICTED, ACK_ERROR_SMAX_INVALID, APP_STATE_HASH_LEN, AccountJidKind,
        AccountMutationKind, AddressingContext, AddressingMode, AlbumContent, AppStateCollection,
        AppStateCollectionRequest, AppStatePatchOperation, AppStateQueryKind,
        AppStateSyncCollection, AppStateSyncResponse, AudioContent, BinaryNode, BinaryNodeContent,
        BlocklistAction, BlocklistUpdateEvent, Browser, BusinessNotificationEvent,
        ButtonReplyContent, CatalogSnapshotContent, ChatEvent, ChatMutationMessageRange,
        ChatMutationMessageRef, ChatMutationPatch, ClientConfig, CommunityLinkedGroups, Connection,
        ConnectionState, ContactContent, ContactEvent, ContactSyncAction, ContactsContent,
        DEFAULT_BASE_KEY_CAPACITY, DEFAULT_BASE_KEY_TTL_MS, DEFAULT_MAX_HISTORY_CHATS,
        DEFAULT_MAX_HISTORY_CONTACTS, DEFAULT_MAX_HISTORY_INFLATED_BYTES,
        DEFAULT_MAX_HISTORY_MESSAGES, DEFAULT_MAX_MESSAGE_RETRY_COUNT, DEFAULT_MEDIA_HOST,
        DEFAULT_MEDIA_ORIGIN, DEFAULT_PHONE_REQUEST_DELAY_MS, DEFAULT_RECENT_MESSAGE_CAPACITY,
        DEFAULT_RECENT_MESSAGE_TTL_MS, DEFAULT_RETRY_COUNTER_TTL_MS,
        DEFAULT_SESSION_RECREATE_TIMEOUT_MS, DecodedInboundMessage, DecodedInboundPayload,
        DefaultDisappearingMode, DeleteContent, DeviceListNotification,
        DeviceListNotificationDevice, DirtyBitType, DirtyNotification, DisappearingModeContent,
        DocumentContent, EditContent, Event, EventBatch, EventBuffer, EventBufferConfig,
        EventContent, EventHub, EventResponseContent, EventResponseKind, EventResponsePayload,
        ExternalBlobReference, FrameSink, FrameStream, GroupAddressingMode, GroupInviteContent,
        GroupInviteKind, GroupInviteV4, GroupJoinApprovalMode, GroupJoinRequest,
        GroupJoinRequestAction, GroupJoinRequestActionResult, GroupMemberAddMode, GroupMetadata,
        GroupMutationKind, GroupParticipant, GroupParticipantAction, GroupParticipantActionResult,
        GroupParticipantChange, GroupParticipantRole, GroupSettingUpdate, GroupUpdateEvent,
        HistoryLidPnMapping, HistorySetEvent, HistorySync, HistorySyncDecodeConfig,
        HistorySyncNotification, HistorySyncProcessConfig, HistorySyncType, ImageContent,
        InboundAck, InboundBinaryNode, InboundCiphertextType, InboundEncryptedPayload,
        InboundFrame, InboundMessageDecryptor, InboundMessageInfo, InboundMessageKind,
        InboundNodeAction, InboundNodeProcessing, InboundNotification, InboundPayloadKind,
        InboundReceipt, InboundReceiptKind, LabelAssociationEvent, LabelAssociationTarget,
        LabelEditMutation, LabelEvent, LabelListType, LidMappingEvent, LimitSharingContent,
        LimitSharingTrigger, LinkPreviewContent, LinkPreviewThumbnail, ListReplyContent,
        LiveLocationContent, LocationContent, MAX_NEWSLETTER_MESSAGE_FETCH_COUNT,
        MediaConnectionInfo, MediaRetryError, MediaRetryEvent, MediaRetryPayload, MediaRetryUpdate,
        MediaUploadHost, MessageCiphertextType, MessageContent, MessageContext, MessageEncryption,
        MessageEncryptor, MessageEvent, MessageEventKey, MessageKey, MessageReceipt,
        MessageReceiptType, MessageRelay, MessageRelayOptions, MessageRelayRecipient,
        MessageRetryConfig, MessageRetryManager, MessageUpdate, NACK_DB_OPERATION_FAILED,
        NACK_INVALID_HOSTED_COMPANION_STANZA, NACK_INVALID_PROTOBUF, NACK_MESSAGE_DELETED_ON_PEER,
        NACK_MISSING_MESSAGE_SECRET, NACK_PARSING_ERROR, NACK_SENDER_REACHOUT_TIMELOCKED,
        NACK_SIGNAL_ERROR_OLD_COUNTER, NACK_UNHANDLED_ERROR, NACK_UNRECOGNIZED_STANZA,
        NACK_UNRECOGNIZED_STANZA_CLASS, NACK_UNRECOGNIZED_STANZA_TYPE,
        NACK_UNSUPPORTED_ADMIN_REVOKE, NACK_UNSUPPORTED_LID_GROUP, NackReason, NewsletterAction,
        NewsletterLinkedProfileMapping, NewsletterLiveUpdateSubscription, NewsletterMetadata,
        NewsletterMetadataLookup, NewsletterMetadataUpdate, NewsletterMuteState,
        NewsletterNotificationUpdate, NewsletterParticipantNotification,
        NewsletterParticipantUpdateEvent, NewsletterPicture, NewsletterReactionCount,
        NewsletterReactionEvent, NewsletterSettingsNotification, NewsletterSettingsUpdateEvent,
        NewsletterThreadMetadata, NewsletterVerification, NewsletterViewEvent,
        NewsletterViewerRole, OnWhatsAppResult, PLACEHOLDER_EXCLUDED_UNAVAILABLE_TYPES,
        PLACEHOLDER_MAX_AGE_SECONDS, PLACEHOLDER_MISSING_KEYS_ERROR_TEXT,
        PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT, PinAction, PinContent, PlaceholderResendRequest,
        PlaceholderUnavailableMessage, PollContent, PollUpdateContent, PollVoteContent,
        PresenceState, PrivacyCategory, PrivacySettings, PrivacyValue, ProcessedHistorySync,
        ProductContent, ProductSnapshotContent, ProfilePictureType, ProtoMessage, QueryManager,
        QuickReplyEvent, QuickReplyMutation, QuotedMessage, ReactionContent, ReactionEvent,
        ReceiptEvent, RecentMessage, RegistrationPayloadKeys, RemoteMediaThumbnail,
        RequestPhoneNumberContent, RetryReason, RetryReceipt, RetryReceiptPlan, RetryReceiptRetry,
        RetryResendJob, RetryResendPreparation, RetryResendTarget, RetrySessionAction,
        RetrySessionSnapshot, RetryStatistics, STATUS_BROADCAST_JID, SenderKeyDistributionContent,
        SessionRecreateDecision, StickerContent, SyncdMutations, SyncdSnapshot,
        TemplateButtonReplyContent, TextFont, TextMessage, USyncBotProfile, USyncBotProfileCommand,
        USyncDevice, USyncDeviceInfo, USyncDeviceJid, USyncDisappearingMode,
        USyncDisappearingModeResult, USyncKeyIndex, USyncLidMapping, USyncProtocol, USyncQuery,
        USyncQueryResult, USyncStatus, USyncStatusResult, USyncUser, USyncUserResult,
        UploadedMedia, UploadedMediaLocation, VideoContent, WaVersion, WebMessageInfo,
        account_jid_kind, aggregate_receipts_from_message_keys, bot_profiles_from_result,
        build_ack_node, build_album_message, build_app_state_patch_query,
        build_app_state_patch_query_from_patch, build_app_state_sync_query,
        build_archive_chat_patch, build_audio_message, build_blocklist_query,
        build_blocklist_update_query, build_bot_profile_query, build_button_reply_message,
        build_call_reject_node, build_chat_label_association_patch, build_chat_state_node,
        build_clean_dirty_bits_node, build_contact_message, build_contact_patch,
        build_contacts_message, build_default_disappearing_mode_query, build_delete_chat_patch,
        build_delete_message, build_device_query, build_device_sent_message,
        build_direct_message_relay, build_disappearing_mode_message, build_disappearing_mode_query,
        build_document_message, build_edit_message, build_event_message,
        build_event_response_message, build_group_accept_invite_query,
        build_group_accept_invite_v4_query, build_group_create_query,
        build_group_description_query, build_group_ephemeral_query, build_group_invite_code_query,
        build_group_invite_info_query, build_group_invite_message,
        build_group_join_approval_mode_query, build_group_join_request_action_query,
        build_group_join_request_list_query, build_group_leave_query,
        build_group_member_add_mode_query, build_group_metadata_query,
        build_group_participants_query, build_group_participating_query,
        build_group_revoke_invite_query, build_group_revoke_invite_v4_query,
        build_group_sender_key_message_relay, build_group_setting_query, build_group_subject_query,
        build_image_message, build_label_edit_patch, build_lid_mapping_query,
        build_limit_sharing_message, build_list_reply_message, build_live_location_message,
        build_location_message, build_login_payload, build_mark_chat_read_patch,
        build_media_connection_query, build_media_retry_request_node, build_message_key,
        build_message_label_association_patch, build_mute_chat_patch, build_nack_node,
        build_newsletter_action_query, build_newsletter_admin_count_query,
        build_newsletter_change_owner_query, build_newsletter_create_query,
        build_newsletter_demote_query, build_newsletter_live_updates_query,
        build_newsletter_message_updates_query, build_newsletter_metadata_query,
        build_newsletter_metadata_update_query, build_newsletter_reaction_node,
        build_newsletter_subscribers_query, build_on_whatsapp_query, build_pin_chat_patch,
        build_pin_message, build_placeholder_resend_request_message, build_poll_message,
        build_poll_update_message, build_presence_subscribe_node, build_presence_update_node,
        build_privacy_settings_query, build_privacy_update_query, build_product_message,
        build_profile_picture_remove_query, build_profile_picture_update_query,
        build_profile_picture_url_query, build_profile_status_update_query, build_ptv_message,
        build_push_name_patch, build_quick_reply_patch, build_reaction_message, build_receipt_node,
        build_registration_payload, build_request_phone_number_message,
        build_sender_key_distribution_message, build_share_phone_number_message,
        build_star_message_patch, build_status_query, build_sticker_message,
        build_sync_action_data, build_template_button_reply_message, build_text_message,
        build_video_message, build_view_once_message, business_notification_event_store_key,
        business_notification_events_from_notification_node, decode_compressed_history_sync,
        decode_history_sync_bytes, decode_inbound_binary_node, decode_inbound_message,
        decode_inbound_message_info, decode_inline_history_sync,
        decode_stored_business_notification_event, decode_stored_message_capping_info,
        decode_stored_newsletter_participant_update_event, decode_stored_newsletter_reaction_event,
        decode_stored_newsletter_settings_update_event, decode_stored_newsletter_view_event,
        decode_stored_reachout_timelock_state, disappearing_modes_from_result,
        dispatch_binary_node, encode_app_state_patch, encode_message,
        encode_stored_business_notification_event, encode_stored_message_capping_info,
        encode_stored_newsletter_participant_update_event, encode_stored_newsletter_reaction_event,
        encode_stored_newsletter_settings_update_event, encode_stored_newsletter_view_event,
        encode_stored_reachout_timelock_state, encode_sync_action_data,
        event_batch_from_group_notification_node, extract_addressing_context, extract_device_jids,
        generate_message_id, generate_message_id_v2, generate_message_id_v2_now,
        generate_participant_hash_v2, group_update_event_from_notification_node,
        lid_mapping_events_from_newsletter_notification_node, lid_mappings_from_result,
        lid_user_jid, media_download_url, media_url_from_direct_path,
        message_capping_info_store_key, message_event_from_decoded,
        message_event_from_placeholder_unavailable, message_event_key_from_proto_key,
        message_info_fields, message_stanza_type, message_updates_from_ack,
        newsletter_mex_update_events_from_notification_node,
        newsletter_participant_update_event_store_key, newsletter_reaction_event_store_key,
        newsletter_settings_update_event_store_key,
        newsletter_update_events_from_notification_node, newsletter_view_event_store_key,
        normalize_account_jid, on_whatsapp_from_result, parse_account_mutation_result,
        parse_app_state_query_result, parse_app_state_sync_response, parse_blocklist,
        parse_dirty_notification_node, parse_dirty_notification_nodes,
        parse_group_accept_invite_result, parse_group_invite_code, parse_group_invite_v4_result,
        parse_group_join_request_action_result, parse_group_join_requests, parse_group_metadata,
        parse_group_mutation_result, parse_group_participant_action_result,
        parse_group_participating_result, parse_inbound_ack, parse_inbound_notification,
        parse_inbound_receipt, parse_media_connection_info, parse_media_retry_update,
        parse_newsletter_action_result, parse_newsletter_admin_count_result,
        parse_newsletter_change_owner_result, parse_newsletter_create_result,
        parse_newsletter_demote_result, parse_newsletter_linked_profile_notification,
        parse_newsletter_live_update_subscription, parse_newsletter_message_updates_result,
        parse_newsletter_metadata_result, parse_newsletter_metadata_update_result,
        parse_newsletter_notification_updates, parse_newsletter_reaction_result,
        parse_newsletter_subscriber_count_result, parse_privacy_settings,
        parse_profile_picture_mutation_result, parse_profile_picture_url, parse_retry_receipt,
        parse_usync_result, placeholder_resend_events_from_message,
        placeholder_resend_request_from_web_message, placeholder_unavailable_message_from_node,
        pn_user_jid, privacy_token_notification_sender_lid, process_history_sync,
        process_inbound_node, process_inline_history_sync_notification,
        push_decoded_message_to_buffer, reachout_timelock_store_key, receipt_events_from_inbound,
        relay_recipients_from_device_jids, response_tag,
        server_sync_collections_from_notification_node, statuses_from_result, unpad_random_max16,
        verify_media_ciphertext_hash, verify_media_plaintext_hash,
    };
    #[cfg(feature = "noise")]
    pub use wa_core::{
        APP_STATE_MAC_LEN, AppStateBlockedCollection, AppStateCollectionSyncOutcome,
        AppStateHashMutation, AppStatePatchBundle, AppStatePatchState, AppStatePendingSnapshot,
        AppStateSyncApplyOutcome, AppStateSyncKeyShareItem, AuthCredentials, ConnectionValidation,
        CredentialLoad, CurrentPreKeyStatus, DEFAULT_MEDIA_FILE_CHUNK_BYTES,
        DEFAULT_MEDIA_RETRY_COORDINATOR_CAPACITY, DEFAULT_MEDIA_RETRY_COORDINATOR_TTL_MS,
        DEFAULT_MEDIA_UPLOAD_CACHE_CAPACITY, DEFAULT_MEDIA_UPLOAD_CACHE_TTL_MS,
        DecodedAppStateMutation, DecodedAppStatePatch, DecodedAppStateSnapshot,
        EncryptedAppStateMutation, EncryptedMedia, INITIAL_PRE_KEY_COUNT, LidPnMapping,
        LidPnMappingStore, LinkCodeCompanionRegistration, LinkCodePairingFinishMaterial,
        MIN_PRE_KEY_COUNT, MediaKind, MediaRetryApplication, MediaRetryBatchError,
        MediaRetryBatchOutcome, MediaRetryCoordinator, MediaRetryCoordinatorConfig,
        MediaRetryDownload, MediaRetryPendingEntry, MediaRetryResult, MediaTransfer,
        MediaTransferConfig, MediaTransport, MediaUploadCache, MediaUploadCacheKey,
        MediaUploadRequest, MediaUploadStreamRequest, MemoryMediaUploadCache,
        MemoryMediaUploadCacheConfig, NoiseFrameSink, NoiseFrameStream, PairDeviceChallenge,
        PairSuccess, PairingCodeRequest, PairingKeyMaterial, PendingMediaRetry,
        PollEventMessageSecret, PollEventMessageSecrets, PreKeyUpload, SERVER_JID,
        SessionInjection, SharedNoiseHandshake, SignalAddress, SignalCiphertext,
        SignalCiphertextType, SignalCryptoProvider, SignalDecryptionRequest,
        SignalEncryptionRequest, SignalLocalIdentity, SignalLocalKeyMaterial, SignalLocalPreKey,
        SignalLocalSignedPreKey, SignalMessageChainKey, SignalMessageChainStep, SignalMessageCodec,
        SignalMessageKeyMaterial, SignalMutationGuard, SignalMutationLocks, SignalPreKey,
        SignalPreKeyBootstrap, SignalPreKeyWhisperMessage, SignalProviderPreKeySessionDecryption,
        SignalProviderPreKeySessionEncryption, SignalProviderRecordKind,
        SignalProviderSessionDecryption, SignalProviderSessionEncryption,
        SignalProviderSessionRecord, SignalProviderStateStore, SignalRepository, SignalRootKey,
        SignalRootRatchetStep, SignalSenderChainKey, SignalSenderChainStep,
        SignalSenderKeyDecryption, SignalSenderKeyDistribution, SignalSenderKeyDistributionMessage,
        SignalSenderKeyDistributionRecord, SignalSenderKeyEncryption, SignalSenderKeyMessage,
        SignalSenderKeyRecord, SignalSenderKeyState, SignalSenderMessageKeyMaterial,
        SignalSenderStoredMessageKey, SignalSession, SignalSessionInfo, SignalSessionMigration,
        SignalSessionValidation, SignalSignedPreKey, SignalWhisperMessage, SignedPreKey,
        SignedPreKeyRotation, StoreSignalRepository, StoreSignalSenderKeyProvider,
        UploadedMediaUpload, ValidatedConnection, ValidationPayload,
        XEdDsaNoiseCertificateVerifier, advance_signal_message_chain_key,
        advance_signal_sender_chain_key, app_state_patch_key_id,
        app_state_sync_key_share_from_message, app_state_sync_key_share_from_message_event,
        app_state_sync_key_store_id, apply_app_state_sync_response_to_store,
        apply_app_state_sync_response_with_store_keys, apply_decoded_app_state_patch_to_store,
        apply_decoded_app_state_snapshot_to_store, apply_media_retry_event,
        apply_signal_sender_key_distribution, build_app_state_patch_bundle,
        build_e2e_session_query, build_encrypted_event_response_content,
        build_encrypted_event_response_content_with_iv, build_encrypted_event_response_message,
        build_encrypted_event_response_message_with_iv, build_encrypted_media_retry_request_node,
        build_encrypted_poll_update_content, build_encrypted_poll_update_content_with_iv,
        build_encrypted_poll_update_message, build_encrypted_poll_update_message_with_iv,
        build_key_bundle_digest_query, build_pairing_code_request,
        build_pairing_code_request_with_material, build_pairing_qr_data, build_pre_key_count_query,
        build_signal_sender_key_distribution_message, build_signed_pre_key_rotation,
        bytes_to_crockford, companion_platform_display, companion_platform_id,
        confirm_pre_key_upload, create_initial_credentials, create_signed_pre_key,
        credentials_with_rotated_signed_pre_key, current_pre_key_status,
        decipher_link_code_public_key, decode_app_state_patch, decode_app_state_snapshot,
        decode_signal_pre_key_whisper_message, decode_signal_provider_session_record,
        decode_signal_sender_key_distribution_message, decode_signal_sender_key_message,
        decode_signal_sender_key_record, decode_signal_whisper_message,
        decode_stored_pending_media_retry, decoded_app_state_mutation_from_chat_mutation_patch,
        decrypt_and_verify_media_bytes, decrypt_event_response_message, decrypt_poll_vote_message,
        decrypt_signal_inbound_pre_key_session_message, decrypt_signal_message_body,
        decrypt_signal_provider_session_record_message, decrypt_signal_sender_key_record_message,
        decrypt_signal_sender_message_body, delete_app_state_blocked_collection,
        derive_signal_inbound_pre_key_root_chain_keys, derive_signal_message_key_seed,
        derive_signal_message_keys, derive_signal_outbound_pre_key_root_chain_keys,
        derive_signal_pre_key_root_chain_keys, derive_signal_root_chain_keys,
        derive_signal_sender_message_key_seed, derive_signal_sender_message_keys,
        derive_verified_signal_outbound_pre_key_root_chain_keys,
        download_and_decode_app_state_snapshot, download_and_process_history_sync,
        download_app_state_external_blob, download_app_state_external_mutations,
        download_app_state_external_snapshot, download_history_sync, download_history_sync_bytes,
        encode_signal_pre_key_whisper_message, encode_signal_provider_session_record,
        encode_signal_sender_key_distribution_message, encode_signal_sender_key_message,
        encode_signal_sender_key_record, encode_signal_whisper_message,
        encode_stored_pending_media_retry, encrypt_chat_mutation_patch,
        encrypt_chat_mutation_patch_with_iv, encrypt_signal_message_body,
        encrypt_signal_outbound_pre_key_session_message,
        encrypt_signal_provider_session_record_message, encrypt_signal_sender_key_record_message,
        encrypt_signal_sender_message_body, event_batch_from_chat_mutation_patch,
        event_batch_from_decoded_app_state_mutations, event_batch_from_decoded_app_state_patch,
        event_batch_from_decoded_app_state_snapshot,
        event_batch_from_decoded_message_with_poll_event_secrets, generate_registration_id,
        handle_link_code_companion_reg_notification,
        handle_link_code_companion_reg_notification_with_material, handle_pair_device_challenge,
        handle_pair_success, has_key_bundle_digest, is_lid_signal_jid,
        load_app_state_blocked_collection, load_app_state_blocked_collections_for_keys,
        load_app_state_patch_state, load_app_state_sync_key_data, load_credentials,
        load_or_init_credentials, mapped_lid_session_jid,
        message_updates_from_decoded_message_with_poll_event_secrets, normalize_signal_public_key,
        parse_e2e_sessions_node, parse_key_bundle_digest_response, parse_pre_key_count_response,
        parse_pre_key_upload_response, parse_signed_pre_key_rotation_response,
        pending_media_retry_store_key, prepare_pre_key_upload,
        process_signal_sender_key_distribution_record, ratchet_signal_message_chain,
        ratchet_signal_root_key, ratchet_signal_sender_chain, remote_thumbnail_from_encrypted,
        save_app_state_blocked_collection, save_app_state_patch_state,
        save_app_state_sync_key_data, save_app_state_sync_key_share, save_credentials,
        shared_noise_handshake, sign_signal_sender_key_message, signal_protocol_address,
        uploaded_media_from_app_state_external_blob, uploaded_media_from_encrypted,
        uploaded_media_from_history_sync_notification, validate_connection,
        verify_signal_sender_key_message, verify_signal_sender_key_message_bytes,
        verify_signal_signed_pre_key, wrap_pairing_ephemeral_public_key,
    };
    pub use wa_core::{
        AccountUpdate, MessageCappingInfo, MessageCappingMultiVariationStatus,
        MessageCappingOneTimeExtensionStatus, MessageCappingStatus,
        ReachoutTimelockEnforcementType, ReachoutTimelockState,
        build_account_reachout_timelock_query, build_message_capping_info_query,
        parse_account_reachout_timelock_result, parse_account_update_notification,
        parse_message_capping_info_result,
    };
    pub use wa_core::{
        BUSINESS_SERVER, BusinessCatalog, BusinessCatalogCollection, BusinessCatalogQuery,
        BusinessCatalogStatus, BusinessCollectionsQuery, BusinessCoverPhoto,
        BusinessCoverPhotoUpload, BusinessHours, BusinessHoursConfig, BusinessOrderDetails,
        BusinessOrderPrice, BusinessOrderProduct, BusinessProduct, BusinessProductCreate,
        BusinessProductImage, BusinessProductImageUrls, BusinessProductOrigin,
        BusinessProductUpdate, BusinessProfile, BusinessProfileUpdate,
        DEFAULT_BUSINESS_CATALOG_LIMIT, DEFAULT_BUSINESS_COLLECTION_LIMIT,
        MAX_BUSINESS_CATALOG_LIMIT, MAX_BUSINESS_COLLECTION_LIMIT, build_business_catalog_query,
        build_business_collections_query, build_business_cover_photo_delete_query,
        build_business_cover_photo_update_query, build_business_order_details_query,
        build_business_product_create_query, build_business_product_delete_query,
        build_business_product_update_query, build_business_profile_query,
        build_business_profile_update_query, business_cover_photo_from_uploaded_media,
        business_cover_photo_upload_from_location, business_product_image_from_uploaded_media,
        parse_business_catalog, parse_business_collections, parse_business_mutation_result,
        parse_business_order_details, parse_business_product_create_result,
        parse_business_product_delete_result, parse_business_product_update_result,
        parse_business_profile,
    };
    pub use wa_core::{
        COMMUNITY_COLLECTION_JID, COMMUNITY_QUERY_XMLNS, CommunityLinkedGroup,
        CommunityMutationKind, build_community_accept_invite_query,
        build_community_accept_invite_v4_query, build_community_create_group_query,
        build_community_create_query, build_community_description_query,
        build_community_ephemeral_query, build_community_invite_code_query,
        build_community_invite_info_query, build_community_join_approval_mode_query,
        build_community_join_request_action_query, build_community_join_request_list_query,
        build_community_leave_query, build_community_link_group_query,
        build_community_linked_groups_query, build_community_member_add_mode_query,
        build_community_metadata_query, build_community_participants_query,
        build_community_participating_query, build_community_revoke_invite_query,
        build_community_revoke_invite_v4_query, build_community_setting_query,
        build_community_subject_query, build_community_unlink_group_query,
        parse_community_accept_invite_result, parse_community_invite_code,
        parse_community_invite_info_result, parse_community_invite_v4_result,
        parse_community_join_request_action_result, parse_community_join_requests,
        parse_community_linked_groups, parse_community_metadata, parse_community_mutation_result,
        parse_community_participant_action_result, parse_community_participating_result,
    };
    #[cfg(feature = "image")]
    pub use wa_core::{
        DEFAULT_IMAGE_DECODE_MAX_ALLOC_BYTES, DEFAULT_LINK_PREVIEW_INLINE_THUMBNAIL_EDGE,
        DEFAULT_LINK_PREVIEW_INLINE_THUMBNAIL_JPEG_QUALITY, DEFAULT_LINK_PREVIEW_THUMBNAIL_EDGE,
        DEFAULT_LINK_PREVIEW_THUMBNAIL_JPEG_QUALITY, DEFAULT_MAX_IMAGE_DIMENSION,
        DEFAULT_MAX_IMAGE_INPUT_BYTES, DEFAULT_MESSAGE_THUMBNAIL_EDGE,
        DEFAULT_MESSAGE_THUMBNAIL_JPEG_QUALITY, DEFAULT_PDF_THUMBNAIL_COMMAND,
        DEFAULT_PDF_THUMBNAIL_DPI, DEFAULT_PDF_THUMBNAIL_PAGE, DEFAULT_PROFILE_PICTURE_EDGE,
        DEFAULT_PROFILE_PICTURE_JPEG_QUALITY, DEFAULT_PROFILE_PICTURE_PREVIEW_EDGE,
        DEFAULT_VIDEO_THUMBNAIL_COMMAND, DEFAULT_VIDEO_THUMBNAIL_SEEK_TIME, GeneratedJpegThumbnail,
        GeneratedLinkPreviewImages, GeneratedProfilePicture, ImageProcessingLimits,
        JpegThumbnailOptions, LinkPreviewImageOptions, PdfThumbnailOptions, ProfilePictureOptions,
        VideoThumbnailOptions, generate_jpeg_thumbnail, generate_link_preview_images,
        generate_pdf_thumbnail_from_file, generate_profile_picture,
        generate_video_thumbnail_from_file,
    };
    #[cfg(feature = "link-preview")]
    pub use wa_core::{
        DEFAULT_LINK_PREVIEW_FETCH_MAX_HTML_BYTES, DEFAULT_LINK_PREVIEW_FETCH_TIMEOUT_MS,
        DEFAULT_LINK_PREVIEW_FETCH_USER_AGENT, DEFAULT_LINK_PREVIEW_IMAGE_FETCH_MAX_BYTES,
        DEFAULT_LINK_PREVIEW_IMAGE_FETCH_TIMEOUT_MS, FetchedLinkPreview, LinkPreviewFetchOptions,
        LinkPreviewImageFetchOptions, fetch_link_preview, fetch_link_preview_image,
        link_preview_thumbnail_from_uploaded_media, upload_link_preview_thumbnail,
        upload_link_preview_thumbnail_cached, upload_link_preview_thumbnail_file,
        upload_link_preview_thumbnail_file_cached,
    };
    #[cfg(all(feature = "link-preview", feature = "image"))]
    pub use wa_core::{
        FetchedLinkPreviewWithThumbnail, GeneratedLinkPreviewThumbnailUpload,
        LinkPreviewThumbnailFetchOptions, fetch_link_preview_with_thumbnail,
        fetch_link_preview_with_thumbnail_cached, upload_generated_link_preview_thumbnail,
        upload_generated_link_preview_thumbnail_cached,
    };
    #[cfg(all(feature = "noise", feature = "image"))]
    pub use wa_core::{
        GeneratedRemoteMediaThumbnailUpload, upload_generated_document_remote_thumbnail_file,
        upload_generated_video_remote_thumbnail_file,
    };
    #[cfg(all(feature = "noise", feature = "http-media"))]
    pub use wa_core::{
        HttpMediaTransport, HttpMediaTransportConfig, media_upload_token, media_upload_url,
    };
    #[cfg(feature = "websocket")]
    pub use wa_core::{connect_websocket, connect_websocket_transport};
    #[cfg(feature = "memory-store")]
    pub use wa_store::MemoryAuthStore;
    #[cfg(feature = "sqlite-store")]
    pub use wa_store::SqliteAuthStore;
    pub use wa_store::{AuthStore, KeyNamespace, SignalKeyStore};
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]

    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    use bytes::{BufMut, BytesMut};
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    use flate2::{Compression, write::ZlibEncoder};
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    use prost::Message as _;
    #[cfg(feature = "noise")]
    use std::collections::BTreeMap;
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use wa_binary::encode_binary_node;
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    use wa_core::ValidationPayload;
    use wa_core::{FrameSink, FrameStream, InboundFrame, decode_inbound_binary_node};
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    use wa_crypto::{
        SecretBytes, aes_256_ctr_apply, derive_pairing_code_key, generate_key_pair, hmac_sha256,
        prefixed_signal_public_key, sign_x25519,
    };
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    use wa_proto::proto::{
        AdvDeviceIdentity, AdvEncryptionType, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac,
        SenderKeyRecordStructure, SenderKeyStateStructure, sender_key_state_structure,
    };
    #[cfg(feature = "memory-store")]
    use wa_store::KeyNamespace;

    struct RelayEncryptor {
        calls: Mutex<Vec<(String, Bytes)>>,
        ciphertext_type: wa_core::MessageCiphertextType,
    }

    impl RelayEncryptor {
        fn pre_key() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                ciphertext_type: wa_core::MessageCiphertextType::PreKey,
            }
        }

        fn sender_key() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                ciphertext_type: wa_core::MessageCiphertextType::SenderKey,
            }
        }
    }

    impl Default for RelayEncryptor {
        fn default() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                ciphertext_type: wa_core::MessageCiphertextType::Message,
            }
        }
    }

    #[async_trait]
    impl wa_core::MessageEncryptor for RelayEncryptor {
        async fn encrypt_message(
            &self,
            recipient_jid: &str,
            plaintext: Bytes,
        ) -> CoreResult<wa_core::MessageEncryption> {
            self.calls
                .lock()
                .unwrap()
                .push((recipient_jid.to_owned(), plaintext.clone()));
            Ok(wa_core::MessageEncryption::new(
                self.ciphertext_type,
                plaintext,
            ))
        }
    }

    struct FailingEncryptor {
        error: &'static str,
    }

    impl FailingEncryptor {
        fn new(error: &'static str) -> Self {
            Self { error }
        }
    }

    #[async_trait]
    impl wa_core::MessageEncryptor for FailingEncryptor {
        async fn encrypt_message(
            &self,
            _recipient_jid: &str,
            _plaintext: Bytes,
        ) -> CoreResult<wa_core::MessageEncryption> {
            Err(wa_core::CoreError::Task(self.error.to_owned()))
        }
    }

    struct FailingAfterEncryptor {
        calls: Mutex<Vec<(String, Bytes)>>,
        fail_at: usize,
        error: &'static str,
    }

    impl FailingAfterEncryptor {
        fn new(fail_at: usize, error: &'static str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_at,
                error,
            }
        }
    }

    #[async_trait]
    impl wa_core::MessageEncryptor for FailingAfterEncryptor {
        async fn encrypt_message(
            &self,
            recipient_jid: &str,
            plaintext: Bytes,
        ) -> CoreResult<wa_core::MessageEncryption> {
            let mut calls = self.calls.lock().unwrap();
            calls.push((recipient_jid.to_owned(), plaintext.clone()));
            if calls.len() == self.fail_at {
                return Err(wa_core::CoreError::Task(self.error.to_owned()));
            }
            Ok(wa_core::MessageEncryption::new(
                wa_core::MessageCiphertextType::Message,
                plaintext,
            ))
        }
    }

    struct DeletingSessionsAfterEncryptor<S> {
        calls: Mutex<Vec<(String, Bytes)>>,
        repository: StoreSignalRepository<S>,
        delete_after: usize,
        delete_jids: Vec<String>,
    }

    impl<S> DeletingSessionsAfterEncryptor<S> {
        fn new(
            repository: StoreSignalRepository<S>,
            delete_after: usize,
            delete_jids: impl IntoIterator<Item = impl Into<String>>,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                repository,
                delete_after,
                delete_jids: delete_jids.into_iter().map(Into::into).collect(),
            }
        }
    }

    #[async_trait]
    impl<S> wa_core::MessageEncryptor for DeletingSessionsAfterEncryptor<S>
    where
        S: wa_store::SignalKeyStore,
    {
        async fn encrypt_message(
            &self,
            recipient_jid: &str,
            plaintext: Bytes,
        ) -> CoreResult<wa_core::MessageEncryption> {
            let should_delete = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((recipient_jid.to_owned(), plaintext.clone()));
                calls.len() == self.delete_after
            };
            if should_delete {
                self.repository.delete_sessions(&self.delete_jids).await?;
            }
            Ok(wa_core::MessageEncryption::new(
                wa_core::MessageCiphertextType::Message,
                plaintext,
            ))
        }
    }

    struct ClosingConnectionAtEncryptor {
        calls: Mutex<Vec<(String, Bytes)>>,
        connection: Connection,
        close_at: usize,
    }

    impl ClosingConnectionAtEncryptor {
        fn new(connection: Connection, close_at: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                connection,
                close_at,
            }
        }
    }

    #[async_trait]
    impl wa_core::MessageEncryptor for ClosingConnectionAtEncryptor {
        async fn encrypt_message(
            &self,
            recipient_jid: &str,
            plaintext: Bytes,
        ) -> CoreResult<wa_core::MessageEncryption> {
            let should_close = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((recipient_jid.to_owned(), plaintext.clone()));
                calls.len() == self.close_at
            };
            if should_close {
                self.connection.close().await?;
            }
            Ok(wa_core::MessageEncryption::new(
                wa_core::MessageCiphertextType::Message,
                plaintext,
            ))
        }
    }

    struct ClosingAfterEncryptor<E> {
        calls: Mutex<Vec<(String, Bytes)>>,
        inner: E,
        connection: Connection,
        close_after: usize,
    }

    impl<E> ClosingAfterEncryptor<E> {
        fn new(inner: E, connection: Connection, close_after: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                inner,
                connection,
                close_after,
            }
        }
    }

    #[async_trait]
    impl<E> wa_core::MessageEncryptor for ClosingAfterEncryptor<E>
    where
        E: wa_core::MessageEncryptor,
    {
        async fn encrypt_message(
            &self,
            recipient_jid: &str,
            plaintext: Bytes,
        ) -> CoreResult<wa_core::MessageEncryption> {
            let encrypted = self
                .inner
                .encrypt_message(recipient_jid, plaintext.clone())
                .await?;
            let should_close = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((recipient_jid.to_owned(), plaintext));
                calls.len() == self.close_after
            };
            if should_close {
                self.connection.close().await?;
            }
            Ok(encrypted)
        }
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    struct IncomingDecryptor;

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[async_trait]
    impl wa_core::InboundMessageDecryptor for IncomingDecryptor {
        async fn decrypt_inbound_message(
            &self,
            payload: wa_core::InboundEncryptedPayload,
        ) -> CoreResult<Bytes> {
            Ok(payload.ciphertext)
        }
    }

    // Relocated from the test region so all feature-gated chunks can use it.
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn single_recipient_status_usync_response(node: BinaryNode) -> BinaryNode {
        assert_eq!(node.attrs["xmlns"], "usync");
        assert_usync_query_protocol(&node, "devices");
        assert_eq!(
            usync_query_user_jids(&node),
            vec![
                "111@s.whatsapp.net".to_owned(),
                "999:7@s.whatsapp.net".to_owned(),
            ]
        );
        BinaryNode::new("iq")
            .with_attr("id", node.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("usync").with_content(vec![
                BinaryNode::new("list").with_content(vec![
                    BinaryNode::new("user")
                        .with_attr("jid", "111@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list")
                                .with_content(vec![BinaryNode::new("device").with_attr("id", "0")]),
                        ])]),
                    BinaryNode::new("user")
                        .with_attr("jid", "999@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list")
                                .with_content(vec![BinaryNode::new("device").with_attr("id", "7")]),
                        ])]),
                ]),
            ])])
    }

    #[cfg(feature = "wat1")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_1 {
        use super::*;
        include!("tests_chunk_1.rs");
    }

    #[cfg(feature = "wat2")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_2 {
        use super::*;
        include!("tests_chunk_2.rs");
    }

    #[cfg(feature = "wat3")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_3 {
        use super::*;
        include!("tests_chunk_3.rs");
    }

    #[cfg(feature = "wat4")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_4 {
        use super::*;
        include!("tests_chunk_4.rs");
    }

    #[cfg(feature = "wat5")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_5 {
        use super::*;
        include!("tests_chunk_5.rs");
    }

    #[cfg(feature = "wat6")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_6 {
        use super::*;
        include!("tests_chunk_6.rs");
    }

    #[cfg(feature = "wat7")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_7 {
        use super::*;
        include!("tests_chunk_7.rs");
    }

    #[cfg(feature = "wat8")]
    #[allow(unused_imports, dead_code, clippy::all)]
    mod chunk_8 {
        use super::*;
        include!("tests_chunk_8.rs");
    }

    fn mock_connection() -> (
        Connection,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<InboundFrame>,
    ) {
        mock_connection_with_events(EventHub::new(8))
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[derive(Clone, Default)]
    struct HistoryDownloadTransport {
        downloads: Arc<Mutex<BTreeMap<String, Bytes>>>,
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    impl HistoryDownloadTransport {
        fn add_download(&self, url: impl Into<String>, bytes: Bytes) {
            self.downloads.lock().unwrap().insert(url.into(), bytes);
        }
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[async_trait]
    impl wa_core::MediaTransport for HistoryDownloadTransport {
        async fn upload_media(
            &self,
            _request: wa_core::MediaUploadRequest,
        ) -> CoreResult<wa_core::UploadedMediaLocation> {
            Err(wa_core::CoreError::Payload(
                "history facade transport does not upload".to_owned(),
            ))
        }

        async fn download_media(&self, url: &str) -> CoreResult<Bytes> {
            self.downloads
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .ok_or_else(|| {
                    wa_core::CoreError::Payload(format!("missing download fixture: {url}"))
                })
        }
    }

    #[cfg(feature = "noise")]
    #[derive(Clone, Default)]
    struct ClientMediaUploadTransport {
        uploads: Arc<Mutex<Vec<wa_core::MediaUploadRequest>>>,
        downloads: Arc<Mutex<BTreeMap<String, Bytes>>>,
    }

    #[cfg(feature = "noise")]
    #[async_trait]
    impl wa_core::MediaTransport for ClientMediaUploadTransport {
        async fn upload_media(
            &self,
            request: wa_core::MediaUploadRequest,
        ) -> CoreResult<wa_core::UploadedMediaLocation> {
            let mut uploads = self.uploads.lock().unwrap();
            let upload_index = uploads.len();
            let direct_path = format!("/client/upload/{upload_index}");
            self.downloads.lock().unwrap().insert(
                format!("https://media.test{direct_path}"),
                request.ciphertext_with_mac.clone(),
            );
            let mut location = wa_core::UploadedMediaLocation::new().with_direct_path(direct_path);
            if request.kind == wa_core::MediaKind::BusinessCoverPhoto {
                location = location
                    .with_upload_id(format!("cover-{upload_index}"))
                    .with_upload_token(format!("token-{upload_index}"))
                    .with_media_key_timestamp(1_700_000_000 + upload_index as i64);
            }
            uploads.push(request);
            Ok(location)
        }

        async fn download_media(&self, url: &str) -> CoreResult<Bytes> {
            self.downloads
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .ok_or_else(|| wa_core::CoreError::Payload(format!("missing media file: {url}")))
        }
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn test_client_media_path(label: &str) -> std::path::PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("wa-client-media-{label}-{suffix}"))
    }

    #[cfg(all(feature = "sqlite-store", feature = "noise"))]
    fn test_client_sqlite_path(label: &str) -> std::path::PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("wa-client-sqlite-{label}-{suffix}"))
    }

    #[cfg(all(feature = "memory-store", feature = "noise", feature = "image", unix))]
    fn sample_client_png() -> Bytes {
        Bytes::from_static(&[
            137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1,
            8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 10, 73, 68, 65, 84, 120, 156, 99, 0, 1, 0, 0,
            5, 0, 1, 13, 10, 45, 180, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
        ])
    }

    #[cfg(all(feature = "memory-store", feature = "noise", feature = "image", unix))]
    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    fn mock_connection_with_events(
        events: EventHub,
    ) -> (
        Connection,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<InboundFrame>,
    ) {
        let (sink_tx, sink_rx) = mpsc::channel(4);
        let (stream_tx, stream_rx) = mpsc::channel(4);
        let connection = Connection::spawn(
            MockSink {
                tx: sink_tx,
                close_count: Arc::new(AtomicUsize::new(0)),
            },
            MockStream { rx: stream_rx },
            QueryManager::new(None),
            events,
            4,
        );

        (connection, sink_rx, stream_tx)
    }

    async fn recv_batch_event(
        events: &mut tokio::sync::broadcast::Receiver<Event>,
    ) -> Box<wa_core::EventBatch> {
        for _ in 0..8 {
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            if let Event::Batch(batch) = event {
                return batch;
            }
        }
        panic!("expected batch event");
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    async fn recv_media_retry_processed_event(
        events: &mut tokio::sync::broadcast::Receiver<Event>,
    ) -> wa_core::MediaRetryBatchOutcome {
        for _ in 0..8 {
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            if let Event::MediaRetryProcessed(outcome) = event {
                return outcome;
            }
        }
        panic!("expected media retry processed event");
    }

    async fn recv_node_event(events: &mut tokio::sync::broadcast::Receiver<Event>) -> BinaryNode {
        for _ in 0..8 {
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            if let Event::Node(node) = event {
                return node;
            }
        }
        panic!("expected processed node event");
    }

    async fn recv_lid_mapping_event(
        events: &mut tokio::sync::broadcast::Receiver<Event>,
    ) -> Vec<wa_core::LidMappingEvent> {
        for _ in 0..8 {
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            if let Event::LidMappingUpdate(mappings) = event {
                return mappings;
            }
        }
        panic!("expected LID mapping event");
    }

    async fn recv_default_disappearing_mode_event(
        events: &mut tokio::sync::broadcast::Receiver<Event>,
    ) -> wa_core::DefaultDisappearingMode {
        for _ in 0..8 {
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            if let Event::DefaultDisappearingModeUpdate(mode) = event {
                return mode;
            }
        }
        panic!("expected default disappearing mode event");
    }

    async fn recv_groups_update_event(
        events: &mut tokio::sync::broadcast::Receiver<Event>,
    ) -> Vec<GroupUpdateEvent> {
        for _ in 0..8 {
            let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            if let Event::GroupsUpdate(update) = event {
                return update;
            }
        }
        panic!("expected groups update event");
    }

    async fn respond_to_next_query<F, Fut>(
        sink_rx: &mut mpsc::Receiver<Bytes>,
        stream_tx: &mpsc::Sender<InboundFrame>,
        response: F,
        pending: &mut Fut,
    ) -> String
    where
        F: FnOnce(BinaryNode) -> BinaryNode,
        Fut: Future + Unpin,
        Fut::Output: std::fmt::Debug,
    {
        let sent_frame = tokio::select! {
            result = pending => panic!("maintenance completed before mock response: {result:?}"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
        let tag = sent.attrs["id"].clone();
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&response(sent)).unwrap(),
            ))
            .await
            .unwrap();
        tag
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    async fn respond_to_single_remote_device_query<Fut>(
        sink_rx: &mut mpsc::Receiver<Bytes>,
        stream_tx: &mpsc::Sender<InboundFrame>,
        pending: &mut Fut,
    ) -> String
    where
        Fut: Future + Unpin,
        Fut::Output: std::fmt::Debug,
    {
        respond_to_next_query(
            sink_rx,
            stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "devices");
                assert_eq!(
                    usync_query_user_jids(&node),
                    vec![
                        "123@s.whatsapp.net".to_owned(),
                        "999:7@s.whatsapp.net".to_owned(),
                    ]
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "0"),
                                    ])],
                                )]),
                            BinaryNode::new("user")
                                .with_attr("jid", "999@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "7"),
                                    ])],
                                )]),
                        ]),
                    ])])
            },
            pending,
        )
        .await
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    async fn recv_app_state_upload<Fut, T>(
        sink_rx: &mut mpsc::Receiver<Bytes>,
        pending: &mut Fut,
        label: &str,
        expected_collection: AppStateCollection,
        expected_previous_version: u64,
    ) -> (BinaryNode, wa_proto::proto::SyncdPatch)
    where
        Fut: Future<Output = CoreResult<T>> + Unpin,
    {
        let sent_frame = tokio::select! {
            _ = pending => panic!("{label} app-state mutation completed before mock response"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let node = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
        let collection = test_child(test_child(&node, "sync"), "collection");
        assert_eq!(collection.attrs["name"], expected_collection.name());
        assert_eq!(
            collection.attrs["version"],
            expected_previous_version.to_string()
        );
        let patch_bytes = test_node_bytes(test_child(collection, "patch")).unwrap();
        let patch = wa_proto::proto::SyncdPatch::decode(patch_bytes.as_ref()).unwrap();
        (node, patch)
    }

    fn empty_result_for(query: &BinaryNode) -> BinaryNode {
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
    }

    fn error_result_for(query: &BinaryNode, code: &str, text: &str) -> BinaryNode {
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "error")
            .with_attr("code", code)
            .with_attr("text", text)
    }

    fn wmex_response_for_query(query: &BinaryNode, path: &str, payload: &str) -> BinaryNode {
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("result").with_content(
                format!(r#"{{"data":{{"{path}":{payload}}}}}"#).into_bytes(),
            )])
    }

    fn business_product_mutation_response(query: &BinaryNode, wrapper: &str) -> BinaryNode {
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new(wrapper).with_content(vec![business_product_node()]),
            ])
    }

    fn business_product_node() -> BinaryNode {
        BinaryNode::new("product")
            .with_attr("is_hidden", "false")
            .with_content(vec![
                BinaryNode::new("id").with_content("sku-1"),
                BinaryNode::new("name").with_content("Widget"),
                BinaryNode::new("retailer_id").with_content("retailer"),
                BinaryNode::new("description").with_content("Useful"),
                BinaryNode::new("price").with_content("12345000"),
                BinaryNode::new("currency").with_content("USD"),
                BinaryNode::new("media").with_content(vec![BinaryNode::new("image").with_content(
                    vec![BinaryNode::new("request_image_url").with_content("https://img/small")],
                )]),
                BinaryNode::new("status_info")
                    .with_content(vec![BinaryNode::new("status").with_content("APPROVED")]),
            ])
    }

    fn test_wmex_query(node: &BinaryNode) -> (&str, serde_json::Value) {
        let query = test_child(node, "query");
        let bytes = test_node_bytes(query).expect("WMex query must contain JSON bytes");
        let payload: serde_json::Value = serde_json::from_slice(bytes.as_ref()).unwrap();
        (
            query.attrs["query_id"].as_str(),
            payload["variables"].clone(),
        )
    }

    fn group_metadata_response(query: &BinaryNode, id: &str, subject: &str) -> BinaryNode {
        group_metadata_response_with_description(query, id, subject, None)
    }

    fn community_metadata_response(query: &BinaryNode, id: &str, subject: &str) -> BinaryNode {
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("community")
                    .with_attr("id", id)
                    .with_attr("subject", subject)
                    .with_content(vec![
                        BinaryNode::new("parent"),
                        BinaryNode::new("addressing_mode").with_content("lid"),
                        BinaryNode::new("description")
                            .with_attr("id", "desc-1")
                            .with_content(vec![BinaryNode::new("body").with_content("Daily")]),
                        BinaryNode::new("participant")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_attr("type", "superadmin"),
                    ]),
            ])
    }

    fn group_metadata_response_with_description(
        query: &BinaryNode,
        id: &str,
        subject: &str,
        description_id: Option<&str>,
    ) -> BinaryNode {
        let mut children = vec![
            BinaryNode::new("participant")
                .with_attr("jid", "111@s.whatsapp.net")
                .with_attr("type", "admin"),
        ];
        if let Some(description_id) = description_id {
            children.push(
                BinaryNode::new("description")
                    .with_attr("id", description_id)
                    .with_content(vec![
                        BinaryNode::new("body").with_content("old description"),
                    ]),
            );
        }
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("group")
                    .with_attr("id", id)
                    .with_attr("subject", subject)
                    .with_attr("s_t", "1")
                    .with_attr("creation", "1")
                    .with_content(children),
            ])
    }

    fn test_child<'a>(node: &'a BinaryNode, tag: &str) -> &'a BinaryNode {
        test_children(node, tag)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing child node {tag}"))
    }

    fn test_node_text(node: &BinaryNode) -> Option<String> {
        match node.content.as_ref()? {
            wa_binary::BinaryNodeContent::Bytes(bytes) => {
                std::str::from_utf8(bytes).ok().map(str::to_owned)
            }
            wa_binary::BinaryNodeContent::Text(text) => Some(text.clone()),
            wa_binary::BinaryNodeContent::Nodes(_) => None,
        }
    }

    fn test_node_bytes(node: &BinaryNode) -> Option<Bytes> {
        match node.content.as_ref()? {
            wa_binary::BinaryNodeContent::Bytes(bytes) => Some(bytes.clone()),
            wa_binary::BinaryNodeContent::Text(text) => {
                Some(Bytes::copy_from_slice(text.as_bytes()))
            }
            wa_binary::BinaryNodeContent::Nodes(_) => None,
        }
    }

    fn test_children<'a>(node: &'a BinaryNode, tag: &str) -> Vec<&'a BinaryNode> {
        let Some(wa_binary::BinaryNodeContent::Nodes(children)) = &node.content else {
            panic!("node has no child list");
        };
        children.iter().filter(|child| child.tag == tag).collect()
    }

    fn assert_child(node: &BinaryNode, tag: &str) {
        let Some(wa_binary::BinaryNodeContent::Nodes(children)) = &node.content else {
            panic!("node has no child list");
        };
        assert!(
            children.iter().any(|child| child.tag == tag),
            "missing child node {tag}"
        );
    }

    fn assert_usync_query_protocol(node: &BinaryNode, tag: &str) {
        let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &node.content else {
            panic!("USync IQ has no child list");
        };
        let usync = iq_children
            .iter()
            .find(|child| child.tag == "usync")
            .unwrap();
        let Some(wa_binary::BinaryNodeContent::Nodes(usync_children)) = &usync.content else {
            panic!("USync node has no child list");
        };
        let query = usync_children
            .iter()
            .find(|child| child.tag == "query")
            .unwrap();
        let Some(wa_binary::BinaryNodeContent::Nodes(query_children)) = &query.content else {
            panic!("USync query has no child list");
        };
        assert!(
            query_children.iter().any(|child| child.tag == tag),
            "missing USync protocol {tag}"
        );
    }

    fn usync_query_user_jids(node: &BinaryNode) -> Vec<String> {
        let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &node.content else {
            panic!("USync IQ has no child list");
        };
        let usync = iq_children
            .iter()
            .find(|child| child.tag == "usync")
            .unwrap();
        let Some(wa_binary::BinaryNodeContent::Nodes(usync_children)) = &usync.content else {
            panic!("USync node has no child list");
        };
        let list = usync_children
            .iter()
            .find(|child| child.tag == "list")
            .unwrap();
        let Some(wa_binary::BinaryNodeContent::Nodes(users)) = &list.content else {
            panic!("USync list has no child list");
        };
        users
            .iter()
            .filter(|child| child.tag == "user")
            .filter_map(|user| user.attrs.get("jid").cloned())
            .collect()
    }

    fn group_retry_primary_device_response(query: &BinaryNode) -> BinaryNode {
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("usync").with_content(vec![
                BinaryNode::new("list").with_content(vec![
                    BinaryNode::new("user")
                        .with_attr("jid", "123@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "0"),
                                BinaryNode::new("device")
                                    .with_attr("id", "1")
                                    .with_attr("key-index", "11"),
                            ]),
                        ])]),
                    BinaryNode::new("user")
                        .with_attr("jid", "999@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device").with_attr("id", "7"),
                        ])]),
                ]),
            ])])
    }

    fn retry_all_devices_with_own_linked_device_response(query: &BinaryNode) -> BinaryNode {
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("usync").with_content(vec![
                BinaryNode::new("list").with_content(vec![
                    BinaryNode::new("user")
                        .with_attr("jid", "123@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device")
                                    .with_attr("id", "1")
                                    .with_attr("key-index", "11"),
                            ]),
                        ])]),
                    BinaryNode::new("user")
                        .with_attr("jid", "999@s.whatsapp.net")
                        .with_content(vec![BinaryNode::new("devices").with_content(vec![
                            BinaryNode::new("device-list").with_content(vec![
                                BinaryNode::new("device").with_attr("id", "7"),
                                BinaryNode::new("device")
                                    .with_attr("id", "8")
                                    .with_attr("key-index", "8"),
                            ]),
                        ])]),
                ]),
            ])])
    }

    fn encrypt_key_query_user_attrs(node: &BinaryNode) -> Vec<(String, Option<String>)> {
        let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &node.content else {
            panic!("encrypt IQ has no child list");
        };
        let key = iq_children.iter().find(|child| child.tag == "key").unwrap();
        let Some(wa_binary::BinaryNodeContent::Nodes(users)) = &key.content else {
            panic!("encrypt key has no user list");
        };
        users
            .iter()
            .filter(|child| child.tag == "user")
            .map(|user| (user.attrs["jid"].clone(), user.attrs.get("reason").cloned()))
            .collect()
    }

    fn session_response_for_query(query: &BinaryNode) -> BinaryNode {
        let users = encrypt_key_query_user_attrs(query)
            .into_iter()
            .map(|(jid, _)| e2e_session_user_node(&jid))
            .collect::<Vec<_>>();
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("list").with_content(users)])
    }

    fn e2e_session_user_node(jid: &str) -> BinaryNode {
        BinaryNode::new("user")
            .with_attr("jid", jid)
            .with_content(vec![
                BinaryNode::new("registration")
                    .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                BinaryNode::new("skey").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                    BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                ]),
                BinaryNode::new("key").with_content(vec![
                    BinaryNode::new("id").with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                    BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                ]),
            ])
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn valid_session_response_for_query(
        query: &BinaryNode,
        remote_credentials: &AuthCredentials,
        remote_one_time_pre_key: &wa_crypto::KeyPair,
        remote_one_time_pre_key_id: u32,
    ) -> BinaryNode {
        let users = encrypt_key_query_user_attrs(query)
            .into_iter()
            .map(|(jid, _)| {
                valid_e2e_session_user_node(
                    &jid,
                    remote_credentials,
                    remote_one_time_pre_key,
                    remote_one_time_pre_key_id,
                )
            })
            .collect::<Vec<_>>();
        BinaryNode::new("iq")
            .with_attr("id", query.attrs["id"].clone())
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("list").with_content(users)])
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn valid_e2e_session_user_node(
        jid: &str,
        remote_credentials: &AuthCredentials,
        remote_one_time_pre_key: &wa_crypto::KeyPair,
        remote_one_time_pre_key_id: u32,
    ) -> BinaryNode {
        BinaryNode::new("user")
            .with_attr("jid", jid)
            .with_content(vec![
                BinaryNode::new("registration").with_content(
                    wa_core::encode_big_endian(remote_credentials.registration_id, 4).unwrap(),
                ),
                BinaryNode::new("identity").with_content(Bytes::copy_from_slice(
                    &remote_credentials.signed_identity_key.public,
                )),
                BinaryNode::new("skey").with_content(vec![
                    BinaryNode::new("id").with_content(
                        wa_core::encode_big_endian(remote_credentials.signed_pre_key.key_id, 3)
                            .unwrap(),
                    ),
                    BinaryNode::new("value").with_content(Bytes::copy_from_slice(
                        &remote_credentials.signed_pre_key.key_pair.public,
                    )),
                    BinaryNode::new("signature")
                        .with_content(remote_credentials.signed_pre_key.signature.clone()),
                ]),
                BinaryNode::new("key").with_content(vec![
                    BinaryNode::new("id").with_content(
                        wa_core::encode_big_endian(remote_one_time_pre_key_id, 3).unwrap(),
                    ),
                    BinaryNode::new("value")
                        .with_content(Bytes::copy_from_slice(&remote_one_time_pre_key.public)),
                ]),
            ])
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn test_signal_local_key_material(
        credentials: &AuthCredentials,
    ) -> wa_core::SignalLocalKeyMaterial {
        wa_core::SignalLocalKeyMaterial {
            registration_id: credentials.registration_id,
            identity: wa_core::SignalLocalIdentity {
                public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &credentials.signed_identity_key.public,
                )),
                key_pair: credentials.signed_identity_key.clone(),
            },
            signed_pre_key: wa_core::SignalLocalSignedPreKey {
                key_id: credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &credentials.signed_pre_key.key_pair.public,
                )),
                key_pair: credentials.signed_pre_key.key_pair.clone(),
                signature: credentials.signed_pre_key.signature.clone(),
            },
        }
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn signal_provider_session_with_receiving_chain_without_remote_ratchet(
        valid_session: &Bytes,
    ) -> Bytes {
        // Decode/mutate/re-encode rather than splicing raw bytes: the provider
        // session wire layout (previous_counter, trailing inbound_base_key) is an
        // implementation detail of wa-core's encoder, so operate on the typed record.
        let mut decoded = wa_core::decode_signal_provider_session_record(valid_session)
            .expect("valid provider session decodes");
        assert!(
            decoded.remote_ratchet_key.is_some(),
            "valid provider session has a remote ratchet key"
        );
        assert!(
            decoded.receiving_chain.is_some(),
            "valid provider session has a receiving chain"
        );
        assert!(
            decoded.message_keys.is_empty(),
            "test session should not include skipped keys"
        );
        decoded.remote_ratchet_key = None;
        test_encode_provider_session_record_unchecked(&decoded)
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn signal_provider_session_with_skipped_key_without_remote_ratchet(
        valid_without_remote_session: &Bytes,
        skipped_ratchet_key: &Bytes,
        skipped_counter: u32,
        skipped_message_keys: &wa_core::SignalMessageKeyMaterial,
    ) -> Bytes {
        let mut decoded =
            wa_core::decode_signal_provider_session_record(valid_without_remote_session)
                .expect("valid provider session decodes");
        assert!(
            decoded.receiving_chain.is_none(),
            "test session should not have a receiving chain"
        );
        assert!(
            decoded.remote_ratchet_key.is_none(),
            "test session should not have a remote ratchet key"
        );
        assert!(
            decoded.message_keys.is_empty(),
            "test session should not include skipped keys"
        );
        decoded.message_keys = vec![wa_core::signal::SignalProviderStoredMessageKey {
            ratchet_key: skipped_ratchet_key.clone(),
            counter: skipped_counter,
            message_keys: skipped_message_keys.clone(),
        }];
        test_encode_provider_session_record_unchecked(&decoded)
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn signal_provider_session_with_remote_ratchet_without_receiving_chain(
        valid_without_remote_session: &Bytes,
        remote_ratchet_key: &Bytes,
    ) -> Bytes {
        let decoded = wa_core::decode_signal_provider_session_record(valid_without_remote_session)
            .expect("valid provider session decodes");
        assert!(
            decoded.receiving_chain.is_none(),
            "test session should not have a receiving chain"
        );
        assert!(
            decoded.remote_ratchet_key.is_none(),
            "test session should not have a remote ratchet key"
        );
        assert!(
            decoded.message_keys.is_empty(),
            "test session should not include skipped keys"
        );
        let mut decoded = decoded;
        decoded.remote_ratchet_key = Some(remote_ratchet_key.clone());
        test_encode_provider_session_record_unchecked(&decoded)
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn signal_provider_session_with_uninitialized_sending_chain_without_remote_ratchet(
        valid_without_remote_session: &Bytes,
    ) -> Bytes {
        let decoded = wa_core::decode_signal_provider_session_record(valid_without_remote_session)
            .expect("valid provider session decodes");
        assert!(
            decoded.receiving_chain.is_none(),
            "test session should not have a receiving chain"
        );
        assert!(
            decoded.remote_ratchet_key.is_none(),
            "test session should not have a remote ratchet key"
        );
        assert!(
            decoded.message_keys.is_empty(),
            "test session should not include skipped keys"
        );
        assert_ne!(decoded.sending_chain.counter, 0);
        let mut decoded = decoded;
        let sending_key_len = decoded.sending_chain.key.expose().len();
        decoded.sending_chain = wa_core::signal::SignalMessageChainKey {
            key: wa_crypto::SecretBytes::from(vec![0u8; sending_key_len]),
            counter: 0,
        };
        test_encode_provider_session_record_unchecked(&decoded)
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn put_test_bytes(out: &mut BytesMut, value: &[u8]) {
        let len = u16::try_from(value.len()).expect("test field fits session length prefix");
        out.put_u16(len);
        out.extend_from_slice(value);
    }

    /// Mirror of `wa_core::encode_signal_provider_session_record` WITHOUT the
    /// record-validity check. Several tests deliberately construct intentionally
    /// invalid sessions (skipped key without remote ratchet, remote ratchet without
    /// receiving chain) to exercise inbound rejection, so they cannot round-trip
    /// through the validating public encoder. Keeping a faithful copy here (versus
    /// raw byte splicing) means the wire layout — including `previous_counter` and
    /// the trailing `inbound_base_key` section — stays correct by construction.
    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn test_encode_provider_session_record_unchecked(
        record: &wa_core::signal::SignalProviderSessionRecord,
    ) -> Bytes {
        let mut out = BytesMut::with_capacity(180);
        out.put_u8(1); // PROVIDER_SESSION_VERSION
        out.put_u8(2); // PROVIDER_SESSION_RECORD_KIND
        out.put_u32(record.remote_registration_id);
        put_test_bytes(
            &mut out,
            &wa_core::normalize_signal_public_key(&record.remote_identity_key).unwrap(),
        );
        put_test_bytes(&mut out, record.root_key.key.expose());
        out.put_u32(record.sending_chain.counter);
        put_test_bytes(&mut out, record.sending_chain.key.expose());
        put_test_bytes(
            &mut out,
            &wa_crypto::prefixed_signal_public_key(&record.local_ratchet_key_pair.public),
        );
        put_test_bytes(&mut out, record.local_ratchet_key_pair.private.expose());
        out.put_u32(record.previous_counter);
        match &record.receiving_chain {
            Some(chain) => {
                out.put_u8(1);
                out.put_u32(chain.counter);
                put_test_bytes(&mut out, chain.key.expose());
            }
            None => out.put_u8(0),
        }
        match &record.remote_ratchet_key {
            Some(key) => {
                out.put_u8(1);
                put_test_bytes(
                    &mut out,
                    &wa_core::normalize_signal_public_key(key).unwrap(),
                );
            }
            None => out.put_u8(0),
        }
        out.put_u32(u32::try_from(record.message_keys.len()).unwrap());
        for message_key in &record.message_keys {
            put_test_bytes(
                &mut out,
                &wa_core::normalize_signal_public_key(&message_key.ratchet_key).unwrap(),
            );
            out.put_u32(message_key.counter);
            put_test_bytes(&mut out, message_key.message_keys.cipher_key.expose());
            put_test_bytes(&mut out, message_key.message_keys.mac_key.expose());
            put_test_bytes(&mut out, &message_key.message_keys.iv);
        }
        match &record.inbound_base_key {
            Some(key) => {
                out.put_u8(1);
                put_test_bytes(
                    &mut out,
                    &wa_core::normalize_signal_public_key(key).unwrap(),
                );
            }
            None => out.put_u8(0),
        }
        out.freeze()
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn test_signal_local_pre_key(
        key_id: u32,
        key_pair: &wa_crypto::KeyPair,
    ) -> wa_core::SignalLocalPreKey {
        wa_core::SignalLocalPreKey {
            key_id,
            key_pair: key_pair.clone(),
            public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(&key_pair.public)),
        }
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn pad_random_max16_for_test(mut bytes: Bytes, pad_len: u8) -> Bytes {
        assert!((1..=16).contains(&pad_len));
        let mut out = Vec::from(bytes.split_to(bytes.len()).as_ref());
        out.extend(std::iter::repeat_n(pad_len, usize::from(pad_len)));
        Bytes::from(out)
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn pre_key_message_outer_unknown_field(message: &[u8]) -> Bytes {
        let mut unknown = message.to_vec();
        unknown.extend_from_slice(&[0x78, 0x63]);
        // The trailing unknown outer protobuf field is ignored on decode, so the
        // decoded message matches the canonical (no-unknown-field) decoding.
        assert_eq!(
            wa_core::decode_signal_pre_key_whisper_message(&unknown).unwrap(),
            wa_core::decode_signal_pre_key_whisper_message(message).unwrap(),
        );
        Bytes::from(unknown)
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn raw_client_sender_key_record(states: Vec<SenderKeyStateStructure>) -> Bytes {
        SenderKeyRecordStructure {
            sender_key_states: states,
        }
        .encode_to_vec()
        .into()
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn raw_client_sender_key_state(
        key_id: u32,
        chain_iteration: u32,
        chain_key_fill: u8,
        signing_public_key: Bytes,
        signing_private_key: Option<Bytes>,
        message_keys: &[(u32, u8)],
    ) -> SenderKeyStateStructure {
        SenderKeyStateStructure {
            sender_key_id: Some(key_id),
            sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                iteration: Some(chain_iteration),
                seed: Some(Bytes::from(vec![chain_key_fill; 32])),
            }),
            sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                public: Some(signing_public_key),
                private: signing_private_key,
            }),
            sender_message_keys: message_keys
                .iter()
                .map(
                    |(iteration, seed_fill)| sender_key_state_structure::SenderMessageKey {
                        iteration: Some(*iteration),
                        seed: Some(Bytes::from(vec![*seed_fill; 32])),
                    },
                )
                .collect(),
        }
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn test_participant_enc_node<'a>(message_node: &'a BinaryNode, jid: &str) -> &'a BinaryNode {
        let participants = test_child(message_node, "participants");
        let to_node = test_children(participants, "to")
            .into_iter()
            .find(|node| node.attrs.get("jid").is_some_and(|value| value == jid))
            .unwrap_or_else(|| panic!("missing relay participant {jid}"));
        test_child(to_node, "enc")
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn assert_signal_placeholder_resend_request(
        message_node: &BinaryNode,
        recipient_jid: &str,
        remote_credentials: &AuthCredentials,
        remote_one_time_pre_key: &wa_crypto::KeyPair,
        remote_one_time_pre_key_id: u32,
        expected_destination_jid: &str,
        expected_key: &MessageKey,
    ) {
        let enc = test_participant_enc_node(message_node, recipient_jid);
        assert_eq!(enc.attrs["type"], "pkmsg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
        assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));
        assert_eq!(
            pre_key_message.signed_pre_key_id,
            remote_credentials.signed_pre_key.key_id
        );

        let remote_material = test_signal_local_key_material(remote_credentials);
        let remote_pre_key =
            test_signal_local_pre_key(remote_one_time_pre_key_id, remote_one_time_pre_key);
        let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
            &remote_material,
            Some(&remote_pre_key),
            &ciphertext,
        )
        .unwrap();
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        let device_sent = decoded.device_sent_message.unwrap();
        assert_eq!(
            device_sent.destination_jid.as_deref(),
            Some(expected_destination_jid)
        );
        let protocol = device_sent.message.unwrap().protocol_message.unwrap();
        assert_eq!(
            protocol.r#type,
            Some(
                wa_proto::proto::message::protocol_message::Type::PeerDataOperationRequestMessage
                    as i32,
            )
        );
        let request = protocol.peer_data_operation_request_message.unwrap();
        assert_eq!(
            request.peer_data_operation_request_type,
            Some(
                wa_proto::proto::message::PeerDataOperationRequestType::PlaceholderMessageResend
                    as i32,
            )
        );
        assert_eq!(request.placeholder_message_resend_request.len(), 1);
        assert_eq!(
            request.placeholder_message_resend_request[0]
                .message_key
                .as_ref(),
            Some(expected_key)
        );
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn assert_signal_conversation_relay(
        message_node: &BinaryNode,
        recipient_jid: &str,
        remote_credentials: &AuthCredentials,
        remote_one_time_pre_key: &wa_crypto::KeyPair,
        remote_one_time_pre_key_id: u32,
        expected_text: &str,
    ) {
        let enc = test_participant_enc_node(message_node, recipient_jid);
        assert_eq!(enc.attrs["type"], "pkmsg");
        let ciphertext = test_node_bytes(enc).unwrap();
        let pre_key_message = wa_core::decode_signal_pre_key_whisper_message(&ciphertext).unwrap();
        assert_eq!(pre_key_message.pre_key_id, Some(remote_one_time_pre_key_id));
        assert_eq!(
            pre_key_message.signed_pre_key_id,
            remote_credentials.signed_pre_key.key_id
        );

        let remote_material = test_signal_local_key_material(remote_credentials);
        let remote_pre_key =
            test_signal_local_pre_key(remote_one_time_pre_key_id, remote_one_time_pre_key);
        let decrypted = wa_core::decrypt_signal_inbound_pre_key_session_message(
            &remote_material,
            Some(&remote_pre_key),
            &ciphertext,
        )
        .unwrap();
        let unpadded = wa_core::unpad_random_max16(&decrypted.plaintext).unwrap();
        let decoded = wa_proto::proto::Message::decode(unpadded).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some(expected_text));
    }

    #[cfg(feature = "noise")]
    fn test_signal_session() -> wa_core::SignalSession {
        wa_core::SignalSession {
            registration_id: 0x0102_0304,
            identity_key: Bytes::from(vec![1u8; 32]),
            signed_pre_key: wa_core::SignalSignedPreKey {
                key_id: 7,
                public_key: Bytes::from(vec![2u8; 32]),
                signature: Bytes::from(vec![3u8; 64]),
            },
            pre_key: Some(wa_core::SignalPreKey {
                key_id: 9,
                public_key: Bytes::from(vec![4u8; 32]),
            }),
        }
    }

    struct MockSink {
        tx: mpsc::Sender<Bytes>,
        close_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl FrameSink for MockSink {
        async fn send(&mut self, frame: Bytes) -> CoreResult<()> {
            self.tx
                .send(frame)
                .await
                .map_err(|err| wa_core::CoreError::Task(err.to_string()))
        }

        async fn close(&mut self) -> CoreResult<()> {
            self.close_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct MockStream {
        rx: mpsc::Receiver<InboundFrame>,
    }

    #[async_trait]
    impl FrameStream for MockStream {
        async fn recv(&mut self) -> CoreResult<Option<InboundFrame>> {
            Ok(self.rx.recv().await)
        }
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    fn pair_success_stanza(
        credentials: &AuthCredentials,
        account_key: &wa_crypto::KeyPair,
    ) -> BinaryNode {
        let device_details = AdvDeviceIdentity {
            raw_id: Some(1),
            timestamp: Some(2),
            key_index: Some(9),
            account_type: Some(AdvEncryptionType::E2ee as i32),
            device_type: Some(AdvEncryptionType::E2ee as i32),
        }
        .encode_to_vec();

        let mut account_message = Vec::new();
        account_message.extend_from_slice(&[6, 0]);
        account_message.extend_from_slice(&device_details);
        account_message.extend_from_slice(&credentials.signed_identity_key.public);
        let account_signature =
            sign_x25519(account_key.private.expose(), &account_message).unwrap();

        let account = AdvSignedDeviceIdentity {
            details: Some(Bytes::from(device_details)),
            account_signature_key: Some(Bytes::copy_from_slice(&account_key.public)),
            account_signature: Some(Bytes::copy_from_slice(&account_signature)),
            device_signature: None,
        };
        let account_details = account.encode_to_vec();
        let hmac = hmac_sha256(&account_details, credentials.adv_secret_key.expose()).unwrap();
        let wrapped = AdvSignedDeviceIdentityHmac {
            details: Some(Bytes::from(account_details)),
            hmac: Some(Bytes::copy_from_slice(&hmac)),
            account_type: Some(AdvEncryptionType::E2ee as i32),
        }
        .encode_to_vec();

        BinaryNode::new("iq")
            .with_attr("id", "success-1")
            .with_content(vec![BinaryNode::new("pair-success").with_content(vec![
                BinaryNode::new("device-identity").with_content(Bytes::from(wrapped)),
                BinaryNode::new("platform").with_attr("name", "Chrome"),
                BinaryNode::new("device")
                    .with_attr("jid", "12345:7@s.whatsapp.net")
                    .with_attr("lid", "abc@lid"),
            ])])
    }
}
