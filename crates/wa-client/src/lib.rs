#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "noise")]
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
#[cfg(feature = "noise")]
use wa_binary::{jid_decode, jid_normalized_user};
#[cfg(feature = "noise")]
use wa_core::BinaryNodeContent;
#[cfg(feature = "noise")]
use wa_core::{
    AccountJidKind, AppStatePatchBundle, AppStatePatchState, AuthCredentials, BlocklistAction,
    ChatMutationMessageRange, ChatMutationPatch, ConnectionValidation, ContactSyncAction,
    FrameSink, FrameStream, LabelEditMutation, LidPnMapping, LidPnMappingStore,
    NoiseCertificateVerifier, PairingCodeRequest, PreKeyUpload, PresenceState, QuickReplyMutation,
    RetryReceiptSessionBundle, RetryResendPreparation, RetryResendTarget, RetrySessionAction,
    RetrySessionSnapshot, SignalRepository, SignedPreKey, SignedPreKeyRotation,
    StoreSignalRepository, USyncDeviceJid, USyncLidMapping, ValidatedConnection,
    XEdDsaNoiseCertificateVerifier, account_jid_kind, build_app_state_patch_bundle,
    build_archive_chat_patch, build_blocklist_update_query, build_chat_label_association_patch,
    build_chat_state_node, build_contact_patch, build_delete_chat_patch,
    build_device_identity_node, build_device_query, build_e2e_session_query,
    build_encrypted_media_retry_request_node, build_key_bundle_digest_query,
    build_label_edit_patch, build_lid_mapping_query, build_mark_chat_read_patch,
    build_message_label_association_patch, build_mute_chat_patch, build_pairing_code_request,
    build_pairing_qr_data, build_pin_chat_patch, build_placeholder_resend_request_message,
    build_pre_key_count_query, build_presence_update_node, build_push_name_patch,
    build_quick_reply_patch, build_signed_pre_key_rotation, build_star_message_patch,
    build_tc_token_issue_query, confirm_pre_key_upload, credentials_with_rotated_signed_pre_key,
    current_pre_key_status, encrypt_chat_mutation_patch, extract_device_jids,
    handle_pair_device_challenge, handle_pair_success, is_lid_signal_jid, lid_mappings_from_result,
    lid_user_jid, load_or_init_credentials, mapped_lid_session_jid, mark_tc_token_issued,
    normalize_account_jid, parse_e2e_sessions_node, parse_key_bundle_digest_response,
    parse_pre_key_count_response, parse_pre_key_upload_response,
    parse_signed_pre_key_rotation_response, placeholder_resend_request_from_web_message,
    pn_user_jid, prepare_pre_key_upload, relay_recipients_from_device_jids,
    retry_receipt_session_bundle, save_credentials, store_tc_tokens_from_issue_result,
    validate_connection,
};
use wa_core::{
    AccountMutationKind, AppStateCollection, AppStateCollectionRequest, AppStateQueryKind,
    BinaryNode, Browser, BusinessCatalog, BusinessCatalogCollection, BusinessCatalogQuery,
    BusinessCollectionsQuery, BusinessOrderDetails, BusinessProduct, BusinessProductCreate,
    BusinessProductUpdate, BusinessProfile, BusinessProfileUpdate, ClientConfig,
    CommunityLinkedGroup, CommunityMutationKind, Connection, ConnectionState, CoreResult,
    DirtyBitType, Event, EventHub, GroupInviteV4, GroupJoinApprovalMode, GroupJoinRequest,
    GroupJoinRequestAction, GroupJoinRequestActionResult, GroupMemberAddMode, GroupMetadata,
    GroupMutationKind, GroupParticipantAction, GroupParticipantActionResult, GroupSettingUpdate,
    GroupUpdateEvent, MediaConnectionInfo, MediaRetryPayload, MessageCappingInfo, MessageContent,
    MessageEncryptor, MessageEvent, MessageKey, MessageReceipt, MessageReceiptType, MessageRelay,
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
    build_group_revoke_invite_v4_query, build_group_setting_query, build_group_subject_query,
    build_media_connection_query, build_media_retry_request_node, build_message_capping_info_query,
    build_nack_node, build_newsletter_action_query, build_newsletter_admin_count_query,
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
    parse_community_accept_invite_result, parse_community_invite_code,
    parse_community_invite_v4_result, parse_community_join_request_action_result,
    parse_community_join_requests, parse_community_linked_groups, parse_community_metadata,
    parse_community_mutation_result, parse_community_participant_action_result,
    parse_community_participating_result, parse_dirty_notification_node,
    parse_group_accept_invite_result, parse_group_invite_code, parse_group_invite_v4_result,
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
use wa_store::{AuthStore, KeyNamespace, StoreError};

#[cfg(feature = "noise")]
const DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS: usize = 4;
#[cfg(feature = "noise")]
const MAX_IN_FLIGHT_TC_TOKEN_ISSUANCE: usize = 1024;
#[cfg(feature = "noise")]
const IDENTITY_CHANGE_DEBOUNCE_MS: u64 = 5_000;
#[cfg(feature = "noise")]
const MAX_IDENTITY_CHANGE_DEBOUNCE_JIDS: usize = 1024;

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
    pub relays: Vec<MessageRelay>,
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
        self.message_retry_lock()?
            .plan_retry_resend(receipt, session, now_ms)
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
        let Some(info) = self
            .signal_repository()
            .get_session_info(participant_jid)
            .await?
        else {
            return Ok(RetrySessionSnapshot::missing());
        };
        Ok(RetrySessionSnapshot {
            has_session: true,
            registration_id: Some(info.registration_id),
            base_key: Some(info.base_key),
            signal_address: Some(participant_jid.to_owned()),
        })
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
                    self.signal_repository()
                        .inject_e2e_session(bundle.session.clone())
                        .await?;
                    injected_bundle = true;
                    injected_key_bundle = Some(bundle);
                } else {
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
        let relays = self
            .execute_retry_resends(connection, &preparation, encryptor)
            .await?;
        Ok(RetryResendOutcome {
            receipt: receipt.clone(),
            plan,
            preparation,
            session_action,
            cleared_group_sender_key_memory,
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
        StoreSignalRepository::new(self.store.clone())
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
        parse_message_capping_info_result(&response.node)
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
        let node = self.node_with_tc_token_for_jid(to_jid, node, false).await?;
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
    ) -> CoreResult<bool> {
        let node = build_group_accept_invite_v4_query(invite, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_group_invite_v4_result(&response.node)
    }

    pub async fn accept_group_invite_v4_with_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
    ) -> CoreResult<bool> {
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig::default());
        let accepted = self
            .accept_group_invite_v4_with_buffered_message_events(
                connection,
                invite,
                invite_message_key,
                &mut buffer,
            )
            .await?;
        emit_buffered_events(&self.events, buffer.drain_events());
        Ok(accepted)
    }

    pub async fn accept_group_invite_v4_with_buffered_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<bool> {
        let accepted = self.accept_group_invite_v4(connection, invite).await?;
        if accepted {
            self.buffer_invite_v4_accept_message_events(
                invite,
                invite_message_key,
                "group_invite_v4_accept",
                buffer,
            )
            .await?;
        }
        Ok(accepted)
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
        parse_community_metadata(&response.node)
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
    ) -> CoreResult<bool> {
        let node = build_community_accept_invite_v4_query(invite, self.queries.next_tag())?;
        let response = connection.query_node(node).await?;
        parse_community_invite_v4_result(&response.node)
    }

    pub async fn accept_community_invite_v4_with_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
    ) -> CoreResult<bool> {
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig::default());
        let accepted = self
            .accept_community_invite_v4_with_buffered_message_events(
                connection,
                invite,
                invite_message_key,
                &mut buffer,
            )
            .await?;
        emit_buffered_events(&self.events, buffer.drain_events());
        Ok(accepted)
    }

    pub async fn accept_community_invite_v4_with_buffered_message_events(
        &self,
        connection: &Connection,
        invite: &GroupInviteV4,
        invite_message_key: Option<wa_core::MessageEventKey>,
        buffer: &mut wa_core::EventBuffer,
    ) -> CoreResult<bool> {
        let accepted = self.accept_community_invite_v4(connection, invite).await?;
        if accepted {
            self.buffer_invite_v4_accept_message_events(
                invite,
                invite_message_key,
                "community_invite_v4_accept",
                buffer,
            )
            .await?;
        }
        Ok(accepted)
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
        let mut unique_jids = Vec::<String>::new();
        for jid in jids {
            push_unique_jid(&mut unique_jids, jid.as_ref());
        }

        let mut missing = Vec::new();
        for jid in unique_jids {
            if !force_identity_refresh {
                let validation = repository.validate_session(&jid).await?;
                if validation.exists {
                    continue;
                }
            }
            missing.push(jid);
        }

        if missing.is_empty() {
            return Ok(false);
        }

        let query_jids = self.session_query_jids(&missing).await?;
        let Some(query) =
            build_e2e_session_query(&query_jids, force_identity_refresh, self.queries.next_tag())?
        else {
            return Ok(false);
        };
        let response = connection.query_node(query).await?;
        for injection in parse_e2e_sessions_node(&response.node)? {
            repository.inject_e2e_session(injection).await?;
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
        let my_jid = self.credentials.account_jid.clone().ok_or_else(|| {
            wa_core::CoreError::Protocol("message send requires account JID".to_owned())
        })?;
        let my_lid = self.credentials.account_lid.clone();
        let mut lookup_jids = Vec::with_capacity(3);
        push_unique_jid(&mut lookup_jids, remote_jid);
        push_unique_jid(&mut lookup_jids, &my_jid);
        if let Some(lid) = my_lid.as_deref() {
            push_unique_jid(&mut lookup_jids, lid);
        }

        let devices = self
            .fetch_device_jids(connection, &lookup_jids, false)
            .await?;
        let recipients = relay_recipients_from_device_jids(&devices, &my_jid, my_lid.as_deref())?;
        let recipient_jids = recipients
            .iter()
            .map(|recipient| recipient.jid.as_str())
            .collect::<Vec<_>>();
        self.assert_sessions(connection, recipient_jids, false)
            .await?;
        let options = self.message_relay_options_with_sender(options)?;
        let options = Self::message_relay_options_with_generated_id(options)?;
        let options = Self::message_relay_options_with_reporting(remote_jid, &message, options)?;
        let options = self
            .message_relay_options_with_tc_token(remote_jid, options)
            .await?;
        let issue_plan = self
            .tc_token_issue_after_send_plan(remote_jid, &message, &options)
            .await?;
        let relay = self
            .relay_proto_message_to_devices(
                connection,
                remote_jid,
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
        let keys = keys.into_iter().collect::<Vec<_>>();
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
        let mut relays = Vec::with_capacity(preparation.jobs.len());
        for job in &preparation.jobs {
            let recipients = self.retry_resend_recipients(connection, job).await?;
            let options = self
                .retry_resend_options(&job.remote_jid, &job.message, &job.message_id)
                .await?;
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
                push_unique_jid(&mut lookup_jids, &job.remote_jid);
                push_unique_jid(&mut lookup_jids, &my_jid);
                if let Some(lid) = my_lid.as_deref() {
                    push_unique_jid(&mut lookup_jids, lid);
                }

                let devices = self
                    .fetch_device_jids(connection, &lookup_jids, false)
                    .await?;
                let recipients =
                    relay_recipients_from_device_jids(&devices, &my_jid, my_lid.as_deref())?;
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
    async fn retry_resend_options(
        &self,
        remote_jid: &str,
        message: &ProtoMessage,
        message_id: &str,
    ) -> CoreResult<MessageRelayOptions>
    where
        S: Clone,
    {
        let options = self.message_relay_options_with_sender(
            MessageRelayOptions::new().with_message_id(message_id.to_owned()),
        )?;
        let options = Self::message_relay_options_with_generated_id(options)?;
        let options = Self::message_relay_options_with_reporting(remote_jid, message, options)?;
        self.message_relay_options_with_tc_token(remote_jid, options)
            .await
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

        let mapping = LidPnMappingStore::new(self.store.clone());
        let storage_jid = if let Some(lid_user) = mapping.lid_for_pn(remote_jid).await? {
            format!("{lid_user}@lid")
        } else {
            remote_jid.to_owned()
        };
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
        if has_child_node(&node, "tctoken")
            || (skip_self && self.is_own_token_target(&normalized_target))
            || !wa_core::is_regular_tc_token_jid(&normalized_target)
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
        let events = buffer.drain_events();
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        let _ = self
            .handle_identity_change_notification(connection, node)
            .await?;
        emit_buffered_events(&self.events, events);
        Ok(result)
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
        let events = buffer.drain_events();
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        let _ = self
            .handle_identity_change_notification(connection, node)
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

        let events = buffer.drain_events();
        persist_receive_events(&self.store, &events).await?;
        resolve_placeholder_resend_events_in_batches(&self.placeholder_resend, &events)?;
        self.handle_app_state_sync_key_share_events(
            connection,
            &events,
            false,
            DEFAULT_APP_STATE_KEY_SHARE_RESYNC_ROUNDS,
        )
        .await?;
        let _ = self
            .handle_identity_change_notification(connection, node)
            .await?;
        let media_retry = self.handle_media_retry_events(transfer, &events).await?;
        emit_buffered_events(&self.events, events);

        Ok(IncomingMediaRetryProcessing {
            inbound: result,
            media_retry,
        })
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
                        if let Some(refresh) =
                            refresh_groups_for_dirty_node_with_queries(&connection, &queries, &node)
                                .await?
                        {
                            emit_group_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }
                        if let Some(refresh) = refresh_communities_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_community_dirty_refresh_events(&event_hub, &refresh);
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
                        let events = buffer.drain_events();
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
                        let _ = client
                            .handle_identity_change_notification(&connection, &node)
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
                        if let Some(refresh) =
                            refresh_groups_for_dirty_node_with_queries(&connection, &queries, &node)
                                .await?
                        {
                            emit_group_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }
                        if let Some(refresh) = refresh_communities_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_community_dirty_refresh_events(&event_hub, &refresh);
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
                        let events = buffer.drain_events();
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
                        let _ = client
                            .handle_identity_change_notification(&connection, &node)
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
                        if let Some(refresh) =
                            refresh_groups_for_dirty_node_with_queries(&connection, &queries, &node)
                                .await?
                        {
                            emit_group_dirty_refresh_events(&event_hub, &refresh);
                            continue;
                        }
                        if let Some(refresh) = refresh_communities_for_dirty_node_with_queries(
                            &connection,
                            &queries,
                            &node,
                        )
                        .await?
                        {
                            emit_community_dirty_refresh_events(&event_hub, &refresh);
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
                        let events = buffer.drain_events();
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
                        let _ = client
                            .handle_identity_change_notification(&connection, &node)
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
    async fn handle_media_retry_events<T>(
        &self,
        transfer: &wa_core::MediaTransfer<T>,
        events: &[Event],
    ) -> CoreResult<wa_core::MediaRetryBatchOutcome>
    where
        T: wa_core::MediaTransport,
    {
        let mut merged = wa_core::MediaRetryBatchOutcome::default();
        for event in events {
            let Event::Batch(batch) = event else {
                continue;
            };
            let outcome = self.handle_media_retry_batch(transfer, batch).await?;
            merged.downloads.extend(outcome.downloads);
            merged.errors.extend(outcome.errors);
            merged.ignored_without_pending += outcome.ignored_without_pending;
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
            let query_jid = if is_lid_signal_jid(jid)? {
                jid.clone()
            } else if let Some(lid_user) = mappings.lid_for_pn(jid).await? {
                mapped_lid_session_jid(jid, &lid_user)?
            } else {
                jid.clone()
            };
            push_unique_jid(&mut out, &query_jid);
        }
        Ok(out)
    }

    #[cfg(feature = "noise")]
    async fn retry_session_jids_for_participant(
        &self,
        participant_jid: &str,
    ) -> CoreResult<Vec<String>>
    where
        S: Clone,
    {
        let mut jids = vec![participant_jid.to_owned()];
        for query_jid in self
            .session_query_jids(&[participant_jid.to_owned()])
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
    {
        return Ok(());
    }

    let chat_updates = batch.chats_update.clone();
    let chat_deletes = batch.chats_delete.clone();
    let contact_updates = batch.contacts_update.clone();
    let contact_deletes = batch.contacts_delete.clone();
    let group_updates = batch.groups_update.clone();

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
    {
        return Ok(());
    }

    let receipts = batch.receipts_update.clone();
    let reactions = batch.reactions_update.clone();
    let calls = batch.calls_update.clone();

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
            }

            Ok(())
        })
        .await?;
    Ok(())
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
async fn persist_receive_events<S>(store: &S, events: &[Event]) -> CoreResult<()>
where
    S: AuthStore + Clone,
{
    persist_lid_mapping_events(store, events).await?;
    for event in events {
        match event {
            Event::Batch(batch) => {
                persist_message_event_batch(store, batch).await?;
                persist_state_event_batch(store, batch).await?;
                persist_interaction_event_batch(store, batch).await?;
                persist_utility_event_batch(store, batch).await?;
                persist_media_retry_event_batch(store, batch).await?;
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
fn merge_persisted_group_event(
    group: &mut wa_core::GroupUpdateEvent,
    update: wa_core::GroupUpdateEvent,
) {
    for (key, value) in update.fields {
        group.fields.insert(key, value);
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

fn encode_store_record(value: CoreResult<Vec<u8>>) -> wa_store::StoreResult<Vec<u8>> {
    value.map_err(store_invalid_data)
}

fn decode_store_record<T>(value: CoreResult<T>) -> wa_store::StoreResult<T> {
    value.map_err(store_invalid_data)
}

fn store_invalid_data(error: wa_core::CoreError) -> StoreError {
    StoreError::InvalidData(error.to_string())
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
    let node = build_group_participating_query(queries.next_tag());
    let response = connection.query_node(node).await?;
    let groups = parse_group_participating_result(&response.node)?;
    let clean =
        build_clean_dirty_bits_node(DirtyBitType::Groups, from_timestamp, queries.next_tag())?;
    connection.send_node(&clean).await?;
    Ok(GroupDirtyRefresh { groups, clean })
}

async fn refresh_groups_for_dirty_node_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    node: &BinaryNode,
) -> CoreResult<Option<GroupDirtyRefresh>> {
    let Some(dirty) = parse_dirty_notification_node(node)? else {
        return Ok(None);
    };
    if dirty.dirty_type != "groups" {
        return Ok(None);
    }
    Ok(Some(
        refresh_dirty_groups_with_queries(connection, queries, dirty.timestamp).await?,
    ))
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
    if let Some(size) = metadata.size {
        event = event.with_field("size", size.to_string());
    }
    if let Some(duration) = metadata.ephemeral_duration {
        event = event.with_field("ephemeral_duration", duration.to_string());
    }
    event
}

async fn refresh_dirty_communities_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    from_timestamp: Option<u64>,
) -> CoreResult<CommunityDirtyRefresh> {
    let node = build_community_participating_query(queries.next_tag());
    let response = connection.query_node(node).await?;
    let communities = parse_community_participating_result(&response.node)?;
    let clean =
        build_clean_dirty_bits_node(DirtyBitType::Groups, from_timestamp, queries.next_tag())?;
    connection.send_node(&clean).await?;
    Ok(CommunityDirtyRefresh { communities, clean })
}

async fn refresh_communities_for_dirty_node_with_queries(
    connection: &Connection,
    queries: &QueryManager,
    node: &BinaryNode,
) -> CoreResult<Option<CommunityDirtyRefresh>> {
    let Some(dirty) = parse_dirty_notification_node(node)? else {
        return Ok(None);
    };
    if dirty.dirty_type != "communities" {
        return Ok(None);
    }
    Ok(Some(
        refresh_dirty_communities_with_queries(connection, queries, dirty.timestamp).await?,
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
    if let Some(size) = metadata.size {
        event = event.with_field("size", size.to_string());
    }
    event
}

#[cfg(feature = "noise")]
fn push_unique_jid(jids: &mut Vec<String>, jid: &str) {
    if !jids.iter().any(|existing| existing == jid) {
        jids.push(jid.to_owned());
    }
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
fn parse_retry_receipt_with_bundle(node: &BinaryNode) -> CoreResult<Option<ParsedRetryReceipt>> {
    let Some(receipt) = wa_core::parse_retry_receipt(node)? else {
        return Ok(None);
    };
    let key_bundle = retry_receipt_session_bundle(node, receipt.requester_jid()?)?;
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
        })
    }
}

pub mod prelude {
    #[cfg(feature = "noise")]
    pub use super::{
        AppStateMutationUpload, AppStateSyncRecoveryOptions, IdentityChangeOutcome,
        IncomingMediaRetryProcessing, IncomingPlaceholderResendProcessing, IncomingProcessor,
        IncomingRetryResendProcessing, MessageLabelTarget, PlaceholderResendCleanup,
        PostAuthMaintenance, RetryResendOutcome, RetrySessionActionOutcome,
        TcTokenPruneMaintenance,
    };
    pub use super::{Client, ClientBuilder, CommunityDirtyRefresh, GroupDirtyRefresh};
    pub use wa_core::{
        ACK_ERROR_ACCOUNT_RESTRICTED, ACK_ERROR_SMAX_INVALID, APP_STATE_HASH_LEN, AccountJidKind,
        AccountMutationKind, AddressingContext, AddressingMode, AlbumContent, AppStateCollection,
        AppStateCollectionRequest, AppStatePatchOperation, AppStateQueryKind,
        AppStateSyncCollection, AppStateSyncResponse, AudioContent, BinaryNode, BinaryNodeContent,
        BlocklistAction, Browser, ButtonReplyContent, CatalogSnapshotContent, ChatEvent,
        ChatMutationMessageRange, ChatMutationMessageRef, ChatMutationPatch, ClientConfig,
        Connection, ConnectionState, ContactContent, ContactEvent, ContactSyncAction,
        ContactsContent, DEFAULT_BASE_KEY_CAPACITY, DEFAULT_BASE_KEY_TTL_MS,
        DEFAULT_MAX_HISTORY_CHATS, DEFAULT_MAX_HISTORY_CONTACTS,
        DEFAULT_MAX_HISTORY_INFLATED_BYTES, DEFAULT_MAX_HISTORY_MESSAGES,
        DEFAULT_MAX_MESSAGE_RETRY_COUNT, DEFAULT_MEDIA_HOST, DEFAULT_MEDIA_ORIGIN,
        DEFAULT_PHONE_REQUEST_DELAY_MS, DEFAULT_RECENT_MESSAGE_CAPACITY,
        DEFAULT_RECENT_MESSAGE_TTL_MS, DEFAULT_RETRY_COUNTER_TTL_MS,
        DEFAULT_SESSION_RECREATE_TIMEOUT_MS, DecodedInboundMessage, DecodedInboundPayload,
        DeleteContent, DirtyBitType, DirtyNotification, DisappearingModeContent, DocumentContent,
        EditContent, Event, EventBatch, EventBuffer, EventBufferConfig, EventContent, EventHub,
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
        PlaceholderUnavailableMessage, PollContent, PresenceState, PrivacyCategory,
        PrivacySettings, PrivacyValue, ProcessedHistorySync, ProductContent,
        ProductSnapshotContent, ProfilePictureType, ProtoMessage, QueryManager, QuickReplyEvent,
        QuickReplyMutation, QuotedMessage, ReactionContent, ReactionEvent, ReceiptEvent,
        RecentMessage, RegistrationPayloadKeys, RequestPhoneNumberContent, RetryReason,
        RetryReceipt, RetryReceiptPlan, RetryReceiptRetry, RetryResendJob, RetryResendPreparation,
        RetryResendTarget, RetrySessionAction, RetrySessionSnapshot, RetryStatistics,
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
        build_chat_label_association_patch, build_chat_state_node, build_clean_dirty_bits_node,
        build_contact_message, build_contact_patch, build_contacts_message,
        build_default_disappearing_mode_query, build_delete_chat_patch, build_delete_message,
        build_device_query, build_device_sent_message, build_direct_message_relay,
        build_disappearing_mode_message, build_disappearing_mode_query, build_document_message,
        build_edit_message, build_event_message, build_group_accept_invite_query,
        build_group_accept_invite_v4_query, build_group_create_query,
        build_group_description_query, build_group_ephemeral_query, build_group_invite_code_query,
        build_group_invite_info_query, build_group_invite_message,
        build_group_join_approval_mode_query, build_group_join_request_action_query,
        build_group_join_request_list_query, build_group_leave_query,
        build_group_member_add_mode_query, build_group_metadata_query,
        build_group_participants_query, build_group_participating_query,
        build_group_revoke_invite_query, build_group_revoke_invite_v4_query,
        build_group_setting_query, build_group_subject_query, build_image_message,
        build_label_edit_patch, build_lid_mapping_query, build_limit_sharing_message,
        build_list_reply_message, build_live_location_message, build_location_message,
        build_login_payload, build_mark_chat_read_patch, build_media_connection_query,
        build_media_retry_request_node, build_message_key, build_message_label_association_patch,
        build_mute_chat_patch, build_nack_node, build_newsletter_action_query,
        build_newsletter_admin_count_query, build_newsletter_change_owner_query,
        build_newsletter_create_query, build_newsletter_demote_query,
        build_newsletter_live_updates_query, build_newsletter_message_updates_query,
        build_newsletter_metadata_query, build_newsletter_metadata_update_query,
        build_newsletter_reaction_node, build_newsletter_subscribers_query,
        build_on_whatsapp_query, build_pin_chat_patch, build_pin_message,
        build_placeholder_resend_request_message, build_poll_message,
        build_presence_subscribe_node, build_presence_update_node, build_privacy_settings_query,
        build_privacy_update_query, build_product_message, build_profile_picture_remove_query,
        build_profile_picture_update_query, build_profile_picture_url_query,
        build_profile_status_update_query, build_ptv_message, build_push_name_patch,
        build_quick_reply_patch, build_reaction_message, build_receipt_node,
        build_registration_payload, build_request_phone_number_message,
        build_share_phone_number_message, build_star_message_patch, build_status_query,
        build_sticker_message, build_sync_action_data, build_template_button_reply_message,
        build_text_message, build_video_message, build_view_once_message,
        decode_compressed_history_sync, decode_history_sync_bytes, decode_inbound_binary_node,
        decode_inbound_message, decode_inbound_message_info, decode_inline_history_sync,
        disappearing_modes_from_result, dispatch_binary_node, encode_app_state_patch,
        encode_message, encode_sync_action_data, event_batch_from_group_notification_node,
        extract_addressing_context, extract_device_jids, generate_message_id,
        generate_message_id_v2, generate_message_id_v2_now, generate_participant_hash_v2,
        group_update_event_from_notification_node,
        lid_mapping_events_from_newsletter_notification_node, lid_mappings_from_result,
        lid_user_jid, media_download_url, media_url_from_direct_path, message_event_from_decoded,
        message_event_from_placeholder_unavailable, message_event_key_from_proto_key,
        message_info_fields, message_stanza_type, message_updates_from_ack,
        newsletter_mex_update_events_from_notification_node,
        newsletter_update_events_from_notification_node, normalize_account_jid,
        on_whatsapp_from_result, parse_account_mutation_result, parse_app_state_query_result,
        parse_app_state_sync_response, parse_blocklist, parse_dirty_notification_node,
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
        pn_user_jid, process_history_sync, process_inbound_node, push_decoded_message_to_buffer,
        receipt_events_from_inbound, relay_recipients_from_device_jids, response_tag,
        statuses_from_result, unpad_random_max16, verify_media_ciphertext_hash,
        verify_media_plaintext_hash,
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
        LidPnMappingStore, MIN_PRE_KEY_COUNT, MediaKind, MediaRetryApplication,
        MediaRetryBatchError, MediaRetryBatchOutcome, MediaRetryCoordinator,
        MediaRetryCoordinatorConfig, MediaRetryDownload, MediaRetryResult, MediaTransfer,
        MediaTransferConfig, MediaTransport, MediaUploadCache, MediaUploadCacheKey,
        MediaUploadRequest, MemoryMediaUploadCache, MemoryMediaUploadCacheConfig, NoiseFrameSink,
        NoiseFrameStream, PairDeviceChallenge, PairSuccess, PairingCodeRequest, PairingKeyMaterial,
        PendingMediaRetry, PreKeyUpload, SERVER_JID, SessionInjection, SharedNoiseHandshake,
        SignalAddress, SignalCiphertext, SignalCiphertextType, SignalCryptoProvider,
        SignalDecryptionRequest, SignalEncryptionRequest, SignalMessageCodec, SignalPreKey,
        SignalRepository, SignalSenderKeyDistribution, SignalSession, SignalSessionInfo,
        SignalSessionMigration, SignalSessionValidation, SignalSignedPreKey, SignedPreKey,
        SignedPreKeyRotation, StoreSignalRepository, UploadedMediaUpload, ValidatedConnection,
        ValidationPayload, XEdDsaNoiseCertificateVerifier, app_state_patch_key_id,
        app_state_sync_key_share_from_message, app_state_sync_key_share_from_message_event,
        app_state_sync_key_store_id, apply_app_state_sync_response_to_store,
        apply_app_state_sync_response_with_store_keys, apply_decoded_app_state_patch_to_store,
        apply_decoded_app_state_snapshot_to_store, apply_media_retry_event,
        build_app_state_patch_bundle, build_e2e_session_query,
        build_encrypted_media_retry_request_node, build_key_bundle_digest_query,
        build_pairing_code_request, build_pairing_code_request_with_material,
        build_pairing_qr_data, build_pre_key_count_query, build_signed_pre_key_rotation,
        bytes_to_crockford, companion_platform_display, companion_platform_id,
        confirm_pre_key_upload, create_initial_credentials, create_signed_pre_key,
        credentials_with_rotated_signed_pre_key, current_pre_key_status, decode_app_state_patch,
        decode_app_state_snapshot, decrypt_and_verify_media_bytes,
        delete_app_state_blocked_collection, download_and_decode_app_state_snapshot,
        download_and_process_history_sync, download_app_state_external_blob,
        download_app_state_external_mutations, download_app_state_external_snapshot,
        download_history_sync, download_history_sync_bytes, encrypt_chat_mutation_patch,
        encrypt_chat_mutation_patch_with_iv, event_batch_from_decoded_app_state_mutations,
        event_batch_from_decoded_app_state_patch, event_batch_from_decoded_app_state_snapshot,
        generate_registration_id, handle_pair_device_challenge, handle_pair_success,
        has_key_bundle_digest, is_lid_signal_jid, load_app_state_blocked_collection,
        load_app_state_blocked_collections_for_keys, load_app_state_patch_state,
        load_app_state_sync_key_data, load_credentials, load_or_init_credentials,
        mapped_lid_session_jid, normalize_signal_public_key, parse_e2e_sessions_node,
        parse_key_bundle_digest_response, parse_pre_key_count_response,
        parse_pre_key_upload_response, parse_signed_pre_key_rotation_response,
        prepare_pre_key_upload, save_app_state_blocked_collection, save_app_state_patch_state,
        save_app_state_sync_key_data, save_app_state_sync_key_share, save_credentials,
        shared_noise_handshake, signal_protocol_address,
        uploaded_media_from_app_state_external_blob, uploaded_media_from_encrypted,
        uploaded_media_from_history_sync_notification, validate_connection,
        wrap_pairing_ephemeral_public_key,
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
        parse_community_invite_v4_result, parse_community_join_request_action_result,
        parse_community_join_requests, parse_community_linked_groups, parse_community_metadata,
        parse_community_mutation_result, parse_community_participant_action_result,
        parse_community_participating_result,
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
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use flate2::{Compression, write::ZlibEncoder};
    use prost::Message;
    use std::collections::BTreeMap;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use wa_binary::encode_binary_node;
    use wa_core::{InboundFrame, ValidationPayload, decode_inbound_binary_node};
    use wa_crypto::{generate_key_pair, hmac_sha256, sign_x25519};
    use wa_proto::proto::{
        AdvDeviceIdentity, AdvEncryptionType, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac,
    };
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

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn connect_wires_query_manager_timeout() {
        let config = ClientConfig {
            default_query_timeout: Some(Duration::from_millis(1)),
            ..ClientConfig::default()
        };

        let client = Client::builder(wa_store::MemoryAuthStore::new())
            .config(config)
            .connect()
            .await
            .unwrap();

        let waiter = client.query_manager().register("timeout").unwrap();
        assert!(matches!(
            waiter.wait().await,
            Err(wa_core::CoreError::TimedOut)
        ));
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn connect_initializes_credentials_once() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();

        assert_eq!(client.credentials(), &stored);

        let second = Client::builder(store.clone()).connect().await.unwrap();
        assert_eq!(second.credentials(), &stored);
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn connection_validation_restores_registered_session() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("12345:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();

        let client = Client::builder(store.clone()).connect().await.unwrap();
        let validation = client.connection_validation().unwrap();

        assert!(matches!(
            validation.payload,
            ValidationPayload::Login { user_jid } if user_jid == "12345:7@s.whatsapp.net"
        ));
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn connection_validation_rejects_registered_session_without_account_jid() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();

        let client = Client::builder(store.clone()).connect().await.unwrap();

        assert!(client.connection_validation().is_err());
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn exposes_store_backed_signal_repository() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let repository = client.signal_repository();

        let validation =
            wa_core::SignalRepository::validate_session(&repository, "123@s.whatsapp.net")
                .await
                .unwrap();
        assert!(!validation.exists);
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn execute_usync_query_sends_node_and_parses_result() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let query = USyncQuery::new()
            .with_contact_protocol()
            .with_user(wa_core::USyncUser::new().with_phone("+123"));
        let query_fut = client.execute_usync_query(&connection, &query);
        tokio::pin!(query_fut);

        let sent_frame = tokio::select! {
            result = &mut query_fut => panic!("USync query completed before mock response: {result:?}"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(sent.attrs["xmlns"], "usync");
        let tag = sent.attrs["id"].clone();
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", tag)
                        .with_attr("type", "result")
                        .with_content(vec![BinaryNode::new("usync").with_content(vec![
                            BinaryNode::new("list").with_content(vec![
                                BinaryNode::new("user")
                                    .with_attr("jid", "123@s.whatsapp.net")
                                    .with_content(vec![
                                        BinaryNode::new("contact").with_attr("type", "in")
                                    ]),
                            ]),
                        ])]),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let result = query_fut.await.unwrap().unwrap();
        assert_eq!(result.list[0].id, "123@s.whatsapp.net");
        assert_eq!(result.list[0].contact, Some(true));

        let failed_query_fut = client.execute_usync_query(&connection, &query);
        tokio::pin!(failed_query_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                error_result_for(&node, "403", "not allowed")
            },
            &mut failed_query_fut,
        )
        .await;
        let err = failed_query_fut.await.unwrap_err();
        assert!(
            err.to_string()
                .contains("USync query failed (403): not allowed")
        );
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn on_whatsapp_sends_contact_query_and_maps_results() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let lookup_fut = client.on_whatsapp(&connection, ["+1 234-567"]);
        tokio::pin!(lookup_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                                BinaryNode::new("user")
                                    .with_attr("jid", "1234567@s.whatsapp.net")
                                    .with_content(vec![
                                        BinaryNode::new("contact").with_attr("type", "in"),
                                    ]),
                            ]),
                    ])])
            },
            &mut lookup_fut,
        )
        .await;

        assert_eq!(
            lookup_fut.await.unwrap(),
            vec![OnWhatsAppResult {
                jid: "1234567@s.whatsapp.net".to_owned(),
                exists: true,
            }]
        );
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn send_text_to_devices_writes_relay_stanza() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();

        let relay = client
            .send_text_to_devices(
                &connection,
                "123@s.whatsapp.net",
                "hello",
                &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
                &encryptor,
                MessageRelayOptions::new().with_message_id("msg-1"),
            )
            .await
            .unwrap();

        assert_eq!(relay.message_id, "msg-1");
        let sent_frame = sink_rx.recv().await.unwrap();
        let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(sent.tag, "message");
        assert_eq!(sent.attrs["id"], "msg-1");
        assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(sent.attrs["type"], "text");
        let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
            panic!("message stanza has no children");
        };
        assert_eq!(content[0].tag, "participants");

        let calls = encryptor.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "123:1@s.whatsapp.net");
        let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
        assert_eq!(
            plaintext
                .extended_text_message
                .as_ref()
                .unwrap()
                .text
                .as_deref(),
            Some("hello")
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn send_text_to_devices_adds_stored_device_identity_for_pre_key_ciphertext() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        credentials.signed_device_identity = Some(Bytes::from_static(b"stored-identity"));
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::pre_key();

        let relay = client
            .send_text_to_devices(
                &connection,
                "123@s.whatsapp.net",
                "hello",
                &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
                &encryptor,
                MessageRelayOptions::new().with_message_id("msg-1"),
            )
            .await
            .unwrap();

        assert!(relay.should_include_device_identity);
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
            panic!("message stanza has no children");
        };
        assert_eq!(content.len(), 2);
        assert_eq!(content[1].tag, "device-identity");
        assert_eq!(
            content[1].content,
            Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
                b"stored-identity"
            )))
        );
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn relay_reaction_to_devices_writes_reaction_stanza() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        let key =
            wa_core::build_message_key("123@s.whatsapp.net", false, "target-1", None).unwrap();

        let relay = client
            .relay_message_to_devices(
                &connection,
                "123@s.whatsapp.net",
                MessageContent::reaction(wa_core::ReactionContent::new(key.clone(), "")),
                &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
                &encryptor,
                MessageRelayOptions::new().with_message_id("msg-1"),
            )
            .await
            .unwrap();

        assert_eq!(relay.message_id, "msg-1");
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.tag, "message");
        assert_eq!(sent.attrs["type"], "reaction");

        let calls = encryptor.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        let plaintext = wa_proto::proto::Message::decode(calls[0].1.clone()).unwrap();
        let reaction = plaintext.reaction_message.unwrap();
        assert_eq!(reaction.key.unwrap(), key);
        assert_eq!(reaction.text.as_deref(), Some(""));
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn send_text_discovers_devices_and_wraps_own_devices() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("ownlid@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new(
                "123@s.whatsapp.net",
                Bytes::from_static(b"trusted-contact-token"),
            )
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
        )
        .await
        .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        let send_fut = client.send_text(
            &connection,
            "123@s.whatsapp.net",
            "hello",
            &encryptor,
            MessageRelayOptions::new().with_message_id("msg-1"),
        );
        tokio::pin!(send_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "devices");
                assert_eq!(
                    usync_query_user_jids(&node),
                    vec![
                        "123@s.whatsapp.net".to_owned(),
                        "999:7@s.whatsapp.net".to_owned(),
                        "ownlid@lid".to_owned(),
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
                                        BinaryNode::new("device")
                                            .with_attr("id", "1")
                                            .with_attr("key-index", "10"),
                                    ])],
                                )]),
                            BinaryNode::new("user")
                                .with_attr("jid", "999@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "0"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "7")
                                            .with_attr("key-index", "11"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "8")
                                            .with_attr("key-index", "12"),
                                    ])],
                                )]),
                            BinaryNode::new("user")
                                .with_attr("jid", "ownlid@lid")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device")
                                            .with_attr("id", "7")
                                            .with_attr("key-index", "13"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "9")
                                            .with_attr("key-index", "14")
                                            .with_attr("is_hosted", "true"),
                                    ])],
                                )]),
                        ]),
                    ])])
            },
            &mut send_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(node.attrs["type"], "get");
                assert_eq!(node.attrs["to"], wa_core::SERVER_JID);
                assert_eq!(
                    encrypt_key_query_user_attrs(&node)
                        .into_iter()
                        .map(|(jid, _)| jid)
                        .collect::<Vec<_>>(),
                    vec![
                        "123@s.whatsapp.net".to_owned(),
                        "123:1@s.whatsapp.net".to_owned(),
                        "999@s.whatsapp.net".to_owned(),
                        "999:8@s.whatsapp.net".to_owned(),
                        "ownlid:9@hosted.lid".to_owned(),
                    ]
                );
                session_response_for_query(&node)
            },
            &mut send_fut,
        )
        .await;

        let relay = send_fut.await.unwrap();
        assert_eq!(relay.message_id, "msg-1");
        assert_eq!(relay.recipient_count, 5);

        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.tag, "message");
        assert_eq!(sent.attrs["id"], "msg-1");
        assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
        let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
            panic!("message should contain child nodes");
        };
        assert!(content.iter().any(|node| {
            node.tag == "tctoken"
                && node.content
                    == Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
                        b"trusted-contact-token",
                    )))
        }));

        let calls = encryptor.calls.lock().unwrap().clone();
        assert_eq!(
            calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
            vec![
                "123@s.whatsapp.net",
                "123:1@s.whatsapp.net",
                "999@s.whatsapp.net",
                "999:8@s.whatsapp.net",
                "ownlid:9@hosted.lid",
            ]
        );
        for call in calls.iter().take(2) {
            let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
            assert_eq!(
                plaintext
                    .extended_text_message
                    .as_ref()
                    .unwrap()
                    .text
                    .as_deref(),
                Some("hello")
            );
            assert!(plaintext.device_sent_message.is_none());
        }
        for call in calls.iter().skip(2) {
            let plaintext = wa_proto::proto::Message::decode(call.1.clone()).unwrap();
            let device_sent = plaintext.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("123@s.whatsapp.net")
            );
            assert_eq!(
                device_sent
                    .message
                    .unwrap()
                    .extended_text_message
                    .unwrap()
                    .text
                    .as_deref(),
                Some("hello")
            );
        }
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn send_text_schedules_post_send_tc_token_issuance() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        let send_fut = client.send_text(
            &connection,
            "123@s.whatsapp.net",
            "hello",
            &encryptor,
            MessageRelayOptions::new().with_message_id("msg-tc-issue"),
        );
        tokio::pin!(send_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "devices");
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
            &mut send_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                session_response_for_query(&node)
            },
            &mut send_fut,
        )
        .await;

        let relay = send_fut.await.unwrap();
        assert_eq!(relay.message_id, "msg-tc-issue");

        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.tag, "message");
        assert_eq!(sent.attrs["id"], "msg-tc-issue");

        let privacy = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(privacy.attrs["xmlns"], "privacy");
        let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &privacy.content else {
            panic!("privacy query should have child nodes");
        };
        let tokens = iq_children
            .iter()
            .find(|child| child.tag == "tokens")
            .unwrap();
        let Some(wa_binary::BinaryNodeContent::Nodes(token_children)) = &tokens.content else {
            panic!("tokens node should have token children");
        };
        assert_eq!(token_children.len(), 1);
        assert_eq!(token_children[0].attrs["jid"], "123@s.whatsapp.net");
        assert_eq!(token_children[0].attrs["type"], "trusted_contact");
        let issue_timestamp = token_children[0].attrs["t"].parse::<u64>().unwrap();
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", privacy.attrs["id"].clone())
                        .with_attr("type", "result")
                        .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                            BinaryNode::new("token")
                                .with_attr("jid", "ignored@s.whatsapp.net")
                                .with_attr("t", (issue_timestamp + 1).to_string())
                                .with_attr("type", "trusted_contact")
                                .with_content(Bytes::from_static(b"auto-peer-token")),
                        ])]),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let mut loaded = None;
        for _ in 0..20 {
            loaded = wa_core::load_tc_token(&store, "123@s.whatsapp.net")
                .await
                .unwrap();
            if loaded
                .as_ref()
                .and_then(|record| record.sender_timestamp_seconds)
                == Some(issue_timestamp)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let loaded = loaded.unwrap();
        assert_eq!(loaded.token, Bytes::from_static(b"auto-peer-token"));
        assert_eq!(loaded.timestamp_seconds, Some(issue_timestamp + 1));
        assert_eq!(loaded.sender_timestamp_seconds, Some(issue_timestamp));
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn issue_tc_token_queries_privacy_and_marks_sender_timestamp() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        wa_core::LidPnMappingStore::new(store.clone())
            .store_mappings(vec![wa_core::LidPnMapping {
                pn: "123@s.whatsapp.net".to_owned(),
                lid: "abc@lid".to_owned(),
            }])
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let issue_fut = client.issue_tc_token_with_options(
            &connection,
            "123@s.whatsapp.net",
            true,
            1_700_000_000,
        );
        tokio::pin!(issue_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "privacy");
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(node.attrs["to"], wa_core::SERVER_JID);
                let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &node.content else {
                    panic!("privacy query should have child nodes");
                };
                let tokens = iq_children
                    .iter()
                    .find(|child| child.tag == "tokens")
                    .unwrap();
                let Some(wa_binary::BinaryNodeContent::Nodes(token_children)) = &tokens.content
                else {
                    panic!("tokens node should have token children");
                };
                assert_eq!(token_children.len(), 1);
                assert_eq!(token_children[0].attrs["jid"], "abc@lid");
                assert_eq!(token_children[0].attrs["t"], "1700000000");
                assert_eq!(token_children[0].attrs["type"], "trusted_contact");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "ignored@s.whatsapp.net")
                            .with_attr("t", "1700000001")
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"peer-token")),
                    ])])
            },
            &mut issue_fut,
        )
        .await;

        let outcome = issue_fut.await.unwrap().unwrap();
        assert_eq!(outcome.storage_jid, "abc@lid");
        assert_eq!(outcome.issue_jid, "abc@lid");
        assert_eq!(outcome.timestamp_seconds, 1_700_000_000);
        assert_eq!(outcome.stored_tokens.len(), 1);
        assert_eq!(
            outcome.sender_record.token,
            Bytes::from_static(b"peer-token")
        );
        assert_eq!(
            outcome.sender_record.sender_timestamp_seconds,
            Some(1_700_000_000)
        );
        let loaded = wa_core::load_tc_token(&store, "abc@lid")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.token, Bytes::from_static(b"peer-token"));
        assert_eq!(loaded.timestamp_seconds, Some(1_700_000_001));
        assert_eq!(loaded.sender_timestamp_seconds, Some(1_700_000_000));
        let node = wa_core::load_tc_token_node_for_send(&store, "abc@lid", 1_700_000_002)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.tag, "tctoken");
        assert_eq!(
            node.content,
            Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
                b"peer-token"
            )))
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn prune_expired_tc_tokens_facade_removes_stale_records() {
        let store = wa_store::MemoryAuthStore::new();
        let now = current_unix_timestamp();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("111@s.whatsapp.net", Bytes::from_static(b"valid"))
                .unwrap()
                .with_timestamp_seconds(now),
        )
        .await
        .unwrap();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("222@s.whatsapp.net", Bytes::from_static(b"expired"))
                .unwrap()
                .with_timestamp_seconds(1),
        )
        .await
        .unwrap();

        let client = Client::builder(store.clone()).connect().await.unwrap();
        let outcome = client
            .prune_expired_tc_tokens_with_batch_size(1)
            .await
            .unwrap();
        assert_eq!(outcome.scanned, 2);
        assert_eq!(outcome.retained, 1);
        assert_eq!(outcome.deleted, 1);
        assert!(
            wa_core::load_tc_token(&store, "111@s.whatsapp.net")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            wa_core::load_tc_token(&store, "222@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn tc_token_prune_maintenance_runs_on_open_and_throttles() {
        let store = wa_store::MemoryAuthStore::new();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("111@s.whatsapp.net", Bytes::from_static(b"expired"))
                .unwrap()
                .with_timestamp_seconds(1),
        )
        .await
        .unwrap();

        let client = Client::builder(store.clone()).connect().await.unwrap();
        let mut maintenance = client
            .spawn_tc_token_prune_on_connection_open(Duration::from_secs(60), 1)
            .unwrap();
        let (first_connection, _sink_rx, _stream_tx) =
            mock_connection_with_events(client.events.clone());
        for _ in 0..20 {
            if wa_core::load_tc_token(&store, "111@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            wa_core::load_tc_token(&store, "111@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("222@s.whatsapp.net", Bytes::from_static(b"expired"))
                .unwrap()
                .with_timestamp_seconds(1),
        )
        .await
        .unwrap();
        let (second_connection, _sink_rx, _stream_tx) =
            mock_connection_with_events(client.events.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            wa_core::load_tc_token(&store, "222@s.whatsapp.net")
                .await
                .unwrap()
                .is_some()
        );

        first_connection.close().await.unwrap();
        second_connection.close().await.unwrap();
        maintenance.abort();

        let invalid_interval =
            match client.spawn_tc_token_prune_on_connection_open(Duration::ZERO, 1) {
                Ok(_) => panic!("zero prune interval should be rejected"),
                Err(err) => err,
            };
        assert!(
            invalid_interval
                .to_string()
                .contains("tctoken prune interval must be non-zero")
        );
        let invalid_batch =
            match client.spawn_tc_token_prune_on_connection_open(Duration::from_secs(1), 0) {
                Ok(_) => panic!("zero prune batch should be rejected"),
                Err(err) => err,
            };
        assert!(
            invalid_batch
                .to_string()
                .contains("tctoken prune batch size must be non-zero")
        );
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn high_level_relay_options_add_reporting_token_for_secret_messages() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let message = wa_core::build_poll_message(wa_core::PollContent::new(
            "Lunch?",
            ["Rice", "Noodles"],
            1,
            Bytes::from(vec![9u8; 32]),
        ))
        .unwrap();

        let options = client
            .message_relay_options_with_sender(MessageRelayOptions::new().with_message_id("msg-1"))
            .unwrap();
        let options =
            Client::<wa_store::MemoryAuthStore>::message_relay_options_with_generated_id(options)
                .unwrap();
        let options = Client::<wa_store::MemoryAuthStore>::message_relay_options_with_reporting(
            "123@s.whatsapp.net",
            &message,
            options,
        )
        .unwrap();

        let reporting = options
            .additional_nodes
            .iter()
            .find(|node| node.tag == "reporting")
            .expect("reporting node should be attached");
        let Some(wa_binary::BinaryNodeContent::Nodes(children)) = &reporting.content else {
            panic!("reporting node should contain children");
        };
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "reporting_token");
        assert_eq!(children[0].attrs.get("v").map(String::as_str), Some("2"));
        let Some(wa_binary::BinaryNodeContent::Bytes(token)) = &children[0].content else {
            panic!("reporting token should contain bytes");
        };
        assert_eq!(token.len(), 16);
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn execute_retry_resends_replays_cached_message_to_requesting_device() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let repository = client.signal_repository();
        repository
            .inject_e2e_session(wa_core::SessionInjection {
                jid: "123:1@s.whatsapp.net".to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        let message = wa_proto::proto::Message {
            conversation: Some("cached".to_owned()),
            ..wa_proto::proto::Message::default()
        };

        client
            .relay_proto_message_to_devices(
                &connection,
                "123@s.whatsapp.net",
                message.clone(),
                &[MessageRelayRecipient::new("123:1@s.whatsapp.net")],
                &encryptor,
                MessageRelayOptions::new().with_message_id("m1"),
            )
            .await
            .unwrap();
        let first = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(first.attrs["id"], "m1");

        let receipt = wa_core::RetryReceipt {
            message_ids: vec!["m1".to_owned()],
            from_jid: Some("123:1@s.whatsapp.net".to_owned()),
            to_jid: None,
            participant: None,
            recipient: Some("123@s.whatsapp.net".to_owned()),
            chat_jid: Some("123@s.whatsapp.net".to_owned()),
            retry: wa_core::RetryReceiptRetry {
                count: 1,
                original_stanza_id: None,
                timestamp: None,
                version: None,
                error: None,
            },
            registration_id: None,
            has_key_bundle: false,
        };
        let plan = client
            .plan_retry_resend(
                &receipt,
                wa_core::RetrySessionSnapshot {
                    has_session: true,
                    registration_id: Some(0x0102_0304),
                    base_key: None,
                    signal_address: None,
                },
                current_unix_timestamp_ms(),
            )
            .unwrap();
        assert_eq!(
            plan.resend_target,
            wa_core::RetryResendTarget::Participant {
                jid: "123:1@s.whatsapp.net".to_owned(),
                count: 1,
            }
        );
        let prepared = client
            .prepare_retry_resends(&plan, current_unix_timestamp_ms())
            .unwrap();
        assert!(prepared.is_complete());
        assert_eq!(prepared.jobs.len(), 1);

        let relays = client
            .execute_retry_resends(&connection, &prepared, &encryptor)
            .await
            .unwrap();

        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].message_id, "m1");
        assert_eq!(relays[0].recipient_count, 1);
        let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(resent.attrs["id"], "m1");
        let calls = encryptor.calls.lock().unwrap().clone();
        assert_eq!(
            calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
            vec!["123:1@s.whatsapp.net", "123:1@s.whatsapp.net"]
        );
        for call in calls {
            let decoded = wa_proto::proto::Message::decode(call.1).unwrap();
            assert_eq!(decoded.conversation.as_deref(), Some("cached"));
        }
        let stats = client.message_retry_statistics().unwrap();
        assert_eq!(stats.successful_retries, 1);
        let prepared_after_success = client
            .prepare_retry_resends(&plan, current_unix_timestamp_ms())
            .unwrap();
        assert!(prepared_after_success.jobs.is_empty());
        assert_eq!(prepared_after_success.missing_message_ids, vec!["m1"]);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn process_incoming_node_with_retry_resend_refreshes_session_and_replays_cached_message()
    {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let repository = client.signal_repository();
        repository
            .inject_e2e_session(wa_core::SessionInjection {
                jid: "123:1@s.whatsapp.net".to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        let message = wa_proto::proto::Message {
            conversation: Some("retry me".to_owned()),
            ..wa_proto::proto::Message::default()
        };
        client
            .cache_recent_message_for_retry(
                "123@s.whatsapp.net",
                "retry-live",
                message,
                current_unix_timestamp_ms(),
            )
            .unwrap();
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "retry-live")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("recipient", "123@s.whatsapp.net")
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("retry")
                    .with_attr("count", "2")
                    .with_attr("error", "7"),
                BinaryNode::new("registration")
                    .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
            ]);
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
            max_pending_items: 8,
        });
        let process_fut = client.process_incoming_node_with_retry_resend(
            &connection,
            &receipt,
            &IncomingDecryptor,
            &encryptor,
            &mut buffer,
        );
        tokio::pin!(process_fut);

        let ack_frame = tokio::select! {
            result = &mut process_fut => panic!("retry processing completed before ACK: {result:?}"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "retry-live");
        assert_eq!(ack.attrs["class"], "receipt");
        assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(encrypt_key_query_user_attrs(&node).len(), 1);
                session_response_for_query(&node)
            },
            &mut process_fut,
        )
        .await;

        let outcome = process_fut.await.unwrap();
        assert_eq!(outcome.inbound.action, wa_core::InboundNodeAction::Receipt);
        let retry = outcome.retry_resend.unwrap();
        assert_eq!(retry.receipt.message_ids, vec!["retry-live"]);
        assert_eq!(
            retry.plan.session_action,
            wa_core::RetrySessionAction::DeleteAndRefresh {
                reason: "registration id mismatch: stored 16909060, received 16909061".to_owned(),
            }
        );
        assert_eq!(
            retry.session_action.deleted_sessions,
            vec!["123:1@s.whatsapp.net"]
        );
        assert!(retry.session_action.refreshed_sessions);
        assert!(retry.preparation.is_complete());
        assert_eq!(retry.relays.len(), 1);
        assert_eq!(retry.relays[0].message_id, "retry-live");

        let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(resent.tag, "message");
        assert_eq!(resent.attrs["id"], "retry-live");
        assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
        assert!(
            repository
                .validate_session("123:1@s.whatsapp.net")
                .await
                .unwrap()
                .exists
        );
        assert_eq!(
            client
                .message_retry_statistics()
                .unwrap()
                .successful_retries,
            1
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn process_incoming_node_with_retry_resend_injects_inline_key_bundle() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let repository = client.signal_repository();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        client
            .cache_recent_message_for_retry(
                "123@s.whatsapp.net",
                "retry-bundle",
                wa_proto::proto::Message {
                    conversation: Some("bundle retry".to_owned()),
                    ..wa_proto::proto::Message::default()
                },
                current_unix_timestamp_ms(),
            )
            .unwrap();
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "retry-bundle")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("recipient", "123@s.whatsapp.net")
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("retry").with_attr("count", "1"),
                BinaryNode::new("registration")
                    .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
                BinaryNode::new("keys").with_content(vec![
                    BinaryNode::new("type")
                        .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                    BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                    BinaryNode::new("skey").with_content(vec![
                        BinaryNode::new("id")
                            .with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                        BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                    ]),
                    BinaryNode::new("key").with_content(vec![
                        BinaryNode::new("id")
                            .with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                    ]),
                    BinaryNode::new("device-identity")
                        .with_content(Bytes::from_static(b"retry-device-identity")),
                ]),
            ]);
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
            max_pending_items: 8,
        });
        let outcome = client
            .process_incoming_node_with_retry_resend(
                &connection,
                &receipt,
                &IncomingDecryptor,
                &encryptor,
                &mut buffer,
            )
            .await
            .unwrap();

        let ack_frame = sink_rx.recv().await.unwrap();
        let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
        assert_eq!(ack.attrs["id"], "retry-bundle");
        assert_eq!(ack.attrs["class"], "receipt");

        let resent_frame = sink_rx.recv().await.unwrap();
        let resent = decode_inbound_binary_node(&resent_frame).unwrap().node;
        assert_eq!(resent.tag, "message");
        assert_eq!(resent.attrs["id"], "retry-bundle");
        assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");

        let retry = outcome.retry_resend.unwrap();
        assert_eq!(
            retry.plan.session_action,
            wa_core::RetrySessionAction::InjectBundle
        );
        assert!(retry.session_action.injected_bundle);
        let injected_bundle = retry.session_action.injected_key_bundle.as_ref().unwrap();
        assert_eq!(injected_bundle.session.jid, "123:1@s.whatsapp.net");
        assert_eq!(
            injected_bundle.device_identity.as_deref(),
            Some(&b"retry-device-identity"[..])
        );
        assert!(!retry.session_action.refreshed_sessions);
        assert!(retry.session_action.deleted_sessions.is_empty());
        assert!(
            repository
                .validate_session("123:1@s.whatsapp.net")
                .await
                .unwrap()
                .exists
        );
        assert!(matches!(
            sink_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn process_incoming_node_with_retry_resend_clears_group_sender_key_memory() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        store
            .set(KeyNamespace::SenderKeyMemory, "555@g.us", b"sender-memory")
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        client
            .cache_recent_message_for_retry(
                "555@g.us",
                "group-retry",
                wa_proto::proto::Message {
                    conversation: Some("group retry".to_owned()),
                    ..wa_proto::proto::Message::default()
                },
                current_unix_timestamp_ms(),
            )
            .unwrap();
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "group-retry")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("recipient", "555@g.us")
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("retry").with_attr("count", "1"),
                BinaryNode::new("registration")
                    .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
                BinaryNode::new("keys").with_content(vec![
                    BinaryNode::new("type")
                        .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                    BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                    BinaryNode::new("skey").with_content(vec![
                        BinaryNode::new("id")
                            .with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                        BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                    ]),
                    BinaryNode::new("key").with_content(vec![
                        BinaryNode::new("id")
                            .with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                    ]),
                ]),
            ]);
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
            max_pending_items: 8,
        });

        let outcome = client
            .process_incoming_node_with_retry_resend(
                &connection,
                &receipt,
                &IncomingDecryptor,
                &encryptor,
                &mut buffer,
            )
            .await
            .unwrap();

        assert!(
            outcome
                .retry_resend
                .as_ref()
                .unwrap()
                .plan
                .should_clear_group_sender_key
        );
        assert!(
            outcome
                .retry_resend
                .as_ref()
                .unwrap()
                .cleared_group_sender_key_memory
        );
        assert!(
            store
                .get(KeyNamespace::SenderKeyMemory, "555@g.us")
                .await
                .unwrap()
                .is_none()
        );
        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.attrs["id"], "group-retry");
        assert_eq!(ack.attrs["class"], "receipt");
        let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(resent.tag, "message");
        assert_eq!(resent.attrs["id"], "group-retry");
        assert_eq!(resent.attrs["to"], "555@g.us");
        assert!(matches!(
            sink_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_with_retry_resend_replays_raw_retry_receipt() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let repository = client.signal_repository();
        repository
            .inject_e2e_session(wa_core::SessionInjection {
                jid: "123:1@s.whatsapp.net".to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
        client
            .cache_recent_message_for_retry(
                "123@s.whatsapp.net",
                "retry-spawn",
                wa_proto::proto::Message {
                    conversation: Some("spawn retry".to_owned()),
                    ..wa_proto::proto::Message::default()
                },
                current_unix_timestamp_ms(),
            )
            .unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor_with_retry_resend(
                connection.clone(),
                IncomingDecryptor,
                RelayEncryptor::default(),
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "retry-spawn")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("recipient", "123@s.whatsapp.net")
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("retry")
                    .with_attr("count", "2")
                    .with_attr("error", "7"),
                BinaryNode::new("registration")
                    .with_content(wa_core::encode_big_endian(0x0102_0305, 4).unwrap()),
            ]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "retry-spawn");
        assert_eq!(ack.attrs["class"], "receipt");
        assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");

        let refresh_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(refresh_query.attrs["xmlns"], "encrypt");
        assert_eq!(encrypt_key_query_user_attrs(&refresh_query).len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&session_response_for_query(&refresh_query)).unwrap(),
            ))
            .await
            .unwrap();

        let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(resent.tag, "message");
        assert_eq!(resent.attrs["id"], "retry-spawn");
        assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(
            client
                .message_retry_statistics()
                .unwrap()
                .successful_retries,
            1
        );
        assert!(
            repository
                .validate_session("123:1@s.whatsapp.net")
                .await
                .unwrap()
                .exists
        );
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_with_retry_resend_injects_inline_key_bundle() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let repository = client.signal_repository();
        client
            .cache_recent_message_for_retry(
                "123@s.whatsapp.net",
                "retry-spawn-bundle",
                wa_proto::proto::Message {
                    conversation: Some("spawn bundle retry".to_owned()),
                    ..wa_proto::proto::Message::default()
                },
                current_unix_timestamp_ms(),
            )
            .unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor_with_retry_resend(
                connection.clone(),
                IncomingDecryptor,
                RelayEncryptor::default(),
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "retry-spawn-bundle")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("recipient", "123@s.whatsapp.net")
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("retry").with_attr("count", "1"),
                BinaryNode::new("registration")
                    .with_content(wa_core::encode_big_endian(0x0102_0304, 4).unwrap()),
                BinaryNode::new("keys").with_content(vec![
                    BinaryNode::new("type")
                        .with_content(Bytes::copy_from_slice(&wa_core::KEY_BUNDLE_TYPE)),
                    BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                    BinaryNode::new("skey").with_content(vec![
                        BinaryNode::new("id")
                            .with_content(wa_core::encode_big_endian(7, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                        BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                    ]),
                    BinaryNode::new("key").with_content(vec![
                        BinaryNode::new("id")
                            .with_content(wa_core::encode_big_endian(9, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                    ]),
                ]),
            ]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&receipt).unwrap()))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.attrs["id"], "retry-spawn-bundle");
        assert_eq!(ack.attrs["class"], "receipt");

        let resent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(resent.tag, "message");
        assert_eq!(resent.attrs["id"], "retry-spawn-bundle");
        assert_eq!(resent.attrs["to"], "123@s.whatsapp.net");
        assert!(
            repository
                .validate_session("123:1@s.whatsapp.net")
                .await
                .unwrap()
                .exists
        );
        assert_eq!(
            client
                .message_retry_statistics()
                .unwrap()
                .successful_retries,
            1
        );
        assert!(matches!(
            sink_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn request_placeholder_resend_sends_peer_data_operation_message() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        let missing_key =
            wa_core::build_message_key("123@s.whatsapp.net", false, "missing-1", None).unwrap();
        let request_fut = client.request_placeholder_resend(
            &connection,
            [missing_key.clone()],
            &encryptor,
            MessageRelayOptions::new().with_message_id("pdo-1"),
        );
        tokio::pin!(request_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "devices");
                assert_eq!(
                    usync_query_user_jids(&node),
                    vec![
                        "999@s.whatsapp.net".to_owned(),
                        "999:7@s.whatsapp.net".to_owned(),
                    ]
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "999@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "0"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "7")
                                            .with_attr("key-index", "11"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "8")
                                            .with_attr("key-index", "12"),
                                    ])],
                                )]),
                        ]),
                    ])])
            },
            &mut request_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(node.attrs["type"], "get");
                assert_eq!(
                    encrypt_key_query_user_attrs(&node)
                        .into_iter()
                        .map(|(jid, _)| jid)
                        .collect::<Vec<_>>(),
                    vec![
                        "999@s.whatsapp.net".to_owned(),
                        "999:8@s.whatsapp.net".to_owned(),
                    ]
                );
                session_response_for_query(&node)
            },
            &mut request_fut,
        )
        .await;

        let relay = request_fut.await.unwrap();
        assert_eq!(relay.message_id, "pdo-1");
        assert_eq!(relay.recipient_count, 2);
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.attrs["id"], "pdo-1");
        assert_eq!(sent.attrs["to"], "999@s.whatsapp.net");
        assert_eq!(sent.attrs["category"], "peer");
        assert_eq!(sent.attrs["push_priority"], "high_force");
        let Some(wa_binary::BinaryNodeContent::Nodes(children)) = &sent.content else {
            panic!("placeholder resend stanza should have children");
        };
        assert!(children.iter().any(|node| {
            node.tag == "meta" && node.attrs.get("appdata").map(String::as_str) == Some("default")
        }));

        let calls = encryptor.calls.lock().unwrap().clone();
        assert_eq!(
            calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
            vec!["999@s.whatsapp.net", "999:8@s.whatsapp.net"]
        );
        for call in calls {
            let plaintext = wa_proto::proto::Message::decode(call.1).unwrap();
            let device_sent = plaintext.device_sent_message.unwrap();
            assert_eq!(
                device_sent.destination_jid.as_deref(),
                Some("999@s.whatsapp.net")
            );
            let protocol = device_sent.message.unwrap().protocol_message.unwrap();
            assert_eq!(
                protocol.r#type,
                Some(
                    wa_proto::proto::message::protocol_message::Type::PeerDataOperationRequestMessage
                        as i32
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
                request.placeholder_message_resend_request[0].message_key,
                Some(missing_key.clone())
            );
        }
        assert!(
            client
                .placeholder_resend_tracker()
                .contains("missing-1", current_unix_timestamp_ms())
                .unwrap()
        );

        let duplicate = client
            .request_placeholder_resend(
                &connection,
                [missing_key],
                &encryptor,
                MessageRelayOptions::new().with_message_id("pdo-duplicate"),
            )
            .await
            .unwrap_err();
        assert!(
            duplicate
                .to_string()
                .contains("placeholder resend already pending for message id missing-1")
        );
        assert!(
            client
                .placeholder_resend_tracker()
                .contains("missing-1", current_unix_timestamp_ms())
                .unwrap()
        );

        let events = vec![
            MessageEvent::new(wa_core::MessageEventKey::new(
                "123@s.whatsapp.net",
                "missing-1",
                None,
            ))
            .with_field("kind", "placeholder_resend"),
            MessageEvent::new(wa_core::MessageEventKey::new(
                "123@s.whatsapp.net",
                "other",
                None,
            ))
            .with_field("kind", "message"),
        ];
        assert_eq!(
            client.resolve_placeholder_resend_events(&events).unwrap(),
            1
        );
        assert!(
            !client
                .placeholder_resend_tracker()
                .contains("missing-1", current_unix_timestamp_ms())
                .unwrap()
        );
        assert_eq!(
            client.resolve_placeholder_resend_events(&events).unwrap(),
            0
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn request_placeholder_resend_for_web_message_requests_eligible_unavailable_stub() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let encryptor = RelayEncryptor::default();
        let missing_key =
            wa_core::build_message_key("123@s.whatsapp.net", false, "missing-auto", None).unwrap();
        let web_message = wa_core::WebMessageInfo {
            key: Some(missing_key),
            message_timestamp: Some(current_unix_timestamp()),
            message_stub_type: Some(wa_proto::proto::web_message_info::StubType::Ciphertext as i32),
            message_stub_parameters: vec![
                wa_core::PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned(),
            ],
            ..wa_core::WebMessageInfo::default()
        };
        let request_fut = client.request_placeholder_resend_for_web_message(
            &connection,
            &web_message,
            None,
            Some("temporary_unavailable"),
            &encryptor,
            MessageRelayOptions::new().with_message_id("pdo-auto"),
        );
        tokio::pin!(request_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "devices");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "999@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "0"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "7")
                                            .with_attr("key-index", "11"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "8")
                                            .with_attr("key-index", "12"),
                                    ])],
                                )]),
                        ]),
                    ])])
            },
            &mut request_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                session_response_for_query(&node)
            },
            &mut request_fut,
        )
        .await;

        let relay = request_fut.await.unwrap().unwrap();
        assert_eq!(relay.message_id, "pdo-auto");
        assert_eq!(relay.recipient_count, 2);
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.attrs["id"], "pdo-auto");
        assert_eq!(sent.attrs["category"], "peer");
        assert!(
            client
                .placeholder_resend_tracker()
                .contains("missing-auto", current_unix_timestamp_ms())
                .unwrap()
        );

        let duplicate = client
            .request_placeholder_resend_for_web_message(
                &connection,
                &web_message,
                None,
                Some("temporary_unavailable"),
                &encryptor,
                MessageRelayOptions::new().with_message_id("pdo-auto-duplicate"),
            )
            .await
            .unwrap();
        assert!(duplicate.is_none());
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn placeholder_resend_cleanup_purges_expired_requests() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let tracker = client.placeholder_resend_tracker();
        let now = current_unix_timestamp_ms();

        tracker.begin_request("fresh-manual", now).unwrap();
        tracker.begin_request("expired-manual", 0).unwrap();
        assert_eq!(client.purge_expired_placeholder_resends().unwrap(), 1);
        assert!(tracker.resolve("expired-manual").unwrap().is_none());
        assert!(tracker.resolve("fresh-manual").unwrap().is_some());

        tracker.begin_request("expired-background", 0).unwrap();
        let mut cleanup = client
            .spawn_placeholder_resend_cleanup(Duration::from_millis(5))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tracker.resolve("expired-background").unwrap().is_none());
        cleanup.abort();

        let invalid = match client.spawn_placeholder_resend_cleanup(Duration::ZERO) {
            Ok(_) => panic!("zero cleanup interval should be rejected"),
            Err(err) => err,
        };
        assert!(
            invalid
                .to_string()
                .contains("placeholder resend cleanup interval must be non-zero")
        );
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn assert_sessions_fetches_missing_sessions_and_persists_them() {
        let store = wa_store::MemoryAuthStore::new();
        wa_core::LidPnMappingStore::new(store.clone())
            .store_mappings(vec![wa_core::LidPnMapping {
                pn: "123@s.whatsapp.net".to_owned(),
                lid: "lid123@lid".to_owned(),
            }])
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let repository = client.signal_repository();
        repository
            .inject_e2e_session(wa_core::SessionInjection {
                jid: "existing:2@s.whatsapp.net".to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let assert_fut = client.assert_sessions(
            &connection,
            [
                "123:1@s.whatsapp.net",
                "existing:2@s.whatsapp.net",
                "lidtarget:3@lid",
                "123:1@s.whatsapp.net",
            ],
            false,
        );
        tokio::pin!(assert_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(
                    encrypt_key_query_user_attrs(&node),
                    vec![
                        ("lid123:1@lid".to_owned(), None),
                        ("lidtarget:3@lid".to_owned(), None),
                    ]
                );
                session_response_for_query(&node)
            },
            &mut assert_fut,
        )
        .await;

        assert!(assert_fut.await.unwrap());
        assert!(
            repository
                .validate_session("lid123:1@lid")
                .await
                .unwrap()
                .exists
        );
        assert!(
            repository
                .validate_session("lidtarget:3@lid")
                .await
                .unwrap()
                .exists
        );

        let force_fut = client.assert_sessions(&connection, ["existing:2@s.whatsapp.net"], true);
        tokio::pin!(force_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(
                    encrypt_key_query_user_attrs(&node),
                    vec![(
                        "existing:2@s.whatsapp.net".to_owned(),
                        Some("identity".to_owned()),
                    )]
                );
                session_response_for_query(&node)
            },
            &mut force_fut,
        )
        .await;

        assert!(force_fut.await.unwrap());

        let failed_fut = client.assert_sessions(&connection, ["failed:3@s.whatsapp.net"], false);
        tokio::pin!(failed_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(
                    encrypt_key_query_user_attrs(&node),
                    vec![("failed:3@s.whatsapp.net".to_owned(), None)]
                );
                error_result_for(&node, "401", "session denied")
            },
            &mut failed_fut,
        )
        .await;

        let err = failed_fut.await.unwrap_err();
        assert!(
            err.to_string()
                .contains("E2E session query failed (401): session denied")
        );
        assert!(
            !repository
                .validate_session("failed:3@s.whatsapp.net")
                .await
                .unwrap()
                .exists
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn identity_change_refresh_schedules_tc_token_reissue() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let sender_timestamp = current_unix_timestamp().saturating_sub(60);
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new(
                "123@s.whatsapp.net",
                Bytes::from_static(b"old-peer-token"),
            )
            .unwrap()
            .with_timestamp_seconds(sender_timestamp)
            .with_sender_timestamp_seconds(sender_timestamp),
        )
        .await
        .unwrap();

        let client = Client::builder(store.clone()).connect().await.unwrap();
        let repository = client.signal_repository();
        repository
            .inject_e2e_session(wa_core::SessionInjection {
                jid: "123@s.whatsapp.net".to_owned(),
                session: test_signal_session(),
            })
            .await
            .unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let notification = BinaryNode::new("notification")
            .with_attr("id", "identity-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "encrypt")
            .with_content(vec![
                BinaryNode::new("identity").with_content(Bytes::from_static(b"changed")),
            ]);

        let handler_client = client.clone();
        let handler_connection = connection.clone();
        let handle_task = tokio::spawn(async move {
            handler_client
                .handle_identity_change_notification(&handler_connection, &notification)
                .await
        });

        let mut saw_privacy = false;
        let mut saw_encrypt = false;
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let node = decode_inbound_binary_node(&frame).unwrap().node;
            match node.attrs.get("xmlns").map(String::as_str) {
                Some("privacy") => {
                    saw_privacy = true;
                    let Some(wa_binary::BinaryNodeContent::Nodes(iq_children)) = &node.content
                    else {
                        panic!("privacy query should have child nodes");
                    };
                    let tokens = iq_children
                        .iter()
                        .find(|child| child.tag == "tokens")
                        .unwrap();
                    let Some(wa_binary::BinaryNodeContent::Nodes(token_children)) = &tokens.content
                    else {
                        panic!("tokens node should have token children");
                    };
                    assert_eq!(token_children.len(), 1);
                    assert_eq!(token_children[0].attrs["jid"], "123@s.whatsapp.net");
                    assert_eq!(token_children[0].attrs["type"], "trusted_contact");
                    assert_eq!(
                        token_children[0].attrs["t"].parse::<u64>().unwrap(),
                        sender_timestamp
                    );
                    stream_tx
                        .send(InboundFrame::new(
                            encode_binary_node(
                                &BinaryNode::new("iq")
                                    .with_attr("id", node.attrs["id"].clone())
                                    .with_attr("type", "result")
                                    .with_content(vec![BinaryNode::new("tokens").with_content(
                                        vec![
                                            BinaryNode::new("token")
                                                .with_attr("jid", "ignored@s.whatsapp.net")
                                                .with_attr(
                                                    "t",
                                                    (sender_timestamp + 1).to_string(),
                                                )
                                                .with_attr("type", "trusted_contact")
                                                .with_content(Bytes::from_static(
                                                    b"identity-peer-token",
                                                )),
                                        ],
                                    )]),
                            )
                            .unwrap(),
                        ))
                        .await
                        .unwrap();
                }
                Some("encrypt") => {
                    saw_encrypt = true;
                    assert_eq!(
                        encrypt_key_query_user_attrs(&node),
                        vec![("123@s.whatsapp.net".to_owned(), Some("identity".to_owned()))]
                    );
                    stream_tx
                        .send(InboundFrame::new(
                            encode_binary_node(&session_response_for_query(&node)).unwrap(),
                        ))
                        .await
                        .unwrap();
                }
                other => panic!("unexpected query xmlns: {other:?}"),
            }
        }

        let outcome = handle_task.await.unwrap().unwrap();
        assert_eq!(
            outcome,
            IdentityChangeOutcome::SessionRefreshed {
                token_reissue_scheduled: true
            }
        );
        assert!(saw_privacy);
        assert!(saw_encrypt);

        let mut loaded = None;
        for _ in 0..20 {
            loaded = wa_core::load_tc_token(&store, "123@s.whatsapp.net")
                .await
                .unwrap();
            if loaded
                .as_ref()
                .is_some_and(|record| record.token == Bytes::from_static(b"identity-peer-token"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let loaded = loaded.unwrap();
        assert_eq!(loaded.token, Bytes::from_static(b"identity-peer-token"));
        assert_eq!(loaded.timestamp_seconds, Some(sender_timestamp + 1));
        assert_eq!(loaded.sender_timestamp_seconds, Some(sender_timestamp));
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn send_receipts_groups_message_keys_and_writes_nodes() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let keys = vec![
            MessageKey {
                remote_jid: Some("123@s.whatsapp.net".to_owned()),
                from_me: Some(false),
                id: Some("m1".to_owned()),
                participant: Some("456@s.whatsapp.net".to_owned()),
            },
            MessageKey {
                remote_jid: Some("123@s.whatsapp.net".to_owned()),
                from_me: Some(false),
                id: Some("m2".to_owned()),
                participant: Some("456@s.whatsapp.net".to_owned()),
            },
            MessageKey {
                remote_jid: Some("999@s.whatsapp.net".to_owned()),
                from_me: Some(true),
                id: Some("own".to_owned()),
                participant: None,
            },
        ];

        let receipts = client
            .send_receipts(&connection, &keys, MessageReceiptType::Read, Some(10))
            .await
            .unwrap();

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].message_ids, vec!["m1", "m2"]);
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.tag, "receipt");
        assert_eq!(sent.attrs["id"], "m1");
        assert_eq!(sent.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(sent.attrs["participant"], "456@s.whatsapp.net");
        assert_eq!(sent.attrs["type"], "read");
        assert_eq!(sent.attrs["t"], "10");
        let Some(wa_binary::BinaryNodeContent::Nodes(content)) = &sent.content else {
            panic!("receipt should contain list");
        };
        let Some(wa_binary::BinaryNodeContent::Nodes(items)) = &content[0].content else {
            panic!("receipt list should contain item nodes");
        };
        assert_eq!(items[0].attrs["id"], "m2");
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn send_ack_and_nack_write_ack_nodes() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let received = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("type", "text");

        let ack = client.send_ack(&connection, &received, None).await.unwrap();
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent, ack);

        let nack = client
            .send_nack(&connection, &received, wa_core::NackReason::ParsingError)
            .await
            .unwrap();
        assert_eq!(nack.attrs["error"], "487");
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent, nack);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn process_incoming_node_sends_ack_and_emits_message_event() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("own@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let text = wa_proto::proto::Message {
            conversation: Some("hello".to_owned()),
            ..wa_proto::proto::Message::default()
        };
        let incoming = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("plaintext").with_content(Bytes::from(text.encode_to_vec())),
            ]);
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
            max_pending_items: 8,
        });

        let result = client
            .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
            .await
            .unwrap();

        assert_eq!(result.action, wa_core::InboundNodeAction::Message);
        assert_eq!(result.event_count, 1);
        assert!(result.error.is_none());
        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "msg-1");
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");

        let Event::Batch(batch) = events.recv().await.unwrap() else {
            panic!("expected typed event batch");
        };
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(
            batch.messages_upsert[0].key.remote_jid,
            "123@s.whatsapp.net"
        );
        assert_eq!(batch.messages_upsert[0].key.id, "msg-1");
        let payload = batch.messages_upsert[0].payload.clone().unwrap();
        let decoded = wa_proto::proto::Message::decode(payload).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("hello"));
        let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
        let stored = store
            .get(KeyNamespace::MessageEvent, &stored_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_message_event(&stored).unwrap();
        assert_eq!(stored, batch.messages_upsert[0]);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn process_incoming_node_with_placeholder_resend_requests_unavailable_stub() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let incoming = BinaryNode::new("message")
            .with_attr("id", "missing-live")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("t", current_unix_timestamp().to_string())
            .with_content(vec![
                BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
            ]);
        let encryptor = RelayEncryptor::default();
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
            max_pending_items: 8,
        });
        let process_fut = client.process_incoming_node_with_placeholder_resend(
            &connection,
            &incoming,
            &IncomingDecryptor,
            &encryptor,
            &mut buffer,
        );
        tokio::pin!(process_fut);

        let ack_frame = tokio::select! {
            result = &mut process_fut => panic!("processing completed before ACK: {result:?}"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let ack = decode_inbound_binary_node(&ack_frame).unwrap().node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "missing-live");
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "devices");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "999@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(
                                    vec![BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "0"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "7")
                                            .with_attr("key-index", "11"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "8")
                                            .with_attr("key-index", "12"),
                                    ])],
                                )]),
                        ]),
                    ])])
            },
            &mut process_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                session_response_for_query(&node)
            },
            &mut process_fut,
        )
        .await;

        let outcome = process_fut.await.unwrap();
        assert_eq!(outcome.inbound.action, wa_core::InboundNodeAction::Message);
        assert_eq!(outcome.inbound.event_count, 1);
        assert!(outcome.inbound.error.is_none());
        let relay = outcome.placeholder_resend.unwrap();
        assert_eq!(relay.recipient_count, 2);

        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.attrs["to"], "999@s.whatsapp.net");
        assert_eq!(sent.attrs["category"], "peer");
        assert_eq!(sent.attrs["push_priority"], "high_force");
        assert!(
            client
                .placeholder_resend_tracker()
                .contains("missing-live", current_unix_timestamp_ms())
                .unwrap()
        );

        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.id, "missing-live");
        assert_eq!(
            batch.messages_upsert[0].fields["kind"],
            "placeholder_unavailable"
        );
        assert_eq!(
            batch.messages_upsert[0].fields["unavailable_type"],
            "temporary_unavailable"
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn process_incoming_node_persists_linked_profile_mappings() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("own@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let incoming = BinaryNode::new("notification")
            .with_attr("id", "n-linked")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationLinkedProfilesUpdates")
                .with_content(
                    br#"{"data":{"xwa2_notify_linked_profiles":{"jid":"abc@lid","added_profiles":[{"pn":"123@s.whatsapp.net"}]}}}"#.to_vec(),
                )]);
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
            max_pending_items: 8,
        });

        let result = client
            .process_incoming_node(&connection, &incoming, &IncomingDecryptor, &mut buffer)
            .await
            .unwrap();

        assert_eq!(result.action, wa_core::InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "n-linked");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let Event::Node(node) = events.recv().await.unwrap() else {
            panic!("expected raw notification event");
        };
        assert_eq!(node, incoming);
        let Event::LidMappingUpdate(mappings) = events.recv().await.unwrap() else {
            panic!("expected LID mapping event");
        };
        assert_eq!(
            mappings,
            vec![wa_core::LidMappingEvent::new(
                "abc@lid",
                "123@s.whatsapp.net"
            )]
        );

        let mapping_store = wa_core::LidPnMappingStore::new(store);
        assert_eq!(
            mapping_store
                .lid_for_pn("123@s.whatsapp.net")
                .await
                .unwrap(),
            Some("abc".to_owned())
        );
        assert_eq!(
            mapping_store.pn_for_lid("abc@lid").await.unwrap(),
            Some("123".to_owned())
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn process_incoming_node_with_media_retry_downloads_pending_media() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("own@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let key = wa_core::MessageEventKey::new(
            "123@s.whatsapp.net",
            "msg-1",
            Some("456@s.whatsapp.net".to_owned()),
        );
        let media_key = [8u8; 32];
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"live retried media",
            wa_core::MediaKind::Image,
            &media_key,
        )
        .unwrap();
        let media = wa_core::uploaded_media_from_encrypted(
            &encrypted,
            wa_core::UploadedMediaLocation::new().with_direct_path("/live/old"),
        )
        .unwrap();
        client
            .register_pending_media_retry(
                key.clone(),
                wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .unwrap();
        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(key.id.clone()),
            direct_path: Some("/live/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            &key.id,
            &[6u8; 12],
        )
        .unwrap();
        let incoming = BinaryNode::new("receipt")
            .with_attr("id", &key.id)
            .with_attr("from", "999@s.whatsapp.net")
            .with_attr("type", "server-error")
            .with_content(vec![
                BinaryNode::new("rmr")
                    .with_attr("jid", &key.remote_jid)
                    .with_attr("from_me", "false")
                    .with_attr("participant", key.participant.as_deref().unwrap()),
                BinaryNode::new("encrypt").with_content(vec![
                    BinaryNode::new("enc_p").with_content(payload.ciphertext),
                    BinaryNode::new("enc_iv").with_content(payload.iv),
                ]),
            ]);
        let transport = ClientMediaUploadTransport::default();
        transport.downloads.lock().unwrap().insert(
            "https://media.test/live/new".to_owned(),
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = wa_core::MediaTransfer::new(transport);
        let mut buffer = wa_core::EventBuffer::new(wa_core::EventBufferConfig {
            max_pending_items: 8,
        });

        let result = client
            .process_incoming_node_with_media_retry(
                &connection,
                &incoming,
                &IncomingDecryptor,
                &mut buffer,
                &transfer,
            )
            .await
            .unwrap();

        assert_eq!(result.inbound.action, wa_core::InboundNodeAction::Receipt);
        assert_eq!(result.inbound.event_count, 2);
        assert_eq!(result.media_retry.downloads.len(), 1);
        assert_eq!(
            result.media_retry.downloads[0].plaintext,
            b"live retried media"
        );
        assert!(result.media_retry.errors.is_empty());
        assert!(
            client
                .media_retry_coordinator()
                .pending(&key)
                .unwrap()
                .is_none()
        );
        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "msg-1");
        assert_eq!(ack.attrs["class"], "receipt");
        assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");
        assert!(!ack.attrs.contains_key("from"));

        let Event::Batch(batch) = events.recv().await.unwrap() else {
            panic!("expected typed event batch");
        };
        assert_eq!(batch.receipts_update.len(), 1);
        assert_eq!(batch.media_retry.len(), 1);
        assert_eq!(batch.media_retry[0].key, key);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_handles_raw_message_nodes() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("own@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor(
                connection.clone(),
                IncomingDecryptor,
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let mut events = client.subscribe();
        let text = wa_proto::proto::Message {
            conversation: Some("automatic".to_owned()),
            ..wa_proto::proto::Message::default()
        };
        let incoming = BinaryNode::new("message")
            .with_attr("id", "auto-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("plaintext").with_content(Bytes::from(text.encode_to_vec())),
            ]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "auto-1");
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");

        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.id, "auto-1");
        let payload = batch.messages_upsert[0].payload.clone().unwrap();
        let decoded = wa_proto::proto::Message::decode(payload).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("automatic"));
        let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[0].key);
        let stored = store
            .get(KeyNamespace::MessageEvent, &stored_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_message_event(&stored).unwrap();
        assert_eq!(stored, batch.messages_upsert[0]);
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_with_placeholder_resend_requests_unavailable_stub() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor_with_placeholder_resend(
                connection.clone(),
                IncomingDecryptor,
                RelayEncryptor::default(),
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let mut events = client.subscribe();
        let incoming = BinaryNode::new("message")
            .with_attr("id", "missing-spawn")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("t", current_unix_timestamp().to_string())
            .with_content(vec![
                BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
            ]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "missing-spawn");
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.id, "missing-spawn");
        assert_eq!(
            batch.messages_upsert[0].fields["kind"],
            "placeholder_unavailable"
        );
        assert_eq!(
            batch.messages_upsert[0].fields["unavailable_type"],
            "temporary_unavailable"
        );

        let usync_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(usync_query.attrs["xmlns"], "usync");
        assert_usync_query_protocol(&usync_query, "devices");
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", usync_query.attrs["id"].clone())
                        .with_attr("type", "result")
                        .with_content(vec![BinaryNode::new("usync").with_content(vec![
                            BinaryNode::new("list").with_content(vec![
                                BinaryNode::new("user")
                                    .with_attr("jid", "999@s.whatsapp.net")
                                    .with_content(vec![BinaryNode::new("devices").with_content(
                                        vec![BinaryNode::new("device-list").with_content(vec![
                                            BinaryNode::new("device").with_attr("id", "0"),
                                            BinaryNode::new("device")
                                                .with_attr("id", "7")
                                                .with_attr("key-index", "11"),
                                            BinaryNode::new("device")
                                                .with_attr("id", "8")
                                                .with_attr("key-index", "12"),
                                        ])],
                                    )]),
                            ]),
                        ])]),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let encrypt_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(encrypt_query.attrs["xmlns"], "encrypt");
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&session_response_for_query(&encrypt_query)).unwrap(),
            ))
            .await
            .unwrap();

        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.tag, "message");
        assert_eq!(sent.attrs["to"], "999@s.whatsapp.net");
        assert_eq!(sent.attrs["category"], "peer");
        assert_eq!(sent.attrs["push_priority"], "high_force");
        assert!(
            client
                .placeholder_resend_tracker()
                .contains("missing-spawn", current_unix_timestamp_ms())
                .unwrap()
        );

        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_persists_linked_profile_mappings() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("own@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor(
                connection.clone(),
                IncomingDecryptor,
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let mut events = client.subscribe();
        let incoming = BinaryNode::new("notification")
            .with_attr("id", "auto-linked")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationLinkedProfilesUpdates")
                .with_content(
                    br#"{"data":{"xwa2_notify_linked_profiles":{"jid":"abc@lid","added_profiles":["123@c.us"]}}}"#.to_vec(),
                )]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&incoming).unwrap()))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "auto-linked");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let mappings = recv_lid_mapping_event(&mut events).await;
        assert_eq!(
            mappings,
            vec![wa_core::LidMappingEvent::new(
                "abc@lid",
                "123@s.whatsapp.net"
            )]
        );
        let mapping_store = wa_core::LidPnMappingStore::new(store);
        assert_eq!(
            mapping_store
                .lid_for_pn("123@s.whatsapp.net")
                .await
                .unwrap(),
            Some("abc".to_owned())
        );
        assert_eq!(
            mapping_store.pn_for_lid("abc@lid").await.unwrap(),
            Some("123".to_owned())
        );
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_does_not_reprocess_processed_node_events() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor(
                connection.clone(),
                IncomingDecryptor,
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let mut events = client.subscribe();
        let notification = BinaryNode::new("notification")
            .with_attr("id", "notify-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "devices");

        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&notification).unwrap(),
            ))
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "notify-1");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(recv_node_event(&mut events).await, notification);
        tokio::task::yield_now().await;
        assert!(matches!(
            sink_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_handles_offline_node_children() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor(
                connection.clone(),
                IncomingDecryptor,
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let mut events = client.subscribe();
        let text_one = wa_proto::proto::Message {
            conversation: Some("one".to_owned()),
            ..wa_proto::proto::Message::default()
        };
        let text_two = wa_proto::proto::Message {
            conversation: Some("two".to_owned()),
            ..wa_proto::proto::Message::default()
        };
        let offline = BinaryNode::new("offline").with_content(vec![
            BinaryNode::new("message")
                .with_attr("id", "offline-1")
                .with_attr("from", "123@s.whatsapp.net")
                .with_attr("type", "text")
                .with_content(vec![
                    BinaryNode::new("plaintext")
                        .with_content(Bytes::from(text_one.encode_to_vec())),
                ]),
            BinaryNode::new("message")
                .with_attr("id", "offline-2")
                .with_attr("from", "456@s.whatsapp.net")
                .with_attr("type", "text")
                .with_content(vec![
                    BinaryNode::new("plaintext")
                        .with_content(Bytes::from(text_two.encode_to_vec())),
                ]),
        ]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&offline).unwrap()))
            .await
            .unwrap();

        let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(first_ack.tag, "ack");
        assert_eq!(first_ack.attrs["id"], "offline-1");
        assert_eq!(first_ack.attrs["class"], "message");
        let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(second_ack.tag, "ack");
        assert_eq!(second_ack.attrs["id"], "offline-2");
        assert_eq!(second_ack.attrs["class"], "message");

        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_upsert.len(), 2);
        assert_eq!(batch.messages_upsert[0].key.id, "offline-1");
        assert_eq!(batch.messages_upsert[1].key.id, "offline-2");

        let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[1].key);
        let stored = store
            .get(KeyNamespace::MessageEvent, &stored_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_message_event(&stored).unwrap();
        assert_eq!(stored, batch.messages_upsert[1]);
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_refreshes_dirty_communities() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor(
                connection.clone(),
                IncomingDecryptor,
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let mut events = client.subscribe();
        let dirty = BinaryNode::new("ib").with_content(vec![
            BinaryNode::new("dirty")
                .with_attr("type", "communities")
                .with_attr("timestamp", "999"),
        ]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&dirty).unwrap()))
            .await
            .unwrap();

        let participating_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(participating_query.attrs["xmlns"], "w:g2");
        assert_eq!(participating_query.attrs["to"], "@g.us");
        assert_eq!(participating_query.attrs["type"], "get");
        assert_child(
            test_child(&participating_query, "participating"),
            "participants",
        );
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", participating_query.attrs["id"].clone())
                        .with_attr("type", "result")
                        .with_content(vec![BinaryNode::new("communities").with_content(vec![
                            BinaryNode::new("community")
                                .with_attr("id", "123")
                                .with_attr("subject", "Updates")
                                .with_content(vec![
                                    BinaryNode::new("parent"),
                                    BinaryNode::new("participant")
                                        .with_attr("jid", "111@s.whatsapp.net"),
                                ]),
                        ])]),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        let clean_child = test_child(&clean, "clean");
        assert_eq!(clean_child.attrs["type"], "groups");
        assert_eq!(clean_child.attrs["timestamp"], "999");
        let update = recv_groups_update_event(&mut events).await;
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].jid, "123@g.us");
        assert_eq!(update[0].fields["source"], "community_dirty_refresh");
        assert_eq!(update[0].fields["subject"], "Updates");
        assert_eq!(update[0].fields["is_community"], "true");
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn incoming_processor_refreshes_dirty_groups() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) =
            mock_connection_with_events(client.events.clone());
        let mut processor = client
            .spawn_incoming_processor(
                connection.clone(),
                IncomingDecryptor,
                wa_core::EventBufferConfig {
                    max_pending_items: 8,
                },
            )
            .unwrap();
        let mut events = client.subscribe();
        let dirty = BinaryNode::new("ib").with_content(vec![
            BinaryNode::new("dirty")
                .with_attr("type", "groups")
                .with_attr("timestamp", "998"),
        ]);

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&dirty).unwrap()))
            .await
            .unwrap();

        let participating_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(participating_query.attrs["xmlns"], "w:g2");
        assert_eq!(participating_query.attrs["to"], "@g.us");
        assert_eq!(participating_query.attrs["type"], "get");
        assert_child(
            test_child(&participating_query, "participating"),
            "participants",
        );
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", participating_query.attrs["id"].clone())
                        .with_attr("type", "result")
                        .with_content(vec![BinaryNode::new("groups").with_content(vec![
                            BinaryNode::new("group")
                                .with_attr("id", "123")
                                .with_attr("subject", "Team")
                                .with_content(vec![BinaryNode::new("participant")
                                    .with_attr("jid", "111@s.whatsapp.net")]),
                        ])]),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        let clean_child = test_child(&clean, "clean");
        assert_eq!(clean_child.attrs["type"], "groups");
        assert_eq!(clean_child.attrs["timestamp"], "998");
        let update = recv_groups_update_event(&mut events).await;
        assert_eq!(update.len(), 1);
        assert_eq!(update[0].jid, "123@g.us");
        assert_eq!(update[0].fields["source"], "group_dirty_refresh");
        assert_eq!(update[0].fields["subject"], "Team");
        processor.abort();
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn send_media_retry_request_with_payload_writes_server_error_receipt() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let key = MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("m1".to_owned()),
            participant: None,
        };

        let node = client
            .send_media_retry_request_with_payload(
                &connection,
                &key,
                "999:7@s.whatsapp.net",
                MediaRetryPayload::new(
                    Bytes::from_static(b"ciphertext"),
                    Bytes::from(vec![1u8; 12]),
                ),
            )
            .await
            .unwrap();
        assert_eq!(node.attrs["type"], "server-error");

        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent, node);
        assert_eq!(sent.attrs["to"], "999@s.whatsapp.net");
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn send_media_retry_request_encrypts_payload_from_stored_account() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let key = MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("m1".to_owned()),
            participant: None,
        };

        let node = client
            .send_media_retry_request(&connection, &key, &[8u8; 32])
            .await
            .unwrap();

        assert_eq!(node.attrs["to"], "999@s.whatsapp.net");
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        let update = wa_core::parse_media_retry_update(&sent).unwrap();
        assert_eq!(update.key, key);
        let media = update.media.unwrap();
        assert_eq!(media.iv.len(), 12);
        assert!(!media.ciphertext.is_empty());
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn read_messages_can_send_read_self_receipts() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let keys = vec![MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("m1".to_owned()),
            participant: None,
        }];

        let receipts = client
            .read_messages(&connection, &keys, false, Some(11))
            .await
            .unwrap();

        assert_eq!(receipts.len(), 1);
        let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent.attrs["id"], "m1");
        assert_eq!(sent.attrs["type"], "read-self");
        assert_eq!(sent.attrs["t"], "11");
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn fetch_statuses_and_disappearing_modes_send_usync_queries() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let status_fut = client.fetch_statuses(&connection, ["123@s.whatsapp.net"]);
        tokio::pin!(status_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "status");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![
                                    BinaryNode::new("status")
                                        .with_attr("t", "42")
                                        .with_content("available"),
                                ]),
                        ]),
                    ])])
            },
            &mut status_fut,
        )
        .await;

        assert_eq!(
            status_fut.await.unwrap(),
            vec![USyncStatusResult {
                jid: "123@s.whatsapp.net".to_owned(),
                status: wa_core::USyncStatus {
                    status: Some("available".to_owned()),
                    set_at: Some(42),
                },
            }]
        );

        let disappearing_fut = client.fetch_disappearing_modes(&connection, ["123@s.whatsapp.net"]);
        tokio::pin!(disappearing_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "disappearing_mode");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![
                                    BinaryNode::new("disappearing_mode")
                                        .with_attr("duration", "604800")
                                        .with_attr("t", "43"),
                                ]),
                        ]),
                    ])])
            },
            &mut disappearing_fut,
        )
        .await;

        assert_eq!(
            disappearing_fut.await.unwrap(),
            vec![USyncDisappearingModeResult {
                jid: "123@s.whatsapp.net".to_owned(),
                mode: wa_core::USyncDisappearingMode {
                    duration: 604800,
                    set_at: Some(43),
                },
            }]
        );
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn fetch_bot_profiles_sends_profile_query_and_maps_results() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let profile_fut =
            client.fetch_bot_profiles(&connection, [("123@s.whatsapp.net", "persona-1")]);
        tokio::pin!(profile_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                assert_usync_query_protocol(&node, "bot");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("bot").with_content(vec![
                                    BinaryNode::new("profile")
                                        .with_attr("persona_id", "persona-1")
                                        .with_content(vec![
                                            BinaryNode::new("name").with_content("Helper"),
                                            BinaryNode::new("commands").with_content(vec![
                                                BinaryNode::new("command").with_content(vec![
                                                    BinaryNode::new("name").with_content("/help"),
                                                    BinaryNode::new("description")
                                                        .with_content("Show help"),
                                                ]),
                                            ]),
                                        ]),
                                ])]),
                        ]),
                    ])])
            },
            &mut profile_fut,
        )
        .await;

        assert_eq!(
            profile_fut.await.unwrap(),
            vec![USyncBotProfile {
                jid: "123@s.whatsapp.net".to_owned(),
                name: Some("Helper".to_owned()),
                attributes: None,
                description: None,
                category: None,
                is_default: false,
                prompts: Vec::new(),
                persona_id: Some("persona-1".to_owned()),
                commands: vec![wa_core::USyncBotProfileCommand {
                    name: "/help".to_owned(),
                    description: "Show help".to_owned(),
                }],
                commands_description: None,
            }]
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn profile_picture_url_attaches_lid_backed_tc_token_for_user_target() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("ownlid@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        wa_core::LidPnMappingStore::new(store.clone())
            .store_mappings(vec![wa_core::LidPnMapping {
                pn: "123@s.whatsapp.net".to_owned(),
                lid: "abc@lid".to_owned(),
            }])
            .await
            .unwrap();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("abc@lid", Bytes::from_static(b"profile-token"))
                .unwrap()
                .with_timestamp_seconds(current_unix_timestamp()),
        )
        .await
        .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let picture_fut =
            client.fetch_profile_picture_url(&connection, "123@c.us", ProfilePictureType::Preview);
        tokio::pin!(picture_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:profile:picture");
                assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
                let picture = test_child(&node, "picture");
                assert_eq!(picture.attrs["type"], "preview");
                assert_eq!(picture.attrs["query"], "url");
                assert_eq!(
                    test_node_bytes(test_child(&node, "tctoken")),
                    Some(Bytes::from_static(b"profile-token"))
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("picture").with_attr("url", "https://example.invalid/u"),
                    ])
            },
            &mut picture_fut,
        )
        .await;

        assert_eq!(
            picture_fut.await.unwrap().as_deref(),
            Some("https://example.invalid/u")
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn profile_picture_url_skips_tc_token_for_group_and_self_targets() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("ownlid@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("123@g.us", Bytes::from_static(b"group-token"))
                .unwrap()
                .with_timestamp_seconds(current_unix_timestamp()),
        )
        .await
        .unwrap();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("999@s.whatsapp.net", Bytes::from_static(b"self-token"))
                .unwrap()
                .with_timestamp_seconds(current_unix_timestamp()),
        )
        .await
        .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let group_picture_fut =
            client.fetch_profile_picture_url(&connection, "123@g.us", ProfilePictureType::Preview);
        tokio::pin!(group_picture_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:profile:picture");
                assert_eq!(node.attrs["target"], "123@g.us");
                assert!(test_children(&node, "tctoken").is_empty());
                empty_result_for(&node)
            },
            &mut group_picture_fut,
        )
        .await;
        assert_eq!(group_picture_fut.await.unwrap(), None);

        let self_picture_fut = client.fetch_profile_picture_url(
            &connection,
            "999:7@s.whatsapp.net",
            ProfilePictureType::Preview,
        );
        tokio::pin!(self_picture_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:profile:picture");
                assert_eq!(node.attrs["target"], "999@s.whatsapp.net");
                assert!(test_children(&node, "tctoken").is_empty());
                empty_result_for(&node)
            },
            &mut self_picture_fut,
        )
        .await;
        assert_eq!(self_picture_fut.await.unwrap(), None);
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn privacy_profile_and_blocklist_methods_use_account_iqs() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let privacy_fut = client.fetch_privacy_settings(&connection);
        tokio::pin!(privacy_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "privacy");
                assert_eq!(node.attrs["type"], "get");
                assert!(test_child(&node, "privacy").attrs.is_empty());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("privacy").with_content(vec![
                        BinaryNode::new("category")
                            .with_attr("name", "last")
                            .with_attr("value", "contacts"),
                    ])])
            },
            &mut privacy_fut,
        )
        .await;
        let settings = privacy_fut.await.unwrap();
        assert_eq!(settings.get(PrivacyCategory::LastSeen), Some("contacts"));

        let update_privacy_fut = client.update_privacy_setting(
            &connection,
            PrivacyCategory::Online,
            PrivacyValue::MatchLastSeen,
        );
        tokio::pin!(update_privacy_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "privacy");
                assert_eq!(node.attrs["type"], "set");
                let category = test_child(test_child(&node, "privacy"), "category");
                assert_eq!(category.attrs["name"], "online");
                assert_eq!(category.attrs["value"], "match_last_seen");
                empty_result_for(&node)
            },
            &mut update_privacy_fut,
        )
        .await;
        update_privacy_fut.await.unwrap();

        let failed_privacy_fut = client.update_privacy_setting(
            &connection,
            PrivacyCategory::Online,
            PrivacyValue::MatchLastSeen,
        );
        tokio::pin!(failed_privacy_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "privacy");
                error_result_for(&node, "403", "denied")
            },
            &mut failed_privacy_fut,
        )
        .await;
        assert!(failed_privacy_fut.await.is_err());

        let disappearing_fut = client.set_default_disappearing_mode(&connection, 604800);
        tokio::pin!(disappearing_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "disappearing_mode");
                assert_eq!(
                    test_child(&node, "disappearing_mode").attrs["duration"],
                    "604800"
                );
                empty_result_for(&node)
            },
            &mut disappearing_fut,
        )
        .await;
        disappearing_fut.await.unwrap();

        let failed_disappearing_fut = client.set_default_disappearing_mode(&connection, 604800);
        tokio::pin!(failed_disappearing_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "disappearing_mode");
                error_result_for(&node, "500", "server rejected update")
            },
            &mut failed_disappearing_fut,
        )
        .await;
        assert!(failed_disappearing_fut.await.is_err());

        let status_fut = client.update_profile_status(&connection, "Busy");
        tokio::pin!(status_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "status");
                assert_eq!(
                    test_node_text(test_child(&node, "status")).as_deref(),
                    Some("Busy")
                );
                empty_result_for(&node)
            },
            &mut status_fut,
        )
        .await;
        status_fut.await.unwrap();

        let failed_status_fut = client.update_profile_status(&connection, "Busy");
        tokio::pin!(failed_status_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "status");
                error_result_for(&node, "400", "bad status")
            },
            &mut failed_status_fut,
        )
        .await;
        assert!(failed_status_fut.await.is_err());

        let picture_fut =
            client.fetch_profile_picture_url(&connection, "123@c.us", ProfilePictureType::Preview);
        tokio::pin!(picture_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:profile:picture");
                assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
                let picture = test_child(&node, "picture");
                assert_eq!(picture.attrs["type"], "preview");
                assert_eq!(picture.attrs["query"], "url");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("picture").with_attr("url", "https://example.invalid/p"),
                    ])
            },
            &mut picture_fut,
        )
        .await;
        assert_eq!(
            picture_fut.await.unwrap().as_deref(),
            Some("https://example.invalid/p")
        );

        let update_picture_fut = client.update_profile_picture(
            &connection,
            Some("123@s.whatsapp.net"),
            b"jpeg".to_vec(),
        );
        tokio::pin!(update_picture_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:profile:picture");
                assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
                let picture = test_child(&node, "picture");
                assert_eq!(picture.attrs["type"], "image");
                assert_eq!(test_node_text(picture).as_deref(), Some("jpeg"));
                empty_result_for(&node)
            },
            &mut update_picture_fut,
        )
        .await;
        update_picture_fut.await.unwrap();

        let failed_picture_update = client.update_profile_picture(
            &connection,
            Some("123@s.whatsapp.net"),
            b"jpeg".to_vec(),
        );
        tokio::pin!(failed_picture_update);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:profile:picture");
                assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
                error_result_for(&node, "403", "denied")
            },
            &mut failed_picture_update,
        )
        .await;
        assert!(failed_picture_update.await.is_err());

        let remove_picture_fut = client.remove_profile_picture(&connection, None);
        tokio::pin!(remove_picture_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:profile:picture");
                assert!(!node.attrs.contains_key("target"));
                assert!(node.content.is_none());
                empty_result_for(&node)
            },
            &mut remove_picture_fut,
        )
        .await;
        remove_picture_fut.await.unwrap();

        let blocklist_fut = client.fetch_blocklist(&connection);
        tokio::pin!(blocklist_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "blocklist");
                assert_eq!(node.attrs["type"], "get");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("item").with_attr("jid", "abc@lid"),
                        BinaryNode::new("item").with_attr("jid", "def@lid"),
                    ])])
            },
            &mut blocklist_fut,
        )
        .await;
        assert_eq!(blocklist_fut.await.unwrap(), vec!["abc@lid", "def@lid"]);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn block_status_and_presence_methods_use_identity_state() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("123:7@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("own@lid".to_owned());
        credentials.account_name = Some("Agent@Desk".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        wa_core::LidPnMappingStore::new(store.clone())
            .store_mappings(vec![wa_core::LidPnMapping {
                pn: "555@s.whatsapp.net".to_owned(),
                lid: "lid555@lid".to_owned(),
            }])
            .await
            .unwrap();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("lid555@lid", Bytes::from_static(b"presence-token"))
                .unwrap()
                .with_timestamp_seconds(current_unix_timestamp()),
        )
        .await
        .unwrap();
        wa_core::save_tc_token(
            &store,
            wa_core::TcTokenRecord::new("777@g.us", Bytes::from_static(b"group-presence-token"))
                .unwrap()
                .with_timestamp_seconds(current_unix_timestamp()),
        )
        .await
        .unwrap();

        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let block_fut =
            client.update_block_status(&connection, "555@s.whatsapp.net", BlocklistAction::Block);
        tokio::pin!(block_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "blocklist");
                let item = test_child(&node, "item");
                assert_eq!(item.attrs["action"], "block");
                assert_eq!(item.attrs["jid"], "lid555@lid");
                assert_eq!(item.attrs["pn_jid"], "555@s.whatsapp.net");
                empty_result_for(&node)
            },
            &mut block_fut,
        )
        .await;
        block_fut.await.unwrap();

        let failed_block_fut =
            client.update_block_status(&connection, "555@s.whatsapp.net", BlocklistAction::Block);
        tokio::pin!(failed_block_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "blocklist");
                let item = test_child(&node, "item");
                assert_eq!(item.attrs["action"], "block");
                error_result_for(&node, "403", "denied")
            },
            &mut failed_block_fut,
        )
        .await;
        assert!(failed_block_fut.await.is_err());

        let unblock_fut =
            client.update_block_status(&connection, "lid555@lid", BlocklistAction::Unblock);
        tokio::pin!(unblock_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let item = test_child(&node, "item");
                assert_eq!(item.attrs["action"], "unblock");
                assert_eq!(item.attrs["jid"], "lid555@lid");
                assert!(!item.attrs.contains_key("pn_jid"));
                empty_result_for(&node)
            },
            &mut unblock_fut,
        )
        .await;
        unblock_fut.await.unwrap();

        let online = client
            .send_presence_update(&connection, PresenceState::Available, None)
            .await
            .unwrap();
        assert_eq!(online.tag, "presence");
        assert_eq!(online.attrs["name"], "AgentDesk");
        assert_eq!(online.attrs["type"], "available");
        let sent_online = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_online, online);

        let recording = client
            .send_presence_update(&connection, PresenceState::Recording, Some("777@lid"))
            .await
            .unwrap();
        assert_eq!(recording.tag, "chatstate");
        assert_eq!(recording.attrs["from"], "own@lid");
        assert_eq!(recording.attrs["to"], "777@lid");
        assert_eq!(test_child(&recording, "composing").attrs["media"], "audio");
        let sent_recording = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_recording, recording);

        let subscribe = client
            .subscribe_presence(&connection, "555@s.whatsapp.net")
            .await
            .unwrap();
        assert_eq!(subscribe.tag, "presence");
        assert_eq!(subscribe.attrs["type"], "subscribe");
        assert_eq!(subscribe.attrs["to"], "555@s.whatsapp.net");
        assert_eq!(
            test_node_bytes(test_child(&subscribe, "tctoken")),
            Some(Bytes::from_static(b"presence-token"))
        );
        let sent_subscribe = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_subscribe, subscribe);

        let group_subscribe = client
            .subscribe_presence(&connection, "777@g.us")
            .await
            .unwrap();
        assert_eq!(group_subscribe.tag, "presence");
        assert_eq!(group_subscribe.attrs["type"], "subscribe");
        assert_eq!(group_subscribe.attrs["to"], "777@g.us");
        assert!(group_subscribe.content.is_none());
        let sent_group_subscribe = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_group_subscribe, group_subscribe);
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn app_state_methods_use_sync_and_dirty_iqs() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let clean = client
            .clean_dirty_bits(&connection, DirtyBitType::Groups, Some(123))
            .await
            .unwrap();
        assert_eq!(clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        assert_eq!(clean.attrs["type"], "set");
        let clean_child = test_child(&clean, "clean");
        assert_eq!(clean_child.attrs["type"], "groups");
        assert_eq!(clean_child.attrs["timestamp"], "123");
        let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_clean, clean);

        let sync_fut = client.sync_app_state(
            &connection,
            [
                AppStateCollectionRequest::new(AppStateCollection::RegularHigh, 0),
                AppStateCollectionRequest::new(AppStateCollection::RegularLow, 9)
                    .with_return_snapshot(false),
            ],
        );
        tokio::pin!(sync_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
                assert_eq!(node.attrs["type"], "set");
                let collections = test_children(test_child(&node, "sync"), "collection");
                assert_eq!(collections[0].attrs["name"], "regular_high");
                assert_eq!(collections[0].attrs["version"], "0");
                assert_eq!(collections[0].attrs["return_snapshot"], "true");
                assert_eq!(collections[1].attrs["name"], "regular_low");
                assert_eq!(collections[1].attrs["version"], "9");
                assert_eq!(collections[1].attrs["return_snapshot"], "false");
                empty_result_for(&node)
            },
            &mut sync_fut,
        )
        .await;
        assert_eq!(sync_fut.await.unwrap().attrs["type"], "result");

        let failed_sync_fut = client.sync_app_state(
            &connection,
            [AppStateCollectionRequest::new(
                AppStateCollection::RegularHigh,
                0,
            )],
        );
        tokio::pin!(failed_sync_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
                error_result_for(&node, "409", "collection conflict")
            },
            &mut failed_sync_fut,
        )
        .await;
        assert!(failed_sync_fut.await.is_err());

        let patch_fut = client.upload_app_state_patch_bytes(
            &connection,
            AppStateCollection::RegularHigh,
            8,
            b"patch".to_vec(),
        );
        tokio::pin!(patch_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular_high");
                assert_eq!(collection.attrs["version"], "8");
                assert_eq!(collection.attrs["return_snapshot"], "false");
                assert_eq!(
                    test_node_text(test_child(collection, "patch")).as_deref(),
                    Some("patch")
                );
                empty_result_for(&node)
            },
            &mut patch_fut,
        )
        .await;
        assert_eq!(patch_fut.await.unwrap().attrs["type"], "result");

        let failed_patch_fut = client.upload_app_state_patch_bytes(
            &connection,
            AppStateCollection::RegularHigh,
            8,
            b"patch".to_vec(),
        );
        tokio::pin!(failed_patch_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular_high");
                error_result_for(&node, "500", "patch rejected")
            },
            &mut failed_patch_fut,
        )
        .await;
        assert!(failed_patch_fut.await.is_err());
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn refresh_dirty_groups_fetches_groups_then_cleans_dirty_bit() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let refresh_fut = client.refresh_dirty_groups(&connection, Some(777));
        tokio::pin!(refresh_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["type"], "get");
                assert_eq!(node.attrs["to"], "@g.us");
                let participating = test_child(&node, "participating");
                assert_child(participating, "participants");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("groups").with_content(vec![
                        BinaryNode::new("group")
                            .with_attr("id", "123")
                            .with_attr("subject", "Team")
                            .with_content(vec![BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")]),
                    ])])
            },
            &mut refresh_fut,
        )
        .await;

        let refresh = refresh_fut.await.unwrap();
        assert_eq!(refresh.groups.len(), 1);
        assert_eq!(refresh.groups[0].jid, "123@g.us");
        assert_eq!(refresh.groups[0].subject.as_deref(), Some("Team"));
        assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        let clean_child = test_child(&refresh.clean, "clean");
        assert_eq!(clean_child.attrs["type"], "groups");
        assert_eq!(clean_child.attrs["timestamp"], "777");
        let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_clean, refresh.clean);
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn process_group_dirty_node_refreshes_and_emits_update() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let dirty = BinaryNode::new("ib").with_content(vec![
            BinaryNode::new("dirty")
                .with_attr("type", "groups")
                .with_attr("timestamp", "900"),
        ]);

        let process_fut = client.process_group_dirty_node(&connection, &dirty);
        tokio::pin!(process_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["to"], "@g.us");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("groups").with_content(vec![
                        BinaryNode::new("group")
                            .with_attr("id", "123")
                            .with_attr("subject", "Team")
                            .with_content(vec![BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")]),
                    ])])
            },
            &mut process_fut,
        )
        .await;
        let refresh = process_fut.await.unwrap().unwrap();
        assert_eq!(refresh.groups.len(), 1);
        assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_clean, refresh.clean);
        let update = recv_groups_update_event(&mut events).await;
        assert_eq!(update[0].jid, "123@g.us");
        assert_eq!(update[0].fields["source"], "group_dirty_refresh");
        assert_eq!(update[0].fields["subject"], "Team");
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn account_reachout_and_message_capping_use_wmex_queries() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let reachout_fut = client.fetch_account_reachout_timelock(&connection);
        tokio::pin!(reachout_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:mex");
                assert_eq!(node.attrs["to"], "s.whatsapp.net");
                let (query_id, variables) = test_wmex_query(&node);
                assert_eq!(query_id, "23983697327930364");
                assert_eq!(variables, serde_json::json!({}));
                wmex_response_for_query(
                    &node,
                    "xwa2_fetch_account_reachout_timelock",
                    r#"{
                        "is_active": true,
                        "time_enforcement_ends": "1700000000",
                        "enforcement_type": "WEB_COMPANION_ONLY"
                    }"#,
                )
            },
            &mut reachout_fut,
        )
        .await;
        let reachout = reachout_fut.await.unwrap();
        assert!(reachout.is_active);
        assert_eq!(reachout.time_enforcement_ends, Some(1_700_000_000));
        assert_eq!(
            reachout.enforcement_type,
            wa_core::ReachoutTimelockEnforcementType::WebCompanionOnly
        );
        assert_eq!(
            events.recv().await.unwrap(),
            Event::ReachoutTimelockUpdate(reachout)
        );

        let capping_fut = client.fetch_message_capping_info(&connection);
        tokio::pin!(capping_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let (query_id, variables) = test_wmex_query(&node);
                assert_eq!(query_id, "24503548349331633");
                assert_eq!(variables["input"]["type"], "INDIVIDUAL_NEW_CHAT_MSG");
                wmex_response_for_query(
                    &node,
                    "xwa2_message_capping_info",
                    r#"{
                        "total_quota": "50",
                        "used_quota": 12,
                        "capping_status": "FIRST_WARNING"
                    }"#,
                )
            },
            &mut capping_fut,
        )
        .await;
        let capping = capping_fut.await.unwrap();
        assert_eq!(capping.total_quota, Some(50));
        assert_eq!(capping.used_quota, Some(12));
        assert_eq!(
            capping.capping_status,
            Some(wa_core::MessageCappingStatus::FirstWarning)
        );

        let failed_capping_fut = client.fetch_message_capping_info(&connection);
        tokio::pin!(failed_capping_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let (query_id, variables) = test_wmex_query(&node);
                assert_eq!(query_id, "24503548349331633");
                assert_eq!(variables["input"]["type"], "INDIVIDUAL_NEW_CHAT_MSG");
                error_result_for(&node, "429", "rate limited")
            },
            &mut failed_capping_fut,
        )
        .await;
        let err = failed_capping_fut.await.unwrap_err();
        assert!(
            err.to_string()
                .contains("WMex query failed (429): rate limited")
        );
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn refresh_dirty_communities_fetches_communities_then_cleans_group_dirty_bit() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let refresh_fut = client.refresh_dirty_communities(&connection, Some(888));
        tokio::pin!(refresh_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["type"], "get");
                assert_eq!(node.attrs["to"], "@g.us");
                let participating = test_child(&node, "participating");
                assert_child(participating, "participants");
                assert_child(participating, "description");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("communities").with_content(vec![
                        BinaryNode::new("community")
                            .with_attr("id", "123")
                            .with_attr("subject", "Updates")
                            .with_content(vec![
                                BinaryNode::new("parent"),
                                BinaryNode::new("participant")
                                    .with_attr("jid", "111@s.whatsapp.net"),
                            ]),
                    ])])
            },
            &mut refresh_fut,
        )
        .await;

        let refresh = refresh_fut.await.unwrap();
        assert_eq!(refresh.communities.len(), 1);
        assert_eq!(refresh.communities[0].jid, "123@g.us");
        assert_eq!(refresh.communities[0].subject.as_deref(), Some("Updates"));
        assert!(refresh.communities[0].is_community);
        assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        let clean_child = test_child(&refresh.clean, "clean");
        assert_eq!(clean_child.attrs["type"], "groups");
        assert_eq!(clean_child.attrs["timestamp"], "888");
        let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_clean, refresh.clean);
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn process_community_dirty_node_refreshes_and_emits_update() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let dirty = BinaryNode::new("ib").with_content(vec![
            BinaryNode::new("dirty")
                .with_attr("type", "communities")
                .with_attr("timestamp", "901"),
        ]);

        let process_fut = client.process_community_dirty_node(&connection, &dirty);
        tokio::pin!(process_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["to"], "@g.us");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("communities").with_content(vec![
                        BinaryNode::new("community")
                            .with_attr("id", "123")
                            .with_attr("subject", "Updates")
                            .with_content(vec![BinaryNode::new("parent")]),
                    ])])
            },
            &mut process_fut,
        )
        .await;
        let refresh = process_fut.await.unwrap().unwrap();
        assert_eq!(refresh.communities.len(), 1);
        assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(sent_clean, refresh.clean);
        let update = recv_groups_update_event(&mut events).await;
        assert_eq!(update[0].jid, "123@g.us");
        assert_eq!(update[0].fields["source"], "community_dirty_refresh");
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn business_profile_and_catalog_methods_use_business_iqs() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let profile_fut = client.fetch_business_profile(&connection, "123@c.us");
        tokio::pin!(profile_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:biz");
                assert_eq!(node.attrs["to"], "s.whatsapp.net");
                assert_eq!(node.attrs["type"], "get");
                let business_profile = test_child(&node, "business_profile");
                assert_eq!(business_profile.attrs["v"], "244");
                assert_eq!(
                    test_child(business_profile, "profile").attrs["jid"],
                    "123@s.whatsapp.net"
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("business_profile").with_content(
                        vec![
                            BinaryNode::new("profile")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![
                                    BinaryNode::new("address").with_content("1 Main"),
                                    BinaryNode::new("description").with_content("Daily goods"),
                                    BinaryNode::new("website").with_content("https://example.com"),
                                    BinaryNode::new("email").with_content("shop@example.com"),
                                    BinaryNode::new("categories").with_content(vec![
                                        BinaryNode::new("category").with_content("Grocery"),
                                    ]),
                                    BinaryNode::new("business_hours")
                                        .with_attr("timezone", "UTC")
                                        .with_content(vec![
                                            BinaryNode::new("business_hours_config")
                                                .with_attr("day_of_week", "mon")
                                                .with_attr("mode", "specific_hours")
                                                .with_attr("open_time", "540")
                                                .with_attr("close_time", "1020"),
                                        ]),
                                ]),
                        ],
                    )])
            },
            &mut profile_fut,
        )
        .await;
        let profile = profile_fut.await.unwrap().unwrap();
        assert_eq!(profile.jid.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(profile.description, "Daily goods");
        assert_eq!(profile.websites, vec!["https://example.com"]);
        assert_eq!(profile.category.as_deref(), Some("Grocery"));
        assert_eq!(
            profile.business_hours.unwrap().config[0].close_time,
            Some(1020)
        );

        let update = BusinessProfileUpdate::new()
            .with_address("2 Main")
            .with_email("team@example.com")
            .with_description("Open daily")
            .with_websites(["https://example.com"])
            .with_hours(wa_core::BusinessHours {
                timezone: Some("UTC".to_owned()),
                config: vec![
                    wa_core::BusinessHoursConfig::new("mon", "specific_hours")
                        .unwrap()
                        .with_open_close(540, 1020),
                ],
            });
        let update_fut = client.update_business_profile(&connection, update);
        tokio::pin!(update_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:biz");
                assert_eq!(node.attrs["to"], "s.whatsapp.net");
                assert_eq!(node.attrs["type"], "set");
                let profile = test_child(&node, "business_profile");
                assert_eq!(profile.attrs["v"], "3");
                assert_eq!(profile.attrs["mutation_type"], "delta");
                assert_eq!(
                    test_node_text(test_child(profile, "address")).as_deref(),
                    Some("2 Main")
                );
                assert_eq!(
                    test_node_text(test_child(profile, "website")).as_deref(),
                    Some("https://example.com")
                );
                let hours = test_child(profile, "business_hours");
                assert_eq!(hours.attrs["timezone"], "UTC");
                let config = test_child(hours, "business_hours_config");
                assert_eq!(config.attrs["day_of_week"], "mon");
                assert_eq!(config.attrs["open_time"], "540");
                empty_result_for(&node)
            },
            &mut update_fut,
        )
        .await;
        update_fut.await.unwrap();

        let cover_upload =
            wa_core::BusinessCoverPhotoUpload::new("cover-1", "token-1", 1_700_000_000).unwrap();
        let cover_update_fut = client.update_business_cover_photo(&connection, cover_upload);
        tokio::pin!(cover_update_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:biz");
                assert_eq!(node.attrs["to"], "s.whatsapp.net");
                assert_eq!(node.attrs["type"], "set");
                let profile = test_child(&node, "business_profile");
                assert_eq!(profile.attrs["v"], "3");
                assert_eq!(profile.attrs["mutation_type"], "delta");
                let cover = test_child(profile, "cover_photo");
                assert_eq!(cover.attrs["op"], "update");
                assert_eq!(cover.attrs["id"], "cover-1");
                assert_eq!(cover.attrs["token"], "token-1");
                assert_eq!(cover.attrs["ts"], "1700000000");
                empty_result_for(&node)
            },
            &mut cover_update_fut,
        )
        .await;
        assert_eq!(cover_update_fut.await.unwrap(), "cover-1");

        let failed_cover_update = client.update_business_cover_photo(
            &connection,
            wa_core::BusinessCoverPhotoUpload::new("cover-2", "token-2", 1_700_000_001).unwrap(),
        );
        tokio::pin!(failed_cover_update);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let profile = test_child(&node, "business_profile");
                let cover = test_child(profile, "cover_photo");
                assert_eq!(cover.attrs["op"], "update");
                assert_eq!(cover.attrs["id"], "cover-2");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "error")
                    .with_attr("code", "403")
                    .with_attr("text", "denied")
            },
            &mut failed_cover_update,
        )
        .await;
        assert!(failed_cover_update.await.is_err());

        let cover_remove_fut = client.remove_business_cover_photo(&connection, "cover-1");
        tokio::pin!(cover_remove_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:biz");
                let profile = test_child(&node, "business_profile");
                let cover = test_child(profile, "cover_photo");
                assert_eq!(cover.attrs["op"], "delete");
                assert_eq!(cover.attrs["id"], "cover-1");
                empty_result_for(&node)
            },
            &mut cover_remove_fut,
        )
        .await;
        cover_remove_fut.await.unwrap();

        let catalog_query = BusinessCatalogQuery::new("123@c.us")
            .unwrap()
            .with_limit(25)
            .unwrap()
            .with_cursor("cursor")
            .unwrap();
        let catalog_fut = client.fetch_business_catalog(&connection, catalog_query);
        tokio::pin!(catalog_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:biz:catalog");
                assert_eq!(node.attrs["to"], "s.whatsapp.net");
                assert_eq!(node.attrs["type"], "get");
                let catalog = test_child(&node, "product_catalog");
                assert_eq!(catalog.attrs["jid"], "123@s.whatsapp.net");
                assert_eq!(catalog.attrs["allow_shop_source"], "true");
                assert_eq!(
                    test_node_text(test_child(catalog, "limit")).as_deref(),
                    Some("25")
                );
                assert_eq!(
                    test_node_text(test_child(catalog, "after")).as_deref(),
                    Some("cursor")
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("product_catalog").with_content(vec![
                            BinaryNode::new("product")
                                .with_attr("is_hidden", "true")
                                .with_content(vec![
                                    BinaryNode::new("id").with_content("sku-1"),
                                    BinaryNode::new("name").with_content("Widget"),
                                    BinaryNode::new("retailer_id").with_content("retailer"),
                                    BinaryNode::new("description").with_content("Useful"),
                                    BinaryNode::new("price").with_content("12345000"),
                                    BinaryNode::new("currency").with_content("USD"),
                                    BinaryNode::new("media").with_content(vec![
                                        BinaryNode::new("image").with_content(vec![
                                            BinaryNode::new("request_image_url")
                                                .with_content("https://img/small"),
                                            BinaryNode::new("original_image_url")
                                                .with_content("https://img/full"),
                                        ]),
                                    ]),
                                    BinaryNode::new("status_info").with_content(vec![
                                        BinaryNode::new("status").with_content("APPROVED"),
                                    ]),
                                ]),
                            BinaryNode::new("paging").with_content(vec![
                                BinaryNode::new("after").with_content("next"),
                            ]),
                        ])])
            },
            &mut catalog_fut,
        )
        .await;
        let catalog = catalog_fut.await.unwrap();
        assert_eq!(catalog.next_page_cursor.as_deref(), Some("next"));
        assert_eq!(catalog.products.len(), 1);
        assert_eq!(catalog.products[0].id, "sku-1");
        assert_eq!(catalog.products[0].price, 12_345_000);
        assert!(catalog.products[0].is_hidden);
        assert_eq!(
            catalog.products[0].image_urls.requested.as_deref(),
            Some("https://img/small")
        );

        let create = BusinessProductCreate::new("Widget", "Useful", 12_345_000, "USD")
            .unwrap()
            .with_retailer_id("retailer")
            .with_url("https://example.com/widget")
            .with_images([wa_core::BusinessProductImage::new("https://img/uploaded").unwrap()])
            .with_origin(wa_core::BusinessProductOrigin::country_code("US").unwrap())
            .hidden(true);
        let create_fut = client.create_business_product(&connection, create);
        tokio::pin!(create_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:biz:catalog");
                assert_eq!(node.attrs["to"], "s.whatsapp.net");
                assert_eq!(node.attrs["type"], "set");
                let add = test_child(&node, "product_catalog_add");
                assert_eq!(add.attrs["v"], "1");
                let product = test_child(add, "product");
                assert_eq!(product.attrs["is_hidden"], "true");
                assert_eq!(
                    test_node_text(test_child(product, "name")).as_deref(),
                    Some("Widget")
                );
                assert_eq!(
                    test_node_text(test_child(product, "price")).as_deref(),
                    Some("12345000")
                );
                let image = test_child(test_child(product, "media"), "image");
                assert_eq!(
                    test_node_text(test_child(image, "url")).as_deref(),
                    Some("https://img/uploaded")
                );
                let compliance = test_child(product, "compliance_info");
                assert_eq!(
                    test_node_text(test_child(compliance, "country_code_origin")).as_deref(),
                    Some("US")
                );
                business_product_mutation_response(&node, "product_catalog_add")
            },
            &mut create_fut,
        )
        .await;
        let created = create_fut.await.unwrap();
        assert_eq!(created.id, "sku-1");
        assert_eq!(created.name, "Widget");

        let update = BusinessProductUpdate::new()
            .with_name("Widget v2")
            .with_price(22)
            .hidden(false);
        let update_fut = client.update_business_product(&connection, "sku-1", update);
        tokio::pin!(update_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let edit = test_child(&node, "product_catalog_edit");
                assert_eq!(edit.attrs["v"], "1");
                let product = test_child(edit, "product");
                assert_eq!(
                    test_node_text(test_child(product, "id")).as_deref(),
                    Some("sku-1")
                );
                assert_eq!(
                    test_node_text(test_child(product, "name")).as_deref(),
                    Some("Widget v2")
                );
                assert_eq!(product.attrs["is_hidden"], "false");
                business_product_mutation_response(&node, "product_catalog_edit")
            },
            &mut update_fut,
        )
        .await;
        let updated = update_fut.await.unwrap();
        assert_eq!(updated.id, "sku-1");

        let delete_fut = client.delete_business_products(&connection, ["sku-1", "sku-2"]);
        tokio::pin!(delete_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let delete = test_child(&node, "product_catalog_delete");
                assert_eq!(delete.attrs["v"], "1");
                let products = test_children(delete, "product");
                assert_eq!(products.len(), 2);
                assert_eq!(
                    test_node_text(test_child(products[0], "id")).as_deref(),
                    Some("sku-1")
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("product_catalog_delete").with_attr("deleted_count", "2"),
                    ])
            },
            &mut delete_fut,
        )
        .await;
        assert_eq!(delete_fut.await.unwrap(), 2);

        let collections_query = BusinessCollectionsQuery::new("123@c.us")
            .unwrap()
            .with_collection_limit(12)
            .unwrap()
            .with_item_limit(5)
            .unwrap();
        let collections_fut = client.fetch_business_collections(&connection, collections_query);
        tokio::pin!(collections_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:biz:catalog");
                assert_eq!(node.attrs["smax_id"], "35");
                let collections = test_child(&node, "collections");
                assert_eq!(collections.attrs["biz_jid"], "123@s.whatsapp.net");
                assert_eq!(
                    test_node_text(test_child(collections, "collection_limit")).as_deref(),
                    Some("12")
                );
                assert_eq!(
                    test_node_text(test_child(collections, "item_limit")).as_deref(),
                    Some("5")
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("collections").with_content(vec![
                        BinaryNode::new("collection").with_content(vec![
                            BinaryNode::new("id").with_content("collection-1"),
                            BinaryNode::new("name").with_content("Featured"),
                            business_product_node(),
                            BinaryNode::new("status_info").with_content(vec![
                                BinaryNode::new("status").with_content("APPROVED"),
                                BinaryNode::new("can_appeal").with_content("true"),
                            ]),
                        ]),
                    ])])
            },
            &mut collections_fut,
        )
        .await;
        let collections = collections_fut.await.unwrap();
        assert_eq!(collections.len(), 1);
        assert_eq!(collections[0].id, "collection-1");
        assert_eq!(collections[0].products[0].id, "sku-1");
        assert!(collections[0].status.can_appeal);

        let order_fut = client.fetch_business_order_details(&connection, "order-1", "token");
        tokio::pin!(order_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "fb:thrift_iq");
                assert_eq!(node.attrs["smax_id"], "5");
                let order = test_child(&node, "order");
                assert_eq!(order.attrs["op"], "get");
                assert_eq!(order.attrs["id"], "order-1");
                assert_eq!(
                    test_node_text(test_child(order, "token")).as_deref(),
                    Some("token")
                );
                let dimensions = test_child(order, "image_dimensions");
                assert_eq!(
                    test_node_text(test_child(dimensions, "width")).as_deref(),
                    Some("100")
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("order").with_content(vec![
                        BinaryNode::new("product").with_content(vec![
                            BinaryNode::new("id").with_content("sku-1"),
                            BinaryNode::new("name").with_content("Widget"),
                            BinaryNode::new("image").with_content(vec![
                                BinaryNode::new("url").with_content("https://img"),
                            ]),
                            BinaryNode::new("price").with_content("12345000"),
                            BinaryNode::new("currency").with_content("USD"),
                            BinaryNode::new("quantity").with_content("2"),
                        ]),
                        BinaryNode::new("price").with_content(vec![
                            BinaryNode::new("total").with_content("24690000"),
                            BinaryNode::new("currency").with_content("USD"),
                        ]),
                    ])])
            },
            &mut order_fut,
        )
        .await;
        let order = order_fut.await.unwrap();
        assert_eq!(order.price.total, 24_690_000);
        assert_eq!(order.products[0].quantity, 2);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn business_product_mutations_upload_images_before_sending_iqs() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let transport = ClientMediaUploadTransport::default();
        let transfer = wa_core::MediaTransfer::new(transport.clone());

        let create = BusinessProductCreate::new("Widget", "Useful", 12_345_000, "USD").unwrap();
        let create_fut = client.create_business_product_with_image_bytes(
            &connection,
            &transfer,
            create,
            vec![b"image a".as_slice(), b"image b".as_slice()],
            Some("media.test"),
        );
        tokio::pin!(create_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let add = test_child(&node, "product_catalog_add");
                let product = test_child(add, "product");
                let images = test_children(test_child(product, "media"), "image");
                assert_eq!(images.len(), 2);
                assert_eq!(
                    test_node_text(test_child(images[0], "url")).as_deref(),
                    Some("https://media.test/client/upload/0")
                );
                assert_eq!(
                    test_node_text(test_child(images[1], "url")).as_deref(),
                    Some("https://media.test/client/upload/1")
                );
                business_product_mutation_response(&node, "product_catalog_add")
            },
            &mut create_fut,
        )
        .await;
        assert_eq!(create_fut.await.unwrap().id, "sku-1");

        {
            let uploads = transport.uploads.lock().unwrap();
            assert_eq!(uploads.len(), 2);
            assert_eq!(uploads[0].kind, wa_core::MediaKind::ProductCatalogImage);
            assert_eq!(uploads[1].kind, wa_core::MediaKind::ProductCatalogImage);
        }

        let input = test_client_media_path("product-update-image");
        tokio::fs::write(&input, b"updated image").await.unwrap();
        let update = BusinessProductUpdate::new().with_name("Widget v2");
        let update_fut = client.update_business_product_with_image_files(
            &connection,
            &transfer,
            "sku-1",
            update,
            [&input],
            Some("media.test"),
        );
        tokio::pin!(update_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let edit = test_child(&node, "product_catalog_edit");
                let product = test_child(edit, "product");
                assert_eq!(
                    test_node_text(test_child(product, "id")).as_deref(),
                    Some("sku-1")
                );
                assert_eq!(
                    test_node_text(test_child(product, "name")).as_deref(),
                    Some("Widget v2")
                );
                let image = test_child(test_child(product, "media"), "image");
                assert_eq!(
                    test_node_text(test_child(image, "url")).as_deref(),
                    Some("https://media.test/client/upload/2")
                );
                business_product_mutation_response(&node, "product_catalog_edit")
            },
            &mut update_fut,
        )
        .await;
        assert_eq!(update_fut.await.unwrap().id, "sku-1");
        {
            let uploads = transport.uploads.lock().unwrap();
            assert_eq!(uploads.len(), 3);
            assert_eq!(uploads[2].kind, wa_core::MediaKind::ProductCatalogImage);
        }

        let _ = tokio::fs::remove_file(&input).await;
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn newsletter_wmex_methods_send_queries_and_parse_results() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let metadata_fut = client.fetch_newsletter_metadata(
            &connection,
            NewsletterMetadataLookup::jid("abc@newsletter"),
        );
        tokio::pin!(metadata_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:mex");
                assert_eq!(node.attrs["to"], "s.whatsapp.net");
                let (query_id, variables) = test_wmex_query(&node);
                assert_eq!(query_id, "6563316087068696");
                assert_eq!(variables["input"]["key"], "abc@newsletter");
                assert_eq!(variables["input"]["type"], "JID");
                wmex_response_for_query(
                    &node,
                    "xwa2_newsletter",
                    r#"{
                        "result": {
                            "id": "abc@newsletter",
                            "thread_metadata": {
                                "name": { "text": "Updates" },
                                "description": { "text": "Daily" },
                                "subscribers_count": "9"
                            },
                            "viewer_metadata": { "mute": "OFF", "role": "SUBSCRIBER" }
                        }
                    }"#,
                )
            },
            &mut metadata_fut,
        )
        .await;
        let metadata = metadata_fut.await.unwrap().unwrap();
        assert_eq!(metadata.id, "abc@newsletter");
        assert_eq!(metadata.name.as_deref(), Some("Updates"));
        assert_eq!(metadata.subscribers, Some(9));

        let follow_fut = client.follow_newsletter(&connection, "abc@newsletter");
        tokio::pin!(follow_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let (query_id, variables) = test_wmex_query(&node);
                assert_eq!(query_id, "24404358912487870");
                assert_eq!(variables["newsletter_id"], "abc@newsletter");
                wmex_response_for_query(&node, "xwa2_newsletter_join_v2", "{}")
            },
            &mut follow_fut,
        )
        .await;
        follow_fut.await.unwrap();

        let subscribers_fut =
            client.fetch_newsletter_subscriber_count(&connection, "abc@newsletter");
        tokio::pin!(subscribers_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let (query_id, _) = test_wmex_query(&node);
                assert_eq!(query_id, "9783111038412085");
                wmex_response_for_query(
                    &node,
                    "xwa2_newsletter_subscribers",
                    r#"{ "subscribers": "12" }"#,
                )
            },
            &mut subscribers_fut,
        )
        .await;
        assert_eq!(subscribers_fut.await.unwrap(), 12);

        let admin_fut = client.fetch_newsletter_admin_count(&connection, "abc@newsletter");
        tokio::pin!(admin_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let (query_id, _) = test_wmex_query(&node);
                assert_eq!(query_id, "7130823597031706");
                wmex_response_for_query(&node, "xwa2_newsletter_admin", r#"{ "admin_count": 2 }"#)
            },
            &mut admin_fut,
        )
        .await;
        assert_eq!(admin_fut.await.unwrap(), 2);
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn newsletter_direct_methods_use_newsletter_iqs_and_message_reactions() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let messages_fut =
            client.fetch_newsletter_messages(&connection, "abc@newsletter", 5, Some(10), Some(20));
        tokio::pin!(messages_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "newsletter");
                assert_eq!(node.attrs["to"], "abc@newsletter");
                assert_eq!(node.attrs["type"], "get");
                let updates = test_child(&node, "message_updates");
                assert_eq!(updates.attrs["count"], "5");
                assert_eq!(updates.attrs["since"], "10");
                assert_eq!(updates.attrs["after"], "20");
                let message = wa_proto::proto::Message {
                    conversation: Some("newsletter text".to_owned()),
                    ..wa_proto::proto::Message::default()
                };
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("message_updates").with_content(vec![
                        BinaryNode::new("message")
                            .with_attr("message_id", "server-1")
                            .with_attr("t", "1700000000")
                            .with_content(vec![
                                BinaryNode::new("plaintext").with_content(message.encode_to_vec()),
                            ]),
                    ])])
            },
            &mut messages_fut,
        )
        .await;
        let messages = messages_fut.await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].key.remote_jid, "abc@newsletter");
        assert_eq!(messages[0].key.id, "server-1");
        assert_eq!(messages[0].timestamp, Some(1_700_000_000));
        assert_eq!(messages[0].fields["kind"], "newsletter");
        assert_eq!(messages[0].fields["payload_kind"], "plaintext");
        assert_eq!(messages[0].fields["source"], "newsletter_fetch");
        let decoded =
            wa_proto::proto::Message::decode(messages[0].payload.clone().unwrap()).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("newsletter text"));

        let live_fut = client.subscribe_newsletter_live_updates(&connection, "abc@newsletter");
        tokio::pin!(live_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "newsletter");
                assert_eq!(node.attrs["type"], "set");
                assert!(test_child(&node, "live_updates").attrs.is_empty());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("live_updates").with_attr("duration", "3600"),
                    ])
            },
            &mut live_fut,
        )
        .await;
        assert_eq!(live_fut.await.unwrap().unwrap().duration, "3600");

        let reaction_fut = client.react_to_newsletter_message(
            &connection,
            "abc@newsletter",
            "server-1",
            Some("+"),
        );
        tokio::pin!(reaction_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.tag, "message");
                assert_eq!(node.attrs["to"], "abc@newsletter");
                assert_eq!(node.attrs["type"], "reaction");
                assert_eq!(node.attrs["server_id"], "server-1");
                assert_eq!(test_child(&node, "reaction").attrs["code"], "+");
                BinaryNode::new("message")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut reaction_fut,
        )
        .await;
        reaction_fut.await.unwrap();
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn app_state_patch_bundle_upload_uses_encoded_patch_and_previous_version() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let chat_patch = wa_core::build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation = wa_core::encrypt_chat_mutation_patch_with_iv(
            &chat_patch,
            &key_id,
            &key_data,
            &[3u8; 16],
        )
        .unwrap();
        let previous = wa_core::AppStatePatchState::new(
            3,
            Bytes::from(vec![0u8; wa_core::APP_STATE_HASH_LEN]),
        )
        .unwrap();
        let bundle = wa_core::build_app_state_patch_bundle(
            AppStateCollection::RegularLow,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();
        let upload_fut = client.upload_app_state_patch_bundle(&connection, &bundle);
        tokio::pin!(upload_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular_low");
                assert_eq!(collection.attrs["version"], "3");
                assert_eq!(collection.attrs["return_snapshot"], "false");
                assert_eq!(
                    test_node_bytes(test_child(collection, "patch")).as_deref(),
                    Some(bundle.encoded_patch.as_ref())
                );
                empty_result_for(&node)
            },
            &mut upload_fut,
        )
        .await;
        assert_eq!(upload_fut.await.unwrap().attrs["type"], "result");

        let failed_upload_fut = client.upload_app_state_patch_bundle(&connection, &bundle);
        tokio::pin!(failed_upload_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular_low");
                error_result_for(&node, "500", "patch rejected")
            },
            &mut failed_upload_fut,
        )
        .await;
        assert!(failed_upload_fut.await.is_err());
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn apply_decoded_app_state_patch_persists_state_and_emits_batch() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let previous = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(previous.version(), 0);

        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let patch =
            wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
                .unwrap();
        let mutation =
            wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let bundle = wa_core::build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();
        let decoded = wa_core::decode_app_state_patch(
            AppStateCollection::Regular,
            &previous,
            &bundle.patch,
            &key_data,
        )
        .unwrap();

        let batch = client
            .apply_decoded_app_state_patch(&decoded, false)
            .await
            .unwrap();
        assert_eq!(batch.quick_replies_update.len(), 1);
        assert_eq!(batch.quick_replies_update[0].id, "qr-1");

        let emitted = recv_batch_event(&mut events).await;
        assert_eq!(emitted.quick_replies_update.len(), 1);
        assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

        let stored = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(stored.version(), bundle.next_state.version());
        assert_eq!(stored.hash(), bundle.next_state.hash());
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn sync_and_apply_app_state_persists_inline_patches_and_emits_batch() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let previous = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let patch =
            wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
                .unwrap();
        let mutation =
            wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let bundle = wa_core::build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();
        let encoded_patch = bundle.patch.encode_to_vec();
        let expected_version = bundle.next_state.version();
        let expected_hash = bundle.next_state.hash().clone();

        let sync_fut = client.sync_and_apply_app_state(
            &connection,
            [AppStateCollectionRequest::new(
                AppStateCollection::Regular,
                0,
            )],
            &key_data,
            false,
        );
        tokio::pin!(sync_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular");
                assert_eq!(collection.attrs["version"], "0");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("sync").with_content(vec![
                        BinaryNode::new("collection")
                            .with_attr("name", "regular")
                            .with_attr("version", expected_version.to_string())
                            .with_content(vec![BinaryNode::new("patches").with_content(vec![
                                BinaryNode::new("patch").with_content(encoded_patch),
                            ])]),
                    ])])
            },
            &mut sync_fut,
        )
        .await;

        let outcome = sync_fut.await.unwrap();
        assert_eq!(outcome.batches.len(), 1);
        assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
        assert_eq!(outcome.collections.len(), 1);
        assert_eq!(
            outcome.collections[0].collection,
            AppStateCollection::Regular
        );
        assert_eq!(outcome.collections[0].applied_patches, 1);
        assert_eq!(outcome.collections[0].emitted_batches, 1);
        assert!(!outcome.collections[0].snapshot_pending);
        assert!(outcome.pending_snapshots.is_empty());

        let emitted = recv_batch_event(&mut events).await;
        assert_eq!(emitted.quick_replies_update.len(), 1);
        assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

        let stored = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(stored.version(), expected_version);
        assert_eq!(stored.hash(), &expected_hash);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn sync_and_apply_app_state_until_current_follows_inline_patch_pages() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let previous = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];

        let quick_patch =
            wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
                .unwrap();
        let quick_mutation = wa_core::encrypt_chat_mutation_patch_with_iv(
            &quick_patch,
            &key_id,
            &key_data,
            &[3u8; 16],
        )
        .unwrap();
        let quick_bundle = wa_core::build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &previous,
            &key_id,
            &key_data,
            [quick_mutation],
        )
        .unwrap();

        let label_patch =
            wa_core::build_label_edit_patch(LabelEditMutation::new("7", "Important"), 20).unwrap();
        let label_mutation = wa_core::encrypt_chat_mutation_patch_with_iv(
            &label_patch,
            &key_id,
            &key_data,
            &[4u8; 16],
        )
        .unwrap();
        let label_bundle = wa_core::build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &quick_bundle.next_state,
            &key_id,
            &key_data,
            [label_mutation],
        )
        .unwrap();
        let quick_patch_bytes = quick_bundle.patch.encode_to_vec();
        let label_patch_bytes = label_bundle.patch.encode_to_vec();
        let quick_version = quick_bundle.next_state.version();
        let label_version = label_bundle.next_state.version();
        let label_hash = label_bundle.next_state.hash().clone();

        let sync_fut = client.sync_and_apply_app_state_until_current(
            &connection,
            [AppStateCollection::Regular],
            &key_data,
            false,
            4,
        );
        tokio::pin!(sync_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular");
                assert_eq!(collection.attrs["version"], "0");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("sync").with_content(vec![
                        BinaryNode::new("collection")
                            .with_attr("name", "regular")
                            .with_attr("version", quick_version.to_string())
                            .with_attr("has_more_patches", "true")
                            .with_content(vec![BinaryNode::new("patches").with_content(vec![
                                BinaryNode::new("patch").with_content(quick_patch_bytes),
                            ])]),
                    ])])
            },
            &mut sync_fut,
        )
        .await;
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular");
                assert_eq!(collection.attrs["version"], quick_version.to_string());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("sync").with_content(vec![
                        BinaryNode::new("collection")
                            .with_attr("name", "regular")
                            .with_attr("version", label_version.to_string())
                            .with_content(vec![BinaryNode::new("patches").with_content(vec![
                                BinaryNode::new("patch").with_content(label_patch_bytes),
                            ])]),
                    ])])
            },
            &mut sync_fut,
        )
        .await;

        let outcome = sync_fut.await.unwrap();
        assert_eq!(outcome.batches.len(), 2);
        assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
        assert_eq!(outcome.batches[1].labels_edit[0].id, "7");
        assert_eq!(outcome.collections.len(), 2);
        assert_eq!(outcome.collections[0].final_version, quick_version);
        assert!(outcome.collections[0].has_more_patches);
        assert_eq!(outcome.collections[1].final_version, label_version);
        assert!(!outcome.collections[1].has_more_patches);

        let first = recv_batch_event(&mut events).await;
        assert_eq!(first.quick_replies_update[0].id, "qr-1");
        let second = recv_batch_event(&mut events).await;
        assert_eq!(second.labels_edit[0].id, "7");

        let stored = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(stored.version(), label_version);
        assert_eq!(stored.hash(), &label_hash);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn sync_with_store_keys_blocks_missing_key_then_retries_after_key_arrives() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let previous = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let patch =
            wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
                .unwrap();
        let mutation =
            wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let bundle = wa_core::build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();
        let encoded_patch = bundle.patch.encode_to_vec();
        let expected_version = bundle.next_state.version();
        let expected_hash = bundle.next_state.hash().clone();

        let blocked_fut = client.sync_and_apply_app_state_until_current_with_store_keys(
            &connection,
            [AppStateCollection::Regular],
            false,
            3,
        );
        tokio::pin!(blocked_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular");
                assert_eq!(collection.attrs["version"], "0");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("sync").with_content(vec![
                        BinaryNode::new("collection")
                            .with_attr("name", "regular")
                            .with_attr("version", expected_version.to_string())
                            .with_attr("has_more_patches", "true")
                            .with_content(vec![BinaryNode::new("patches").with_content(vec![
                                BinaryNode::new("patch").with_content(encoded_patch.clone()),
                            ])]),
                    ])])
            },
            &mut blocked_fut,
        )
        .await;
        let blocked = blocked_fut.await.unwrap();
        assert!(blocked.batches.is_empty());
        assert_eq!(blocked.blocked.len(), 1);
        assert_eq!(blocked.blocked[0].collection, AppStateCollection::Regular);
        assert_eq!(blocked.blocked[0].key_id, Bytes::copy_from_slice(&key_id));
        assert_eq!(blocked.blocked[0].previous_version, 0);
        assert_eq!(
            client
                .load_app_state_patch_state(AppStateCollection::Regular)
                .await
                .unwrap()
                .version(),
            0
        );

        let key_share_message = wa_proto::proto::Message {
            protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
                r#type: Some(
                    wa_proto::proto::message::protocol_message::Type::AppStateSyncKeyShare as i32,
                ),
                app_state_sync_key_share: Some(wa_proto::proto::message::AppStateSyncKeyShare {
                    keys: vec![wa_proto::proto::message::AppStateSyncKey {
                        key_id: Some(wa_proto::proto::message::AppStateSyncKeyId {
                            key_id: Some(Bytes::copy_from_slice(&key_id)),
                        }),
                        key_data: Some(wa_proto::proto::message::AppStateSyncKeyData {
                            key_data: Some(Bytes::copy_from_slice(&key_data)),
                            fingerprint: None,
                            timestamp: None,
                        }),
                    }],
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let key_share_event = Event::MessagesUpsert(vec![
            MessageEvent::new(wa_core::MessageEventKey::new(
                "own@s.whatsapp.net",
                "key-share",
                None,
            ))
            .with_payload(Bytes::from(key_share_message.encode_to_vec()))
            .with_field("from_me", "true"),
        ]);
        let key_share_events = [key_share_event];
        let retry_fut =
            client.handle_app_state_sync_key_share_events(&connection, &key_share_events, false, 3);
        tokio::pin!(retry_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular");
                assert_eq!(collection.attrs["version"], "0");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("sync").with_content(vec![
                        BinaryNode::new("collection")
                            .with_attr("name", "regular")
                            .with_attr("version", expected_version.to_string())
                            .with_content(vec![BinaryNode::new("patches").with_content(vec![
                                BinaryNode::new("patch").with_content(encoded_patch),
                            ])]),
                    ])])
            },
            &mut retry_fut,
        )
        .await;
        let applied = retry_fut.await.unwrap();
        assert_eq!(
            client
                .load_app_state_sync_key_data(&key_id)
                .await
                .unwrap()
                .unwrap(),
            key_data.to_vec()
        );
        assert!(applied.blocked.is_empty());
        assert_eq!(applied.batches.len(), 1);
        assert_eq!(applied.batches[0].quick_replies_update[0].id, "qr-1");
        let emitted = recv_batch_event(&mut events).await;
        assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

        let stored = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(stored.version(), expected_version);
        assert_eq!(stored.hash(), &expected_hash);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn sync_recover_and_apply_app_state_until_current_downloads_snapshot() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];

        let patch =
            wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
                .unwrap();
        let mutation =
            wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let expected_state = AppStatePatchState::empty()
            .apply_hash_mutations_at_version(
                11,
                [wa_core::AppStateHashMutation::from_encrypted(&mutation).unwrap()],
            )
            .unwrap();
        let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
        let snapshot_mac = wa_crypto::app_state_snapshot_mac(
            expected_state.hash(),
            11,
            AppStateCollection::Regular.name(),
            &keys,
        )
        .unwrap();
        let snapshot = wa_proto::proto::SyncdSnapshot {
            version: Some(wa_proto::proto::SyncdVersion { version: Some(11) }),
            records: vec![mutation.mutation.record.clone().unwrap()],
            mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
            key_id: Some(wa_proto::proto::KeyId {
                id: Some(Bytes::copy_from_slice(&key_id)),
            }),
        };
        let snapshot_bytes = Bytes::from(snapshot.encode_to_vec());
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &snapshot_bytes,
            wa_crypto::MediaKind::AppState,
            &[6u8; 32],
        )
        .unwrap();
        let snapshot_ref = wa_core::ExternalBlobReference {
            media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
            direct_path: Some("/app-state/snapshot".to_owned()),
            handle: None,
            file_size_bytes: Some(encrypted.file_length),
            file_sha256: Some(encrypted.file_sha256.clone()),
            file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
        };
        let snapshot_ref_bytes = Bytes::from(snapshot_ref.encode_to_vec());
        let transport = HistoryDownloadTransport::default();
        transport.add_download(
            "https://snapshot.test/app-state/snapshot",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = wa_core::MediaTransfer::new(transport);

        let sync_fut = client.sync_recover_and_apply_app_state_until_current(
            &connection,
            &transfer,
            [AppStateCollection::Regular],
            AppStateSyncRecoveryOptions::new(&key_data, 2)
                .with_initial_sync(true)
                .with_fallback_host("snapshot.test"),
        );
        tokio::pin!(sync_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let collection = test_child(test_child(&node, "sync"), "collection");
                assert_eq!(collection.attrs["name"], "regular");
                assert_eq!(collection.attrs["version"], "0");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("sync").with_content(vec![
                        BinaryNode::new("collection")
                            .with_attr("name", "regular")
                            .with_attr("version", "0")
                            .with_content(vec![
                                BinaryNode::new("snapshot").with_content(snapshot_ref_bytes),
                            ]),
                    ])])
            },
            &mut sync_fut,
        )
        .await;

        let outcome = sync_fut.await.unwrap();
        assert!(outcome.pending_snapshots.is_empty());
        assert_eq!(outcome.batches.len(), 1);
        assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
        assert_eq!(outcome.collections.len(), 2);
        assert!(outcome.collections[0].snapshot_pending);
        assert_eq!(outcome.collections[1].final_version, 11);
        assert!(!outcome.collections[1].snapshot_pending);

        let emitted = recv_batch_event(&mut events).await;
        assert_eq!(emitted.quick_replies_update.len(), 1);
        assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

        let stored = client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(stored.version(), expected_state.version());
        assert_eq!(stored.hash(), expected_state.hash());
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn high_level_chat_mutation_methods_build_and_upload_patch_bundles() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let previous = wa_core::AppStatePatchState::new(
            3,
            Bytes::from(vec![0u8; wa_core::APP_STATE_HASH_LEN]),
        )
        .unwrap();
        let upload = AppStateMutationUpload::new(&previous, &key_id, &key_data);

        let pin_fut = client.set_chat_pinned(&connection, "123@s.whatsapp.net", true, 13, upload);
        tokio::pin!(pin_fut);
        let sent_frame = tokio::select! {
            _ = &mut pin_fut => panic!("pin chat mutation completed before mock response"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let node = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
        let collection = test_child(test_child(&node, "sync"), "collection");
        assert_eq!(collection.attrs["name"], "regular_low");
        assert_eq!(collection.attrs["version"], "3");
        let patch_bytes = test_node_bytes(test_child(collection, "patch")).unwrap();
        let patch = wa_proto::proto::SyncdPatch::decode(patch_bytes.as_ref()).unwrap();
        assert_eq!(
            patch.version.as_ref().and_then(|version| version.version),
            Some(4)
        );
        assert_eq!(patch.mutations.len(), 1);
        assert_eq!(
            patch.key_id.as_ref().and_then(|key| key.id.as_deref()),
            Some(key_id.as_slice())
        );
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();

        let bundle = pin_fut.await.unwrap();
        assert_eq!(bundle.collection, AppStateCollection::RegularLow);
        assert_eq!(bundle.previous_version, 3);
        assert_eq!(bundle.next_state.version(), 4);
        assert_eq!(bundle.patch.mutations.len(), 1);

        let delete_fut = client.delete_chat(&connection, "123@s.whatsapp.net", None, 15, upload);
        tokio::pin!(delete_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut delete_fut,
            "delete chat",
            AppStateCollection::RegularHigh,
            3,
        )
        .await;
        assert_eq!(
            patch.version.as_ref().and_then(|version| version.version),
            Some(4)
        );
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        let bundle = delete_fut.await.unwrap();
        assert_eq!(bundle.collection, AppStateCollection::RegularHigh);
        assert_eq!(bundle.previous_version, 3);
        assert_eq!(bundle.next_state.version(), 4);

        let key = MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("msg-1".to_owned()),
            participant: None,
        };
        let star_fut = client.set_message_starred(&connection, key, true, 16, upload);
        tokio::pin!(star_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut star_fut,
            "star message",
            AppStateCollection::RegularLow,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        let bundle = star_fut.await.unwrap();
        assert_eq!(bundle.collection, AppStateCollection::RegularLow);
        assert_eq!(bundle.next_state.version(), 4);

        let profile_name_fut = client.update_profile_name(&connection, "Agent", 17, upload);
        tokio::pin!(profile_name_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut profile_name_fut,
            "profile name",
            AppStateCollection::CriticalBlock,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        let bundle = profile_name_fut.await.unwrap();
        assert_eq!(bundle.collection, AppStateCollection::CriticalBlock);
        assert_eq!(bundle.next_state.version(), 4);

        let contact = ContactSyncAction::new()
            .with_full_name("Agent Smith")
            .with_pn_jid("123@s.whatsapp.net");
        let contact_fut =
            client.update_contact(&connection, "123@s.whatsapp.net", contact, 18, upload);
        tokio::pin!(contact_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut contact_fut,
            "contact",
            AppStateCollection::CriticalUnblockLow,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        let bundle = contact_fut.await.unwrap();
        assert_eq!(bundle.collection, AppStateCollection::CriticalUnblockLow);
        assert_eq!(bundle.next_state.version(), 4);

        let remove_contact_fut =
            client.remove_contact(&connection, "123@s.whatsapp.net", 19, upload);
        tokio::pin!(remove_contact_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut remove_contact_fut,
            "remove contact",
            AppStateCollection::CriticalUnblockLow,
            3,
        )
        .await;
        assert_eq!(
            patch.mutations[0].operation,
            Some(wa_core::AppStatePatchOperation::Remove.proto_value())
        );
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        let bundle = remove_contact_fut.await.unwrap();
        assert_eq!(bundle.collection, AppStateCollection::CriticalUnblockLow);

        let quick_reply = QuickReplyMutation::new("1700000000", "/hi", "hello");
        let quick_reply_fut = client.upsert_quick_reply(&connection, quick_reply, 20, upload);
        tokio::pin!(quick_reply_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut quick_reply_fut,
            "quick reply",
            AppStateCollection::Regular,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            quick_reply_fut.await.unwrap().collection,
            AppStateCollection::Regular
        );

        let delete_quick_reply_fut =
            client.delete_quick_reply(&connection, "1700000000", 21, upload);
        tokio::pin!(delete_quick_reply_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut delete_quick_reply_fut,
            "delete quick reply",
            AppStateCollection::Regular,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            delete_quick_reply_fut.await.unwrap().collection,
            AppStateCollection::Regular
        );

        let label = LabelEditMutation::new("7", "Important");
        let label_fut = client.upsert_label(&connection, label, 22, upload);
        tokio::pin!(label_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut label_fut,
            "label",
            AppStateCollection::Regular,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            label_fut.await.unwrap().collection,
            AppStateCollection::Regular
        );

        let delete_label_fut = client.delete_label(&connection, "7", 23, upload);
        tokio::pin!(delete_label_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut delete_label_fut,
            "delete label",
            AppStateCollection::Regular,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            delete_label_fut.await.unwrap().collection,
            AppStateCollection::Regular
        );

        let chat_label_fut =
            client.set_chat_label(&connection, "123@s.whatsapp.net", "7", true, 24, upload);
        tokio::pin!(chat_label_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut chat_label_fut,
            "chat label",
            AppStateCollection::Regular,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            chat_label_fut.await.unwrap().collection,
            AppStateCollection::Regular
        );

        let message_label_fut = client.set_message_label(
            &connection,
            MessageLabelTarget::new("123@s.whatsapp.net", "7", "msg-1"),
            false,
            25,
            upload,
        );
        tokio::pin!(message_label_fut);
        let (node, patch) = recv_app_state_upload(
            &mut sink_rx,
            &mut message_label_fut,
            "message label",
            AppStateCollection::Regular,
            3,
        )
        .await;
        assert_eq!(patch.mutations.len(), 1);
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&empty_result_for(&node)).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            message_label_fut.await.unwrap().collection,
            AppStateCollection::Regular
        );

        let failed_pin_fut =
            client.set_chat_pinned(&connection, "123@s.whatsapp.net", false, 14, upload);
        tokio::pin!(failed_pin_fut);
        let sent_frame = tokio::select! {
            _ = &mut failed_pin_fut => panic!("failed pin chat mutation completed before mock response"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let node = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
        let collection = test_child(test_child(&node, "sync"), "collection");
        assert_eq!(collection.attrs["name"], "regular_low");
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(&error_result_for(&node, "500", "patch rejected")).unwrap(),
            ))
            .await
            .unwrap();
        assert!(failed_pin_fut.await.is_err());
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn group_metadata_create_and_participants_use_group_iqs() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let metadata_fut = client.fetch_group_metadata(&connection, "123@g.us");
        tokio::pin!(metadata_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "get");
                assert_eq!(test_child(&node, "query").attrs["request"], "interactive");
                group_metadata_response(&node, "123", "Team")
            },
            &mut metadata_fut,
        )
        .await;
        let metadata = metadata_fut.await.unwrap();
        assert_eq!(metadata.jid, "123@g.us");
        assert_eq!(metadata.subject.as_deref(), Some("Team"));

        let create_fut = client.create_group(
            &connection,
            "New team",
            ["111@s.whatsapp.net", "222@s.whatsapp.net"],
        );
        tokio::pin!(create_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["to"], "@g.us");
                assert_eq!(node.attrs["type"], "set");
                let create = test_child(&node, "create");
                assert_eq!(create.attrs["subject"], "New team");
                assert!(!create.attrs["key"].is_empty());
                assert_eq!(test_children(create, "participant").len(), 2);
                group_metadata_response(&node, "456", "New team")
            },
            &mut create_fut,
        )
        .await;
        assert_eq!(create_fut.await.unwrap().jid, "456@g.us");

        let participants_fut = client.update_group_participants(
            &connection,
            "123@g.us",
            GroupParticipantAction::Add,
            ["333@s.whatsapp.net", "444@s.whatsapp.net"],
        );
        tokio::pin!(participants_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                let add = test_child(&node, "add");
                assert_eq!(test_children(add, "participant").len(), 2);
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_attr("from", "123@g.us")
                    .with_content(vec![BinaryNode::new("add").with_content(vec![
                        BinaryNode::new("participant").with_attr("jid", "333@s.whatsapp.net"),
                        BinaryNode::new("participant")
                            .with_attr("jid", "444@s.whatsapp.net")
                            .with_attr("error", "403"),
                    ])])
            },
            &mut participants_fut,
        )
        .await;
        let result = participants_fut.await.unwrap();
        assert_eq!(result.group_jid.as_deref(), Some("123@g.us"));
        assert_eq!(result.action, GroupParticipantAction::Add);
        assert_eq!(result.participants[0].status, 200);
        assert_eq!(result.participants[1].error_code, Some(403));

        let leave_fut = client.leave_group(&connection, "123@g.us");
        tokio::pin!(leave_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["to"], "@g.us");
                assert_eq!(node.attrs["type"], "set");
                let leave = test_child(&node, "leave");
                assert_eq!(test_child(leave, "group").attrs["id"], "123@g.us");
                empty_result_for(&node)
            },
            &mut leave_fut,
        )
        .await;
        leave_fut.await.unwrap();

        let subject_fut = client.set_group_subject(&connection, "123@g.us", "Renamed");
        tokio::pin!(subject_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(
                    test_node_text(test_child(&node, "subject")).as_deref(),
                    Some("Renamed")
                );
                empty_result_for(&node)
            },
            &mut subject_fut,
        )
        .await;
        subject_fut.await.unwrap();
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn group_description_invites_settings_and_join_requests_use_group_iqs() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let description_fut =
            client.set_group_description(&connection, "123@g.us", Some("New description"));
        tokio::pin!(description_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "get");
                group_metadata_response_with_description(&node, "123", "Team", Some("old-desc"))
            },
            &mut description_fut,
        )
        .await;
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                let description = test_child(&node, "description");
                assert_eq!(description.attrs["prev"], "old-desc");
                assert!(!description.attrs["id"].is_empty());
                assert_eq!(
                    test_child(description, "body")
                        .content
                        .as_ref()
                        .and_then(|content| {
                            match content {
                                wa_binary::BinaryNodeContent::Bytes(bytes) => {
                                    std::str::from_utf8(bytes).ok().map(str::to_owned)
                                }
                                wa_binary::BinaryNodeContent::Text(text) => Some(text.clone()),
                                wa_binary::BinaryNodeContent::Nodes(_) => None,
                            }
                        }),
                    Some("New description".to_owned())
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut description_fut,
        )
        .await;
        description_fut.await.unwrap();

        let invite_fut = client.fetch_group_invite_code(&connection, "123@g.us");
        tokio::pin!(invite_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "get");
                assert!(test_child(&node, "invite").attrs.is_empty());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("invite").with_attr("code", "invite-code"),
                    ])
            },
            &mut invite_fut,
        )
        .await;
        assert_eq!(invite_fut.await.unwrap().as_deref(), Some("invite-code"));

        let accept_fut = client.accept_group_invite(&connection, "invite-code");
        tokio::pin!(accept_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "@g.us");
                assert_eq!(test_child(&node, "invite").attrs["code"], "invite-code");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("group").with_attr("jid", "789@g.us")])
            },
            &mut accept_fut,
        )
        .await;
        assert_eq!(accept_fut.await.unwrap().as_deref(), Some("789@g.us"));

        let invite_v4 =
            GroupInviteV4::new("123@g.us", "v4-code", 1_700_000_000, "222@s.whatsapp.net").unwrap();
        let accept_v4_fut = client.accept_group_invite_v4(&connection, &invite_v4);
        tokio::pin!(accept_v4_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "set");
                let accept = test_child(&node, "accept");
                assert_eq!(accept.attrs["code"], "v4-code");
                assert_eq!(accept.attrs["expiration"], "1700000000");
                assert_eq!(accept.attrs["admin"], "222@s.whatsapp.net");
                empty_result_for(&node)
            },
            &mut accept_v4_fut,
        )
        .await;
        assert!(accept_v4_fut.await.unwrap());

        let revoke_v4_fut =
            client.revoke_group_invite_v4(&connection, "123@g.us", "333@s.whatsapp.net");
        tokio::pin!(revoke_v4_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "set");
                let revoke = test_child(&node, "revoke");
                assert_eq!(
                    test_child(revoke, "participant").attrs["jid"],
                    "333@s.whatsapp.net"
                );
                empty_result_for(&node)
            },
            &mut revoke_v4_fut,
        )
        .await;
        assert!(revoke_v4_fut.await.unwrap());

        let setting_fut =
            client.update_group_setting(&connection, "123@g.us", GroupSettingUpdate::Locked);
        tokio::pin!(setting_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert!(test_child(&node, "locked").attrs.is_empty());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut setting_fut,
        )
        .await;
        setting_fut.await.unwrap();

        let failed_setting_fut =
            client.update_group_setting(&connection, "123@g.us", GroupSettingUpdate::Locked);
        tokio::pin!(failed_setting_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert!(test_child(&node, "locked").attrs.is_empty());
                error_result_for(&node, "403", "denied")
            },
            &mut failed_setting_fut,
        )
        .await;
        assert!(failed_setting_fut.await.is_err());

        let ephemeral_fut = client.set_group_ephemeral(&connection, "123@g.us", 86400);
        tokio::pin!(ephemeral_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(test_child(&node, "ephemeral").attrs["expiration"], "86400");
                empty_result_for(&node)
            },
            &mut ephemeral_fut,
        )
        .await;
        ephemeral_fut.await.unwrap();

        let member_add_fut = client.set_group_member_add_mode(
            &connection,
            "123@g.us",
            GroupMemberAddMode::AllMembers,
        );
        tokio::pin!(member_add_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(
                    test_node_text(test_child(&node, "member_add_mode")).as_deref(),
                    Some("all_member_add")
                );
                empty_result_for(&node)
            },
            &mut member_add_fut,
        )
        .await;
        member_add_fut.await.unwrap();

        let join_approval_fut =
            client.set_group_join_approval_mode(&connection, "123@g.us", GroupJoinApprovalMode::On);
        tokio::pin!(join_approval_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                let mode = test_child(&node, "membership_approval_mode");
                assert_eq!(test_child(mode, "group_join").attrs["state"], "on");
                empty_result_for(&node)
            },
            &mut join_approval_fut,
        )
        .await;
        join_approval_fut.await.unwrap();

        let join_list_fut = client.fetch_group_join_requests(&connection, "123@g.us");
        tokio::pin!(join_list_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "get");
                assert!(
                    test_child(&node, "membership_approval_requests")
                        .attrs
                        .is_empty()
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("membership_approval_requests").with_content(vec![
                            BinaryNode::new("membership_approval_request")
                                .with_attr("jid", "555@s.whatsapp.net")
                                .with_attr("t", "44")
                                .with_attr("request_method", "invite_link"),
                        ]),
                    ])
            },
            &mut join_list_fut,
        )
        .await;
        let requests = join_list_fut.await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].jid, "555@s.whatsapp.net");
        assert_eq!(requests[0].requested_at, Some(44));

        let join_update_fut = client.update_group_join_requests(
            &connection,
            "123@g.us",
            GroupJoinRequestAction::Approve,
            ["555@s.whatsapp.net"],
        );
        tokio::pin!(join_update_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                let wrapper = test_child(&node, "membership_requests_action");
                let approve = test_child(wrapper, "approve");
                assert_eq!(test_children(approve, "participant").len(), 1);
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("membership_requests_action").with_content(vec![
                            BinaryNode::new("approve").with_content(vec![
                                BinaryNode::new("participant")
                                    .with_attr("jid", "555@s.whatsapp.net"),
                            ]),
                        ]),
                    ])
            },
            &mut join_update_fut,
        )
        .await;
        let update = join_update_fut.await.unwrap();
        assert_eq!(update.action, GroupJoinRequestAction::Approve);
        assert_eq!(update.participants[0].status, 200);
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn accept_group_invite_v4_with_message_events_emits_update_and_stub() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let invite =
            GroupInviteV4::new("123@g.us", "v4-code", 1_700_000_000, "222@s.whatsapp.net").unwrap();
        let invite_key = wa_core::MessageEventKey::new("222@s.whatsapp.net", "invite-msg", None);

        let accept_fut = client.accept_group_invite_v4_with_message_events(
            &connection,
            &invite,
            Some(invite_key.clone()),
        );
        tokio::pin!(accept_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "set");
                let accept = test_child(&node, "accept");
                assert_eq!(accept.attrs["code"], "v4-code");
                assert_eq!(accept.attrs["expiration"], "1700000000");
                assert_eq!(accept.attrs["admin"], "222@s.whatsapp.net");
                empty_result_for(&node)
            },
            &mut accept_fut,
        )
        .await;
        assert!(accept_fut.await.unwrap());

        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_update.len(), 1);
        assert_eq!(batch.messages_update[0].key, invite_key);
        assert_eq!(
            batch.messages_update[0].fields["source"],
            "group_invite_v4_accept"
        );
        assert_eq!(batch.messages_update[0].fields["invite_status"], "accepted");
        assert_eq!(batch.messages_update[0].fields["invite_code"], "");
        assert_eq!(batch.messages_update[0].fields["invite_expiration"], "0");
        assert_eq!(batch.messages_upsert.len(), 1);
        let stub = &batch.messages_upsert[0];
        assert_eq!(stub.key.remote_jid, "123@g.us");
        assert_eq!(stub.key.participant.as_deref(), Some("222@s.whatsapp.net"));
        assert_eq!(stub.fields["source"], "group_invite_v4_accept");
        assert_eq!(stub.fields["kind"], "notify");
        assert_eq!(stub.fields["stub_type"], "group_participant_add");
        assert_eq!(stub.fields["participant"], "222@s.whatsapp.net");

        let stored_update_key = wa_core::message_event_store_key(&invite_key);
        let stored_update = store
            .get(KeyNamespace::MessageUpdate, &stored_update_key)
            .await
            .unwrap()
            .unwrap();
        let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
        assert_eq!(stored_update, batch.messages_update[0]);

        let stored_stub_key = wa_core::message_event_store_key(&stub.key);
        let stored_stub = store
            .get(KeyNamespace::MessageEvent, &stored_stub_key)
            .await
            .unwrap()
            .unwrap();
        let stored_stub = wa_core::decode_stored_message_event(&stored_stub).unwrap();
        assert_eq!(stored_stub, *stub);
        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn persisted_message_event_batch_merges_updates_and_deletes() {
        let store = wa_store::MemoryAuthStore::new();
        let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None);
        let store_key = wa_core::message_event_store_key(&key);
        let upsert = MessageEvent::new(key.clone())
            .with_timestamp(10)
            .with_field("status", "pending");

        persist_message_event_batch(
            &store,
            &wa_core::EventBatch {
                messages_upsert: vec![upsert],
                ..wa_core::EventBatch::default()
            },
        )
        .await
        .unwrap();

        persist_message_event_batch(
            &store,
            &wa_core::EventBatch {
                messages_update: vec![
                    wa_core::MessageUpdate::new(key.clone())
                        .with_timestamp(11)
                        .with_field("status", "server_ack"),
                ],
                ..wa_core::EventBatch::default()
            },
        )
        .await
        .unwrap();

        let stored = store
            .get(KeyNamespace::MessageEvent, &store_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_message_event(&stored).unwrap();
        assert_eq!(stored.timestamp, Some(11));
        assert_eq!(stored.fields["status"], "server_ack");
        assert_eq!(
            store
                .get(KeyNamespace::MessageUpdate, &store_key)
                .await
                .unwrap(),
            None
        );

        persist_message_event_batch(
            &store,
            &wa_core::EventBatch {
                messages_delete: vec![key],
                ..wa_core::EventBatch::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            store
                .get(KeyNamespace::MessageEvent, &store_key)
                .await
                .unwrap(),
            None
        );
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn receive_persistence_stores_history_chat_contact_and_group_state() {
        let store = wa_store::MemoryAuthStore::new();
        let history = wa_core::HistorySetEvent {
            chats: vec![
                wa_core::ChatEvent::new("123@s.whatsapp.net").with_field("display_name", "Alice"),
            ],
            contacts: vec![
                wa_core::ContactEvent::new("123@s.whatsapp.net").with_field("name", "Alice"),
            ],
            messages: Vec::new(),
            is_latest: true,
        };
        let group = wa_core::GroupUpdateEvent::new("456@g.us").with_field("subject", "Team");
        let batch = wa_core::EventBatch {
            history: Some(history),
            groups_update: vec![group],
            ..wa_core::EventBatch::default()
        };

        persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
            .await
            .unwrap();

        let chat = store
            .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        let chat = wa_core::decode_stored_chat_event(&chat).unwrap();
        assert_eq!(chat.fields["display_name"], "Alice");

        let contact = store
            .get(KeyNamespace::ContactEvent, "123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        let contact = wa_core::decode_stored_contact_event(&contact).unwrap();
        assert_eq!(contact.fields["name"], "Alice");

        let group = store
            .get(KeyNamespace::GroupEvent, "456@g.us")
            .await
            .unwrap()
            .unwrap();
        let group = wa_core::decode_stored_group_event(&group).unwrap();
        assert_eq!(group.fields["subject"], "Team");

        persist_receive_events(
            &store,
            &[
                Event::ChatsUpdate(vec![
                    wa_core::ChatEvent::new("123@s.whatsapp.net").with_field("unread_count", "3"),
                ]),
                Event::ContactsUpdate(vec![
                    wa_core::ContactEvent::new("123@s.whatsapp.net").with_field("notify", "A"),
                ]),
                Event::GroupsUpdate(vec![
                    wa_core::GroupUpdateEvent::new("456@g.us").with_field("announce", "false"),
                ]),
            ],
        )
        .await
        .unwrap();

        let chat = store
            .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        let chat = wa_core::decode_stored_chat_event(&chat).unwrap();
        assert_eq!(chat.fields["display_name"], "Alice");
        assert_eq!(chat.fields["unread_count"], "3");

        let contact = store
            .get(KeyNamespace::ContactEvent, "123@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        let contact = wa_core::decode_stored_contact_event(&contact).unwrap();
        assert_eq!(contact.fields["name"], "Alice");
        assert_eq!(contact.fields["notify"], "A");

        let group = store
            .get(KeyNamespace::GroupEvent, "456@g.us")
            .await
            .unwrap()
            .unwrap();
        let group = wa_core::decode_stored_group_event(&group).unwrap();
        assert_eq!(group.fields["subject"], "Team");
        assert_eq!(group.fields["announce"], "false");

        persist_receive_events(
            &store,
            &[
                Event::ChatsDelete(vec!["123@s.whatsapp.net".to_owned()]),
                Event::ContactsDelete(vec!["123@s.whatsapp.net".to_owned()]),
            ],
        )
        .await
        .unwrap();

        assert_eq!(
            store
                .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .get(KeyNamespace::ContactEvent, "123@s.whatsapp.net")
                .await
                .unwrap(),
            None
        );
        assert!(
            store
                .get(KeyNamespace::GroupEvent, "456@g.us")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn receive_persistence_stores_receipts_and_reactions() {
        let store = wa_store::MemoryAuthStore::new();
        let key = wa_core::MessageEventKey::new(
            "123@s.whatsapp.net",
            "msg-1",
            Some("456@s.whatsapp.net".to_owned()),
        );
        let receipt = wa_core::ReceiptEvent::new(key.clone(), "read")
            .with_participant("789@s.whatsapp.net")
            .with_timestamp(1_700_000_004);
        let reaction = wa_core::ReactionEvent::new(key, "789@s.whatsapp.net")
            .with_text("+")
            .with_timestamp(1_700_000_005);
        let batch = wa_core::EventBatch {
            receipts_update: vec![receipt.clone()],
            reactions_update: vec![reaction.clone()],
            ..wa_core::EventBatch::default()
        };

        persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
            .await
            .unwrap();

        let receipt_key = wa_core::receipt_event_store_key(&receipt);
        let stored_receipt = store
            .get(KeyNamespace::ReceiptEvent, &receipt_key)
            .await
            .unwrap()
            .unwrap();
        let stored_receipt = wa_core::decode_stored_receipt_event(&stored_receipt).unwrap();
        assert_eq!(stored_receipt, receipt);

        let reaction_key = wa_core::reaction_event_store_key(&reaction);
        let stored_reaction = store
            .get(KeyNamespace::ReactionEvent, &reaction_key)
            .await
            .unwrap()
            .unwrap();
        let stored_reaction = wa_core::decode_stored_reaction_event(&stored_reaction).unwrap();
        assert_eq!(stored_reaction, reaction);

        let replacement =
            wa_core::ReactionEvent::new(stored_reaction.key.clone(), "789@s.whatsapp.net")
                .with_text("-")
                .with_timestamp(1_700_000_006);
        persist_receive_events(&store, &[Event::ReactionsUpdate(vec![replacement.clone()])])
            .await
            .unwrap();
        let stored_reaction = store
            .get(KeyNamespace::ReactionEvent, &reaction_key)
            .await
            .unwrap()
            .unwrap();
        let stored_reaction = wa_core::decode_stored_reaction_event(&stored_reaction).unwrap();
        assert_eq!(stored_reaction, replacement);
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn receive_persistence_stores_media_retry_events() {
        let store = wa_store::MemoryAuthStore::new();
        let key = wa_core::MessageEventKey::new(
            "123@s.whatsapp.net",
            "msg-1",
            Some("456@s.whatsapp.net".to_owned()),
        );
        let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
            .with_encrypted_payload(Bytes::from_static(b"cipher"), Bytes::from_static(b"iv"));
        let batch = wa_core::EventBatch {
            media_retry: vec![retry.clone()],
            ..wa_core::EventBatch::default()
        };

        persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
            .await
            .unwrap();

        let store_key = wa_core::media_retry_event_store_key(&retry);
        let stored = store
            .get(KeyNamespace::MediaRetryEvent, &store_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_media_retry_event(&stored).unwrap();
        assert_eq!(stored, retry);

        let replacement = wa_core::MediaRetryEvent::new(key, false).with_error(
            2,
            Some("missing".to_owned()),
            404,
        );
        persist_receive_events(&store, &[Event::MediaRetry(vec![replacement.clone()])])
            .await
            .unwrap();

        let stored = store
            .get(KeyNamespace::MediaRetryEvent, &store_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_media_retry_event(&stored).unwrap();
        assert_eq!(stored, replacement);
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn receive_persistence_stores_call_events() {
        let store = wa_store::MemoryAuthStore::new();
        let call = wa_core::CallEvent::new("call-stanza-1", "123@s.whatsapp.net", "offer")
            .with_call_id("call-1")
            .with_participant("456@s.whatsapp.net")
            .with_timestamp(1_700_000_007)
            .with_field("child_audio", "true");
        let batch = wa_core::EventBatch {
            calls_update: vec![call.clone()],
            ..wa_core::EventBatch::default()
        };

        persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
            .await
            .unwrap();

        let store_key = wa_core::call_event_store_key(&call);
        let stored = store
            .get(KeyNamespace::CallEvent, &store_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_call_event(&stored).unwrap();
        assert_eq!(stored, call);

        let replacement = wa_core::CallEvent::new("call-stanza-1", "123@s.whatsapp.net", "offer")
            .with_call_id("call-1")
            .with_participant("789@s.whatsapp.net")
            .with_timestamp(1_700_000_008)
            .with_field("child_video", "true");
        persist_receive_events(&store, &[Event::CallsUpdate(vec![replacement.clone()])])
            .await
            .unwrap();

        let stored = store
            .get(KeyNamespace::CallEvent, &store_key)
            .await
            .unwrap()
            .unwrap();
        let stored = wa_core::decode_stored_call_event(&stored).unwrap();
        assert_eq!(stored, replacement);
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn receive_persistence_stores_labels_associations_and_quick_replies() {
        let store = wa_store::MemoryAuthStore::new();
        let label = wa_core::LabelEvent::new("7")
            .with_field("name", "Important")
            .with_field("color", "4");
        let association = wa_core::LabelAssociationEvent::chat("7", "123@s.whatsapp.net", true);
        let quick_reply = wa_core::QuickReplyEvent::new("qr-1")
            .with_field("shortcut", "/hi")
            .with_field("message", "hello");
        let batch = wa_core::EventBatch {
            labels_edit: vec![label.clone()],
            labels_association: vec![association.clone()],
            quick_replies_update: vec![quick_reply.clone()],
            ..wa_core::EventBatch::default()
        };

        persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
            .await
            .unwrap();

        let stored_label = store
            .get(KeyNamespace::LabelEvent, "7")
            .await
            .unwrap()
            .unwrap();
        let stored_label = wa_core::decode_stored_label_event(&stored_label).unwrap();
        assert_eq!(stored_label, label);

        let association_key = wa_core::label_association_store_key(&association);
        let stored_association = store
            .get(KeyNamespace::LabelAssociation, &association_key)
            .await
            .unwrap()
            .unwrap();
        let stored_association =
            wa_core::decode_stored_label_association_event(&stored_association).unwrap();
        assert_eq!(stored_association, association);

        let stored_quick_reply = store
            .get(KeyNamespace::QuickReplyEvent, "qr-1")
            .await
            .unwrap()
            .unwrap();
        let stored_quick_reply =
            wa_core::decode_stored_quick_reply_event(&stored_quick_reply).unwrap();
        assert_eq!(stored_quick_reply, quick_reply);

        persist_receive_events(
            &store,
            &[
                Event::LabelsEdit(vec![
                    wa_core::LabelEvent::new("7").with_field("name", "Renamed"),
                ]),
                Event::LabelsAssociation(vec![wa_core::LabelAssociationEvent::chat(
                    "7",
                    "123@s.whatsapp.net",
                    false,
                )]),
                Event::QuickRepliesUpdate(vec![
                    wa_core::QuickReplyEvent::new("qr-1").with_field("count", "2"),
                ]),
            ],
        )
        .await
        .unwrap();

        let stored_label = store
            .get(KeyNamespace::LabelEvent, "7")
            .await
            .unwrap()
            .unwrap();
        let stored_label = wa_core::decode_stored_label_event(&stored_label).unwrap();
        assert_eq!(stored_label.fields["name"], "Renamed");
        assert_eq!(stored_label.fields["color"], "4");

        let stored_association = store
            .get(KeyNamespace::LabelAssociation, &association_key)
            .await
            .unwrap()
            .unwrap();
        let stored_association =
            wa_core::decode_stored_label_association_event(&stored_association).unwrap();
        assert!(!stored_association.labeled);

        let stored_quick_reply = store
            .get(KeyNamespace::QuickReplyEvent, "qr-1")
            .await
            .unwrap()
            .unwrap();
        let stored_quick_reply =
            wa_core::decode_stored_quick_reply_event(&stored_quick_reply).unwrap();
        assert_eq!(stored_quick_reply.fields["shortcut"], "/hi");
        assert_eq!(stored_quick_reply.fields["message"], "hello");
        assert_eq!(stored_quick_reply.fields["count"], "2");
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn community_methods_use_community_iqs_and_parse_results() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let metadata_fut = client.fetch_community_metadata(&connection, "123@g.us");
        tokio::pin!(metadata_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "w:g2");
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "get");
                assert_eq!(test_child(&node, "query").attrs["request"], "interactive");
                community_metadata_response(&node, "123", "Updates")
            },
            &mut metadata_fut,
        )
        .await;
        let metadata = metadata_fut.await.unwrap();
        assert_eq!(metadata.jid, "123@g.us");
        assert_eq!(metadata.subject.as_deref(), Some("Updates"));
        assert!(metadata.is_community);

        let participating_fut = client.fetch_participating_communities(&connection);
        tokio::pin!(participating_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "@g.us");
                assert!(test_child(&node, "participating").attrs.is_empty());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("communities").with_content(vec![
                        BinaryNode::new("community")
                            .with_attr("id", "123")
                            .with_attr("subject", "Updates")
                            .with_content(vec![BinaryNode::new("parent")]),
                    ])])
            },
            &mut participating_fut,
        )
        .await;
        let communities = participating_fut.await.unwrap();
        assert_eq!(communities.len(), 1);
        assert_eq!(communities[0].jid, "123@g.us");

        let create_fut = client.create_community(&connection, "Rust users", "Daily updates");
        tokio::pin!(create_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "@g.us");
                assert_eq!(node.attrs["type"], "set");
                let create = test_child(&node, "create");
                assert_eq!(create.attrs["subject"], "Rust users");
                let description = test_child(create, "description");
                assert!(!description.attrs["id"].is_empty());
                assert_eq!(
                    test_node_text(test_child(description, "body")).as_deref(),
                    Some("Daily updates")
                );
                assert_eq!(
                    test_child(create, "parent").attrs["default_membership_approval_mode"],
                    "request_required"
                );
                assert_child(create, "allow_non_admin_sub_group_creation");
                assert_child(create, "create_general_chat");
                community_metadata_response(&node, "456", "Rust users")
            },
            &mut create_fut,
        )
        .await;
        assert_eq!(create_fut.await.unwrap().jid, "456@g.us");

        let subgroup_fut = client.create_community_group(
            &connection,
            "Announcements",
            ["111@s.whatsapp.net"],
            "123@g.us",
        );
        tokio::pin!(subgroup_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "@g.us");
                let create = test_child(&node, "create");
                assert_eq!(create.attrs["subject"], "Announcements");
                assert!(!create.attrs["key"].is_empty());
                assert_eq!(test_children(create, "participant").len(), 1);
                assert_eq!(test_child(create, "linked_parent").attrs["jid"], "123@g.us");
                community_metadata_response(&node, "789", "Announcements")
            },
            &mut subgroup_fut,
        )
        .await;
        assert_eq!(subgroup_fut.await.unwrap().jid, "789@g.us");

        let leave_fut = client.leave_community(&connection, "123@g.us");
        tokio::pin!(leave_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "@g.us");
                assert_eq!(node.attrs["type"], "set");
                let leave = test_child(&node, "leave");
                assert_eq!(test_child(leave, "community").attrs["id"], "123@g.us");
                empty_result_for(&node)
            },
            &mut leave_fut,
        )
        .await;
        leave_fut.await.unwrap();

        let subject_fut = client.set_community_subject(&connection, "123@g.us", "Renamed");
        tokio::pin!(subject_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(
                    test_node_text(test_child(&node, "subject")).as_deref(),
                    Some("Renamed")
                );
                empty_result_for(&node)
            },
            &mut subject_fut,
        )
        .await;
        subject_fut.await.unwrap();

        let description_fut =
            client.set_community_description(&connection, "123@g.us", Some("New description"));
        tokio::pin!(description_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "get");
                community_metadata_response(&node, "123", "Updates")
            },
            &mut description_fut,
        )
        .await;
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                let description = test_child(&node, "description");
                assert_eq!(description.attrs["prev"], "desc-1");
                assert!(!description.attrs["id"].is_empty());
                assert_eq!(
                    test_node_text(test_child(description, "body")).as_deref(),
                    Some("New description")
                );
                empty_result_for(&node)
            },
            &mut description_fut,
        )
        .await;
        description_fut.await.unwrap();

        let link_fut = client.link_community_group(&connection, "789@g.us", "123@g.us");
        tokio::pin!(link_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                let link = test_child(test_child(&node, "links"), "link");
                assert_eq!(link.attrs["link_type"], "sub_group");
                assert_eq!(test_child(link, "group").attrs["jid"], "789@g.us");
                empty_result_for(&node)
            },
            &mut link_fut,
        )
        .await;
        link_fut.await.unwrap();

        let failed_link_fut = client.link_community_group(&connection, "789@g.us", "123@g.us");
        tokio::pin!(failed_link_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                let link = test_child(test_child(&node, "links"), "link");
                assert_eq!(link.attrs["link_type"], "sub_group");
                error_result_for(&node, "403", "denied")
            },
            &mut failed_link_fut,
        )
        .await;
        assert!(failed_link_fut.await.is_err());

        let linked_fut = client.fetch_community_linked_groups(&connection, "123@g.us");
        tokio::pin!(linked_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "get");
                assert!(test_child(&node, "sub_groups").attrs.is_empty());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("sub_groups").with_content(vec![
                        BinaryNode::new("group")
                            .with_attr("id", "789")
                            .with_attr("subject", "Announcements")
                            .with_attr("creator", "111@c.us")
                            .with_attr("creation", "10")
                            .with_attr("size", "4"),
                    ])])
            },
            &mut linked_fut,
        )
        .await;
        let linked = linked_fut.await.unwrap();
        assert_eq!(linked[0].jid, "789@g.us");
        assert_eq!(linked[0].owner.as_deref(), Some("111@s.whatsapp.net"));
        assert_eq!(linked[0].size, Some(4));

        let participants_fut = client.update_community_participants(
            &connection,
            "123@g.us",
            GroupParticipantAction::Remove,
            ["111@s.whatsapp.net"],
        );
        tokio::pin!(participants_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let remove = test_child(&node, "remove");
                assert_eq!(remove.attrs["linked_groups"], "true");
                assert_eq!(
                    test_child(remove, "participant").attrs["jid"],
                    "111@s.whatsapp.net"
                );
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("remove").with_content(vec![
                        BinaryNode::new("participant").with_attr("jid", "111@s.whatsapp.net"),
                    ])])
            },
            &mut participants_fut,
        )
        .await;
        let participants = participants_fut.await.unwrap();
        assert_eq!(participants.action, GroupParticipantAction::Remove);
        assert_eq!(participants.participants[0].status, 200);

        let invite_fut = client.fetch_community_invite_code(&connection, "123@g.us");
        tokio::pin!(invite_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "get");
                assert!(test_child(&node, "invite").attrs.is_empty());
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("invite").with_attr("code", "community-code"),
                    ])
            },
            &mut invite_fut,
        )
        .await;
        assert_eq!(invite_fut.await.unwrap().as_deref(), Some("community-code"));

        let ephemeral_fut = client.set_community_ephemeral(&connection, "123@g.us", 86400);
        tokio::pin!(ephemeral_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(test_child(&node, "ephemeral").attrs["expiration"], "86400");
                empty_result_for(&node)
            },
            &mut ephemeral_fut,
        )
        .await;
        ephemeral_fut.await.unwrap();

        let setting_fut =
            client.update_community_setting(&connection, "123@g.us", GroupSettingUpdate::Locked);
        tokio::pin!(setting_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert!(test_child(&node, "locked").attrs.is_empty());
                empty_result_for(&node)
            },
            &mut setting_fut,
        )
        .await;
        setting_fut.await.unwrap();

        let member_add_fut = client.set_community_member_add_mode(
            &connection,
            "123@g.us",
            GroupMemberAddMode::AllMembers,
        );
        tokio::pin!(member_add_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(
                    test_node_text(test_child(&node, "member_add_mode")).as_deref(),
                    Some("all_member_add")
                );
                empty_result_for(&node)
            },
            &mut member_add_fut,
        )
        .await;
        member_add_fut.await.unwrap();

        let approval_fut = client.set_community_join_approval_mode(
            &connection,
            "123@g.us",
            GroupJoinApprovalMode::On,
        );
        tokio::pin!(approval_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let mode = test_child(&node, "membership_approval_mode");
                assert_eq!(test_child(mode, "community_join").attrs["state"], "on");
                empty_result_for(&node)
            },
            &mut approval_fut,
        )
        .await;
        approval_fut.await.unwrap();

        let unlink_fut = client.unlink_community_group(&connection, "789@g.us", "123@g.us");
        tokio::pin!(unlink_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                let unlink = test_child(&node, "unlink");
                assert_eq!(unlink.attrs["unlink_type"], "sub_group");
                assert_eq!(test_child(unlink, "group").attrs["jid"], "789@g.us");
                empty_result_for(&node)
            },
            &mut unlink_fut,
        )
        .await;
        unlink_fut.await.unwrap();

        connection.close().await.unwrap();
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn accept_community_invite_v4_with_message_events_emits_update_and_stub() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let invite =
            GroupInviteV4::new("123@g.us", "v4-code", 1_700_000_000, "222@s.whatsapp.net").unwrap();
        let invite_key =
            wa_core::MessageEventKey::new("222@s.whatsapp.net", "community-invite-msg", None);

        let accept_fut = client.accept_community_invite_v4_with_message_events(
            &connection,
            &invite,
            Some(invite_key.clone()),
        );
        tokio::pin!(accept_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["to"], "123@g.us");
                assert_eq!(node.attrs["type"], "set");
                let accept = test_child(&node, "accept");
                assert_eq!(accept.attrs["code"], "v4-code");
                assert_eq!(accept.attrs["expiration"], "1700000000");
                assert_eq!(accept.attrs["admin"], "222@s.whatsapp.net");
                empty_result_for(&node)
            },
            &mut accept_fut,
        )
        .await;
        assert!(accept_fut.await.unwrap());

        let batch = recv_batch_event(&mut events).await;
        assert_eq!(batch.messages_update.len(), 1);
        assert_eq!(batch.messages_update[0].key, invite_key);
        assert_eq!(
            batch.messages_update[0].fields["source"],
            "community_invite_v4_accept"
        );
        assert_eq!(batch.messages_update[0].fields["invite_status"], "accepted");
        assert_eq!(batch.messages_update[0].fields["invite_expiration"], "0");
        assert_eq!(batch.messages_upsert.len(), 1);
        let stub = &batch.messages_upsert[0];
        assert_eq!(stub.key.remote_jid, "123@g.us");
        assert_eq!(stub.key.participant.as_deref(), Some("222@s.whatsapp.net"));
        assert_eq!(stub.fields["source"], "community_invite_v4_accept");
        assert_eq!(stub.fields["stub_type"], "group_participant_add");

        let stored_update_key = wa_core::message_event_store_key(&invite_key);
        let stored_update = store
            .get(KeyNamespace::MessageUpdate, &stored_update_key)
            .await
            .unwrap()
            .unwrap();
        let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
        assert_eq!(stored_update, batch.messages_update[0]);

        let stored_stub_key = wa_core::message_event_store_key(&stub.key);
        let stored_stub = store
            .get(KeyNamespace::MessageEvent, &stored_stub_key)
            .await
            .unwrap()
            .unwrap();
        let stored_stub = wa_core::decode_stored_message_event(&stored_stub).unwrap();
        assert_eq!(stored_stub, *stub);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn fetch_lid_mappings_sends_query_and_persists_mappings() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let mapping_fut = client.fetch_lid_mappings(&connection, ["123@s.whatsapp.net"]);
        tokio::pin!(mapping_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                                BinaryNode::new("user")
                                    .with_attr("jid", "123@s.whatsapp.net")
                                    .with_content(vec![
                                        BinaryNode::new("lid").with_attr("val", "abc@lid"),
                                    ]),
                            ]),
                    ])])
            },
            &mut mapping_fut,
        )
        .await;

        assert_eq!(
            mapping_fut.await.unwrap(),
            vec![wa_core::USyncLidMapping {
                pn: "123@s.whatsapp.net".to_owned(),
                lid: "abc@lid".to_owned(),
            }]
        );
        let mapping_store = wa_core::LidPnMappingStore::new(store);
        assert_eq!(
            mapping_store
                .lid_for_pn("123@s.whatsapp.net")
                .await
                .unwrap(),
            Some("abc".to_owned())
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn fetch_device_jids_sends_query_and_excludes_own_device() {
        let store = wa_store::MemoryAuthStore::new();
        let mut credentials = wa_core::create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("123:7@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("abc@lid".to_owned());
        wa_core::save_credentials(&store, credentials)
            .await
            .unwrap();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let devices_fut = client.fetch_device_jids(&connection, ["123@s.whatsapp.net"], false);
        tokio::pin!(devices_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "usync");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("usync").with_content(vec![
                        BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![BinaryNode::new("devices").with_content(vec![
                                    BinaryNode::new("device-list").with_content(vec![
                                        BinaryNode::new("device").with_attr("id", "0"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "7")
                                            .with_attr("key-index", "1"),
                                        BinaryNode::new("device")
                                            .with_attr("id", "8")
                                            .with_attr("key-index", "2"),
                                    ]),
                                ])]),
                        ]),
                    ])])
            },
            &mut devices_fut,
        )
        .await;

        assert_eq!(
            devices_fut.await.unwrap(),
            vec![
                USyncDeviceJid {
                    jid: "123@s.whatsapp.net".to_owned(),
                    key_index: None,
                    is_hosted: false,
                },
                USyncDeviceJid {
                    jid: "123:8@s.whatsapp.net".to_owned(),
                    key_index: Some(2),
                    is_hosted: false,
                },
            ]
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn prepare_pairing_code_request_persists_state() {
        let store = wa_store::MemoryAuthStore::new();
        let mut client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();

        let request = client
            .prepare_pairing_code_request("+1 234-567", Some("ABCDEFGH"))
            .await
            .unwrap();

        assert_eq!(request.pairing_code, "ABCDEFGH");
        assert_eq!(request.account_jid, "1234567@s.whatsapp.net");
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::CredentialsUpdated
        ));

        let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(stored.pairing_code.as_deref(), Some("ABCDEFGH"));
        assert_eq!(
            stored.account_jid.as_deref(),
            Some("1234567@s.whatsapp.net")
        );
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn send_pairing_code_request_writes_encoded_node() {
        let store = wa_store::MemoryAuthStore::new();
        let mut client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();

        let request = client
            .send_pairing_code_request(&connection, "+1 234-567", Some("ABCDEFGH"))
            .await
            .unwrap();

        let sent_frame = sink_rx.recv().await.unwrap();
        assert_eq!(sent_frame, encode_binary_node(&request.node).unwrap());

        let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(sent.tag, "iq");
        assert_eq!(sent.attrs["id"], request.node.attrs["id"]);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn respond_to_pair_device_challenge_sends_ack_and_emits_qr() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();
        let stanza = BinaryNode::new("iq")
            .with_attr("id", "pair-1")
            .with_content(vec![BinaryNode::new("pair-device").with_content(vec![
                BinaryNode::new("ref").with_content("ref-a"),
                BinaryNode::new("ref").with_content("ref-b"),
            ])]);

        let qr_codes = client
            .respond_to_pair_device_challenge(&connection, &stanza)
            .await
            .unwrap();

        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(
            ack,
            BinaryNode::new("iq")
                .with_attr("to", "s.whatsapp.net")
                .with_attr("type", "result")
                .with_attr("id", "pair-1")
        );
        assert_eq!(qr_codes.len(), 2);
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::Qr(qr) if qr.contains("#ref-a,")
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::Qr(qr) if qr.contains("#ref-b,")
        ));
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn respond_to_pair_success_sends_reply_and_persists_credentials() {
        let store = wa_store::MemoryAuthStore::new();
        let mut client = Client::builder(store.clone()).connect().await.unwrap();
        let credentials = client.credentials().clone();
        let account_key = generate_key_pair();
        let stanza = pair_success_stanza(&credentials, &account_key);
        let mut events = client.subscribe();
        let (connection, mut sink_rx, _stream_tx) = mock_connection();

        client
            .respond_to_pair_success(&connection, &stanza)
            .await
            .unwrap();

        let reply = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(reply.attrs["id"], "success-1");
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::CredentialsUpdated
        ));

        let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert!(stored.registered);
        assert_eq!(
            stored.account_jid.as_deref(),
            Some("12345:7@s.whatsapp.net")
        );
        assert_eq!(stored.account_lid.as_deref(), Some("abc@lid"));
        assert_eq!(
            stored.account_signature_key,
            Some(Bytes::copy_from_slice(&account_key.public))
        );
        assert!(
            stored
                .signed_device_identity
                .as_ref()
                .is_some_and(|identity| !identity.is_empty())
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn query_available_pre_key_count_sends_count_iq() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let count_fut = client.query_available_pre_key_count(&connection);
        tokio::pin!(count_fut);

        let sent_frame = tokio::select! {
            result = &mut count_fut => panic!("count query completed before the mock server response: {result:?}"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(sent.attrs["xmlns"], "encrypt");
        assert_eq!(sent.attrs["type"], "get");
        assert_eq!(sent.attrs["to"], wa_core::SERVER_JID);
        let tag = sent.attrs["id"].clone();
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", tag)
                        .with_attr("type", "result")
                        .with_content(vec![BinaryNode::new("count").with_attr("value", "7")]),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(count_fut.await.unwrap(), 7);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn validates_key_bundle_digest_as_typed_result() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let valid_fut = client.validate_key_bundle_digest(&connection);
        tokio::pin!(valid_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(node.attrs["type"], "get");
                assert_eq!(node.attrs["to"], wa_core::SERVER_JID);
                assert_child(&node, "digest");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("digest")])
            },
            &mut valid_fut,
        )
        .await;
        assert!(valid_fut.await.unwrap());

        let missing_fut = client.validate_key_bundle_digest(&connection);
        tokio::pin!(missing_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_child(&node, "digest");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut missing_fut,
        )
        .await;
        assert!(!missing_fut.await.unwrap());
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn upload_pre_keys_sends_query_and_persists_keys() {
        let store = wa_store::MemoryAuthStore::new();
        let mut client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let upload = {
            let upload_fut = client.upload_pre_keys(&connection, 3);
            tokio::pin!(upload_fut);

            let sent_frame = tokio::select! {
                result = &mut upload_fut => panic!("pre-key upload completed before the mock server response: {result:?}"),
                sent = sink_rx.recv() => sent.unwrap(),
            };
            let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
            assert_eq!(sent.attrs["xmlns"], "encrypt");
            assert_eq!(sent.attrs["type"], "set");
            assert_eq!(sent.attrs["to"], wa_core::SERVER_JID);
            let tag = sent.attrs["id"].clone();
            stream_tx
                .send(InboundFrame::new(
                    encode_binary_node(
                        &BinaryNode::new("iq")
                            .with_attr("id", tag)
                            .with_attr("type", "result"),
                    )
                    .unwrap(),
                ))
                .await
                .unwrap();

            upload_fut.await.unwrap()
        };

        assert_eq!(upload.pre_key_ids, vec![1, 2, 3]);
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::CredentialsUpdated
        ));
        let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(stored.next_pre_key_id, 4);
        assert_eq!(stored.first_unuploaded_pre_key_id, 4);
        for key_id in 1..=3 {
            assert!(
                store
                    .get(KeyNamespace::PreKey, &key_id.to_string())
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        {
            let failed_upload_fut = client.upload_pre_keys(&connection, 1);
            tokio::pin!(failed_upload_fut);
            respond_to_next_query(
                &mut sink_rx,
                &stream_tx,
                |node| {
                    assert_eq!(node.attrs["xmlns"], "encrypt");
                    assert_eq!(node.attrs["type"], "set");
                    assert_child(&node, "list");
                    error_result_for(&node, "500", "upload failed")
                },
                &mut failed_upload_fut,
            )
            .await;
            let err = failed_upload_fut.await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("pre-key upload failed (500): upload failed")
            );
        }
        let failed_stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(failed_stored.next_pre_key_id, 5);
        assert_eq!(failed_stored.first_unuploaded_pre_key_id, 4);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn rotate_signed_pre_key_sends_query_then_persists_rotation() {
        let store = wa_store::MemoryAuthStore::new();
        let mut client = Client::builder(store.clone()).connect().await.unwrap();
        let original_key_id = client.credentials().signed_pre_key.key_id;
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();

        let rotated = {
            let rotate_fut = client.rotate_signed_pre_key(&connection);
            tokio::pin!(rotate_fut);

            let sent_frame = tokio::select! {
                result = &mut rotate_fut => panic!("signed pre-key rotation completed before the mock server response: {result:?}"),
                sent = sink_rx.recv() => sent.unwrap(),
            };
            let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
            assert_eq!(sent.attrs["xmlns"], "encrypt");
            assert_eq!(sent.attrs["type"], "set");
            assert_eq!(sent.attrs["to"], wa_core::SERVER_JID);
            let tag = sent.attrs["id"].clone();
            stream_tx
                .send(InboundFrame::new(
                    encode_binary_node(
                        &BinaryNode::new("iq")
                            .with_attr("id", tag)
                            .with_attr("type", "result"),
                    )
                    .unwrap(),
                ))
                .await
                .unwrap();

            rotate_fut.await.unwrap()
        };

        assert_eq!(rotated.key_id, original_key_id + 1);
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::CredentialsUpdated
        ));
        let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(stored.signed_pre_key, rotated);

        {
            let failed_rotate_fut = client.rotate_signed_pre_key(&connection);
            tokio::pin!(failed_rotate_fut);
            respond_to_next_query(
                &mut sink_rx,
                &stream_tx,
                |node| {
                    assert_eq!(node.attrs["xmlns"], "encrypt");
                    assert_eq!(node.attrs["type"], "set");
                    assert_child(&node, "rotate");
                    error_result_for(&node, "409", "rotation rejected")
                },
                &mut failed_rotate_fut,
            )
            .await;
            let err = failed_rotate_fut.await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("signed pre-key rotation failed (409): rotation rejected")
            );
        }
        let stored_after_error = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(stored_after_error.signed_pre_key, rotated);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn post_auth_maintenance_uploads_minimum_when_digest_valid_but_server_count_low() {
        let store = wa_store::MemoryAuthStore::new();
        let mut client = Client::builder(store.clone()).connect().await.unwrap();
        let mut events = client.subscribe();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let maintenance_fut = client.run_post_auth_key_maintenance(&connection);
        tokio::pin!(maintenance_fut);

        let digest_tag = respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_child(&node, "digest");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("digest")])
            },
            &mut maintenance_fut,
        )
        .await;
        assert!(digest_tag.starts_with("q-"));

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_child(&node, "count");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("count").with_attr("value", "1")])
            },
            &mut maintenance_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_child(&node, "list");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut maintenance_fut,
        )
        .await;

        let maintenance = maintenance_fut.await.unwrap();
        assert!(maintenance.digest_validated);
        assert_eq!(
            maintenance.pre_key_upload.unwrap().pre_key_ids,
            vec![1, 2, 3, 4, 5]
        );
        assert!(maintenance.signed_pre_key_rotation.is_none());
        assert!(matches!(
            events.recv().await.unwrap(),
            Event::CredentialsUpdated
        ));
        let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(stored.next_pre_key_id, 6);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn post_auth_maintenance_uploads_initial_keys_after_missing_digest_and_rotates_when_enabled()
     {
        let store = wa_store::MemoryAuthStore::new();
        let config = ClientConfig {
            rotate_signed_pre_key_on_connect: true,
            ..ClientConfig::default()
        };
        let mut client = Client::builder(store.clone())
            .config(config)
            .connect()
            .await
            .unwrap();
        let original_signed_pre_key_id = client.credentials().signed_pre_key.key_id;
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let maintenance_fut = client.run_post_auth_key_maintenance(&connection);
        tokio::pin!(maintenance_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_child(&node, "digest");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut maintenance_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_child(&node, "list");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut maintenance_fut,
        )
        .await;

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_child(&node, "rotate");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
            },
            &mut maintenance_fut,
        )
        .await;

        let maintenance = maintenance_fut.await.unwrap();
        assert!(!maintenance.digest_validated);
        assert_eq!(
            maintenance.pre_key_upload.unwrap().pre_key_ids.len(),
            wa_core::INITIAL_PRE_KEY_COUNT
        );
        assert_eq!(
            maintenance.signed_pre_key_rotation.unwrap().key_id,
            original_signed_pre_key_id + 1
        );

        let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(
            stored.next_pre_key_id,
            wa_core::INITIAL_PRE_KEY_COUNT as u32 + 1
        );
        assert_eq!(stored.signed_pre_key.key_id, original_signed_pre_key_id + 1);
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn history_sync_facade_downloads_and_processes_payload() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let history = wa_core::HistorySync {
            sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
            conversations: vec![wa_proto::proto::Conversation {
                id: "123@s.whatsapp.net".to_owned(),
                display_name: Some("Alice".to_owned()),
                messages: vec![wa_proto::proto::HistorySyncMsg {
                    msg_order_id: Some(1),
                    message: Some(wa_proto::proto::WebMessageInfo {
                        key: Some(wa_proto::proto::MessageKey {
                            remote_jid: Some("123@s.whatsapp.net".to_owned()),
                            from_me: Some(false),
                            id: Some("msg-1".to_owned()),
                            participant: None,
                        }),
                        message_timestamp: Some(1_700_000_000),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&history.encode_to_vec()).unwrap();
        let compressed = Bytes::from(encoder.finish().unwrap());
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &compressed,
            wa_crypto::MediaKind::HistorySync,
            &[5u8; 32],
        )
        .unwrap();
        let notification = wa_core::HistorySyncNotification {
            file_sha256: Some(encrypted.file_sha256.clone()),
            file_length: Some(encrypted.file_length),
            media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
            file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
            direct_path: Some("/history/sync".to_owned()),
            ..Default::default()
        };
        let transport = HistoryDownloadTransport::default();
        transport.add_download(
            "https://history.test/history/sync",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = wa_core::MediaTransfer::new(transport);

        let processed = client
            .download_and_process_history_sync(
                &transfer,
                &notification,
                Some("history.test"),
                wa_core::HistorySyncDecodeConfig::default(),
                wa_core::HistorySyncProcessConfig::default().latest(true),
            )
            .await
            .unwrap();

        let history = processed.batch.history.unwrap();
        assert!(history.is_latest);
        assert_eq!(history.chats.len(), 1);
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.messages[0].key.id, "msg-1");
    }

    #[cfg(feature = "memory-store")]
    #[tokio::test]
    async fn fetch_media_connection_info_sends_query_and_parses_hosts() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let (connection, mut sink_rx, stream_tx) = mock_connection();
        let media_fut = client.fetch_media_connection_info(&connection);
        tokio::pin!(media_fut);

        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(node.attrs["xmlns"], "w:m");
                assert_child(&node, "media_conn");
                BinaryNode::new("iq")
                    .with_attr("id", node.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("media_conn")
                            .with_attr("auth", "auth-token")
                            .with_attr("ttl", "90")
                            .with_content(vec![
                                BinaryNode::new("host")
                                    .with_attr("hostname", "media.example")
                                    .with_attr("maxContentLengthBytes", "4096"),
                            ]),
                    ])
            },
            &mut media_fut,
        )
        .await;

        let info = media_fut.await.unwrap();
        assert_eq!(info.auth, "auth-token");
        assert_eq!(info.ttl_seconds, 90);
        assert_eq!(info.hosts[0].hostname, "media.example");
        assert_eq!(info.hosts[0].max_content_length_bytes, Some(4096));

        let failed_media_fut = client.fetch_media_connection_info(&connection);
        tokio::pin!(failed_media_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["type"], "set");
                assert_eq!(node.attrs["xmlns"], "w:m");
                assert_child(&node, "media_conn");
                error_result_for(&node, "401", "media denied")
            },
            &mut failed_media_fut,
        )
        .await;

        let err = failed_media_fut.await.unwrap_err();
        assert!(
            err.to_string()
                .contains("media connection query failed (401): media denied")
        );
        connection.close().await.unwrap();
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn upload_media_bytes_cached_reuses_cached_descriptor() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let transport = ClientMediaUploadTransport::default();
        let transfer = wa_core::MediaTransfer::new(transport.clone());
        let cache = wa_core::MemoryMediaUploadCache::default();

        let first = client
            .upload_media_bytes_cached(
                &transfer,
                b"client cached media",
                wa_core::MediaKind::Image,
                &cache,
            )
            .await
            .unwrap();
        let second = client
            .upload_media_bytes_cached(
                &transfer,
                b"client cached media",
                wa_core::MediaKind::Image,
                &cache,
            )
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(transport.uploads.lock().unwrap().len(), 1);
        assert_eq!(cache.len().unwrap(), 1);
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn business_media_upload_facade_uses_business_media_kinds() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let transport = ClientMediaUploadTransport::default();
        let transfer = wa_core::MediaTransfer::new(transport.clone());
        let cache = wa_core::MemoryMediaUploadCache::default();
        let input = test_client_media_path("business-image");
        tokio::fs::write(&input, b"product file image")
            .await
            .unwrap();

        let product = client
            .upload_business_product_image_bytes_cached(
                &transfer,
                b"product image",
                Some("media.test"),
                &cache,
            )
            .await
            .unwrap();
        let product_again = client
            .upload_business_product_image_bytes_cached(
                &transfer,
                b"product image",
                Some("media.test"),
                &cache,
            )
            .await
            .unwrap();
        assert_eq!(product, product_again);
        assert_eq!(product.url, "https://media.test/client/upload/0");

        let product_file = client
            .upload_business_product_image_file_cached(
                &transfer,
                &input,
                Some("media.test"),
                &cache,
            )
            .await
            .unwrap();
        let product_file_again = client
            .upload_business_product_image_file_cached(
                &transfer,
                &input,
                Some("media.test"),
                &cache,
            )
            .await
            .unwrap();
        assert_eq!(product_file, product_file_again);
        assert_eq!(product_file.url, "https://media.test/client/upload/1");

        let batch_bytes = client
            .upload_business_product_images_bytes(
                &transfer,
                vec![b"batch image a".as_slice(), b"batch image b".as_slice()],
                Some("media.test"),
            )
            .await
            .unwrap();
        assert_eq!(batch_bytes.len(), 2);
        assert_eq!(batch_bytes[0].url, "https://media.test/client/upload/2");
        assert_eq!(batch_bytes[1].url, "https://media.test/client/upload/3");

        let batch_files = client
            .upload_business_product_image_files(&transfer, [&input, &input], Some("media.test"))
            .await
            .unwrap();
        assert_eq!(batch_files.len(), 2);
        assert_eq!(batch_files[0].url, "https://media.test/client/upload/4");
        assert_eq!(batch_files[1].url, "https://media.test/client/upload/5");

        let cover = client
            .upload_business_cover_photo_bytes(&transfer, b"cover image")
            .await
            .unwrap();
        assert_eq!(cover.id, "cover-6");
        assert_eq!(cover.token, "token-6");
        assert_eq!(cover.timestamp, 1_700_000_006);

        let cover_file = client
            .upload_business_cover_photo_file(&transfer, &input)
            .await
            .unwrap();
        assert_eq!(cover_file.id, "cover-7");
        assert_eq!(cover_file.token, "token-7");
        assert_eq!(cover_file.timestamp, 1_700_000_007);

        {
            let uploads = transport.uploads.lock().unwrap();
            assert_eq!(uploads.len(), 8);
            for upload in uploads.iter().take(6) {
                assert_eq!(upload.kind, wa_core::MediaKind::ProductCatalogImage);
            }
            assert_eq!(uploads[6].kind, wa_core::MediaKind::BusinessCoverPhoto);
            assert_eq!(uploads[7].kind, wa_core::MediaKind::BusinessCoverPhoto);
        }

        let _ = tokio::fs::remove_file(&input).await;
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn media_file_facade_uploads_caches_and_downloads_files() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let transport = ClientMediaUploadTransport::default();
        let transfer = wa_core::MediaTransfer::new(transport.clone());
        let cache = wa_core::MemoryMediaUploadCache::default();
        let input = test_client_media_path("input");
        let output = test_client_media_path("output");
        tokio::fs::write(&input, b"client file media")
            .await
            .unwrap();

        let first = client
            .upload_media_file_cached(&transfer, &input, wa_core::MediaKind::Image, &cache)
            .await
            .unwrap();
        let second = client
            .upload_media_file_cached(&transfer, &input, wa_core::MediaKind::Image, &cache)
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(transport.uploads.lock().unwrap().len(), 1);

        let written = client
            .download_media_to_file(
                &transfer,
                &first,
                wa_core::MediaKind::Image,
                Some("media.test"),
                &output,
            )
            .await
            .unwrap();
        assert_eq!(written, 17);
        assert_eq!(
            tokio::fs::read(&output).await.unwrap(),
            b"client file media"
        );

        let _ = tokio::fs::remove_file(&input).await;
        let _ = tokio::fs::remove_file(&output).await;
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[tokio::test]
    async fn media_retry_facade_refreshes_descriptor_and_downloads() {
        let store = wa_store::MemoryAuthStore::new();
        let client = Client::builder(store).connect().await.unwrap();
        let media_key = [8u8; 32];
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"client retried media",
            wa_core::MediaKind::Image,
            &media_key,
        )
        .unwrap();
        let media = wa_core::uploaded_media_from_encrypted(
            &encrypted,
            wa_core::UploadedMediaLocation::new().with_direct_path("/client/old"),
        )
        .unwrap();
        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some("msg-1".to_owned()),
            direct_path: Some("/client/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            "msg-1",
            &[4u8; 12],
        )
        .unwrap();
        let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None);
        let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
            .with_encrypted_payload(payload.ciphertext, payload.iv);

        let application = client.apply_media_retry_event(&retry, &media).unwrap();
        assert_eq!(
            application.media.direct_path.as_deref(),
            Some("/client/new")
        );

        let transport = ClientMediaUploadTransport::default();
        transport.downloads.lock().unwrap().insert(
            "https://media.test/client/new".to_owned(),
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = wa_core::MediaTransfer::new(transport);
        let download = client
            .download_media_bytes_after_retry(
                &transfer,
                &media,
                wa_core::MediaKind::Image,
                &retry,
                Some("media.test"),
            )
            .await
            .unwrap();

        assert_eq!(download.plaintext, b"client retried media");
        assert_eq!(
            download.application.media.direct_path.as_deref(),
            Some("/client/new")
        );

        client
            .register_pending_media_retry(
                key.clone(),
                wa_core::PendingMediaRetry::new(media.clone(), wa_core::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .unwrap();
        let coordinated = client
            .download_pending_media_after_retry(&transfer, &retry)
            .await
            .unwrap();
        assert_eq!(coordinated.plaintext, b"client retried media");
        assert!(
            client
                .media_retry_coordinator()
                .pending(&key)
                .unwrap()
                .is_none()
        );

        client
            .register_pending_media_retry(
                key.clone(),
                wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .unwrap();
        let batch = wa_core::EventBatch {
            media_retry: vec![retry],
            ..wa_core::EventBatch::default()
        };
        let outcome = client
            .handle_media_retry_batch(&transfer, &batch)
            .await
            .unwrap();
        assert_eq!(outcome.downloads.len(), 1);
        assert_eq!(outcome.downloads[0].plaintext, b"client retried media");
        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.ignored_without_pending, 0);
        assert!(
            client
                .media_retry_coordinator()
                .pending(&key)
                .unwrap()
                .is_none()
        );
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

    #[cfg(all(feature = "memory-store", feature = "noise"))]
    #[derive(Clone, Default)]
    struct ClientMediaUploadTransport {
        uploads: Arc<Mutex<Vec<wa_core::MediaUploadRequest>>>,
        downloads: Arc<Mutex<BTreeMap<String, Bytes>>>,
    }

    #[cfg(all(feature = "memory-store", feature = "noise"))]
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
    async fn recv_app_state_upload<Fut>(
        sink_rx: &mut mpsc::Receiver<Bytes>,
        pending: &mut Fut,
        label: &str,
        expected_collection: AppStateCollection,
        expected_previous_version: u64,
    ) -> (BinaryNode, wa_proto::proto::SyncdPatch)
    where
        Fut: Future<Output = CoreResult<AppStatePatchBundle>> + Unpin,
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
