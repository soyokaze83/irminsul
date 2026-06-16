use crate::{CoreError, CoreResult};
use bytes::Bytes;
use std::collections::{BTreeMap, VecDeque};
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, jid_decode};
use wa_proto::proto::Message;

const MESSAGE_KEY_SEPARATOR: char = '\0';

pub const DEFAULT_RECENT_MESSAGE_CAPACITY: usize = 512;
pub const DEFAULT_RECENT_MESSAGE_TTL_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_RETRY_COUNTER_TTL_MS: u64 = 15 * 60 * 1000;
pub const DEFAULT_SESSION_RECREATE_TIMEOUT_MS: u64 = 60 * 60 * 1000;
pub const DEFAULT_BASE_KEY_CAPACITY: usize = 1024;
pub const DEFAULT_BASE_KEY_TTL_MS: u64 = 15 * 60 * 1000;
pub const DEFAULT_PHONE_REQUEST_DELAY_MS: u64 = 3000;
pub const DEFAULT_MAX_MESSAGE_RETRY_COUNT: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RetryReason {
    UnknownError = 0,
    SignalErrorNoSession = 1,
    SignalErrorInvalidKey = 2,
    SignalErrorInvalidKeyId = 3,
    SignalErrorInvalidMessage = 4,
    SignalErrorInvalidSignature = 5,
    SignalErrorFutureMessage = 6,
    SignalErrorBadMac = 7,
    SignalErrorInvalidSession = 8,
    SignalErrorInvalidMsgKey = 9,
    BadBroadcastEphemeralSetting = 10,
    UnknownCompanionNoPrekey = 11,
    AdvFailure = 12,
    StatusRevokeDelay = 13,
}

impl RetryReason {
    #[must_use]
    pub fn parse(value: Option<&str>) -> Option<Self> {
        let value = value?;
        if value.is_empty() {
            return None;
        }
        let Ok(code) = value.parse::<u8>() else {
            return None;
        };
        Some(Self::from_code(code).unwrap_or(Self::UnknownError))
    }

    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::UnknownError),
            1 => Some(Self::SignalErrorNoSession),
            2 => Some(Self::SignalErrorInvalidKey),
            3 => Some(Self::SignalErrorInvalidKeyId),
            4 => Some(Self::SignalErrorInvalidMessage),
            5 => Some(Self::SignalErrorInvalidSignature),
            6 => Some(Self::SignalErrorFutureMessage),
            7 => Some(Self::SignalErrorBadMac),
            8 => Some(Self::SignalErrorInvalidSession),
            9 => Some(Self::SignalErrorInvalidMsgKey),
            10 => Some(Self::BadBroadcastEphemeralSetting),
            11 => Some(Self::UnknownCompanionNoPrekey),
            12 => Some(Self::AdvFailure),
            13 => Some(Self::StatusRevokeDelay),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_mac_error(self) -> bool {
        matches!(
            self,
            Self::SignalErrorInvalidMessage | Self::SignalErrorBadMac
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageRetryConfig {
    pub recent_message_capacity: usize,
    pub recent_message_ttl_ms: u64,
    pub retry_counter_ttl_ms: u64,
    pub session_recreate_timeout_ms: u64,
    pub base_key_capacity: usize,
    pub base_key_ttl_ms: u64,
    pub phone_request_delay_ms: u64,
    pub max_message_retry_count: u32,
}

impl Default for MessageRetryConfig {
    fn default() -> Self {
        Self {
            recent_message_capacity: DEFAULT_RECENT_MESSAGE_CAPACITY,
            recent_message_ttl_ms: DEFAULT_RECENT_MESSAGE_TTL_MS,
            retry_counter_ttl_ms: DEFAULT_RETRY_COUNTER_TTL_MS,
            session_recreate_timeout_ms: DEFAULT_SESSION_RECREATE_TIMEOUT_MS,
            base_key_capacity: DEFAULT_BASE_KEY_CAPACITY,
            base_key_ttl_ms: DEFAULT_BASE_KEY_TTL_MS,
            phone_request_delay_ms: DEFAULT_PHONE_REQUEST_DELAY_MS,
            max_message_retry_count: DEFAULT_MAX_MESSAGE_RETRY_COUNT,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecentMessage {
    pub message: Message,
    pub timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryStatistics {
    pub total_retries: u64,
    pub successful_retries: u64,
    pub failed_retries: u64,
    pub media_retries: u64,
    pub session_recreations: u64,
    pub phone_requests: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecreateDecision {
    pub recreate: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryReceiptRetry {
    pub count: u32,
    pub original_stanza_id: Option<String>,
    pub timestamp: Option<u64>,
    pub version: Option<u32>,
    pub error: Option<RetryReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryReceipt {
    pub message_ids: Vec<String>,
    pub from_jid: Option<String>,
    pub to_jid: Option<String>,
    pub participant: Option<String>,
    pub recipient: Option<String>,
    pub chat_jid: Option<String>,
    pub retry: RetryReceiptRetry,
    pub registration_id: Option<u32>,
    pub has_key_bundle: bool,
}

impl RetryReceipt {
    pub fn requester_jid(&self) -> CoreResult<&str> {
        self.participant
            .as_deref()
            .or(self.from_jid.as_deref())
            .ok_or_else(|| CoreError::Protocol("retry receipt missing requester JID".to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrySessionSnapshot {
    pub has_session: bool,
    pub registration_id: Option<u32>,
    pub base_key: Option<Bytes>,
    pub signal_address: Option<String>,
}

impl RetrySessionSnapshot {
    #[must_use]
    pub fn missing() -> Self {
        Self {
            has_session: false,
            registration_id: None,
            base_key: None,
            signal_address: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryResendTarget {
    AllDevices,
    Participant { jid: String, count: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetrySessionAction {
    None,
    InjectBundle,
    Refresh { reason: String },
    DeleteAndRefresh { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryReceiptPlan {
    pub remote_jid: String,
    pub message_ids: Vec<String>,
    pub participant_jid: String,
    pub retry_count: u32,
    pub resend_target: RetryResendTarget,
    pub session_action: RetrySessionAction,
    pub should_clear_group_sender_key: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RetryResendJob {
    pub remote_jid: String,
    pub message_id: String,
    pub message: Message,
    pub target: RetryResendTarget,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RetryResendPreparation {
    pub jobs: Vec<RetryResendJob>,
    pub missing_message_ids: Vec<String>,
    pub session_action: RetrySessionAction,
    pub should_clear_group_sender_key: bool,
}

impl RetryResendPreparation {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing_message_ids.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct MessageRetryManager {
    config: MessageRetryConfig,
    recent_messages: BTreeMap<String, RecentMessage>,
    recent_order: VecDeque<String>,
    message_key_index: BTreeMap<String, String>,
    session_recreate_history: BTreeMap<String, u64>,
    retry_counters: BTreeMap<String, (u32, u64)>,
    base_keys: BTreeMap<String, (Bytes, u64)>,
    base_key_order: VecDeque<String>,
    pending_phone_requests: BTreeMap<String, u64>,
    statistics: RetryStatistics,
}

impl Default for MessageRetryManager {
    fn default() -> Self {
        Self::new(MessageRetryConfig::default())
    }
}

impl MessageRetryManager {
    #[must_use]
    pub fn new(config: MessageRetryConfig) -> Self {
        Self {
            config,
            recent_messages: BTreeMap::new(),
            recent_order: VecDeque::new(),
            message_key_index: BTreeMap::new(),
            session_recreate_history: BTreeMap::new(),
            retry_counters: BTreeMap::new(),
            base_keys: BTreeMap::new(),
            base_key_order: VecDeque::new(),
            pending_phone_requests: BTreeMap::new(),
            statistics: RetryStatistics::default(),
        }
    }

    #[must_use]
    pub fn config(&self) -> &MessageRetryConfig {
        &self.config
    }

    #[must_use]
    pub fn statistics(&self) -> RetryStatistics {
        self.statistics
    }

    pub fn add_recent_message(
        &mut self,
        to: &str,
        id: &str,
        message: Message,
        now_ms: u64,
    ) -> CoreResult<()> {
        validate_jid("recent message destination", to)?;
        validate_non_empty("recent message id", id)?;
        self.purge_recent_messages(now_ms);

        if let Some(old_key) = self.message_key_index.remove(id) {
            self.recent_messages.remove(&old_key);
        }

        let key = recent_message_key(to, id);
        self.recent_messages.insert(
            key.clone(),
            RecentMessage {
                message,
                timestamp_ms: now_ms,
            },
        );
        self.recent_order.push_back(key.clone());
        self.message_key_index.insert(id.to_owned(), key);
        self.enforce_recent_message_capacity();
        Ok(())
    }

    pub fn get_recent_message(&mut self, to: &str, id: &str, now_ms: u64) -> Option<RecentMessage> {
        self.purge_recent_messages(now_ms);
        self.recent_messages
            .get(&recent_message_key(to, id))
            .cloned()
    }

    pub fn remove_recent_message(&mut self, id: &str) -> Option<RecentMessage> {
        let key = self.message_key_index.remove(id)?;
        self.recent_messages.remove(&key)
    }

    pub fn increment_retry_count(&mut self, message_id: &str, now_ms: u64) -> CoreResult<u32> {
        validate_non_empty("message id", message_id)?;
        self.purge_retry_counters(now_ms);
        let count = self
            .retry_counters
            .get(message_id)
            .map_or(1, |(count, _)| count.saturating_add(1));
        self.retry_counters
            .insert(message_id.to_owned(), (count, now_ms));
        self.statistics.total_retries = self.statistics.total_retries.saturating_add(1);
        Ok(count)
    }

    pub fn retry_count(&mut self, message_id: &str, now_ms: u64) -> u32 {
        self.purge_retry_counters(now_ms);
        let Some((count, last_seen)) = self.retry_counters.get_mut(message_id) else {
            return 0;
        };
        *last_seen = now_ms;
        *count
    }

    pub fn has_exceeded_max_retries(&mut self, message_id: &str, now_ms: u64) -> bool {
        self.retry_count(message_id, now_ms) >= self.config.max_message_retry_count
    }

    pub fn mark_retry_success(&mut self, message_id: &str) {
        self.statistics.successful_retries = self.statistics.successful_retries.saturating_add(1);
        self.retry_counters.remove(message_id);
        self.cancel_phone_request(message_id);
        self.remove_recent_message(message_id);
    }

    pub fn mark_retry_failed(&mut self, message_id: &str) {
        self.statistics.failed_retries = self.statistics.failed_retries.saturating_add(1);
        self.retry_counters.remove(message_id);
        self.cancel_phone_request(message_id);
        self.remove_recent_message(message_id);
    }

    pub fn should_recreate_session(
        &mut self,
        jid: &str,
        has_session: bool,
        error_code: Option<RetryReason>,
        now_ms: u64,
    ) -> CoreResult<SessionRecreateDecision> {
        validate_jid("session recreate JID", jid)?;
        self.purge_session_recreate_history(now_ms);

        let reason = if !has_session {
            Some("missing Signal session".to_owned())
        } else if error_code.is_some_and(RetryReason::is_mac_error) {
            Some(format!(
                "MAC error code {}",
                error_code.expect("checked as some") as u8
            ))
        } else {
            let previous = self.session_recreate_history.get(jid).copied();
            previous
                .is_none_or(|previous| {
                    now_ms.saturating_sub(previous) > self.config.session_recreate_timeout_ms
                })
                .then(|| "retry outside session recreation cooldown".to_owned())
        };

        let Some(reason) = reason else {
            return Ok(SessionRecreateDecision {
                recreate: false,
                reason: None,
            });
        };

        self.session_recreate_history.insert(jid.to_owned(), now_ms);
        self.statistics.session_recreations = self.statistics.session_recreations.saturating_add(1);
        Ok(SessionRecreateDecision {
            recreate: true,
            reason: Some(reason),
        })
    }

    pub fn schedule_phone_request(&mut self, message_id: &str, now_ms: u64) -> CoreResult<u64> {
        self.schedule_phone_request_with_delay(
            message_id,
            now_ms,
            self.config.phone_request_delay_ms,
        )
    }

    pub fn schedule_phone_request_with_delay(
        &mut self,
        message_id: &str,
        now_ms: u64,
        delay_ms: u64,
    ) -> CoreResult<u64> {
        validate_non_empty("message id", message_id)?;
        let due_at = now_ms.saturating_add(delay_ms);
        self.pending_phone_requests
            .insert(message_id.to_owned(), due_at);
        Ok(due_at)
    }

    pub fn cancel_phone_request(&mut self, message_id: &str) -> bool {
        self.pending_phone_requests.remove(message_id).is_some()
    }

    pub fn take_due_phone_requests(&mut self, now_ms: u64) -> Vec<String> {
        let due = self
            .pending_phone_requests
            .iter()
            .filter(|(_, due_at)| **due_at <= now_ms)
            .map(|(message_id, _)| message_id.clone())
            .collect::<Vec<_>>();
        for message_id in &due {
            self.pending_phone_requests.remove(message_id);
        }
        self.statistics.phone_requests = self
            .statistics
            .phone_requests
            .saturating_add(u64::try_from(due.len()).unwrap_or(u64::MAX));
        due
    }

    #[must_use]
    pub fn pending_phone_request_count(&self) -> usize {
        self.pending_phone_requests.len()
    }

    pub fn save_base_key(
        &mut self,
        address: &str,
        message_id: &str,
        base_key: Bytes,
        now_ms: u64,
    ) -> CoreResult<()> {
        validate_non_empty("signal address", address)?;
        validate_non_empty("message id", message_id)?;
        self.purge_base_keys(now_ms);
        let key = base_key_id(address, message_id);
        self.base_keys.insert(key.clone(), (base_key, now_ms));
        self.base_key_order.push_back(key);
        self.enforce_base_key_capacity();
        Ok(())
    }

    pub fn has_same_base_key(
        &mut self,
        address: &str,
        message_id: &str,
        base_key: &[u8],
        now_ms: u64,
    ) -> bool {
        self.purge_base_keys(now_ms);
        let Some((stored, _)) = self.base_keys.get(&base_key_id(address, message_id)) else {
            return false;
        };
        constant_time_eq(stored, base_key)
    }

    pub fn delete_base_key(&mut self, address: &str, message_id: &str) -> bool {
        self.base_keys
            .remove(&base_key_id(address, message_id))
            .is_some()
    }

    pub fn clear(&mut self) {
        self.recent_messages.clear();
        self.recent_order.clear();
        self.message_key_index.clear();
        self.session_recreate_history.clear();
        self.retry_counters.clear();
        self.base_keys.clear();
        self.base_key_order.clear();
        self.pending_phone_requests.clear();
        self.statistics = RetryStatistics::default();
    }

    pub fn plan_retry_resend(
        &mut self,
        receipt: &RetryReceipt,
        session: RetrySessionSnapshot,
        now_ms: u64,
    ) -> CoreResult<RetryReceiptPlan> {
        if receipt.message_ids.is_empty() {
            return Err(CoreError::Protocol(
                "retry receipt has no message ids".to_owned(),
            ));
        }
        let participant_jid = receipt.requester_jid()?.to_owned();
        validate_jid("retry participant JID", &participant_jid)?;
        let remote_jid = receipt.chat_jid.as_deref().ok_or_else(|| {
            CoreError::Protocol("retry receipt missing chat JID for resend".to_owned())
        })?;
        validate_jid("retry chat JID", remote_jid)?;
        let decoded = jid_decode(&participant_jid)
            .ok_or_else(|| CoreError::Protocol("invalid retry participant JID".to_owned()))?;
        let send_to_all = decoded.device.unwrap_or(0) == 0;
        let resend_target = if send_to_all {
            RetryResendTarget::AllDevices
        } else {
            RetryResendTarget::Participant {
                jid: participant_jid.clone(),
                count: receipt.retry.count,
            }
        };

        let should_clear_group_sender_key = receipt
            .chat_jid
            .as_deref()
            .and_then(jid_decode)
            .is_some_and(|jid| jid.server == JidServer::GUs);

        let mut action = if receipt.has_key_bundle {
            RetrySessionAction::InjectBundle
        } else if let (Some(stored), Some(received)) =
            (session.registration_id, receipt.registration_id)
            && stored != 0
            && stored != received
        {
            RetrySessionAction::DeleteAndRefresh {
                reason: format!("registration id mismatch: stored {stored}, received {received}"),
            }
        } else {
            RetrySessionAction::Refresh {
                reason: "retry receipt without key bundle".to_owned(),
            }
        };

        if !receipt.has_key_bundle
            && let (Some(signal_address), Some(base_key), Some(message_id)) = (
                session.signal_address.as_deref(),
                session.base_key.as_ref(),
                receipt.message_ids.first(),
            )
        {
            if receipt.retry.count == 2 {
                self.save_base_key(signal_address, message_id, base_key.clone(), now_ms)?;
            } else if receipt.retry.count > 2 {
                if self.has_same_base_key(signal_address, message_id, base_key, now_ms) {
                    action = RetrySessionAction::DeleteAndRefresh {
                        reason: "base key collision across retries".to_owned(),
                    };
                }
                self.delete_base_key(signal_address, message_id);
            }
        }

        if !receipt.has_key_bundle
            && !matches!(action, RetrySessionAction::DeleteAndRefresh { .. })
            && receipt.retry.count > 1
        {
            let decision = self.should_recreate_session(
                &participant_jid,
                session.has_session,
                receipt.retry.error,
                now_ms,
            )?;
            if decision.recreate {
                action = RetrySessionAction::DeleteAndRefresh {
                    reason: decision
                        .reason
                        .unwrap_or_else(|| "session recreation requested".to_owned()),
                };
            }
        }

        Ok(RetryReceiptPlan {
            remote_jid: remote_jid.to_owned(),
            message_ids: receipt.message_ids.clone(),
            participant_jid,
            retry_count: receipt.retry.count,
            resend_target,
            session_action: action,
            should_clear_group_sender_key,
        })
    }

    pub fn prepare_retry_resends(
        &mut self,
        plan: &RetryReceiptPlan,
        now_ms: u64,
    ) -> CoreResult<RetryResendPreparation> {
        validate_jid("retry resend remote JID", &plan.remote_jid)?;
        if plan.message_ids.is_empty() {
            return Err(CoreError::Protocol(
                "retry resend plan has no message ids".to_owned(),
            ));
        }

        let mut jobs = Vec::new();
        let mut missing_message_ids = Vec::new();
        for message_id in &plan.message_ids {
            validate_non_empty("retry resend message id", message_id)?;
            match self.get_recent_message(&plan.remote_jid, message_id, now_ms) {
                Some(recent) => jobs.push(RetryResendJob {
                    remote_jid: plan.remote_jid.clone(),
                    message_id: message_id.clone(),
                    message: recent.message,
                    target: plan.resend_target.clone(),
                }),
                None => missing_message_ids.push(message_id.clone()),
            }
        }

        Ok(RetryResendPreparation {
            jobs,
            missing_message_ids,
            session_action: plan.session_action.clone(),
            should_clear_group_sender_key: plan.should_clear_group_sender_key,
        })
    }

    fn purge_recent_messages(&mut self, now_ms: u64) {
        let ttl = self.config.recent_message_ttl_ms;
        let expired = self
            .recent_messages
            .iter()
            .filter(|(_, message)| now_ms.saturating_sub(message.timestamp_ms) > ttl)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            self.remove_recent_message_key(&key);
        }
    }

    fn enforce_recent_message_capacity(&mut self) {
        while self.recent_messages.len() > self.config.recent_message_capacity {
            let Some(key) = self.recent_order.pop_front() else {
                break;
            };
            if self.recent_messages.contains_key(&key) {
                self.remove_recent_message_key(&key);
            }
        }
    }

    fn remove_recent_message_key(&mut self, key: &str) -> Option<RecentMessage> {
        if let Some((_, id)) = key.rsplit_once(MESSAGE_KEY_SEPARATOR) {
            self.message_key_index.remove(id);
        }
        self.recent_messages.remove(key)
    }

    fn purge_retry_counters(&mut self, now_ms: u64) {
        let ttl = self.config.retry_counter_ttl_ms;
        self.retry_counters
            .retain(|_, (_, last_seen)| now_ms.saturating_sub(*last_seen) <= ttl);
    }

    fn purge_session_recreate_history(&mut self, now_ms: u64) {
        let ttl = self.config.session_recreate_timeout_ms.saturating_mul(2);
        self.session_recreate_history
            .retain(|_, timestamp| now_ms.saturating_sub(*timestamp) <= ttl);
    }

    fn purge_base_keys(&mut self, now_ms: u64) {
        let ttl = self.config.base_key_ttl_ms;
        self.base_keys
            .retain(|_, (_, timestamp)| now_ms.saturating_sub(*timestamp) <= ttl);
    }

    fn enforce_base_key_capacity(&mut self) {
        while self.base_keys.len() > self.config.base_key_capacity {
            let Some(key) = self.base_key_order.pop_front() else {
                break;
            };
            if self.base_keys.remove(&key).is_some() {
                break;
            }
        }
    }
}

pub fn parse_retry_receipt(node: &BinaryNode) -> CoreResult<Option<RetryReceipt>> {
    if node.tag != "receipt" || node.attrs.get("type").is_none_or(|value| value != "retry") {
        return Ok(None);
    }

    let id = required_attr(node, "id")?.to_owned();
    validate_non_empty("retry receipt id", &id)?;
    let mut message_ids = vec![id];
    if let Some(list) = child_node(node, "list")
        && let Some(BinaryNodeContent::Nodes(items)) = &list.content
    {
        for item in items.iter().filter(|item| item.tag == "item") {
            message_ids.push(required_attr(item, "id")?.to_owned());
        }
    }

    for attr in ["from", "to", "participant", "recipient"] {
        if let Some(jid) = node.attrs.get(attr) {
            validate_jid(attr, jid)?;
        }
    }

    let retry_node = child_node(node, "retry")
        .ok_or_else(|| CoreError::Protocol("retry receipt missing retry node".to_owned()))?;
    let retry = parse_retry_node(retry_node)?;
    let registration_id = child_node(node, "registration").map(node_u32).transpose()?;
    let has_key_bundle = child_node(node, "keys").is_some();
    let from_jid = node.attrs.get("from").cloned();
    let recipient = node.attrs.get("recipient").cloned();
    let chat_jid = recipient.clone().or_else(|| from_jid.clone());

    Ok(Some(RetryReceipt {
        message_ids,
        from_jid,
        to_jid: node.attrs.get("to").cloned(),
        participant: node.attrs.get("participant").cloned(),
        recipient,
        chat_jid,
        retry,
        registration_id,
        has_key_bundle,
    }))
}

fn recent_message_key(to: &str, id: &str) -> String {
    format!("{to}{MESSAGE_KEY_SEPARATOR}{id}")
}

fn base_key_id(address: &str, message_id: &str) -> String {
    format!("{address}:{message_id}")
}

fn validate_jid(label: &str, jid: &str) -> CoreResult<()> {
    if jid_decode(jid).is_none() {
        return Err(CoreError::Payload(format!("invalid {label}: {jid}")));
    }
    Ok(())
}

fn validate_non_empty(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(CoreError::Payload(format!("{label} must not be empty")));
    }
    Ok(())
}

fn parse_retry_node(node: &BinaryNode) -> CoreResult<RetryReceiptRetry> {
    let count = node
        .attrs
        .get("count")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|err| CoreError::Protocol(format!("invalid retry receipt count: {err}")))
        })
        .transpose()?
        .filter(|count| *count > 0)
        .unwrap_or(1);
    let timestamp = optional_attr_u64(node, "t")?;
    let version = optional_attr_u32(node, "v")?;
    Ok(RetryReceiptRetry {
        count,
        original_stanza_id: node.attrs.get("id").cloned(),
        timestamp,
        version,
        error: RetryReason::parse(node.attrs.get("error").map(String::as_str)),
    })
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return None;
    };
    children.iter().find(|child| child.tag == tag)
}

fn required_attr<'a>(node: &'a BinaryNode, attr: &str) -> CoreResult<&'a str> {
    node.attrs
        .get(attr)
        .map(String::as_str)
        .ok_or_else(|| CoreError::Protocol(format!("node {} missing {attr} attr", node.tag)))
}

fn optional_attr_u32(node: &BinaryNode, attr: &str) -> CoreResult<Option<u32>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|err| CoreError::Protocol(format!("invalid {attr} attr: {err}")))
        })
        .transpose()
}

fn optional_attr_u64(node: &BinaryNode, attr: &str) -> CoreResult<Option<u64>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|err| CoreError::Protocol(format!("invalid {attr} attr: {err}")))
        })
        .transpose()
}

fn node_u32(node: &BinaryNode) -> CoreResult<u32> {
    let bytes = node_bytes(node)?;
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(CoreError::Protocol(format!(
            "invalid uint node length for {}: {}",
            node.tag,
            bytes.len()
        )));
    }
    Ok(bytes
        .iter()
        .fold(0u32, |out, byte| (out << 8) | u32::from(*byte)))
}

fn node_bytes(node: &BinaryNode) -> CoreResult<Bytes> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(value)) => Ok(value.clone()),
        Some(BinaryNodeContent::Text(value)) => Ok(Bytes::copy_from_slice(value.as_bytes())),
        _ => Err(CoreError::Protocol(format!(
            "node {} has no byte content",
            node.tag
        ))),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MessageRetryConfig {
        MessageRetryConfig {
            recent_message_capacity: 2,
            recent_message_ttl_ms: 10,
            retry_counter_ttl_ms: 10,
            session_recreate_timeout_ms: 100,
            base_key_capacity: 2,
            base_key_ttl_ms: 10,
            phone_request_delay_ms: 3,
            max_message_retry_count: 2,
        }
    }

    #[test]
    fn caches_recent_messages_with_capacity_and_ttl() {
        let mut manager = MessageRetryManager::new(test_config());
        manager
            .add_recent_message("123@s.whatsapp.net", "m1", Message::default(), 0)
            .unwrap();
        manager
            .add_recent_message("123@s.whatsapp.net", "m2", Message::default(), 1)
            .unwrap();
        manager
            .add_recent_message("123@s.whatsapp.net", "m3", Message::default(), 2)
            .unwrap();

        assert!(
            manager
                .get_recent_message("123@s.whatsapp.net", "m1", 2)
                .is_none()
        );
        assert!(
            manager
                .get_recent_message("123@s.whatsapp.net", "m2", 2)
                .is_some()
        );
        assert!(
            manager
                .get_recent_message("123@s.whatsapp.net", "m2", 20)
                .is_none()
        );
        assert!(
            manager
                .add_recent_message("invalid", "m4", Message::default(), 20)
                .is_err()
        );
    }

    #[test]
    fn tracks_retry_counters_and_completion() {
        let mut manager = MessageRetryManager::new(test_config());

        assert_eq!(manager.increment_retry_count("m1", 0).unwrap(), 1);
        assert_eq!(manager.increment_retry_count("m1", 1).unwrap(), 2);
        assert!(manager.has_exceeded_max_retries("m1", 1));
        assert_eq!(manager.statistics().total_retries, 2);

        manager
            .add_recent_message("123@s.whatsapp.net", "m1", Message::default(), 1)
            .unwrap();
        manager.schedule_phone_request("m1", 1).unwrap();
        manager.mark_retry_success("m1");

        assert_eq!(manager.retry_count("m1", 1), 0);
        assert!(
            manager
                .get_recent_message("123@s.whatsapp.net", "m1", 1)
                .is_none()
        );
        assert_eq!(manager.pending_phone_request_count(), 0);
        assert_eq!(manager.statistics().successful_retries, 1);
    }

    #[test]
    fn decides_session_recreation_with_cooldown_and_mac_errors() {
        let mut manager = MessageRetryManager::new(test_config());

        let decision = manager
            .should_recreate_session("123@s.whatsapp.net", false, None, 0)
            .unwrap();
        assert!(decision.recreate);
        assert!(decision.reason.unwrap().contains("missing"));

        let decision = manager
            .should_recreate_session("123@s.whatsapp.net", true, None, 50)
            .unwrap();
        assert!(!decision.recreate);

        let decision = manager
            .should_recreate_session("123@s.whatsapp.net", true, None, 101)
            .unwrap();
        assert!(decision.recreate);

        let decision = manager
            .should_recreate_session(
                "123@s.whatsapp.net",
                true,
                Some(RetryReason::SignalErrorBadMac),
                102,
            )
            .unwrap();
        assert!(decision.recreate);
        assert_eq!(manager.statistics().session_recreations, 3);
        assert!(
            manager
                .should_recreate_session("invalid", true, None, 0)
                .is_err()
        );
    }

    #[test]
    fn parses_retry_reasons_and_mac_errors() {
        assert_eq!(RetryReason::parse(None), None);
        assert_eq!(RetryReason::parse(Some("")), None);
        assert_eq!(
            RetryReason::parse(Some("4")),
            Some(RetryReason::SignalErrorInvalidMessage)
        );
        assert_eq!(
            RetryReason::parse(Some("99")),
            Some(RetryReason::UnknownError)
        );
        assert_eq!(RetryReason::parse(Some("abc")), None);
        assert!(RetryReason::SignalErrorBadMac.is_mac_error());
        assert!(!RetryReason::SignalErrorNoSession.is_mac_error());
    }

    #[test]
    fn schedules_due_phone_requests_without_runtime_timers() {
        let mut manager = MessageRetryManager::new(test_config());

        assert_eq!(manager.schedule_phone_request("m1", 10).unwrap(), 13);
        assert_eq!(manager.take_due_phone_requests(12), Vec::<String>::new());
        assert_eq!(manager.take_due_phone_requests(13), vec!["m1".to_owned()]);
        assert_eq!(manager.statistics().phone_requests, 1);

        manager.schedule_phone_request("m2", 20).unwrap();
        assert!(manager.cancel_phone_request("m2"));
        assert!(manager.take_due_phone_requests(30).is_empty());
    }

    #[test]
    fn tracks_base_keys_with_ttl_capacity_and_constant_time_compare() {
        let mut manager = MessageRetryManager::new(test_config());

        manager
            .save_base_key("123.1", "m1", Bytes::from_static(b"abc"), 0)
            .unwrap();
        assert!(manager.has_same_base_key("123.1", "m1", b"abc", 0));
        assert!(!manager.has_same_base_key("123.1", "m1", b"abd", 0));

        manager
            .save_base_key("123.1", "m2", Bytes::from_static(b"def"), 1)
            .unwrap();
        manager
            .save_base_key("123.1", "m3", Bytes::from_static(b"ghi"), 2)
            .unwrap();
        assert!(!manager.has_same_base_key("123.1", "m1", b"abc", 2));
        assert!(!manager.has_same_base_key("123.1", "m2", b"def", 20));
        assert!(manager.save_base_key("", "m4", Bytes::new(), 20).is_err());
    }

    #[test]
    fn parses_retry_receipt_nodes() {
        let node = BinaryNode::new("receipt")
            .with_attr("type", "retry")
            .with_attr("id", "m1")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("participant", "123:2@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("retry")
                    .with_attr("count", "2")
                    .with_attr("id", "stanza-1")
                    .with_attr("t", "99")
                    .with_attr("v", "1")
                    .with_attr("error", "4"),
                BinaryNode::new("registration").with_content(vec![0, 0, 0x12, 0x34]),
                BinaryNode::new("list").with_content(vec![
                    BinaryNode::new("item").with_attr("id", "m2"),
                    BinaryNode::new("item").with_attr("id", "m3"),
                ]),
            ]);

        let receipt = parse_retry_receipt(&node).unwrap().unwrap();
        assert_eq!(receipt.message_ids, vec!["m1", "m2", "m3"]);
        assert_eq!(receipt.requester_jid().unwrap(), "123:2@s.whatsapp.net");
        assert_eq!(receipt.retry.count, 2);
        assert_eq!(
            receipt.retry.error,
            Some(RetryReason::SignalErrorInvalidMessage)
        );
        assert_eq!(receipt.registration_id, Some(0x1234));
        assert!(!receipt.has_key_bundle);

        assert!(
            parse_retry_receipt(&BinaryNode::new("message"))
                .unwrap()
                .is_none()
        );
        assert!(
            parse_retry_receipt(
                &BinaryNode::new("receipt")
                    .with_attr("type", "retry")
                    .with_attr("id", "m1")
                    .with_attr("from", "invalid")
                    .with_content(vec![BinaryNode::new("retry")]),
            )
            .is_err()
        );
    }

    #[test]
    fn plans_retry_resend_target_and_refresh_action() {
        let mut manager = MessageRetryManager::new(test_config());
        let receipt = RetryReceipt {
            message_ids: vec!["m1".to_owned()],
            from_jid: Some("123:1@s.whatsapp.net".to_owned()),
            to_jid: None,
            participant: None,
            recipient: Some("999@g.us".to_owned()),
            chat_jid: Some("999@g.us".to_owned()),
            retry: RetryReceiptRetry {
                count: 1,
                original_stanza_id: None,
                timestamp: None,
                version: None,
                error: None,
            },
            registration_id: None,
            has_key_bundle: false,
        };

        let plan = manager
            .plan_retry_resend(
                &receipt,
                RetrySessionSnapshot {
                    has_session: true,
                    registration_id: Some(10),
                    base_key: None,
                    signal_address: None,
                },
                0,
            )
            .unwrap();

        assert_eq!(
            plan.resend_target,
            RetryResendTarget::Participant {
                jid: "123:1@s.whatsapp.net".to_owned(),
                count: 1,
            }
        );
        assert_eq!(
            plan.session_action,
            RetrySessionAction::Refresh {
                reason: "retry receipt without key bundle".to_owned(),
            }
        );
        assert!(plan.should_clear_group_sender_key);
    }

    #[test]
    fn prepares_retry_resend_jobs_from_recent_messages() {
        let mut manager = MessageRetryManager::new(test_config());
        let message = Message {
            conversation: Some("cached".to_owned()),
            ..Message::default()
        };
        manager
            .add_recent_message("999@g.us", "m1", message.clone(), 0)
            .unwrap();
        let receipt = RetryReceipt {
            message_ids: vec!["m1".to_owned(), "m2".to_owned()],
            from_jid: Some("123:1@s.whatsapp.net".to_owned()),
            to_jid: None,
            participant: None,
            recipient: Some("999@g.us".to_owned()),
            chat_jid: Some("999@g.us".to_owned()),
            retry: RetryReceiptRetry {
                count: 1,
                original_stanza_id: None,
                timestamp: None,
                version: None,
                error: None,
            },
            registration_id: None,
            has_key_bundle: false,
        };
        let plan = manager
            .plan_retry_resend(
                &receipt,
                RetrySessionSnapshot {
                    has_session: true,
                    registration_id: Some(10),
                    base_key: None,
                    signal_address: None,
                },
                0,
            )
            .unwrap();

        let prepared = manager.prepare_retry_resends(&plan, 0).unwrap();

        assert!(!prepared.is_complete());
        assert_eq!(prepared.jobs.len(), 1);
        assert_eq!(prepared.jobs[0].remote_jid, "999@g.us");
        assert_eq!(prepared.jobs[0].message_id, "m1");
        assert_eq!(prepared.jobs[0].message, message);
        assert_eq!(prepared.jobs[0].target, plan.resend_target);
        assert_eq!(prepared.missing_message_ids, vec!["m2".to_owned()]);
        assert_eq!(prepared.session_action, plan.session_action);
        assert!(prepared.should_clear_group_sender_key);
    }

    #[test]
    fn plans_all_device_resend_for_primary_requester_and_bundle_injection() {
        let mut manager = MessageRetryManager::new(test_config());
        let receipt = RetryReceipt {
            message_ids: vec!["m1".to_owned()],
            from_jid: Some("123@s.whatsapp.net".to_owned()),
            to_jid: None,
            participant: None,
            recipient: None,
            chat_jid: Some("123@s.whatsapp.net".to_owned()),
            retry: RetryReceiptRetry {
                count: 1,
                original_stanza_id: None,
                timestamp: None,
                version: None,
                error: None,
            },
            registration_id: None,
            has_key_bundle: true,
        };

        let plan = manager
            .plan_retry_resend(&receipt, RetrySessionSnapshot::missing(), 0)
            .unwrap();

        assert_eq!(plan.resend_target, RetryResendTarget::AllDevices);
        assert_eq!(plan.session_action, RetrySessionAction::InjectBundle);
        assert!(!plan.should_clear_group_sender_key);
    }

    #[test]
    fn plans_delete_for_registration_mismatch_and_base_key_collision() {
        let mut manager = MessageRetryManager::new(test_config());
        let mut receipt = RetryReceipt {
            message_ids: vec!["m1".to_owned()],
            from_jid: Some("123:1@s.whatsapp.net".to_owned()),
            to_jid: None,
            participant: None,
            recipient: None,
            chat_jid: Some("123@s.whatsapp.net".to_owned()),
            retry: RetryReceiptRetry {
                count: 2,
                original_stanza_id: None,
                timestamp: None,
                version: None,
                error: None,
            },
            registration_id: Some(10),
            has_key_bundle: false,
        };
        let snapshot = RetrySessionSnapshot {
            has_session: true,
            registration_id: Some(11),
            base_key: Some(Bytes::from_static(b"base")),
            signal_address: Some("123.1".to_owned()),
        };

        let plan = manager
            .plan_retry_resend(&receipt, snapshot.clone(), 0)
            .unwrap();
        assert!(matches!(
            plan.session_action,
            RetrySessionAction::DeleteAndRefresh { .. }
        ));

        receipt.registration_id = None;
        let plan = manager
            .plan_retry_resend(&receipt, snapshot.clone(), 1)
            .unwrap();
        assert!(matches!(
            plan.session_action,
            RetrySessionAction::DeleteAndRefresh { .. }
        ));
        assert!(manager.has_same_base_key("123.1", "m1", b"base", 1));

        receipt.retry.count = 3;
        let plan = manager.plan_retry_resend(&receipt, snapshot, 2).unwrap();
        assert_eq!(
            plan.session_action,
            RetrySessionAction::DeleteAndRefresh {
                reason: "base key collision across retries".to_owned(),
            }
        );
        assert!(!manager.has_same_base_key("123.1", "m1", b"base", 2));
    }
}
