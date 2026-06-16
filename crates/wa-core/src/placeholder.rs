use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{CoreError, CoreResult};
use wa_binary::jid_decode;
use wa_proto::proto::{MessageKey, WebMessageInfo, web_message_info::StubType};

pub const PLACEHOLDER_MAX_AGE_SECONDS: u64 = 14 * 24 * 60 * 60;
pub const DEFAULT_PLACEHOLDER_RESEND_CAPACITY: usize = 512;
pub const DEFAULT_PLACEHOLDER_RESEND_TTL_MS: u64 = 60 * 60 * 1000;
pub const PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT: &str = "Message absent from node";
pub const PLACEHOLDER_MISSING_KEYS_ERROR_TEXT: &str = "Key used already or never filled";
pub const PLACEHOLDER_EXCLUDED_UNAVAILABLE_TYPES: [&str; 3] = [
    "bot_unavailable_fanout",
    "hosted_unavailable_fanout",
    "view_once_unavailable_fanout",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceholderResendTrackerConfig {
    pub capacity: usize,
    pub ttl_ms: u64,
}

impl Default for PlaceholderResendTrackerConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_PLACEHOLDER_RESEND_CAPACITY,
            ttl_ms: DEFAULT_PLACEHOLDER_RESEND_TTL_MS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceholderResendRecord {
    pub message_id: String,
    pub requested_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceholderResendRequest {
    pub key: MessageKey,
    pub message_timestamp_secs: u64,
    pub unavailable_type: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PlaceholderResendTracker {
    inner: Arc<Mutex<PlaceholderResendTrackerInner>>,
}

impl Default for PlaceholderResendTracker {
    fn default() -> Self {
        Self::new(PlaceholderResendTrackerConfig::default())
    }
}

impl PlaceholderResendTracker {
    #[must_use]
    pub fn new(config: PlaceholderResendTrackerConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PlaceholderResendTrackerInner {
                config,
                records: BTreeMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub fn begin_request(&self, message_id: &str, now_ms: u64) -> CoreResult<bool> {
        validate_message_id(message_id)?;
        let mut inner = self.lock()?;
        inner.purge_expired(now_ms);
        if inner.records.contains_key(message_id) {
            return Ok(false);
        }
        let record = PlaceholderResendRecord {
            message_id: message_id.to_owned(),
            requested_at_ms: now_ms,
        };
        inner.records.insert(message_id.to_owned(), record);
        inner.order.push_back(message_id.to_owned());
        inner.enforce_capacity();
        Ok(true)
    }

    pub fn resolve(&self, message_id: &str) -> CoreResult<Option<PlaceholderResendRecord>> {
        validate_message_id(message_id)?;
        Ok(self.lock()?.records.remove(message_id))
    }

    pub fn contains(&self, message_id: &str, now_ms: u64) -> CoreResult<bool> {
        validate_message_id(message_id)?;
        let mut inner = self.lock()?;
        inner.purge_expired(now_ms);
        Ok(inner.records.contains_key(message_id))
    }

    pub fn len(&self, now_ms: u64) -> CoreResult<usize> {
        let mut inner = self.lock()?;
        inner.purge_expired(now_ms);
        Ok(inner.records.len())
    }

    pub fn purge_expired(&self, now_ms: u64) -> CoreResult<usize> {
        Ok(self.lock()?.purge_expired(now_ms))
    }

    pub fn clear(&self) -> CoreResult<()> {
        let mut inner = self.lock()?;
        inner.records.clear();
        inner.order.clear();
        Ok(())
    }

    fn lock(&self) -> CoreResult<MutexGuard<'_, PlaceholderResendTrackerInner>> {
        self.inner
            .lock()
            .map_err(|_| CoreError::Task("placeholder resend tracker lock poisoned".to_owned()))
    }
}

#[must_use]
pub fn is_placeholder_resend_age_allowed(message_timestamp_secs: u64, now_secs: u64) -> bool {
    now_secs.saturating_sub(message_timestamp_secs) <= PLACEHOLDER_MAX_AGE_SECONDS
}

#[must_use]
pub fn is_excluded_placeholder_unavailable_type(value: &str) -> bool {
    PLACEHOLDER_EXCLUDED_UNAVAILABLE_TYPES.contains(&value)
}

pub fn placeholder_resend_request_from_web_message(
    message: &WebMessageInfo,
    category: Option<&str>,
    unavailable_type: Option<&str>,
    now_secs: u64,
) -> CoreResult<Option<PlaceholderResendRequest>> {
    if category == Some("peer") {
        return Ok(None);
    }
    if message.message_stub_type != Some(StubType::Ciphertext as i32) {
        return Ok(None);
    }
    let Some(error_text) = message.message_stub_parameters.first().map(String::as_str) else {
        return Ok(None);
    };
    if error_text == PLACEHOLDER_MISSING_KEYS_ERROR_TEXT {
        return Ok(None);
    }
    if error_text != PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT {
        return Ok(None);
    }
    if let Some(unavailable_type) = unavailable_type
        && is_excluded_placeholder_unavailable_type(unavailable_type)
    {
        return Ok(None);
    }
    let Some(timestamp) = message.message_timestamp else {
        return Ok(None);
    };
    if !is_placeholder_resend_age_allowed(timestamp, now_secs) {
        return Ok(None);
    }
    let key = message.key.as_ref().ok_or_else(|| {
        CoreError::Protocol("placeholder resend candidate missing key".to_owned())
    })?;
    validate_placeholder_message_key(key)?;
    Ok(Some(PlaceholderResendRequest {
        key: key.clone(),
        message_timestamp_secs: timestamp,
        unavailable_type: unavailable_type.map(str::to_owned),
    }))
}

#[derive(Clone, Debug)]
struct PlaceholderResendTrackerInner {
    config: PlaceholderResendTrackerConfig,
    records: BTreeMap<String, PlaceholderResendRecord>,
    order: VecDeque<String>,
}

impl PlaceholderResendTrackerInner {
    fn purge_expired(&mut self, now_ms: u64) -> usize {
        let before = self.records.len();
        let ttl = self.config.ttl_ms;
        self.records
            .retain(|_, record| now_ms.saturating_sub(record.requested_at_ms) <= ttl);
        before.saturating_sub(self.records.len())
    }

    fn enforce_capacity(&mut self) {
        while self.records.len() > self.config.capacity {
            let Some(message_id) = self.order.pop_front() else {
                break;
            };
            if self.records.remove(&message_id).is_some() {
                continue;
            }
        }
    }
}

fn validate_message_id(message_id: &str) -> CoreResult<()> {
    if message_id.is_empty() {
        return Err(CoreError::Payload(
            "placeholder resend message id must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn validate_placeholder_message_key(key: &MessageKey) -> CoreResult<()> {
    let remote_jid = key.remote_jid.as_deref().ok_or_else(|| {
        CoreError::Payload("placeholder resend message key missing remote JID".to_owned())
    })?;
    if jid_decode(remote_jid).is_none() {
        return Err(CoreError::Payload(format!(
            "invalid placeholder resend remote JID: {remote_jid}"
        )));
    }
    let id = key.id.as_deref().ok_or_else(|| {
        CoreError::Payload("placeholder resend message key missing id".to_owned())
    })?;
    validate_message_id(id)?;
    if let Some(participant) = key.participant.as_deref()
        && jid_decode(participant).is_none()
    {
        return Err(CoreError::Payload(format!(
            "invalid placeholder resend participant JID: {participant}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_proto::proto::WebMessageInfo;

    #[test]
    fn tracks_placeholder_resend_requests_with_ttl_and_capacity() {
        let tracker = PlaceholderResendTracker::new(PlaceholderResendTrackerConfig {
            capacity: 2,
            ttl_ms: 10,
        });

        assert!(tracker.begin_request("m1", 0).unwrap());
        assert!(!tracker.begin_request("m1", 1).unwrap());
        assert!(tracker.contains("m1", 1).unwrap());
        assert!(tracker.begin_request("m2", 2).unwrap());
        assert!(tracker.begin_request("m3", 3).unwrap());
        assert!(!tracker.contains("m1", 3).unwrap());
        assert_eq!(tracker.len(3).unwrap(), 2);

        let resolved = tracker.resolve("m2").unwrap().unwrap();
        assert_eq!(resolved.message_id, "m2");
        assert!(!tracker.contains("m2", 3).unwrap());
        assert_eq!(tracker.purge_expired(20).unwrap(), 1);
        assert_eq!(tracker.len(20).unwrap(), 0);
    }

    #[test]
    fn checks_placeholder_resend_age() {
        assert!(is_placeholder_resend_age_allowed(100, 100));
        assert!(is_placeholder_resend_age_allowed(
            100,
            100 + PLACEHOLDER_MAX_AGE_SECONDS
        ));
        assert!(!is_placeholder_resend_age_allowed(
            100,
            101 + PLACEHOLDER_MAX_AGE_SECONDS
        ));
        assert!(is_placeholder_resend_age_allowed(200, 100));
    }

    #[test]
    fn plans_placeholder_resend_for_eligible_unavailable_message() {
        let key = MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("m1".to_owned()),
            participant: None,
        };
        let message = WebMessageInfo {
            key: Some(key.clone()),
            message_timestamp: Some(100),
            message_stub_type: Some(StubType::Ciphertext as i32),
            message_stub_parameters: vec![PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()],
            ..WebMessageInfo::default()
        };

        let request = placeholder_resend_request_from_web_message(
            &message,
            None,
            Some("transient_unavailable"),
            101,
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.key, key);
        assert_eq!(request.message_timestamp_secs, 100);
        assert_eq!(
            request.unavailable_type.as_deref(),
            Some("transient_unavailable")
        );
    }

    #[test]
    fn skips_ineligible_placeholder_resend_messages() {
        let mut message = WebMessageInfo {
            key: Some(MessageKey {
                remote_jid: Some("123@s.whatsapp.net".to_owned()),
                from_me: Some(false),
                id: Some("m1".to_owned()),
                participant: None,
            }),
            message_timestamp: Some(100),
            message_stub_type: Some(StubType::Ciphertext as i32),
            message_stub_parameters: vec![PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()],
            ..WebMessageInfo::default()
        };

        assert!(
            placeholder_resend_request_from_web_message(&message, Some("peer"), None, 101)
                .unwrap()
                .is_none()
        );
        assert!(
            placeholder_resend_request_from_web_message(
                &message,
                None,
                Some("bot_unavailable_fanout"),
                101,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            placeholder_resend_request_from_web_message(
                &message,
                None,
                None,
                101 + PLACEHOLDER_MAX_AGE_SECONDS,
            )
            .unwrap()
            .is_none()
        );

        message.message_stub_parameters = vec![PLACEHOLDER_MISSING_KEYS_ERROR_TEXT.to_owned()];
        assert!(
            placeholder_resend_request_from_web_message(&message, None, None, 101)
                .unwrap()
                .is_none()
        );

        message.message_stub_parameters = vec![PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()];
        message.message_stub_type = Some(StubType::Revoke as i32);
        assert!(
            placeholder_resend_request_from_web_message(&message, None, None, 101)
                .unwrap()
                .is_none()
        );

        message.message_stub_type = Some(StubType::Ciphertext as i32);
        message.message_timestamp = None;
        assert!(
            placeholder_resend_request_from_web_message(&message, None, None, 101)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_invalid_placeholder_resend_candidate_key() {
        let message = WebMessageInfo {
            key: Some(MessageKey {
                remote_jid: Some("not a jid".to_owned()),
                from_me: Some(false),
                id: Some("m1".to_owned()),
                participant: None,
            }),
            message_timestamp: Some(100),
            message_stub_type: Some(StubType::Ciphertext as i32),
            message_stub_parameters: vec![PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()],
            ..WebMessageInfo::default()
        };

        assert!(placeholder_resend_request_from_web_message(&message, None, None, 101).is_err());
    }
}
