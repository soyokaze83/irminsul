use crate::{CoreError, CoreResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, jid_decode, jid_normalized_user};
use wa_store::{AuthStore, KeyNamespace};

const STORED_TC_TOKEN_MAGIC: &[u8; 4] = b"TCTK";
const STORED_TC_TOKEN_VERSION: u8 = 1;
const MAX_TC_TOKEN_BYTES: usize = 16 * 1024;
const TRUSTED_CONTACT_TOKEN_TYPE: &str = "trusted_contact";
const TC_TOKEN_SERVER_JID: &str = "@s.whatsapp.net";
pub const TC_TOKEN_BUCKET_DURATION_SECONDS: u64 = 604_800;
pub const TC_TOKEN_BUCKET_COUNT: u64 = 4;
pub const DEFAULT_TC_TOKEN_PRUNE_BATCH_SIZE: usize = 128;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcTokenPruneOutcome {
    pub scanned: usize,
    pub retained: usize,
    pub deleted: usize,
    pub malformed_deleted: usize,
    pub markers_preserved: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcTokenRecord {
    pub jid: String,
    pub token: Bytes,
    pub timestamp_seconds: Option<u64>,
    pub sender_timestamp_seconds: Option<u64>,
}

impl TcTokenRecord {
    pub fn new(jid: impl Into<String>, token: impl Into<Bytes>) -> CoreResult<Self> {
        let jid = jid.into();
        validate_jid("tctoken JID", &jid)?;
        let token = token.into();
        validate_token_bytes(&token)?;
        Ok(Self {
            jid,
            token,
            timestamp_seconds: None,
            sender_timestamp_seconds: None,
        })
    }

    pub fn sender_marker(
        jid: impl Into<String>,
        sender_timestamp_seconds: u64,
    ) -> CoreResult<Self> {
        let jid = jid.into();
        validate_jid("tctoken JID", &jid)?;
        if sender_timestamp_seconds == 0 {
            return Err(CoreError::Protocol(
                "tctoken sender timestamp must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            jid,
            token: Bytes::new(),
            timestamp_seconds: None,
            sender_timestamp_seconds: Some(sender_timestamp_seconds),
        })
    }

    #[must_use]
    pub fn with_timestamp_seconds(mut self, timestamp_seconds: u64) -> Self {
        self.timestamp_seconds = Some(timestamp_seconds);
        self
    }

    #[must_use]
    pub fn with_sender_timestamp_seconds(mut self, sender_timestamp_seconds: u64) -> Self {
        self.sender_timestamp_seconds = Some(sender_timestamp_seconds);
        self
    }
}

pub fn encode_stored_tc_token(record: &TcTokenRecord) -> CoreResult<Vec<u8>> {
    validate_record(record)?;
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_TC_TOKEN_MAGIC);
    out.put_u8(STORED_TC_TOKEN_VERSION);
    put_string(&mut out, &record.jid)?;
    put_bytes(&mut out, &record.token)?;
    match record.timestamp_seconds {
        Some(timestamp_seconds) => {
            out.put_u8(1);
            out.put_u64(timestamp_seconds);
        }
        None => out.put_u8(0),
    }
    match record.sender_timestamp_seconds {
        Some(timestamp_seconds) => {
            out.put_u8(1);
            out.put_u64(timestamp_seconds);
        }
        None => out.put_u8(0),
    }
    Ok(out.to_vec())
}

pub fn decode_stored_tc_token(value: &[u8]) -> CoreResult<TcTokenRecord> {
    if value.len() > MAX_TC_TOKEN_BYTES + 128 {
        return Err(CoreError::Protocol(
            "stored tctoken record is too large".to_owned(),
        ));
    }
    let mut input = value;
    read_magic(&mut input)?;
    let jid = read_string(&mut input)?;
    validate_jid("tctoken JID", &jid)?;
    let token = Bytes::from(read_bytes(&mut input)?);
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored tctoken missing timestamp tag".to_owned(),
        ));
    }
    let timestamp_seconds = match input.get_u8() {
        0 => None,
        1 => {
            if input.remaining() < 8 {
                return Err(CoreError::Protocol(
                    "stored tctoken has truncated timestamp".to_owned(),
                ));
            }
            Some(input.get_u64())
        }
        tag => {
            return Err(CoreError::Protocol(format!(
                "stored tctoken has invalid timestamp tag {tag}"
            )));
        }
    };
    let sender_timestamp_seconds = if input.is_empty() {
        None
    } else {
        match input.get_u8() {
            0 => None,
            1 => {
                if input.remaining() < 8 {
                    return Err(CoreError::Protocol(
                        "stored tctoken has truncated sender timestamp".to_owned(),
                    ));
                }
                Some(input.get_u64())
            }
            tag => {
                return Err(CoreError::Protocol(format!(
                    "stored tctoken has invalid sender timestamp tag {tag}"
                )));
            }
        }
    };
    if !input.is_empty() {
        return Err(CoreError::Protocol(format!(
            "stored tctoken has {} trailing bytes",
            input.len()
        )));
    }
    let record = TcTokenRecord {
        jid,
        token,
        timestamp_seconds,
        sender_timestamp_seconds,
    };
    validate_record(&record)?;
    Ok(record)
}

#[must_use]
pub fn is_tc_token_expired(timestamp_seconds: Option<u64>, now_seconds: u64) -> bool {
    let Some(timestamp_seconds) = timestamp_seconds else {
        return true;
    };
    let current_bucket = now_seconds / TC_TOKEN_BUCKET_DURATION_SECONDS;
    let cutoff_bucket = current_bucket.saturating_sub(TC_TOKEN_BUCKET_COUNT.saturating_sub(1));
    let cutoff_timestamp = cutoff_bucket.saturating_mul(TC_TOKEN_BUCKET_DURATION_SECONDS);
    timestamp_seconds < cutoff_timestamp
}

#[must_use]
pub fn should_send_new_tc_token(sender_timestamp_seconds: Option<u64>, now_seconds: u64) -> bool {
    let Some(sender_timestamp_seconds) = sender_timestamp_seconds else {
        return true;
    };
    let current_bucket = now_seconds / TC_TOKEN_BUCKET_DURATION_SECONDS;
    let sender_bucket = sender_timestamp_seconds / TC_TOKEN_BUCKET_DURATION_SECONDS;
    current_bucket > sender_bucket
}

#[must_use]
pub fn is_regular_tc_token_jid(jid: &str) -> bool {
    let Some(decoded) = jid_decode(jid) else {
        return false;
    };
    if decoded.user == "0" || is_bot_phone_user(&decoded.user) {
        return false;
    }
    matches!(
        decoded.server,
        JidServer::CUs
            | JidServer::SWhatsAppNet
            | JidServer::Lid
            | JidServer::Hosted
            | JidServer::HostedLid
    )
}

pub fn tc_token_node(record: &TcTokenRecord, now_seconds: u64) -> CoreResult<Option<BinaryNode>> {
    validate_jid("tctoken JID", &record.jid)?;
    if record.token.is_empty() {
        return Ok(None);
    }
    validate_token_bytes(&record.token)?;
    if !is_regular_tc_token_jid(&record.jid)
        || is_tc_token_expired(record.timestamp_seconds, now_seconds)
    {
        return Ok(None);
    }
    Ok(Some(
        BinaryNode::new("tctoken").with_content(record.token.clone()),
    ))
}

pub fn build_tc_token_issue_query<I, T>(
    jids: I,
    timestamp_seconds: u64,
    tag: impl Into<String>,
) -> CoreResult<Option<BinaryNode>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    if timestamp_seconds == 0 {
        return Err(CoreError::Protocol(
            "tctoken issue timestamp must be greater than zero".to_owned(),
        ));
    }
    let timestamp = timestamp_seconds.to_string();
    let mut token_nodes = Vec::new();
    let mut seen = Vec::<String>::new();
    for jid in jids {
        let jid = normalize_tc_token_jid(jid.as_ref())?;
        if !is_regular_tc_token_jid(&jid) || seen.iter().any(|known| known == &jid) {
            continue;
        }
        seen.push(jid.clone());
        token_nodes.push(
            BinaryNode::new("token")
                .with_attr("jid", jid)
                .with_attr("t", timestamp.as_str())
                .with_attr("type", TRUSTED_CONTACT_TOKEN_TYPE),
        );
    }
    if token_nodes.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        BinaryNode::new("iq")
            .with_attr("id", tag.into())
            .with_attr("xmlns", "privacy")
            .with_attr("type", "set")
            .with_attr("to", TC_TOKEN_SERVER_JID)
            .with_content(vec![BinaryNode::new("tokens").with_content(token_nodes)]),
    ))
}

pub fn tc_token_records_from_issue_result(
    node: &BinaryNode,
    fallback_jid: Option<&str>,
) -> CoreResult<Vec<TcTokenRecord>> {
    if let Some(error) = tc_token_issue_error_from_result(node) {
        return Err(error);
    }
    let Some(tokens) = child_node(node, "tokens") else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for token_node in child_nodes(tokens)
        .iter()
        .filter(|child| child.tag == "token")
    {
        if token_node
            .attrs
            .get("type")
            .is_none_or(|value| value != TRUSTED_CONTACT_TOKEN_TYPE)
        {
            continue;
        }
        let Some(token) = node_bytes(token_node) else {
            continue;
        };
        if token.is_empty() {
            continue;
        }
        let Some(timestamp) = token_node
            .attrs
            .get("t")
            .and_then(|value| value.parse().ok())
        else {
            continue;
        };
        if timestamp == 0 {
            continue;
        }
        let raw_jid = fallback_jid
            .or_else(|| token_node.attrs.get("jid").map(String::as_str))
            .ok_or_else(|| CoreError::Protocol("tctoken result token missing jid".to_owned()))?;
        let jid = normalize_tc_token_jid(raw_jid)?;
        if !is_regular_tc_token_jid(&jid) {
            continue;
        }
        records.push(TcTokenRecord::new(jid, token)?.with_timestamp_seconds(timestamp));
    }
    Ok(records)
}

#[must_use]
pub fn privacy_token_notification_sender_lid(node: &BinaryNode) -> Option<String> {
    if node.tag != "notification"
        || node.attrs.get("type").map(String::as_str) != Some("privacy_token")
    {
        return None;
    }
    let sender_lid = node
        .attrs
        .get("sender_lid")
        .filter(|value| !value.is_empty())?;
    let normalized = jid_normalized_user(sender_lid)?;
    let decoded = jid_decode(&normalized)?;
    matches!(decoded.server, JidServer::Lid | JidServer::HostedLid).then_some(normalized)
}

pub fn tc_token_records_from_privacy_token_notification(
    node: &BinaryNode,
    fallback_jid: Option<&str>,
) -> CoreResult<Vec<TcTokenRecord>> {
    if node.tag != "notification"
        || node.attrs.get("type").map(String::as_str) != Some("privacy_token")
        || child_node(node, "tokens").is_none()
    {
        return Ok(Vec::new());
    }
    tc_token_records_from_issue_result(node, fallback_jid)
}

pub async fn save_tc_token<S>(store: &S, record: TcTokenRecord) -> CoreResult<()>
where
    S: AuthStore,
{
    let encoded = encode_stored_tc_token(&record)?;
    store
        .set(KeyNamespace::TcToken, &record.jid, &encoded)
        .await?;
    Ok(())
}

pub async fn store_tc_tokens_from_issue_result<S>(
    store: &S,
    node: &BinaryNode,
    fallback_jid: Option<&str>,
) -> CoreResult<Vec<TcTokenRecord>>
where
    S: AuthStore,
{
    let records = tc_token_records_from_issue_result(node, fallback_jid)?;
    store_tc_token_records(store, records).await
}

pub async fn store_tc_tokens_from_privacy_token_notification<S>(
    store: &S,
    node: &BinaryNode,
    fallback_jid: Option<&str>,
) -> CoreResult<Vec<TcTokenRecord>>
where
    S: AuthStore,
{
    let records = tc_token_records_from_privacy_token_notification(node, fallback_jid)?;
    store_tc_token_records(store, records).await
}

async fn store_tc_token_records<S>(
    store: &S,
    records: Vec<TcTokenRecord>,
) -> CoreResult<Vec<TcTokenRecord>>
where
    S: AuthStore,
{
    let mut saved = Vec::new();
    for mut record in records {
        let existing = load_tc_token(store, &record.jid).await?;
        if existing
            .as_ref()
            .and_then(|record| record.timestamp_seconds)
            .is_some_and(|timestamp| {
                record
                    .timestamp_seconds
                    .is_some_and(|newer| timestamp > newer)
            })
        {
            continue;
        }
        record.sender_timestamp_seconds =
            existing.and_then(|record| record.sender_timestamp_seconds);
        save_tc_token(store, record.clone()).await?;
        saved.push(record);
    }
    Ok(saved)
}

pub async fn mark_tc_token_issued<S>(
    store: &S,
    jid: &str,
    sender_timestamp_seconds: u64,
) -> CoreResult<TcTokenRecord>
where
    S: AuthStore,
{
    let jid = normalize_tc_token_jid(jid)?;
    if !is_regular_tc_token_jid(&jid) {
        return Err(CoreError::Protocol(format!(
            "cannot mark tctoken issued for non-regular JID: {jid}"
        )));
    }
    let mut record = load_tc_token(store, &jid)
        .await?
        .unwrap_or(TcTokenRecord::sender_marker(jid, sender_timestamp_seconds)?);
    record.sender_timestamp_seconds = Some(sender_timestamp_seconds);
    save_tc_token(store, record.clone()).await?;
    Ok(record)
}

pub async fn load_tc_token<S>(store: &S, jid: &str) -> CoreResult<Option<TcTokenRecord>>
where
    S: AuthStore,
{
    validate_jid("tctoken JID", jid)?;
    let Some(value) = store.get(KeyNamespace::TcToken, jid).await? else {
        return Ok(None);
    };
    decode_stored_tc_token(&value).map(Some)
}

pub async fn delete_tc_token<S>(store: &S, jid: &str) -> CoreResult<()>
where
    S: AuthStore,
{
    validate_jid("tctoken JID", jid)?;
    store.delete(KeyNamespace::TcToken, jid).await?;
    Ok(())
}

pub async fn prune_expired_tc_tokens<S>(
    store: &S,
    now_seconds: u64,
    batch_size: usize,
) -> CoreResult<TcTokenPruneOutcome>
where
    S: AuthStore,
{
    let batch_size = batch_size.max(1);
    let mut after = None::<String>;
    let mut outcome = TcTokenPruneOutcome::default();

    loop {
        let keys = store
            .list_keys(KeyNamespace::TcToken, after.as_deref(), batch_size)
            .await?;
        if keys.is_empty() {
            break;
        }
        after = keys.last().cloned();

        for key in &keys {
            outcome.scanned += 1;
            let Some(value) = store.get(KeyNamespace::TcToken, key).await? else {
                continue;
            };
            let record = match decode_stored_tc_token(&value) {
                Ok(record) => record,
                Err(_) => {
                    store.delete(KeyNamespace::TcToken, key).await?;
                    outcome.deleted += 1;
                    outcome.malformed_deleted += 1;
                    continue;
                }
            };

            if !is_regular_tc_token_jid(&record.jid) {
                store.delete(KeyNamespace::TcToken, key).await?;
                outcome.deleted += 1;
                continue;
            }

            let sender_timestamp_is_valid = record
                .sender_timestamp_seconds
                .is_some_and(|timestamp| !is_tc_token_expired(Some(timestamp), now_seconds));
            let token_is_usable = !record.token.is_empty()
                && !is_tc_token_expired(record.timestamp_seconds, now_seconds);

            match (token_is_usable, sender_timestamp_is_valid) {
                (true, _) => outcome.retained += 1,
                (false, true) if !record.token.is_empty() => {
                    save_tc_token(
                        store,
                        TcTokenRecord::sender_marker(
                            record.jid,
                            record.sender_timestamp_seconds.unwrap_or_default(),
                        )?,
                    )
                    .await?;
                    outcome.retained += 1;
                    outcome.markers_preserved += 1;
                }
                (false, true) => outcome.retained += 1,
                (false, false) => {
                    store.delete(KeyNamespace::TcToken, key).await?;
                    outcome.deleted += 1;
                }
            }
        }

        if keys.len() < batch_size {
            break;
        }
    }

    Ok(outcome)
}

pub async fn load_tc_token_node_for_send<S>(
    store: &S,
    jid: &str,
    now_seconds: u64,
) -> CoreResult<Option<BinaryNode>>
where
    S: AuthStore,
{
    if !is_regular_tc_token_jid(jid) {
        return Ok(None);
    }
    let Some(record) = load_tc_token(store, jid).await? else {
        return Ok(None);
    };
    if record.token.is_empty() {
        return Ok(None);
    }
    if is_tc_token_expired(record.timestamp_seconds, now_seconds) {
        if let Some(sender_timestamp_seconds) = record.sender_timestamp_seconds {
            save_tc_token(
                store,
                TcTokenRecord::sender_marker(record.jid, sender_timestamp_seconds)?,
            )
            .await?;
        } else {
            delete_tc_token(store, jid).await?;
        }
        return Ok(None);
    }
    tc_token_node(&record, now_seconds)
}

fn validate_record(record: &TcTokenRecord) -> CoreResult<()> {
    validate_jid("tctoken JID", &record.jid)?;
    if record.token.is_empty() {
        if record.sender_timestamp_seconds.is_some() {
            return Ok(());
        }
        return Err(CoreError::Protocol(
            "stored tctoken record has neither token nor sender timestamp".to_owned(),
        ));
    }
    validate_token_bytes(&record.token)
}

fn validate_token_bytes(token: &[u8]) -> CoreResult<()> {
    if token.is_empty() {
        return Err(CoreError::Protocol("tctoken must not be empty".to_owned()));
    }
    if token.len() > MAX_TC_TOKEN_BYTES {
        return Err(CoreError::Protocol(format!(
            "tctoken exceeds {MAX_TC_TOKEN_BYTES} bytes"
        )));
    }
    Ok(())
}

fn normalize_tc_token_jid(jid: &str) -> CoreResult<String> {
    jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid tctoken JID: {jid}")))?;
    Ok(jid_normalized_user(jid).unwrap_or_else(|| jid.to_owned()))
}

fn validate_jid(label: &str, jid: &str) -> CoreResult<()> {
    if jid_decode(jid).is_none() {
        return Err(CoreError::Protocol(format!("invalid {label}: {jid}")));
    }
    Ok(())
}

fn tc_token_issue_error_from_result(node: &BinaryNode) -> Option<CoreError> {
    let error_node = child_node(node, "error");
    if node.attrs.get("type").is_none_or(|value| value != "error") && error_node.is_none() {
        return None;
    }
    let code = error_node
        .and_then(|error| error.attrs.get("code"))
        .or_else(|| node.attrs.get("code"))
        .or_else(|| node.attrs.get("error"))
        .map(String::as_str)
        .unwrap_or("500");
    let text = error_node
        .and_then(|error| error.attrs.get("text"))
        .or_else(|| node.attrs.get("text"))
        .or_else(|| node.attrs.get("reason"))
        .map(String::as_str)
        .unwrap_or("tctoken issue failed");
    Some(CoreError::Protocol(format!(
        "tctoken issue failed ({code}): {text}"
    )))
}

fn child_nodes(node: &BinaryNode) -> &[BinaryNode] {
    match &node.content {
        Some(BinaryNodeContent::Nodes(children)) => children,
        _ => &[],
    }
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    child_nodes(node).iter().find(|child| child.tag == tag)
}

fn node_bytes(node: &BinaryNode) -> Option<Bytes> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(value)) => Some(value.clone()),
        Some(BinaryNodeContent::Text(value)) => Some(Bytes::copy_from_slice(value.as_bytes())),
        _ => None,
    }
}

fn is_bot_phone_user(user: &str) -> bool {
    let bytes = user.as_bytes();
    if bytes.len() == 11 && user.starts_with("1313555") {
        return bytes[7..].iter().all(u8::is_ascii_digit);
    }
    bytes.len() == 11 && user.starts_with("131655500") && bytes[9..].iter().all(u8::is_ascii_digit)
}

fn put_string(out: &mut BytesMut, value: &str) -> CoreResult<()> {
    put_bytes(out, value.as_bytes())
}

fn read_string(input: &mut &[u8]) -> CoreResult<String> {
    String::from_utf8(read_bytes(input)?)
        .map_err(|err| CoreError::Protocol(format!("stored tctoken has invalid UTF-8: {err}")))
}

fn put_bytes(out: &mut BytesMut, value: &[u8]) -> CoreResult<()> {
    if value.len() > MAX_TC_TOKEN_BYTES {
        return Err(CoreError::Protocol(format!(
            "stored tctoken field exceeds {MAX_TC_TOKEN_BYTES} bytes"
        )));
    }
    out.put_u32(
        u32::try_from(value.len())
            .map_err(|_| CoreError::Protocol("stored tctoken field is too large".to_owned()))?,
    );
    out.extend_from_slice(value);
    Ok(())
}

fn read_bytes(input: &mut &[u8]) -> CoreResult<Vec<u8>> {
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored tctoken missing field length".to_owned(),
        ));
    }
    let len = input.get_u32() as usize;
    if len > MAX_TC_TOKEN_BYTES {
        return Err(CoreError::Protocol(format!(
            "stored tctoken field exceeds {MAX_TC_TOKEN_BYTES} bytes"
        )));
    }
    if input.remaining() < len {
        return Err(CoreError::Protocol(
            "stored tctoken field is truncated".to_owned(),
        ));
    }
    let value = input[..len].to_vec();
    input.advance(len);
    Ok(value)
}

fn read_magic(input: &mut &[u8]) -> CoreResult<()> {
    if input.remaining() < 5 {
        return Err(CoreError::Protocol(
            "stored tctoken record is truncated".to_owned(),
        ));
    }
    if &input[..4] != STORED_TC_TOKEN_MAGIC {
        return Err(CoreError::Protocol(
            "stored tctoken has invalid magic".to_owned(),
        ));
    }
    input.advance(4);
    let version = input.get_u8();
    if version != STORED_TC_TOKEN_VERSION {
        return Err(CoreError::Protocol(format!(
            "stored tctoken version {version} is not supported"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_tc_token_round_trips() {
        let record = TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"token"))
            .unwrap()
            .with_timestamp_seconds(1_700_000_008)
            .with_sender_timestamp_seconds(1_700_000_010);

        let encoded = encode_stored_tc_token(&record).unwrap();
        assert_eq!(decode_stored_tc_token(&encoded).unwrap(), record);

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_stored_tc_token(&trailing).is_err());
    }

    #[test]
    fn sender_marker_round_trips_without_send_node() {
        let marker = TcTokenRecord::sender_marker("123@s.whatsapp.net", 1_700_000_010).unwrap();
        let encoded = encode_stored_tc_token(&marker).unwrap();
        assert_eq!(decode_stored_tc_token(&encoded).unwrap(), marker);
        assert_eq!(tc_token_node(&marker, 1_700_000_010).unwrap(), None);
        assert!(!should_send_new_tc_token(
            marker.sender_timestamp_seconds,
            1_700_000_011
        ));
        assert!(should_send_new_tc_token(
            marker.sender_timestamp_seconds,
            1_700_000_010 + TC_TOKEN_BUCKET_DURATION_SECONDS
        ));
    }

    #[tokio::test]
    async fn tc_token_store_helpers_round_trip_and_delete() {
        let dir = std::env::temp_dir().join(format!("wa-core-tctoken-{}", rand::random::<u128>()));
        let store = wa_store::SqliteAuthStore::open(dir.join("session.db"))
            .await
            .unwrap();
        let record = TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"token"))
            .unwrap()
            .with_timestamp_seconds(1);

        save_tc_token(&store, record.clone()).await.unwrap();
        assert_eq!(
            load_tc_token(&store, "123@s.whatsapp.net").await.unwrap(),
            Some(record)
        );

        delete_tc_token(&store, "123@s.whatsapp.net").await.unwrap();
        assert_eq!(
            load_tc_token(&store, "123@s.whatsapp.net").await.unwrap(),
            None
        );
    }

    #[test]
    fn rejects_invalid_tc_token_inputs() {
        assert!(TcTokenRecord::new("invalid", Bytes::from_static(b"token")).is_err());
        assert!(TcTokenRecord::new("123@s.whatsapp.net", Bytes::new()).is_err());
        assert!(
            TcTokenRecord::new(
                "123@s.whatsapp.net",
                Bytes::from(vec![1u8; MAX_TC_TOKEN_BYTES + 1])
            )
            .is_err()
        );
    }

    #[test]
    fn builds_tc_token_node_only_for_valid_unexpired_regular_user_tokens() {
        let now = 1_700_000_000;
        let valid_timestamp = now - TC_TOKEN_BUCKET_DURATION_SECONDS;
        let record = TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"token"))
            .unwrap()
            .with_timestamp_seconds(valid_timestamp);

        let node = tc_token_node(&record, now).unwrap().unwrap();
        assert_eq!(node.tag, "tctoken");
        assert_eq!(
            node.content,
            Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
                b"token"
            )))
        );

        let expired = TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"token"))
            .unwrap()
            .with_timestamp_seconds(now - TC_TOKEN_BUCKET_DURATION_SECONDS * 4);
        assert_eq!(tc_token_node(&expired, now).unwrap(), None);
        assert!(!is_regular_tc_token_jid("123@g.us"));
        assert!(!is_regular_tc_token_jid("0@c.us"));
        assert!(!is_regular_tc_token_jid("13135550002@c.us"));
        assert!(is_regular_tc_token_jid("abc@lid"));
    }

    #[test]
    fn builds_and_parses_tc_token_issue_query() {
        let query = build_tc_token_issue_query(
            ["123@c.us", "123@s.whatsapp.net", "0@c.us"],
            1_700_000_000,
            "q-1",
        )
        .unwrap()
        .unwrap();
        assert_eq!(query.attrs["to"], TC_TOKEN_SERVER_JID);
        assert_eq!(query.attrs["type"], "set");
        assert_eq!(query.attrs["xmlns"], "privacy");
        let tokens = child_node(&query, "tokens").unwrap();
        let token_nodes = child_nodes(tokens);
        assert_eq!(token_nodes.len(), 1);
        assert_eq!(token_nodes[0].attrs["jid"], "123@s.whatsapp.net");
        assert_eq!(token_nodes[0].attrs["t"], "1700000000");
        assert_eq!(token_nodes[0].attrs["type"], TRUSTED_CONTACT_TOKEN_TYPE);

        let response = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                BinaryNode::new("token")
                    .with_attr("jid", "456@s.whatsapp.net")
                    .with_attr("t", "1700000001")
                    .with_attr("type", TRUSTED_CONTACT_TOKEN_TYPE)
                    .with_content(Bytes::from_static(b"peer-token")),
                BinaryNode::new("token")
                    .with_attr("jid", "789@s.whatsapp.net")
                    .with_attr("t", "1700000001")
                    .with_attr("type", "other")
                    .with_content(Bytes::from_static(b"ignored")),
            ])]);
        let records = tc_token_records_from_issue_result(&response, Some("123@c.us")).unwrap();
        assert_eq!(
            records,
            vec![
                TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"peer-token"))
                    .unwrap()
                    .with_timestamp_seconds(1_700_000_001)
            ]
        );
    }

    #[test]
    fn privacy_token_notification_sender_lid_only_accepts_lid_jids() {
        let notification = BinaryNode::new("notification")
            .with_attr("type", "privacy_token")
            .with_attr("sender_lid", "abc:7@lid");
        assert_eq!(
            privacy_token_notification_sender_lid(&notification),
            Some("abc@lid".to_owned())
        );

        let pn_sender = BinaryNode::new("notification")
            .with_attr("type", "privacy_token")
            .with_attr("sender_lid", "123@c.us");
        assert_eq!(privacy_token_notification_sender_lid(&pn_sender), None);

        let other_notification = BinaryNode::new("notification")
            .with_attr("type", "devices")
            .with_attr("sender_lid", "abc@lid");
        assert_eq!(
            privacy_token_notification_sender_lid(&other_notification),
            None
        );
    }

    #[tokio::test]
    async fn privacy_token_notification_store_uses_fallback_jid() {
        let dir = std::env::temp_dir().join(format!(
            "wa-core-tctoken-privacy-{}",
            rand::random::<u128>()
        ));
        let store = wa_store::SqliteAuthStore::open(dir.join("session.db"))
            .await
            .unwrap();
        save_tc_token(
            &store,
            TcTokenRecord::sender_marker("abc@lid", 1_700_000_000).unwrap(),
        )
        .await
        .unwrap();
        let notification = BinaryNode::new("notification")
            .with_attr("id", "privacy-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "privacy_token")
            .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                BinaryNode::new("token")
                    .with_attr("t", "1700000001")
                    .with_attr("type", TRUSTED_CONTACT_TOKEN_TYPE)
                    .with_content(Bytes::from_static(b"peer-token")),
            ])]);

        let stored =
            store_tc_tokens_from_privacy_token_notification(&store, &notification, Some("abc@lid"))
                .await
                .unwrap();
        assert_eq!(
            stored,
            vec![
                TcTokenRecord::new("abc@lid", Bytes::from_static(b"peer-token"))
                    .unwrap()
                    .with_timestamp_seconds(1_700_000_001)
                    .with_sender_timestamp_seconds(1_700_000_000)
            ]
        );
        assert_eq!(
            load_tc_token(&store, "abc@lid").await.unwrap(),
            stored.into_iter().next()
        );
    }

    #[tokio::test]
    async fn tc_token_send_loader_clears_expired_tokens() {
        let dir =
            std::env::temp_dir().join(format!("wa-core-tctoken-send-{}", rand::random::<u128>()));
        let store = wa_store::SqliteAuthStore::open(dir.join("session.db"))
            .await
            .unwrap();
        let expired = TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"token"))
            .unwrap()
            .with_timestamp_seconds(1);
        save_tc_token(&store, expired).await.unwrap();

        assert_eq!(
            load_tc_token_node_for_send(&store, "123@s.whatsapp.net", 1_700_000_000)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            load_tc_token(&store, "123@s.whatsapp.net").await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn tc_token_issue_result_store_preserves_sender_timestamp_and_newer_token() {
        let dir =
            std::env::temp_dir().join(format!("wa-core-tctoken-issue-{}", rand::random::<u128>()));
        let store = wa_store::SqliteAuthStore::open(dir.join("session.db"))
            .await
            .unwrap();
        save_tc_token(
            &store,
            TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"old-token"))
                .unwrap()
                .with_timestamp_seconds(100)
                .with_sender_timestamp_seconds(200),
        )
        .await
        .unwrap();
        let stale = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                BinaryNode::new("token")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_attr("t", "99")
                    .with_attr("type", TRUSTED_CONTACT_TOKEN_TYPE)
                    .with_content(Bytes::from_static(b"stale-token")),
            ])]);
        assert!(
            store_tc_tokens_from_issue_result(&store, &stale, Some("123@s.whatsapp.net"))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            load_tc_token(&store, "123@s.whatsapp.net")
                .await
                .unwrap()
                .unwrap()
                .token,
            Bytes::from_static(b"old-token")
        );

        let fresh = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                BinaryNode::new("token")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_attr("t", "101")
                    .with_attr("type", TRUSTED_CONTACT_TOKEN_TYPE)
                    .with_content(Bytes::from_static(b"new-token")),
            ])]);
        let saved = store_tc_tokens_from_issue_result(&store, &fresh, Some("123@s.whatsapp.net"))
            .await
            .unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].sender_timestamp_seconds, Some(200));
        assert_eq!(
            load_tc_token(&store, "123@s.whatsapp.net")
                .await
                .unwrap()
                .unwrap()
                .token,
            Bytes::from_static(b"new-token")
        );
    }

    #[tokio::test]
    async fn prunes_expired_tc_tokens_in_batches_and_preserves_sender_markers() {
        let dir =
            std::env::temp_dir().join(format!("wa-core-tctoken-prune-{}", rand::random::<u128>()));
        let store = wa_store::SqliteAuthStore::open(dir.join("session.db"))
            .await
            .unwrap();
        let now = 1_700_000_000;
        let valid_timestamp = now - TC_TOKEN_BUCKET_DURATION_SECONDS;
        let expired_timestamp = now - TC_TOKEN_BUCKET_DURATION_SECONDS * 4;
        let recent_sender_timestamp = now - 60;

        save_tc_token(
            &store,
            TcTokenRecord::new("111@s.whatsapp.net", Bytes::from_static(b"valid"))
                .unwrap()
                .with_timestamp_seconds(valid_timestamp),
        )
        .await
        .unwrap();
        save_tc_token(
            &store,
            TcTokenRecord::new("222@s.whatsapp.net", Bytes::from_static(b"expired"))
                .unwrap()
                .with_timestamp_seconds(expired_timestamp),
        )
        .await
        .unwrap();
        save_tc_token(
            &store,
            TcTokenRecord::new(
                "333@s.whatsapp.net",
                Bytes::from_static(b"expired-with-marker"),
            )
            .unwrap()
            .with_timestamp_seconds(expired_timestamp)
            .with_sender_timestamp_seconds(recent_sender_timestamp),
        )
        .await
        .unwrap();
        save_tc_token(
            &store,
            TcTokenRecord::sender_marker("444@s.whatsapp.net", expired_timestamp).unwrap(),
        )
        .await
        .unwrap();
        store
            .set(KeyNamespace::TcToken, "555@s.whatsapp.net", b"not-a-record")
            .await
            .unwrap();
        save_tc_token(
            &store,
            TcTokenRecord::new("123@g.us", Bytes::from_static(b"group-token"))
                .unwrap()
                .with_timestamp_seconds(valid_timestamp),
        )
        .await
        .unwrap();

        let outcome = prune_expired_tc_tokens(&store, now, 2).await.unwrap();
        assert_eq!(
            outcome,
            TcTokenPruneOutcome {
                scanned: 6,
                retained: 2,
                deleted: 4,
                malformed_deleted: 1,
                markers_preserved: 1,
            }
        );
        assert_eq!(
            load_tc_token(&store, "111@s.whatsapp.net")
                .await
                .unwrap()
                .unwrap()
                .token,
            Bytes::from_static(b"valid")
        );
        assert!(
            load_tc_token(&store, "222@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        let marker = load_tc_token(&store, "333@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        assert!(marker.token.is_empty());
        assert_eq!(
            marker.sender_timestamp_seconds,
            Some(recent_sender_timestamp)
        );
        assert!(
            load_tc_token(&store, "444@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get(KeyNamespace::TcToken, "555@s.whatsapp.net")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store.get(KeyNamespace::TcToken, "123@g.us").await.unwrap(),
            None
        );
    }
}
