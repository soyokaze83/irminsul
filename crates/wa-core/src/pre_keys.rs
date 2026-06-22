use crate::auth::{read_credentials_from_tx, write_credentials_to_tx};
use crate::{
    AuthCredentials, CoreError, CoreResult, SignedPreKey, create_signed_pre_key, encode_big_endian,
};
use bytes::Bytes;
use wa_binary::{BinaryNode, BinaryNodeContent};
use wa_crypto::{KeyPair, SecretBytes, generate_key_pair};
use wa_store::{AuthStore, KeyNamespace, StoreError, StoreResult, StoreTransaction};
use zeroize::Zeroize;

pub const MIN_PRE_KEY_COUNT: usize = 5;
pub const INITIAL_PRE_KEY_COUNT: usize = 812;
pub const SERVER_JID: &str = "@s.whatsapp.net";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreKeyUpload {
    pub node: BinaryNode,
    pub credentials: AuthCredentials,
    pub pre_key_ids: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPreKeyRotation {
    pub node: BinaryNode,
    pub signed_pre_key: SignedPreKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentPreKeyStatus {
    pub current_pre_key_id: u32,
    pub exists: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredPreKey {
    key_id: u32,
    key_pair: KeyPair,
}

struct PreparedPreKeys {
    credentials: AuthCredentials,
    pre_keys: Vec<StoredPreKey>,
}

pub async fn prepare_pre_key_upload<S>(
    store: &S,
    credentials: &AuthCredentials,
    count: usize,
    tag: impl Into<String>,
) -> CoreResult<PreKeyUpload>
where
    S: AuthStore,
{
    if count == 0 {
        return Err(CoreError::Payload(
            "pre-key upload count must be greater than zero".to_owned(),
        ));
    }

    let tag = tag.into();
    let fallback = credentials.clone();
    let prepared = store
        .transaction("prepare-pre-key-upload", move |tx| {
            let credentials = read_credentials_from_tx(tx)?.unwrap_or_else(|| fallback.clone());
            prepare_pre_keys_in_tx(tx, credentials, count)
        })
        .await?;

    let node = build_pre_key_upload_node(&prepared.credentials, &prepared.pre_keys, tag)?;
    let pre_key_ids = prepared
        .pre_keys
        .iter()
        .map(|pre_key| pre_key.key_id)
        .collect();

    Ok(PreKeyUpload {
        node,
        credentials: prepared.credentials,
        pre_key_ids,
    })
}

pub async fn current_pre_key_status<S>(
    store: &S,
    credentials: &AuthCredentials,
) -> CoreResult<CurrentPreKeyStatus>
where
    S: AuthStore,
{
    let Some(current_pre_key_id) = credentials.next_pre_key_id.checked_sub(1) else {
        return Ok(CurrentPreKeyStatus {
            current_pre_key_id: 0,
            exists: false,
        });
    };
    if current_pre_key_id == 0 {
        return Ok(CurrentPreKeyStatus {
            current_pre_key_id,
            exists: false,
        });
    }

    let exists = store
        .get(KeyNamespace::PreKey, &current_pre_key_id.to_string())
        .await?
        .is_some();
    Ok(CurrentPreKeyStatus {
        current_pre_key_id,
        exists,
    })
}

pub async fn confirm_pre_key_upload<S>(
    store: &S,
    credentials: &AuthCredentials,
    pre_key_ids: &[u32],
) -> CoreResult<AuthCredentials>
where
    S: AuthStore,
{
    if pre_key_ids.is_empty() {
        return Err(CoreError::Payload(
            "confirmed pre-key upload must include at least one key id".to_owned(),
        ));
    }
    let fallback = credentials.clone();
    let pre_key_ids = pre_key_ids.to_vec();
    store
        .transaction("confirm-pre-key-upload", move |tx| {
            let credentials = read_credentials_from_tx(tx)?.unwrap_or_else(|| fallback.clone());
            confirm_pre_key_upload_in_tx(tx, credentials, &pre_key_ids)
        })
        .await
        .map_err(Into::into)
}

pub fn build_pre_key_count_query(tag: impl Into<String>) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag)
        .with_attr("xmlns", "encrypt")
        .with_attr("type", "get")
        .with_attr("to", SERVER_JID)
        .with_content(vec![BinaryNode::new("count")])
}

pub fn parse_pre_key_count_response(node: &BinaryNode) -> CoreResult<usize> {
    if let Some(error) = encrypt_error_from_result(node, "pre-key count query") {
        return Err(error);
    }

    let count = child_node(node, "count")
        .and_then(|node| node.attrs.get("value"))
        .ok_or_else(|| CoreError::Protocol("pre-key count response missing value".to_owned()))?;
    count
        .parse::<usize>()
        .map_err(|err| CoreError::Protocol(format!("invalid pre-key count response value: {err}")))
}

pub fn build_key_bundle_digest_query(tag: impl Into<String>) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag)
        .with_attr("to", SERVER_JID)
        .with_attr("type", "get")
        .with_attr("xmlns", "encrypt")
        .with_content(vec![BinaryNode::new("digest")])
}

#[must_use]
pub fn has_key_bundle_digest(node: &BinaryNode) -> bool {
    child_node(node, "digest").is_some()
}

pub fn parse_key_bundle_digest_response(node: &BinaryNode) -> CoreResult<()> {
    if let Some(error) = encrypt_error_from_result(node, "key-bundle digest query") {
        return Err(error);
    }

    if has_key_bundle_digest(node) {
        Ok(())
    } else {
        Err(CoreError::Protocol(
            "key-bundle digest response missing digest node".to_owned(),
        ))
    }
}

pub fn parse_pre_key_upload_response(node: &BinaryNode) -> CoreResult<()> {
    parse_encrypt_ack_result(node, "pre-key upload")
}

pub fn parse_signed_pre_key_rotation_response(node: &BinaryNode) -> CoreResult<()> {
    parse_encrypt_ack_result(node, "signed pre-key rotation")
}

pub fn build_signed_pre_key_rotation(
    credentials: &AuthCredentials,
    tag: impl Into<String>,
) -> CoreResult<SignedPreKeyRotation> {
    let new_id = credentials
        .signed_pre_key
        .key_id
        .checked_add(1)
        .ok_or_else(|| {
            CoreError::Payload("signed pre-key id overflow during rotation".to_owned())
        })?;
    let signed_pre_key = create_signed_pre_key(&credentials.signed_identity_key, new_id)?;
    let node = BinaryNode::new("iq")
        .with_attr("id", tag)
        .with_attr("to", SERVER_JID)
        .with_attr("type", "set")
        .with_attr("xmlns", "encrypt")
        .with_content(vec![
            BinaryNode::new("rotate").with_content(vec![xmpp_signed_pre_key(&signed_pre_key)?]),
        ]);

    Ok(SignedPreKeyRotation {
        node,
        signed_pre_key,
    })
}

#[must_use]
pub fn credentials_with_rotated_signed_pre_key(
    credentials: &AuthCredentials,
    signed_pre_key: SignedPreKey,
) -> AuthCredentials {
    let mut updated = credentials.clone();
    updated.signed_pre_key = signed_pre_key;
    updated
}

fn prepare_pre_keys_in_tx(
    tx: &mut dyn StoreTransaction,
    mut credentials: AuthCredentials,
    count: usize,
) -> StoreResult<PreparedPreKeys> {
    let requested = u32::try_from(count)
        .map_err(|_| StoreError::InvalidData("pre-key upload count exceeds u32".to_owned()))?;
    if credentials.first_unuploaded_pre_key_id > credentials.next_pre_key_id {
        return Err(StoreError::InvalidData(
            "first unuploaded pre-key id is ahead of next pre-key id".to_owned(),
        ));
    }

    let first_pre_key_id = credentials.first_unuploaded_pre_key_id;
    let available = credentials.next_pre_key_id - credentials.first_unuploaded_pre_key_id;
    let remaining = requested.saturating_sub(available);
    let last_pre_key_id = if remaining == 0 {
        first_pre_key_id
            .checked_add(requested)
            .and_then(|value| value.checked_sub(1))
    } else {
        credentials
            .next_pre_key_id
            .checked_add(remaining)
            .and_then(|value| value.checked_sub(1))
    }
    .ok_or_else(|| StoreError::InvalidData("pre-key id overflow".to_owned()))?;

    if remaining > 0 {
        for key_id in credentials.next_pre_key_id..=last_pre_key_id {
            let key_pair = generate_key_pair();
            write_pre_key_to_tx(tx, key_id, &key_pair)?;
        }
    }

    let end_pre_key_id = first_pre_key_id
        .checked_add(requested)
        .ok_or_else(|| StoreError::InvalidData("pre-key range overflow".to_owned()))?;
    let mut pre_keys = Vec::with_capacity(count);
    for key_id in first_pre_key_id..end_pre_key_id {
        pre_keys.push(StoredPreKey {
            key_id,
            key_pair: read_pre_key_from_tx(tx, key_id)?,
        });
    }

    let next_after_generated = last_pre_key_id
        .checked_add(1)
        .ok_or_else(|| StoreError::InvalidData("pre-key id overflow".to_owned()))?;
    credentials.next_pre_key_id = credentials.next_pre_key_id.max(next_after_generated);
    write_credentials_to_tx(tx, &credentials)?;

    Ok(PreparedPreKeys {
        credentials,
        pre_keys,
    })
}

fn confirm_pre_key_upload_in_tx(
    tx: &mut dyn StoreTransaction,
    mut credentials: AuthCredentials,
    pre_key_ids: &[u32],
) -> StoreResult<AuthCredentials> {
    if credentials.first_unuploaded_pre_key_id > credentials.next_pre_key_id {
        return Err(StoreError::InvalidData(
            "first unuploaded pre-key id is ahead of next pre-key id".to_owned(),
        ));
    }

    let max_uploaded = pre_key_ids
        .iter()
        .copied()
        .max()
        .ok_or_else(|| StoreError::InvalidData("pre-key upload id list is empty".to_owned()))?;
    let next_unuploaded = max_uploaded
        .checked_add(1)
        .ok_or_else(|| StoreError::InvalidData("pre-key id overflow".to_owned()))?;
    if next_unuploaded > credentials.next_pre_key_id {
        return Err(StoreError::InvalidData(
            "confirmed pre-key upload is ahead of generated pre-key state".to_owned(),
        ));
    }

    credentials.first_unuploaded_pre_key_id =
        credentials.first_unuploaded_pre_key_id.max(next_unuploaded);
    write_credentials_to_tx(tx, &credentials)?;
    Ok(credentials)
}

fn build_pre_key_upload_node(
    credentials: &AuthCredentials,
    pre_keys: &[StoredPreKey],
    tag: String,
) -> CoreResult<BinaryNode> {
    let key_nodes = pre_keys
        .iter()
        .map(|pre_key| xmpp_pre_key(&pre_key.key_pair, pre_key.key_id))
        .collect::<CoreResult<Vec<_>>>()?;

    Ok(BinaryNode::new("iq")
        .with_attr("id", tag)
        .with_attr("xmlns", "encrypt")
        .with_attr("type", "set")
        .with_attr("to", SERVER_JID)
        .with_content(vec![
            BinaryNode::new("registration")
                .with_content(encode_big_endian(credentials.registration_id, 4)?),
            BinaryNode::new("type").with_content(Bytes::copy_from_slice(&crate::KEY_BUNDLE_TYPE)),
            BinaryNode::new("identity").with_content(Bytes::copy_from_slice(
                &credentials.signed_identity_key.public,
            )),
            BinaryNode::new("list").with_content(key_nodes),
            xmpp_signed_pre_key(&credentials.signed_pre_key)?,
        ]))
}

fn xmpp_signed_pre_key(key: &SignedPreKey) -> CoreResult<BinaryNode> {
    Ok(BinaryNode::new("skey").with_content(vec![
        BinaryNode::new("id").with_content(encode_big_endian(key.key_id, 3)?),
        BinaryNode::new("value").with_content(Bytes::copy_from_slice(&key.key_pair.public)),
        BinaryNode::new("signature").with_content(key.signature.clone()),
    ]))
}

fn xmpp_pre_key(pair: &KeyPair, id: u32) -> CoreResult<BinaryNode> {
    Ok(BinaryNode::new("key").with_content(vec![
        BinaryNode::new("id").with_content(encode_big_endian(id, 3)?),
        BinaryNode::new("value").with_content(Bytes::copy_from_slice(&pair.public)),
    ]))
}

fn write_pre_key_to_tx(
    tx: &mut dyn StoreTransaction,
    key_id: u32,
    key_pair: &KeyPair,
) -> StoreResult<()> {
    let mut encoded = [0u8; 64];
    encoded[..32].copy_from_slice(&key_pair.public);
    encoded[32..].copy_from_slice(key_pair.private.expose());
    let result = tx.set(KeyNamespace::PreKey, &key_id.to_string(), &encoded);
    encoded.zeroize();
    result
}

pub(crate) fn read_pre_key_from_tx(
    tx: &mut dyn StoreTransaction,
    key_id: u32,
) -> StoreResult<KeyPair> {
    read_optional_pre_key_from_tx(tx, key_id)?
        .ok_or_else(|| StoreError::InvalidData(format!("missing pre-key {key_id}")))
}

pub(crate) fn read_optional_pre_key_from_tx(
    tx: &mut dyn StoreTransaction,
    key_id: u32,
) -> StoreResult<Option<KeyPair>> {
    let Some(value) = tx.get(KeyNamespace::PreKey, &key_id.to_string())? else {
        return Ok(None);
    };
    if value.len() != 64 {
        return Err(StoreError::InvalidData(format!(
            "invalid pre-key {key_id} length: {}",
            value.len()
        )));
    }

    let public: [u8; 32] = value[..32]
        .try_into()
        .map_err(|_| StoreError::InvalidData(format!("invalid public pre-key {key_id} length")))?;
    let private: [u8; 32] = value[32..]
        .try_into()
        .map_err(|_| StoreError::InvalidData(format!("invalid private pre-key {key_id} length")))?;

    Ok(Some(KeyPair {
        public,
        private: SecretBytes::from(private),
    }))
}

fn parse_encrypt_ack_result(node: &BinaryNode, operation: &str) -> CoreResult<()> {
    if let Some(error) = encrypt_error_from_result(node, operation) {
        return Err(error);
    }

    if node.tag != "iq" {
        return Err(CoreError::Protocol(format!(
            "{operation} response must be an iq node"
        )));
    }

    match node.attrs.get("type").map(String::as_str) {
        Some("result") => Ok(()),
        Some(value) => Err(CoreError::Protocol(format!(
            "{operation} response has unexpected type: {value}"
        ))),
        None => Err(CoreError::Protocol(format!(
            "{operation} response missing type"
        ))),
    }
}

fn encrypt_error_from_result(node: &BinaryNode, operation: &str) -> Option<CoreError> {
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
        .unwrap_or("encrypt query failed");
    Some(CoreError::Protocol(format!(
        "{operation} failed ({code}): {text}"
    )))
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return None;
    };

    children.iter().find(|child| child.tag == tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_initial_credentials, load_credentials, save_credentials};
    use wa_store::SqliteAuthStore;

    #[tokio::test]
    async fn prepare_pre_key_upload_generates_stores_and_leaves_upload_pending() {
        let store = temp_store().await;
        let credentials = create_initial_credentials().unwrap();
        save_credentials(&store, credentials.clone()).await.unwrap();

        let upload = prepare_pre_key_upload(&store, &credentials, 3, "upload-1")
            .await
            .unwrap();

        assert_eq!(upload.pre_key_ids, vec![1, 2, 3]);
        assert_eq!(upload.credentials.next_pre_key_id, 4);
        assert_eq!(upload.credentials.first_unuploaded_pre_key_id, 1);
        assert_eq!(
            load_credentials(&store).await.unwrap().unwrap(),
            upload.credentials
        );

        for key_id in 1..=3 {
            assert!(
                store
                    .get(KeyNamespace::PreKey, &key_id.to_string())
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        assert_eq!(upload.node.tag, "iq");
        assert_eq!(upload.node.attrs["id"], "upload-1");
        assert_eq!(upload.node.attrs["to"], SERVER_JID);
        assert_eq!(upload.node.attrs["xmlns"], "encrypt");

        let list = child_node(&upload.node, "list").unwrap();
        let Some(BinaryNodeContent::Nodes(keys)) = &list.content else {
            panic!("list content must be key nodes");
        };
        assert_eq!(keys.len(), 3);
        assert!(child_node(&upload.node, "skey").is_some());

        let confirmed = confirm_pre_key_upload(&store, &upload.credentials, &upload.pre_key_ids)
            .await
            .unwrap();
        assert_eq!(confirmed.next_pre_key_id, 4);
        assert_eq!(confirmed.first_unuploaded_pre_key_id, 4);
        assert_eq!(load_credentials(&store).await.unwrap().unwrap(), confirmed);
    }

    #[tokio::test]
    async fn prepare_pre_key_upload_reuses_pending_keys_before_generating_more() {
        let store = temp_store().await;
        let credentials = create_initial_credentials().unwrap();
        save_credentials(&store, credentials.clone()).await.unwrap();

        let first = prepare_pre_key_upload(&store, &credentials, 4, "first")
            .await
            .unwrap();
        let second = prepare_pre_key_upload(&store, &first.credentials, 2, "second")
            .await
            .unwrap();

        assert_eq!(first.pre_key_ids, vec![1, 2, 3, 4]);
        assert_eq!(second.pre_key_ids, vec![1, 2]);
        assert_eq!(second.credentials.next_pre_key_id, 5);
        assert_eq!(second.credentials.first_unuploaded_pre_key_id, 1);

        let confirmed = confirm_pre_key_upload(&store, &first.credentials, &first.pre_key_ids)
            .await
            .unwrap();
        let third = prepare_pre_key_upload(&store, &confirmed, 2, "third")
            .await
            .unwrap();
        assert_eq!(third.pre_key_ids, vec![5, 6]);
        assert_eq!(third.credentials.next_pre_key_id, 7);
        assert_eq!(third.credentials.first_unuploaded_pre_key_id, 5);
    }

    #[tokio::test]
    async fn current_pre_key_status_detects_persisted_key() {
        let store = temp_store().await;
        let credentials = create_initial_credentials().unwrap();
        save_credentials(&store, credentials.clone()).await.unwrap();
        let upload = prepare_pre_key_upload(&store, &credentials, 1, "upload")
            .await
            .unwrap();

        let status = current_pre_key_status(&store, &upload.credentials)
            .await
            .unwrap();
        assert_eq!(status.current_pre_key_id, 1);
        assert!(status.exists);
    }

    #[test]
    fn builds_and_parses_pre_key_count_query() {
        let query = build_pre_key_count_query("count-1");
        assert_eq!(query.attrs["id"], "count-1");
        assert_eq!(query.attrs["to"], SERVER_JID);
        assert_eq!(query.attrs["type"], "get");
        assert_eq!(query.attrs["xmlns"], "encrypt");
        assert!(child_node(&query, "count").is_some());

        let response = BinaryNode::new("iq")
            .with_attr("id", "count-1")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("count").with_attr("value", "42")]);
        assert_eq!(parse_pre_key_count_response(&response).unwrap(), 42);

        let error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "count denied");
        let err = parse_pre_key_count_response(&error).unwrap_err();
        assert!(
            err.to_string()
                .contains("pre-key count query failed (403): count denied")
        );
    }

    #[test]
    fn builds_digest_query_and_detects_digest_response() {
        let query = build_key_bundle_digest_query("digest-1");
        assert_eq!(query.attrs["id"], "digest-1");
        assert!(child_node(&query, "digest").is_some());
        assert!(has_key_bundle_digest(
            &BinaryNode::new("iq").with_content(vec![BinaryNode::new("digest")])
        ));
        assert!(!has_key_bundle_digest(&BinaryNode::new("iq")));
        assert!(
            parse_key_bundle_digest_response(
                &BinaryNode::new("iq").with_content(vec![BinaryNode::new("digest")])
            )
            .is_ok()
        );
        assert!(matches!(
            parse_key_bundle_digest_response(&BinaryNode::new("iq")),
            Err(CoreError::Protocol(message))
                if message == "key-bundle digest response missing digest node"
        ));

        let error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "503")
                    .with_attr("text", "digest unavailable"),
            ]);
        let err = parse_key_bundle_digest_response(&error).unwrap_err();
        assert!(
            err.to_string()
                .contains("key-bundle digest query failed (503): digest unavailable")
        );
    }

    #[test]
    fn parses_encrypt_ack_results() {
        let ok = BinaryNode::new("iq").with_attr("type", "result");
        assert!(parse_pre_key_upload_response(&ok).is_ok());
        assert!(parse_signed_pre_key_rotation_response(&ok).is_ok());

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "500")
            .with_attr("text", "upload failed");
        let err = parse_pre_key_upload_response(&attr_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("pre-key upload failed (500): upload failed")
        );

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "409")
                    .with_attr("text", "rotation rejected"),
            ]);
        let err = parse_signed_pre_key_rotation_response(&child_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("signed pre-key rotation failed (409): rotation rejected")
        );

        let missing_type = BinaryNode::new("iq");
        assert!(matches!(
            parse_pre_key_upload_response(&missing_type),
            Err(CoreError::Protocol(message))
                if message == "pre-key upload response missing type"
        ));
    }

    #[test]
    fn builds_signed_pre_key_rotation_node() {
        let credentials = create_initial_credentials().unwrap();
        let rotation = build_signed_pre_key_rotation(&credentials, "rotate-1").unwrap();

        assert_eq!(
            rotation.signed_pre_key.key_id,
            credentials.signed_pre_key.key_id + 1
        );
        assert_eq!(rotation.node.attrs["id"], "rotate-1");
        assert_eq!(rotation.node.attrs["to"], SERVER_JID);
        let rotate = child_node(&rotation.node, "rotate").unwrap();
        assert!(child_node(rotate, "skey").is_some());

        let updated =
            credentials_with_rotated_signed_pre_key(&credentials, rotation.signed_pre_key.clone());
        assert_eq!(updated.signed_pre_key, rotation.signed_pre_key);
    }

    async fn temp_store() -> SqliteAuthStore {
        let dir = std::env::temp_dir().join(format!("wa-core-pre-keys-{}", rand::random::<u128>()));
        SqliteAuthStore::open(dir.join("session.db")).await.unwrap()
    }
}
