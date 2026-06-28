use crate::{CoreError, CoreResult};
use async_trait::async_trait;
use bytes::Bytes;
use prost::Message as ProstMessage;
use std::str::FromStr;
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, jid_decode};
use wa_proto::proto::{Message, MessageKey, message::SenderKeyDistributionMessage};

pub const NACK_SENDER_REACHOUT_TIMELOCKED: u16 = 463;
pub const NACK_PARSING_ERROR: u16 = 487;
pub const NACK_UNRECOGNIZED_STANZA: u16 = 488;
pub const NACK_UNRECOGNIZED_STANZA_CLASS: u16 = 489;
pub const NACK_UNRECOGNIZED_STANZA_TYPE: u16 = 490;
pub const NACK_INVALID_PROTOBUF: u16 = 491;
pub const NACK_INVALID_HOSTED_COMPANION_STANZA: u16 = 493;
pub const NACK_MISSING_MESSAGE_SECRET: u16 = 495;
pub const NACK_SIGNAL_ERROR_OLD_COUNTER: u16 = 496;
pub const NACK_MESSAGE_DELETED_ON_PEER: u16 = 499;
pub const NACK_UNHANDLED_ERROR: u16 = 500;
pub const NACK_UNSUPPORTED_ADMIN_REVOKE: u16 = 550;
pub const NACK_UNSUPPORTED_LID_GROUP: u16 = 551;
pub const NACK_DB_OPERATION_FAILED: u16 = 552;

pub const ACK_ERROR_ACCOUNT_RESTRICTED: u16 = 463;
pub const ACK_ERROR_SMAX_INVALID: u16 = 479;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NackReason {
    SenderReachoutTimelocked = NACK_SENDER_REACHOUT_TIMELOCKED,
    ParsingError = NACK_PARSING_ERROR,
    UnrecognizedStanza = NACK_UNRECOGNIZED_STANZA,
    UnrecognizedStanzaClass = NACK_UNRECOGNIZED_STANZA_CLASS,
    UnrecognizedStanzaType = NACK_UNRECOGNIZED_STANZA_TYPE,
    InvalidProtobuf = NACK_INVALID_PROTOBUF,
    InvalidHostedCompanionStanza = NACK_INVALID_HOSTED_COMPANION_STANZA,
    MissingMessageSecret = NACK_MISSING_MESSAGE_SECRET,
    SignalErrorOldCounter = NACK_SIGNAL_ERROR_OLD_COUNTER,
    MessageDeletedOnPeer = NACK_MESSAGE_DELETED_ON_PEER,
    UnhandledError = NACK_UNHANDLED_ERROR,
    UnsupportedAdminRevoke = NACK_UNSUPPORTED_ADMIN_REVOKE,
    UnsupportedLidGroup = NACK_UNSUPPORTED_LID_GROUP,
    DbOperationFailed = NACK_DB_OPERATION_FAILED,
}

impl NackReason {
    #[must_use]
    pub fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundAck {
    pub id: String,
    pub class: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub participant: Option<String>,
    pub recipient: Option<String>,
    pub ack_type: Option<String>,
    pub error_code: Option<u16>,
    pub participant_hash: Option<String>,
}

impl InboundAck {
    #[must_use]
    pub fn is_message_error(&self) -> bool {
        self.class == "message" && self.error_code.is_some()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundReceiptKind {
    Delivery,
    Read,
    ReadSelf,
    HistorySync,
    PeerMessage,
    Sender,
    Inactive,
    Played,
    Retry,
    ServerError,
    Other(String),
}

impl InboundReceiptKind {
    #[must_use]
    pub fn from_wire(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::Delivery,
            Some("read") => Self::Read,
            Some("read-self") => Self::ReadSelf,
            Some("hist_sync") => Self::HistorySync,
            Some("peer_msg") => Self::PeerMessage,
            Some("sender") => Self::Sender,
            Some("inactive") => Self::Inactive,
            Some("played") => Self::Played,
            Some("retry") => Self::Retry,
            Some("server-error") => Self::ServerError,
            Some(value) => Self::Other(value.to_owned()),
        }
    }

    #[must_use]
    pub fn as_event_type(&self) -> &str {
        match self {
            Self::Delivery => "delivery",
            Self::Read => "read",
            Self::ReadSelf => "read-self",
            Self::HistorySync => "hist_sync",
            Self::PeerMessage => "peer_msg",
            Self::Sender => "sender",
            Self::Inactive => "inactive",
            Self::Played => "played",
            Self::Retry => "retry",
            Self::ServerError => "server-error",
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundReceipt {
    pub id: String,
    pub from: String,
    pub recipient: Option<String>,
    pub participant: Option<String>,
    pub kind: InboundReceiptKind,
    pub timestamp: Option<u64>,
    pub message_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundNotification {
    pub id: String,
    pub from: String,
    pub participant: Option<String>,
    pub notification_type: Option<String>,
    pub timestamp: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressingMode {
    Lid,
    PhoneNumber,
    Other(String),
}

impl AddressingMode {
    #[must_use]
    pub fn as_wire_str(&self) -> &str {
        match self {
            Self::Lid => "lid",
            Self::PhoneNumber => "pn",
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressingContext {
    pub mode: AddressingMode,
    pub sender_alt: Option<String>,
    pub recipient_alt: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundMessageKind {
    Chat,
    Group,
    PeerBroadcast,
    OtherBroadcast,
    DirectPeerStatus,
    OtherStatus,
    Newsletter,
}

impl InboundMessageKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Group => "group",
            Self::PeerBroadcast => "peer_broadcast",
            Self::OtherBroadcast => "other_broadcast",
            Self::DirectPeerStatus => "direct_peer_status",
            Self::OtherStatus => "other_status",
            Self::Newsletter => "newsletter",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundMessageInfo {
    pub key: MessageKey,
    pub kind: InboundMessageKind,
    pub author: String,
    pub sender: String,
    pub category: Option<String>,
    pub push_name: Option<String>,
    pub timestamp: Option<u64>,
    pub addressing: AddressingContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundCiphertextType {
    Message,
    PreKey,
    SenderKey,
}

impl InboundCiphertextType {
    pub fn from_wire(value: &str) -> CoreResult<Self> {
        match value {
            "msg" => Ok(Self::Message),
            "pkmsg" => Ok(Self::PreKey),
            "skmsg" => Ok(Self::SenderKey),
            _ => Err(CoreError::Protocol(format!(
                "unsupported inbound ciphertext type: {value}"
            ))),
        }
    }

    #[must_use]
    pub fn as_wire_type(self) -> &'static str {
        match self {
            Self::Message => "msg",
            Self::PreKey => "pkmsg",
            Self::SenderKey => "skmsg",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundPayloadKind {
    Plaintext,
    Encrypted(InboundCiphertextType),
}

impl InboundPayloadKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Encrypted(ciphertext_type) => ciphertext_type.as_wire_type(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundEncryptedPayload {
    pub sender_jid: String,
    pub chat_jid: String,
    pub ciphertext_type: InboundCiphertextType,
    pub ciphertext: Bytes,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedInboundPayload {
    pub kind: InboundPayloadKind,
    pub message: Message,
    pub device_sent_unwrapped: bool,
    pub sender_key_distribution_count: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedInboundMessage {
    pub info: InboundMessageInfo,
    pub payloads: Vec<DecodedInboundPayload>,
}

impl DecodedInboundMessage {
    #[must_use]
    pub fn last_message(&self) -> Option<&Message> {
        self.payloads.last().map(|payload| &payload.message)
    }
}

#[async_trait]
pub trait InboundMessageDecryptor: Send + Sync {
    async fn decrypt_inbound_message(&self, payload: InboundEncryptedPayload) -> CoreResult<Bytes>;

    async fn process_sender_key_distribution(
        &self,
        _author_jid: &str,
        _message: &SenderKeyDistributionMessage,
    ) -> CoreResult<()> {
        Ok(())
    }
}

pub fn build_ack_node(
    received: &BinaryNode,
    local_jid: Option<&str>,
    error_code: Option<u16>,
) -> CoreResult<BinaryNode> {
    validate_non_empty("ack class", &received.tag)?;
    let id = required_attr(received, "id")?;
    let to = required_attr(received, "from")?;
    validate_jid("ack destination JID", to)?;

    if let Some(local_jid) = local_jid {
        validate_jid("ack sender JID", local_jid)?;
    }

    let mut ack = BinaryNode::new("ack")
        .with_attr("id", id)
        .with_attr("to", to)
        .with_attr("class", received.tag.clone());

    if let Some(error_code) = error_code {
        ack = ack.with_attr("error", error_code.to_string());
    }
    if let Some(participant) = received.attrs.get("participant") {
        validate_jid("ack participant JID", participant)?;
        ack = ack.with_attr("participant", participant.clone());
    }
    if let Some(recipient) = received.attrs.get("recipient") {
        validate_jid("ack recipient JID", recipient)?;
        ack = ack.with_attr("recipient", recipient.clone());
    }
    if let Some(stanza_type) = received.attrs.get("type")
        && !stanza_type.is_empty()
    {
        ack = ack.with_attr("type", stanza_type.clone());
    }
    if received.tag == "message"
        && let Some(local_jid) = local_jid
    {
        ack = ack.with_attr("from", local_jid.to_owned());
    }

    Ok(ack)
}

pub fn build_nack_node(
    received: &BinaryNode,
    local_jid: Option<&str>,
    reason: NackReason,
) -> CoreResult<BinaryNode> {
    build_ack_node(received, local_jid, Some(reason.code()))
}

pub fn parse_inbound_ack(node: &BinaryNode) -> CoreResult<InboundAck> {
    ensure_tag(node, "ack")?;
    let id = required_attr(node, "id")?.to_owned();
    let class = required_attr(node, "class")?.to_owned();
    validate_non_empty("ack class", &class)?;
    let error_code = optional_u16_attr(node, "error")?;

    let from = optional_jid_attr(node, "from")?;
    let to = optional_jid_attr(node, "to")?;
    let participant = optional_jid_attr(node, "participant")?;
    let recipient = optional_jid_attr(node, "recipient")?;

    Ok(InboundAck {
        id,
        class,
        from,
        to,
        participant,
        recipient,
        ack_type: optional_non_empty_attr(node, "type"),
        error_code,
        participant_hash: optional_non_empty_attr(node, "phash"),
    })
}

pub fn parse_inbound_receipt(node: &BinaryNode) -> CoreResult<InboundReceipt> {
    ensure_tag(node, "receipt")?;
    let id = required_attr(node, "id")?.to_owned();
    let from = required_jid_attr(node, "from")?;
    let recipient = optional_jid_attr(node, "recipient")?;
    let participant = optional_jid_attr(node, "participant")?;
    let kind = InboundReceiptKind::from_wire(node.attrs.get("type").map(String::as_str));
    let timestamp = optional_u64_attr(node, "t")?;
    let mut message_ids = vec![id.clone()];

    if let Some(BinaryNodeContent::Nodes(children)) = &node.content {
        for list in children.iter().filter(|child| child.tag == "list") {
            if let Some(BinaryNodeContent::Nodes(items)) = &list.content {
                for item in items.iter().filter(|item| item.tag == "item") {
                    let item_id = required_attr(item, "id")?;
                    message_ids.push(item_id.to_owned());
                }
            }
        }
    }

    Ok(InboundReceipt {
        id,
        from,
        recipient,
        participant,
        kind,
        timestamp,
        message_ids,
    })
}

pub fn parse_inbound_notification(node: &BinaryNode) -> CoreResult<InboundNotification> {
    ensure_tag(node, "notification")?;
    Ok(InboundNotification {
        id: required_attr(node, "id")?.to_owned(),
        from: required_jid_attr(node, "from")?,
        participant: optional_jid_attr(node, "participant")?,
        notification_type: optional_non_empty_attr(node, "type"),
        timestamp: optional_u64_attr(node, "t")?,
    })
}

pub fn extract_addressing_context(stanza: &BinaryNode) -> AddressingContext {
    let sender = stanza
        .attrs
        .get("participant")
        .or_else(|| stanza.attrs.get("from"))
        .map(String::as_str);
    let mode = stanza
        .attrs
        .get("addressing_mode")
        .map(|value| addressing_mode_from_wire(value))
        .unwrap_or_else(|| inferred_addressing_mode(sender));

    let (sender_alt, recipient_alt) = match mode {
        AddressingMode::Lid => (
            first_attr(
                stanza,
                &["participant_pn", "sender_pn", "peer_recipient_pn"],
            ),
            optional_non_empty_attr(stanza, "recipient_pn"),
        ),
        AddressingMode::PhoneNumber | AddressingMode::Other(_) => (
            first_attr(
                stanza,
                &["participant_lid", "sender_lid", "peer_recipient_lid"],
            ),
            optional_non_empty_attr(stanza, "recipient_lid"),
        ),
    };

    AddressingContext {
        mode,
        sender_alt,
        recipient_alt,
    }
}

pub fn decode_inbound_message_info(
    stanza: &BinaryNode,
    own_jid: &str,
    own_lid: Option<&str>,
) -> CoreResult<InboundMessageInfo> {
    ensure_tag(stanza, "message")?;
    validate_jid("own JID", own_jid)?;
    if let Some(own_lid) = own_lid {
        validate_jid("own LID", own_lid)?;
    }

    let id = required_attr(stanza, "id")?.to_owned();
    let from = required_jid_attr(stanza, "from")?;
    let participant = optional_jid_attr(stanza, "participant")?;
    let recipient = optional_jid_attr(stanza, "recipient")?;
    let addressing = extract_addressing_context(stanza);
    let from_decoded = jid_decode(&from)
        .ok_or_else(|| CoreError::Protocol(format!("invalid message sender JID: {from}")))?;

    let (kind, remote_jid, author, from_me) = if is_user_server(from_decoded.server) {
        if let Some(recipient) = recipient.as_deref() {
            if !is_own_jid(&from, own_jid, own_lid) {
                return Err(CoreError::Protocol(
                    "recipient is present on a message not sent by this client".to_owned(),
                ));
            }
            (
                InboundMessageKind::Chat,
                recipient.to_owned(),
                from.clone(),
                true,
            )
        } else {
            (
                InboundMessageKind::Chat,
                from.clone(),
                from.clone(),
                is_own_jid(&from, own_jid, own_lid),
            )
        }
    } else if from_decoded.server == JidServer::GUs {
        let participant = participant.ok_or_else(|| {
            CoreError::Protocol("group message is missing participant JID".to_owned())
        })?;
        let from_me = is_own_jid(&participant, own_jid, own_lid);
        (
            InboundMessageKind::Group,
            from.clone(),
            participant,
            from_me,
        )
    } else if from_decoded.server == JidServer::Broadcast {
        let participant = participant.ok_or_else(|| {
            CoreError::Protocol("broadcast message is missing participant JID".to_owned())
        })?;
        let from_me = is_own_jid(&participant, own_jid, own_lid);
        let kind = if from_decoded.user == "status" {
            if from_me {
                InboundMessageKind::DirectPeerStatus
            } else {
                InboundMessageKind::OtherStatus
            }
        } else if from_me {
            InboundMessageKind::PeerBroadcast
        } else {
            InboundMessageKind::OtherBroadcast
        };
        (kind, from.clone(), participant, from_me)
    } else if from_decoded.server == JidServer::Newsletter {
        (
            InboundMessageKind::Newsletter,
            from.clone(),
            from.clone(),
            is_own_jid(&from, own_jid, own_lid),
        )
    } else {
        return Err(CoreError::Protocol(format!(
            "unsupported message sender JID server: {}",
            from_decoded.server_raw
        )));
    };

    let sender = if kind == InboundMessageKind::Chat {
        author.clone()
    } else {
        remote_jid.clone()
    };

    Ok(InboundMessageInfo {
        key: MessageKey {
            remote_jid: Some(remote_jid),
            from_me: Some(from_me),
            id: Some(id),
            participant: (kind != InboundMessageKind::Chat).then_some(author.clone()),
        },
        kind,
        author,
        sender,
        category: optional_non_empty_attr(stanza, "category"),
        push_name: optional_non_empty_attr(stanza, "notify"),
        timestamp: optional_u64_attr(stanza, "t")?,
        addressing,
    })
}

pub async fn decode_inbound_message<D>(
    stanza: &BinaryNode,
    own_jid: &str,
    own_lid: Option<&str>,
    decryptor: &D,
) -> CoreResult<DecodedInboundMessage>
where
    D: InboundMessageDecryptor,
{
    let info = decode_inbound_message_info(stanza, own_jid, own_lid)?;
    let mut payloads = Vec::new();

    for child in decryptable_children(stanza)? {
        let payload = decode_inbound_payload(&info, child, decryptor).await?;
        process_sender_key_distributions(&info.author, &payload.message, decryptor).await?;
        payloads.push(payload);
    }

    if payloads.is_empty() {
        return Err(CoreError::Protocol(
            "message stanza contains no decryptable payload".to_owned(),
        ));
    }

    Ok(DecodedInboundMessage { info, payloads })
}

pub fn unpad_random_max16(input: &[u8]) -> CoreResult<Bytes> {
    let Some(&pad_len) = input.last() else {
        return Err(CoreError::Protocol(
            "random padding removal requires non-empty bytes".to_owned(),
        ));
    };
    let pad_len = usize::from(pad_len);
    if pad_len == 0 || pad_len > 16 || pad_len > input.len() {
        return Err(CoreError::Protocol(format!(
            "invalid random padding length {pad_len} for {} bytes",
            input.len()
        )));
    }
    if !input[input.len() - pad_len..]
        .iter()
        .all(|byte| usize::from(*byte) == pad_len)
    {
        return Err(CoreError::Protocol(
            "random padding bytes are inconsistent".to_owned(),
        ));
    }
    Ok(Bytes::copy_from_slice(&input[..input.len() - pad_len]))
}

#[must_use]
pub fn pad_random_max16(input: Bytes) -> Bytes {
    let pad_len = rand::random::<u8>() % 16 + 1;
    let mut out = Vec::with_capacity(input.len() + usize::from(pad_len));
    out.extend_from_slice(&input);
    out.extend(std::iter::repeat_n(pad_len, usize::from(pad_len)));
    Bytes::from(out)
}

fn ensure_tag(node: &BinaryNode, expected: &str) -> CoreResult<()> {
    if node.tag != expected {
        return Err(CoreError::Protocol(format!(
            "expected {expected} node, got {}",
            node.tag
        )));
    }
    Ok(())
}

fn required_attr<'a>(node: &'a BinaryNode, attr: &str) -> CoreResult<&'a str> {
    let value = node.attrs.get(attr).ok_or_else(|| {
        CoreError::Protocol(format!("{} node missing {attr} attribute", node.tag))
    })?;
    validate_non_empty(attr, value)?;
    Ok(value)
}

fn required_jid_attr(node: &BinaryNode, attr: &str) -> CoreResult<String> {
    let jid = required_attr(node, attr)?;
    validate_jid(attr, jid)?;
    Ok(jid.to_owned())
}

fn optional_jid_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<String>> {
    let Some(value) = node.attrs.get(attr) else {
        return Ok(None);
    };
    validate_non_empty(attr, value)?;
    validate_jid(attr, value)?;
    Ok(Some(value.clone()))
}

fn optional_non_empty_attr(node: &BinaryNode, attr: &str) -> Option<String> {
    node.attrs
        .get(attr)
        .filter(|value| !value.is_empty())
        .cloned()
}

fn optional_u16_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u16>> {
    let Some(value) = node.attrs.get(attr) else {
        return Ok(None);
    };
    parse_attr(value, attr).map(Some)
}

fn optional_u64_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u64>> {
    let Some(value) = node.attrs.get(attr) else {
        return Ok(None);
    };
    parse_attr(value, attr).map(Some)
}

fn parse_attr<T>(value: &str, attr: &str) -> CoreResult<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|err| CoreError::Protocol(format!("invalid {attr} attribute: {err}")))
}

fn validate_non_empty(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    Ok(())
}

fn validate_jid(label: &str, value: &str) -> CoreResult<()> {
    let Some(jid) = jid_decode(value) else {
        return Err(CoreError::Protocol(format!("invalid {label}: {value}")));
    };
    if jid.user.is_empty() || jid.server_raw.is_empty() {
        return Err(CoreError::Protocol(format!("invalid {label}: {value}")));
    }
    Ok(())
}

fn first_attr(stanza: &BinaryNode, attrs: &[&str]) -> Option<String> {
    attrs
        .iter()
        .find_map(|attr| optional_non_empty_attr(stanza, attr))
}

fn addressing_mode_from_wire(value: &str) -> AddressingMode {
    match value {
        "lid" => AddressingMode::Lid,
        "pn" | "" => AddressingMode::PhoneNumber,
        other => AddressingMode::Other(other.to_owned()),
    }
}

fn inferred_addressing_mode(sender: Option<&str>) -> AddressingMode {
    let Some(sender) = sender else {
        return AddressingMode::PhoneNumber;
    };
    match jid_decode(sender).map(|jid| jid.server) {
        Some(JidServer::Lid | JidServer::HostedLid) => AddressingMode::Lid,
        _ => AddressingMode::PhoneNumber,
    }
}

fn is_user_server(server: JidServer) -> bool {
    matches!(
        server,
        JidServer::CUs
            | JidServer::SWhatsAppNet
            | JidServer::Lid
            | JidServer::Hosted
            | JidServer::HostedLid
    )
}

fn is_own_jid(candidate: &str, own_jid: &str, own_lid: Option<&str>) -> bool {
    same_user(candidate, own_jid) || own_lid.is_some_and(|own_lid| same_user(candidate, own_lid))
}

fn same_user(left: &str, right: &str) -> bool {
    jid_decode(left)
        .zip(jid_decode(right))
        .is_some_and(|(left, right)| left.user == right.user)
}

fn decryptable_children(stanza: &BinaryNode) -> CoreResult<Vec<&BinaryNode>> {
    let Some(BinaryNodeContent::Nodes(children)) = &stanza.content else {
        return Ok(Vec::new());
    };
    Ok(children
        .iter()
        .filter(|child| child.tag == "plaintext" || child.tag == "enc")
        .collect())
}

async fn decode_inbound_payload<D>(
    info: &InboundMessageInfo,
    node: &BinaryNode,
    decryptor: &D,
) -> CoreResult<DecodedInboundPayload>
where
    D: InboundMessageDecryptor,
{
    let (kind, message_bytes) = match node.tag.as_str() {
        "plaintext" => (InboundPayloadKind::Plaintext, node_bytes(node)?),
        "enc" => {
            let ciphertext_type = InboundCiphertextType::from_wire(required_attr(node, "type")?)?;
            let decrypted = decryptor
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: info.author.clone(),
                    chat_jid: info.sender.clone(),
                    ciphertext_type,
                    ciphertext: node_bytes(node)?,
                })
                .await?;
            (
                InboundPayloadKind::Encrypted(ciphertext_type),
                unpad_random_max16(&decrypted)?,
            )
        }
        _ => {
            return Err(CoreError::Protocol(format!(
                "unsupported inbound payload node: {}",
                node.tag
            )));
        }
    };

    let decoded = <Message as ProstMessage>::decode(message_bytes)
        .map_err(|err| CoreError::Protocol(format!("failed to decode inbound message: {err}")))?;
    let (message, device_sent_unwrapped) = unwrap_device_sent_message(decoded)?;
    let sender_key_distribution_count = sender_key_distribution_count(&message);
    Ok(DecodedInboundPayload {
        kind,
        message,
        device_sent_unwrapped,
        sender_key_distribution_count,
    })
}

fn node_bytes(node: &BinaryNode) -> CoreResult<Bytes> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => Err(CoreError::Protocol(format!(
            "{} node must contain bytes",
            node.tag
        ))),
        None => Err(CoreError::Protocol(format!(
            "{} node is missing bytes",
            node.tag
        ))),
    }
}

fn unwrap_device_sent_message(message: Message) -> CoreResult<(Message, bool)> {
    if let Some(device_sent) = message.device_sent_message {
        let inner = device_sent.message.ok_or_else(|| {
            CoreError::Protocol("device-sent message is missing inner message".to_owned())
        })?;
        return Ok((*inner, true));
    }
    Ok((message, false))
}

async fn process_sender_key_distributions<D>(
    author_jid: &str,
    message: &Message,
    decryptor: &D,
) -> CoreResult<()>
where
    D: InboundMessageDecryptor,
{
    if let Some(sender_key) = &message.sender_key_distribution_message {
        decryptor
            .process_sender_key_distribution(author_jid, sender_key)
            .await?;
    }
    if let Some(sender_key) = &message.fast_ratchet_key_sender_key_distribution_message {
        decryptor
            .process_sender_key_distribution(author_jid, sender_key)
            .await?;
    }
    Ok(())
}

fn sender_key_distribution_count(message: &Message) -> usize {
    usize::from(message.sender_key_distribution_message.is_some())
        + usize::from(
            message
                .fast_ratchet_key_sender_key_distribution_message
                .is_some(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[test]
    fn builds_ack_and_nack_nodes() {
        let stanza = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "123:1@s.whatsapp.net")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("recipient", "999@s.whatsapp.net")
            .with_attr("type", "text");

        let ack = build_ack_node(&stanza, Some("999:2@s.whatsapp.net"), None).unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "msg-1");
        assert_eq!(ack.attrs["to"], "123:1@s.whatsapp.net");
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");
        assert_eq!(ack.attrs["participant"], "456@s.whatsapp.net");
        assert_eq!(ack.attrs["recipient"], "999@s.whatsapp.net");
        assert_eq!(ack.attrs["type"], "text");

        let nack = build_nack_node(
            &stanza,
            Some("999:2@s.whatsapp.net"),
            NackReason::ParsingError,
        )
        .unwrap();
        assert_eq!(nack.attrs["error"], "487");
    }

    #[test]
    fn rejects_invalid_ack_inputs() {
        assert!(build_ack_node(&BinaryNode::new("message"), None, None).is_err());
        assert!(
            build_ack_node(
                &BinaryNode::new("message")
                    .with_attr("id", "msg-1")
                    .with_attr("from", "not-a-jid"),
                None,
                None,
            )
            .is_err()
        );
        assert!(
            build_ack_node(
                &BinaryNode::new("message")
                    .with_attr("id", "msg-1")
                    .with_attr("from", "123@s.whatsapp.net"),
                Some("invalid"),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn parses_inbound_ack_with_error() {
        let ack = BinaryNode::new("ack")
            .with_attr("id", "msg-1")
            .with_attr("class", "message")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("error", "479")
            .with_attr("phash", "2:abc");

        let parsed = parse_inbound_ack(&ack).unwrap();
        assert_eq!(parsed.id, "msg-1");
        assert_eq!(parsed.error_code, Some(ACK_ERROR_SMAX_INVALID));
        assert_eq!(parsed.participant_hash.as_deref(), Some("2:abc"));
        assert!(parsed.is_message_error());
        assert!(parse_inbound_ack(&ack.with_attr("error", "nan")).is_err());
    }

    #[test]
    fn parses_inbound_receipt_ids_and_kind() {
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "m1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("type", "retry")
            .with_attr("t", "10")
            .with_content(vec![BinaryNode::new("list").with_content(vec![
                BinaryNode::new("item").with_attr("id", "m2"),
                BinaryNode::new("item").with_attr("id", "m3"),
            ])]);

        let parsed = parse_inbound_receipt(&receipt).unwrap();
        assert_eq!(parsed.kind, InboundReceiptKind::Retry);
        assert_eq!(parsed.timestamp, Some(10));
        assert_eq!(parsed.message_ids, vec!["m1", "m2", "m3"]);
        assert_eq!(parsed.participant.as_deref(), Some("456@s.whatsapp.net"));
    }

    #[test]
    fn parses_inbound_notification_metadata() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("type", "devices")
            .with_attr("t", "10");

        let parsed = parse_inbound_notification(&notification).unwrap();
        assert_eq!(parsed.notification_type.as_deref(), Some("devices"));
        assert_eq!(parsed.timestamp, Some(10));
        assert_eq!(parsed.participant.as_deref(), Some("456@s.whatsapp.net"));
    }

    #[test]
    fn extracts_addressing_context() {
        let lid_stanza = BinaryNode::new("message")
            .with_attr("from", "abc@lid")
            .with_attr("sender_pn", "123@s.whatsapp.net")
            .with_attr("recipient_pn", "999@s.whatsapp.net");
        let context = extract_addressing_context(&lid_stanza);
        assert_eq!(context.mode, AddressingMode::Lid);
        assert_eq!(context.sender_alt.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(context.recipient_alt.as_deref(), Some("999@s.whatsapp.net"));

        let pn_stanza = BinaryNode::new("message")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("sender_lid", "abc@lid");
        let context = extract_addressing_context(&pn_stanza);
        assert_eq!(context.mode, AddressingMode::PhoneNumber);
        assert_eq!(context.sender_alt.as_deref(), Some("abc@lid"));
    }

    #[test]
    fn decodes_chat_message_info() {
        let stanza = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("notify", "Alice")
            .with_attr("t", "10");

        let info =
            decode_inbound_message_info(&stanza, "999@s.whatsapp.net", Some("own@lid")).unwrap();
        assert_eq!(info.kind, InboundMessageKind::Chat);
        assert_eq!(info.key.remote_jid.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(info.key.from_me, Some(false));
        assert_eq!(info.key.participant, None);
        assert_eq!(info.author, "123@s.whatsapp.net");
        assert_eq!(info.sender, "123@s.whatsapp.net");
        assert_eq!(info.push_name.as_deref(), Some("Alice"));
        assert_eq!(info.timestamp, Some(10));
    }

    #[test]
    fn decodes_own_device_message_info_with_recipient() {
        let stanza = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "999:2@s.whatsapp.net")
            .with_attr("recipient", "123@s.whatsapp.net");

        let info =
            decode_inbound_message_info(&stanza, "999@s.whatsapp.net", Some("own@lid")).unwrap();
        assert_eq!(info.key.remote_jid.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(info.key.from_me, Some(true));
        assert!(
            decode_inbound_message_info(&stanza, "111@s.whatsapp.net", Some("own@lid")).is_err()
        );
    }

    #[test]
    fn decodes_group_broadcast_and_newsletter_message_info() {
        let group = BinaryNode::new("message")
            .with_attr("id", "g1")
            .with_attr("from", "123@g.us")
            .with_attr("participant", "999@s.whatsapp.net");
        let info =
            decode_inbound_message_info(&group, "999@s.whatsapp.net", Some("own@lid")).unwrap();
        assert_eq!(info.kind, InboundMessageKind::Group);
        assert_eq!(info.key.remote_jid.as_deref(), Some("123@g.us"));
        assert_eq!(info.key.participant.as_deref(), Some("999@s.whatsapp.net"));
        assert_eq!(info.key.from_me, Some(true));
        assert_eq!(info.author, "999@s.whatsapp.net");
        assert_eq!(info.sender, "123@g.us");

        let status = BinaryNode::new("message")
            .with_attr("id", "s1")
            .with_attr("from", "status@broadcast")
            .with_attr("participant", "123@s.whatsapp.net");
        let info =
            decode_inbound_message_info(&status, "999@s.whatsapp.net", Some("own@lid")).unwrap();
        assert_eq!(info.kind, InboundMessageKind::OtherStatus);

        let newsletter = BinaryNode::new("message")
            .with_attr("id", "n1")
            .with_attr("from", "abc@newsletter");
        let info = decode_inbound_message_info(&newsletter, "999@s.whatsapp.net", None).unwrap();
        assert_eq!(info.kind, InboundMessageKind::Newsletter);
        assert_eq!(info.key.remote_jid.as_deref(), Some("abc@newsletter"));
    }

    #[tokio::test]
    async fn decodes_plaintext_inbound_message_payload() {
        let stanza = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("plaintext").with_content(encode_proto(&text_message("hello"))),
            ]);

        let decryptor = RecordingDecryptor::default();
        let decoded =
            decode_inbound_message(&stanza, "999@s.whatsapp.net", Some("own@lid"), &decryptor)
                .await
                .unwrap();

        assert_eq!(decoded.info.key.id.as_deref(), Some("msg-1"));
        assert_eq!(decoded.payloads.len(), 1);
        assert_eq!(decoded.payloads[0].kind, InboundPayloadKind::Plaintext);
        assert_eq!(
            decoded.payloads[0].message.conversation.as_deref(),
            Some("hello")
        );
        assert_eq!(decoded.last_message(), Some(&decoded.payloads[0].message));
        assert!(decryptor.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn decrypts_and_unpads_encrypted_inbound_message_payload() {
        let decryptor = RecordingDecryptor::new(vec![pad_random_max16(
            encode_proto(&text_message("secret")),
            4,
        )]);
        let stanza = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "msg")
                    .with_content(Bytes::from_static(b"ciphertext")),
            ]);

        let decoded =
            decode_inbound_message(&stanza, "999@s.whatsapp.net", Some("own@lid"), &decryptor)
                .await
                .unwrap();

        assert_eq!(
            decoded.payloads[0].kind,
            InboundPayloadKind::Encrypted(InboundCiphertextType::Message)
        );
        assert_eq!(
            decoded.payloads[0].message.conversation.as_deref(),
            Some("secret")
        );
        let calls = decryptor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].sender_jid, "123@s.whatsapp.net");
        assert_eq!(calls[0].chat_jid, "123@s.whatsapp.net");
        assert_eq!(calls[0].ciphertext_type, InboundCiphertextType::Message);
        assert_eq!(calls[0].ciphertext, Bytes::from_static(b"ciphertext"));
    }

    #[tokio::test]
    async fn unwraps_device_sent_inbound_message_payload() {
        let outer = Message {
            device_sent_message: Some(Box::new(wa_proto::proto::message::DeviceSentMessage {
                destination_jid: Some("123@s.whatsapp.net".to_owned()),
                message: Some(Box::new(text_message("from device"))),
                phash: Some("2:abc".to_owned()),
            })),
            ..Message::default()
        };
        let decryptor = RecordingDecryptor::new(vec![pad_random_max16(encode_proto(&outer), 2)]);
        let stanza = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "999:2@s.whatsapp.net")
            .with_attr("recipient", "123@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "pkmsg")
                    .with_content(Bytes::from_static(b"ciphertext")),
            ]);

        let decoded =
            decode_inbound_message(&stanza, "999@s.whatsapp.net", Some("own@lid"), &decryptor)
                .await
                .unwrap();

        assert_eq!(
            decoded.info.key.remote_jid.as_deref(),
            Some("123@s.whatsapp.net")
        );
        assert_eq!(decoded.info.key.from_me, Some(true));
        assert_eq!(
            decoded.payloads[0].kind,
            InboundPayloadKind::Encrypted(InboundCiphertextType::PreKey)
        );
        assert!(decoded.payloads[0].device_sent_unwrapped);
        assert_eq!(
            decoded.payloads[0].message.conversation.as_deref(),
            Some("from device")
        );
    }

    #[tokio::test]
    async fn handles_sender_key_distribution_messages() {
        let message = Message {
            sender_key_distribution_message: Some(SenderKeyDistributionMessage {
                group_id: Some("123@g.us".to_owned()),
                axolotl_sender_key_distribution_message: Some(Bytes::from_static(b"sender-key")),
            }),
            conversation: Some("group hello".to_owned()),
            ..Message::default()
        };
        let decryptor = RecordingDecryptor::new(vec![pad_random_max16(encode_proto(&message), 1)]);
        let stanza = BinaryNode::new("message")
            .with_attr("id", "g1")
            .with_attr("from", "123@g.us")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "skmsg")
                    .with_content(Bytes::from_static(b"group-ciphertext")),
            ]);

        let decoded =
            decode_inbound_message(&stanza, "999@s.whatsapp.net", Some("own@lid"), &decryptor)
                .await
                .unwrap();

        assert_eq!(decoded.info.kind, InboundMessageKind::Group);
        assert_eq!(decoded.info.author, "456@s.whatsapp.net");
        assert_eq!(decoded.info.sender, "123@g.us");
        assert_eq!(
            decoded.payloads[0].kind,
            InboundPayloadKind::Encrypted(InboundCiphertextType::SenderKey)
        );
        assert_eq!(decoded.payloads[0].sender_key_distribution_count, 1);
        assert_eq!(
            decryptor.sender_keys.lock().unwrap().as_slice(),
            &[("456@s.whatsapp.net".to_owned(), "123@g.us".to_owned())]
        );
    }

    #[tokio::test]
    async fn rejects_malformed_inbound_payloads() {
        let decryptor = RecordingDecryptor::default();
        assert!(
            decode_inbound_message(
                &BinaryNode::new("message")
                    .with_attr("id", "msg-1")
                    .with_attr("from", "123@s.whatsapp.net"),
                "999@s.whatsapp.net",
                None,
                &decryptor,
            )
            .await
            .is_err()
        );

        assert!(
            decode_inbound_message(
                &BinaryNode::new("message")
                    .with_attr("id", "msg-1")
                    .with_attr("from", "123@s.whatsapp.net")
                    .with_content(vec![
                        BinaryNode::new("enc")
                            .with_attr("type", "unknown")
                            .with_content(Bytes::from_static(b"ciphertext")),
                    ]),
                "999@s.whatsapp.net",
                None,
                &decryptor,
            )
            .await
            .is_err()
        );

        assert!(unpad_random_max16(&[]).is_err());
        assert!(unpad_random_max16(&[1, 2, 17]).is_err());
        assert!(unpad_random_max16(&[1, 3, 2]).is_err());
    }

    #[test]
    fn pads_random_max16_payloads() {
        let padded = super::pad_random_max16(Bytes::from_static(b"hello"));
        assert!(padded.len() > 5);
        let pad_len = usize::from(*padded.last().unwrap());
        assert!((1..=16).contains(&pad_len));
        assert!(
            padded[padded.len() - pad_len..]
                .iter()
                .all(|byte| usize::from(*byte) == pad_len)
        );
        assert_eq!(
            unpad_random_max16(&padded).unwrap(),
            Bytes::from_static(b"hello")
        );
    }

    #[test]
    fn rejects_malformed_message_info() {
        assert!(
            decode_inbound_message_info(
                &BinaryNode::new("message")
                    .with_attr("id", "m1")
                    .with_attr("from", "123@g.us"),
                "999@s.whatsapp.net",
                None,
            )
            .is_err()
        );
        assert!(
            decode_inbound_message_info(
                &BinaryNode::new("message")
                    .with_attr("id", "m1")
                    .with_attr("from", "123@s.whatsapp.net")
                    .with_attr("t", "nan"),
                "999@s.whatsapp.net",
                None,
            )
            .is_err()
        );
    }

    fn text_message(text: &str) -> Message {
        Message {
            conversation: Some(text.to_owned()),
            ..Message::default()
        }
    }

    fn encode_proto(message: &Message) -> Bytes {
        let mut out = Vec::new();
        ProstMessage::encode(message, &mut out).unwrap();
        Bytes::from(out)
    }

    fn pad_random_max16(mut bytes: Bytes, pad_len: u8) -> Bytes {
        assert!((1..=16).contains(&pad_len));
        let mut out = Vec::from(bytes.split_to(bytes.len()).as_ref());
        out.extend(std::iter::repeat_n(pad_len, usize::from(pad_len)));
        Bytes::from(out)
    }

    #[derive(Default)]
    struct RecordingDecryptor {
        responses: Arc<Mutex<Vec<Bytes>>>,
        calls: Arc<Mutex<Vec<InboundEncryptedPayload>>>,
        sender_keys: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl RecordingDecryptor {
        fn new(responses: Vec<Bytes>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses)),
                calls: Arc::new(Mutex::new(Vec::new())),
                sender_keys: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl InboundMessageDecryptor for RecordingDecryptor {
        async fn decrypt_inbound_message(
            &self,
            payload: InboundEncryptedPayload,
        ) -> CoreResult<Bytes> {
            self.calls.lock().unwrap().push(payload);
            Ok(self.responses.lock().unwrap().remove(0))
        }

        async fn process_sender_key_distribution(
            &self,
            author_jid: &str,
            message: &SenderKeyDistributionMessage,
        ) -> CoreResult<()> {
            self.sender_keys.lock().unwrap().push((
                author_jid.to_owned(),
                message.group_id.clone().unwrap_or_default(),
            ));
            Ok(())
        }
    }
}
