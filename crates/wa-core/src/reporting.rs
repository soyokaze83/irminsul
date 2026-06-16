use bytes::Bytes;
use prost::Message as _;
use wa_binary::{BinaryNode, jid_decode};
use wa_proto::proto::{Message, MessageKey};

use crate::{CoreError, CoreResult};

const REPORTING_TOKEN_VERSION: &str = "2";
const REPORT_TOKEN_INFO: &[u8] = b"Report Token";
const REPORTING_TOKEN_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReportingField {
    num: u32,
    recursive: bool,
    children: &'static [ReportingField],
}

#[derive(Debug, Eq, PartialEq)]
struct FieldBytes {
    num: u32,
    order: usize,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedVarint {
    value: u64,
    bytes: usize,
}

const fn keep(num: u32) -> ReportingField {
    ReportingField {
        num,
        recursive: false,
        children: &[],
    }
}

const fn nested(num: u32, children: &'static [ReportingField]) -> ReportingField {
    ReportingField {
        num,
        recursive: true,
        children,
    }
}

const CONTEXT_21_22: &[ReportingField] = &[keep(21), keep(22)];
const PAIR_1_2: &[ReportingField] = &[keep(1), keep(2)];
const SINGLE_MESSAGE: &[ReportingField] = &[nested(1, &[])];

const IMAGE_FIELDS: &[ReportingField] = &[
    keep(2),
    keep(3),
    keep(8),
    keep(11),
    nested(17, CONTEXT_21_22),
    keep(25),
];
const CONTACT_FIELDS: &[ReportingField] = &[keep(1), keep(16), nested(17, CONTEXT_21_22)];
const LOCATION_FIELDS: &[ReportingField] = &[
    keep(3),
    keep(4),
    keep(5),
    keep(16),
    nested(17, CONTEXT_21_22),
];
const EXTENDED_TEXT_FIELDS: &[ReportingField] = &[keep(1), nested(17, CONTEXT_21_22), keep(30)];
const DOCUMENT_FIELDS: &[ReportingField] = &[
    keep(2),
    keep(7),
    keep(10),
    nested(17, CONTEXT_21_22),
    keep(20),
];
const AUDIO_FIELDS: &[ReportingField] = &[
    keep(2),
    keep(7),
    keep(9),
    nested(17, CONTEXT_21_22),
    keep(21),
];
const VIDEO_FIELDS: &[ReportingField] = &[
    keep(2),
    keep(6),
    keep(7),
    keep(13),
    nested(17, CONTEXT_21_22),
    keep(20),
];
const PROTOCOL_FIELDS: &[ReportingField] = &[keep(1), keep(2), nested(14, &[]), keep(15)];
const LIVE_LOCATION_FIELDS: &[ReportingField] = &[keep(6), keep(16), nested(17, CONTEXT_21_22)];
const STICKER_FIELDS: &[ReportingField] = &[
    keep(4),
    keep(5),
    keep(8),
    keep(13),
    nested(17, CONTEXT_21_22),
];
const GROUP_INVITE_FIELDS: &[ReportingField] = &[
    keep(1),
    keep(2),
    keep(4),
    keep(5),
    keep(6),
    nested(7, CONTEXT_21_22),
];
const POLL_FIELDS: &[ReportingField] = &[
    keep(2),
    nested(3, PAIR_1_2),
    nested(5, CONTEXT_21_22),
    nested(8, PAIR_1_2),
];
const POLL_RESULT_FIELDS: &[ReportingField] =
    &[keep(1), nested(2, &[keep(1)]), nested(3, CONTEXT_21_22)];

const REPORTING_FIELDS: &[ReportingField] = &[
    keep(1),
    nested(3, IMAGE_FIELDS),
    nested(4, CONTACT_FIELDS),
    nested(5, LOCATION_FIELDS),
    nested(6, EXTENDED_TEXT_FIELDS),
    nested(7, DOCUMENT_FIELDS),
    nested(8, AUDIO_FIELDS),
    nested(9, VIDEO_FIELDS),
    nested(12, PROTOCOL_FIELDS),
    nested(18, LIVE_LOCATION_FIELDS),
    nested(26, STICKER_FIELDS),
    nested(28, GROUP_INVITE_FIELDS),
    nested(37, SINGLE_MESSAGE),
    nested(49, POLL_FIELDS),
    nested(53, SINGLE_MESSAGE),
    nested(55, SINGLE_MESSAGE),
    nested(58, SINGLE_MESSAGE),
    nested(59, SINGLE_MESSAGE),
    nested(60, POLL_FIELDS),
    nested(64, POLL_FIELDS),
    nested(66, VIDEO_FIELDS),
    nested(74, SINGLE_MESSAGE),
    nested(87, SINGLE_MESSAGE),
    nested(88, POLL_RESULT_FIELDS),
    nested(92, SINGLE_MESSAGE),
    nested(93, SINGLE_MESSAGE),
    nested(94, SINGLE_MESSAGE),
];

#[must_use]
pub fn should_include_reporting_token(message: &Message) -> bool {
    message.reaction_message.is_none()
        && message.enc_reaction_message.is_none()
        && message.enc_event_response_message.is_none()
        && message.poll_update_message.is_none()
}

pub fn build_reporting_token_node(
    message: &Message,
    key: &MessageKey,
) -> CoreResult<Option<BinaryNode>> {
    let encoded = message.encode_to_vec();
    build_reporting_token_node_from_encoded(&encoded, message, key)
}

pub fn build_reporting_token_node_from_encoded(
    encoded: &[u8],
    message: &Message,
    key: &MessageKey,
) -> CoreResult<Option<BinaryNode>> {
    if !should_include_reporting_token(message) {
        return Ok(None);
    }

    let Some(message_secret) = message
        .message_context_info
        .as_ref()
        .and_then(|context| context.message_secret.as_ref())
    else {
        return Ok(None);
    };
    let Some(message_id) = key.id.as_deref().filter(|id| !id.is_empty()) else {
        return Ok(None);
    };

    let Some((from, to)) = reporting_key_jids(key) else {
        return Ok(None);
    };
    validate_reporting_jid("reporting source JID", from)?;
    validate_reporting_jid("reporting target JID", to)?;

    let mut info =
        Vec::with_capacity(message_id.len() + from.len() + to.len() + REPORT_TOKEN_INFO.len());
    info.extend_from_slice(message_id.as_bytes());
    info.extend_from_slice(from.as_bytes());
    info.extend_from_slice(to.as_bytes());
    info.extend_from_slice(REPORT_TOKEN_INFO);

    let reporting_secret = wa_crypto::hkdf_sha256(message_secret.as_ref(), 32, &[], &info)
        .map_err(CoreError::Crypto)?;
    let Some(content) = extract_reporting_token_content(encoded, REPORTING_FIELDS) else {
        return Ok(None);
    };
    if content.is_empty() {
        return Ok(None);
    }

    let mac = wa_crypto::hmac_sha256(&content, &reporting_secret).map_err(CoreError::Crypto)?;
    let reporting_token = Bytes::copy_from_slice(&mac[..REPORTING_TOKEN_BYTES]);
    Ok(Some(BinaryNode::new("reporting").with_content(vec![
        BinaryNode::new("reporting_token")
            .with_attr("v", REPORTING_TOKEN_VERSION)
            .with_content(reporting_token),
    ])))
}

fn reporting_key_jids(key: &MessageKey) -> Option<(&str, &str)> {
    let remote_jid = key.remote_jid.as_deref()?;
    if key.from_me.unwrap_or(false) {
        Some((remote_jid, key.participant.as_deref().unwrap_or(remote_jid)))
    } else {
        Some((key.participant.as_deref().unwrap_or(remote_jid), remote_jid))
    }
}

fn validate_reporting_jid(label: &str, jid: &str) -> CoreResult<()> {
    if jid_decode(jid).is_none() {
        return Err(CoreError::Payload(format!("invalid {label}: {jid}")));
    }
    Ok(())
}

fn extract_reporting_token_content(data: &[u8], cfg: &'static [ReportingField]) -> Option<Vec<u8>> {
    let mut out = Vec::<FieldBytes>::new();
    let mut i = 0usize;
    let mut order = 0usize;

    while i < data.len() {
        let field_start = i;
        let tag = decode_varint(data, i)?;
        i = i.checked_add(tag.bytes)?;

        let field_num = u32::try_from(tag.value >> 3).ok()?;
        let wire_type = u8::try_from(tag.value & 0x7).ok()?;
        let field_cfg = find_reporting_field(cfg, field_num);

        match wire_type {
            0 => {
                let value = decode_varint(data, i)?;
                let end = i.checked_add(value.bytes)?;
                push_or_skip_field(
                    data,
                    &mut out,
                    field_cfg,
                    field_num,
                    &mut order,
                    field_start,
                    end,
                )?;
                i = end;
            }
            1 => {
                let end = i.checked_add(8)?;
                push_or_skip_field(
                    data,
                    &mut out,
                    field_cfg,
                    field_num,
                    &mut order,
                    field_start,
                    end,
                )?;
                i = end;
            }
            2 => {
                let len = decode_varint(data, i)?;
                let value_start = i.checked_add(len.bytes)?;
                let value_len = usize::try_from(len.value).ok()?;
                let value_end = value_start.checked_add(value_len)?;
                if value_end > data.len() {
                    return None;
                }

                let Some(field_cfg) = field_cfg else {
                    i = value_end;
                    continue;
                };

                if field_cfg.recursive {
                    let sub = extract_reporting_token_content(
                        &data[value_start..value_end],
                        field_cfg.children,
                    )?;
                    if !sub.is_empty() {
                        let mut bytes = Vec::with_capacity(
                            encoded_varint_len(tag.value)
                                + encoded_varint_len(sub.len() as u64)
                                + sub.len(),
                        );
                        encode_varint(tag.value, &mut bytes);
                        encode_varint(sub.len() as u64, &mut bytes);
                        bytes.extend_from_slice(&sub);
                        out.push(FieldBytes {
                            num: field_num,
                            order,
                            bytes,
                        });
                        order = order.checked_add(1)?;
                    }
                } else {
                    push_original_slice(
                        data,
                        &mut out,
                        field_num,
                        &mut order,
                        field_start,
                        value_end,
                    )?;
                }
                i = value_end;
            }
            5 => {
                let end = i.checked_add(4)?;
                push_or_skip_field(
                    data,
                    &mut out,
                    field_cfg,
                    field_num,
                    &mut order,
                    field_start,
                    end,
                )?;
                i = end;
            }
            _ => return None,
        }
    }

    if out.is_empty() {
        return Some(Vec::new());
    }

    out.sort_by(|left, right| left.num.cmp(&right.num).then(left.order.cmp(&right.order)));
    let len = out
        .iter()
        .try_fold(0usize, |total, field| total.checked_add(field.bytes.len()))?;
    let mut filtered = Vec::with_capacity(len);
    for field in out {
        filtered.extend_from_slice(&field.bytes);
    }
    Some(filtered)
}

fn push_or_skip_field(
    data: &[u8],
    out: &mut Vec<FieldBytes>,
    field_cfg: Option<&ReportingField>,
    field_num: u32,
    order: &mut usize,
    field_start: usize,
    end: usize,
) -> Option<()> {
    if end > data.len() {
        return None;
    }
    if field_cfg.is_some() {
        push_original_slice(data, out, field_num, order, field_start, end)?;
    }
    Some(())
}

fn push_original_slice(
    data: &[u8],
    out: &mut Vec<FieldBytes>,
    field_num: u32,
    order: &mut usize,
    field_start: usize,
    end: usize,
) -> Option<()> {
    if end > data.len() {
        return None;
    }
    out.push(FieldBytes {
        num: field_num,
        order: *order,
        bytes: data.get(field_start..end)?.to_vec(),
    });
    *order = order.checked_add(1)?;
    Some(())
}

fn find_reporting_field(
    cfg: &'static [ReportingField],
    field_num: u32,
) -> Option<&'static ReportingField> {
    cfg.iter().find(|field| field.num == field_num)
}

fn decode_varint(data: &[u8], offset: usize) -> Option<DecodedVarint> {
    let mut value = 0u64;
    let mut bytes = 0usize;
    let mut shift = 0u32;

    while offset.checked_add(bytes)? < data.len() {
        let current = *data.get(offset + bytes)?;
        value |= u64::from(current & 0x7f) << shift;
        bytes = bytes.checked_add(1)?;

        if current & 0x80 == 0 {
            return Some(DecodedVarint { value, bytes });
        }

        shift = shift.checked_add(7)?;
        if shift > 63 {
            return None;
        }
    }

    None
}

fn encoded_varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value > 0x7f {
        len += 1;
        value >>= 7;
    }
    len
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value > 0x7f {
        out.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_binary::BinaryNodeContent;
    use wa_proto::proto::{MessageContextInfo, message};

    #[test]
    fn builds_reporting_token_node_for_message_with_secret() {
        let message = Message {
            conversation: Some("hello".to_owned()),
            message_context_info: Some(MessageContextInfo {
                message_secret: Some(Bytes::from(vec![7u8; 32])),
                ..MessageContextInfo::default()
            }),
            ..Message::default()
        };
        let key = MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(true),
            id: Some("msg-1".to_owned()),
            participant: None,
        };

        let node = build_reporting_token_node(&message, &key).unwrap().unwrap();
        let repeated = build_reporting_token_node(&message, &key).unwrap().unwrap();

        assert_eq!(node.tag, "reporting");
        assert_eq!(node, repeated);
        let Some(BinaryNodeContent::Nodes(children)) = node.content else {
            panic!("reporting node should contain a token child");
        };
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "reporting_token");
        assert_eq!(children[0].attrs.get("v").map(String::as_str), Some("2"));
        let Some(BinaryNodeContent::Bytes(token)) = &children[0].content else {
            panic!("reporting token child should contain bytes");
        };
        assert_eq!(token.len(), REPORTING_TOKEN_BYTES);
    }

    #[test]
    fn skips_reporting_token_for_ineligible_or_incomplete_messages() {
        let key = MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(true),
            id: Some("msg-1".to_owned()),
            participant: None,
        };
        let with_secret = Message {
            conversation: Some("hello".to_owned()),
            message_context_info: Some(MessageContextInfo {
                message_secret: Some(Bytes::from(vec![7u8; 32])),
                ..MessageContextInfo::default()
            }),
            ..Message::default()
        };
        let without_secret = Message {
            conversation: Some("hello".to_owned()),
            ..Message::default()
        };
        let reaction = Message {
            reaction_message: Some(message::ReactionMessage::default()),
            message_context_info: Some(MessageContextInfo {
                message_secret: Some(Bytes::from(vec![7u8; 32])),
                ..MessageContextInfo::default()
            }),
            ..Message::default()
        };
        let mut without_id = key.clone();
        without_id.id = None;

        assert!(
            build_reporting_token_node(&without_secret, &key)
                .unwrap()
                .is_none()
        );
        assert!(
            build_reporting_token_node(&reaction, &key)
                .unwrap()
                .is_none()
        );
        assert!(
            build_reporting_token_node(&with_secret, &without_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reporting_token_filter_sorts_allowed_fields_and_drops_unknown_fields() {
        let data = [
            0x12, 0x03, b'b', b'a', b'd', 0x32, 0x02, 0x08, 0x01, 0x0a, 0x02, b'o', b'k',
        ];

        let filtered = extract_reporting_token_content(&data, REPORTING_FIELDS).unwrap();

        assert_eq!(
            filtered,
            vec![0x0a, 0x02, b'o', b'k', 0x32, 0x02, 0x08, 0x01]
        );
        assert!(extract_reporting_token_content(&[0x80], REPORTING_FIELDS).is_none());
    }
}
