use crate::jid::{JidServer, WaJidDomain, jid_decode, jid_encode};
use crate::node::{BinaryNode, BinaryNodeContent};
use crate::tokens::{double_token, single_token, token_for};
use bytes::{BufMut, Bytes, BytesMut};
use flate2::read::ZlibDecoder;
use std::collections::BTreeMap;
use std::io::Read;

const LIST_EMPTY: u8 = 0;
const DICTIONARY_0: u8 = 236;
const DICTIONARY_3: u8 = 239;
const LIST_8: u8 = 248;
const LIST_16: u8 = 249;
const JID_PAIR: u8 = 250;
const HEX_8: u8 = 251;
const BINARY_8: u8 = 252;
const BINARY_20: u8 = 253;
const BINARY_32: u8 = 254;
const NIBBLE_8: u8 = 255;
const PACKED_MAX: usize = 127;

#[derive(Debug, thiserror::Error)]
pub enum BinaryEncodeError {
    #[error("node tag cannot be empty")]
    EmptyTag,
    #[error("string too large to encode: {0}")]
    StringTooLarge(usize),
    #[error("list too large to encode: {0}")]
    ListTooLarge(usize),
    #[error("invalid nibble character: {0}")]
    InvalidNibble(char),
    #[error("invalid hex character: {0}")]
    InvalidHex(char),
}

#[derive(Debug, thiserror::Error)]
pub enum BinaryDecodeError {
    #[error("end of stream")]
    EndOfStream,
    #[error("invalid list tag: {0}")]
    InvalidListTag(u8),
    #[error("invalid node")]
    InvalidNode,
    #[error("invalid string tag: {0}")]
    InvalidStringTag(u8),
    #[error("invalid packed byte")]
    InvalidPackedByte,
    #[error("invalid jid pair")]
    InvalidJidPair,
    #[error("invalid utf-8")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("decompression failed")]
    Decompression(#[from] std::io::Error),
}

pub fn encode_binary_node(node: &BinaryNode) -> Result<Bytes, BinaryEncodeError> {
    let mut out = BytesMut::with_capacity(128);
    out.put_u8(0);
    encode_node_inner(node, &mut out)?;
    Ok(out.freeze())
}

pub fn decode_binary_node(input: &[u8]) -> Result<BinaryNode, BinaryDecodeError> {
    let decompressed = decompress_if_required(input)?;
    let mut cursor = Cursor::new(&decompressed);
    decode_node_inner(&mut cursor)
}

fn decompress_if_required(input: &[u8]) -> Result<Vec<u8>, BinaryDecodeError> {
    let Some((&prefix, rest)) = input.split_first() else {
        return Err(BinaryDecodeError::EndOfStream);
    };

    if prefix & 2 == 2 {
        let mut decoder = ZlibDecoder::new(rest);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    } else {
        Ok(rest.to_vec())
    }
}

fn encode_node_inner(node: &BinaryNode, out: &mut BytesMut) -> Result<(), BinaryEncodeError> {
    if node.tag.is_empty() {
        return Err(BinaryEncodeError::EmptyTag);
    }

    let attr_count = node.attrs.len();
    let has_content = usize::from(node.content.is_some());
    write_list_start(1 + attr_count * 2 + has_content, out)?;
    write_string(&node.tag, out)?;

    for (key, value) in &node.attrs {
        write_string(key, out)?;
        write_string(value, out)?;
    }

    if let Some(content) = &node.content {
        match content {
            BinaryNodeContent::Nodes(nodes) => {
                write_list_start(nodes.len(), out)?;
                for child in nodes {
                    encode_node_inner(child, out)?;
                }
            }
            BinaryNodeContent::Text(value) => write_string(value, out)?,
            BinaryNodeContent::Bytes(value) => {
                write_byte_length(value.len(), out)?;
                out.put_slice(value);
            }
        }
    }

    Ok(())
}

fn write_list_start(len: usize, out: &mut BytesMut) -> Result<(), BinaryEncodeError> {
    if len == 0 {
        out.put_u8(LIST_EMPTY);
    } else if len < 256 {
        out.put_u8(LIST_8);
        out.put_u8(len as u8);
    } else if len <= u16::MAX as usize {
        out.put_u8(LIST_16);
        out.put_u16(len as u16);
    } else {
        return Err(BinaryEncodeError::ListTooLarge(len));
    }
    Ok(())
}

fn write_byte_length(len: usize, out: &mut BytesMut) -> Result<(), BinaryEncodeError> {
    if len >= u32::MAX as usize {
        return Err(BinaryEncodeError::StringTooLarge(len));
    }
    if len >= 1 << 20 {
        out.put_u8(BINARY_32);
        out.put_u32(len as u32);
    } else if len >= 256 {
        out.put_u8(BINARY_20);
        out.put_u8(((len >> 16) & 0x0f) as u8);
        out.put_u8(((len >> 8) & 0xff) as u8);
        out.put_u8((len & 0xff) as u8);
    } else {
        out.put_u8(BINARY_8);
        out.put_u8(len as u8);
    }
    Ok(())
}

fn write_string(value: &str, out: &mut BytesMut) -> Result<(), BinaryEncodeError> {
    if value.is_empty() {
        write_raw_string(value, out)
    } else if let Some(token) = token_for(value) {
        if let Some(dict) = token.dict {
            out.put_u8(DICTIONARY_0 + dict);
        }
        out.put_u8(token.index);
        Ok(())
    } else if is_nibble(value) {
        write_packed(value, PackedKind::Nibble, out)
    } else if is_hex(value) {
        write_packed(value, PackedKind::Hex, out)
    } else if let Some(jid) = jid_decode(value) {
        if jid.device.is_some() {
            out.put_u8(247);
            out.put_u8(jid.domain_type as u8);
            out.put_u8(jid.device.unwrap_or_default() as u8);
            write_string(&jid.user, out)
        } else {
            out.put_u8(JID_PAIR);
            if jid.user.is_empty() {
                out.put_u8(LIST_EMPTY);
            } else {
                write_string(&jid.user, out)?;
            }
            write_raw_string(&jid.server_raw, out)
        }
    } else {
        write_raw_string(value, out)
    }
}

fn write_raw_string(value: &str, out: &mut BytesMut) -> Result<(), BinaryEncodeError> {
    write_byte_length(value.len(), out)?;
    out.put_slice(value.as_bytes());
    Ok(())
}

#[derive(Clone, Copy)]
enum PackedKind {
    Nibble,
    Hex,
}

fn write_packed(
    value: &str,
    kind: PackedKind,
    out: &mut BytesMut,
) -> Result<(), BinaryEncodeError> {
    if value.len() > PACKED_MAX {
        return write_raw_string(value, out);
    }

    out.put_u8(match kind {
        PackedKind::Nibble => NIBBLE_8,
        PackedKind::Hex => HEX_8,
    });

    let mut rounded = value.len().div_ceil(2) as u8;
    if !value.len().is_multiple_of(2) {
        rounded |= 128;
    }
    out.put_u8(rounded);

    let mut chars = value.chars();
    while let Some(first) = chars.next() {
        let second = chars.next().unwrap_or('\0');
        let byte = match kind {
            PackedKind::Nibble => (pack_nibble(first)? << 4) | pack_nibble(second)?,
            PackedKind::Hex => (pack_hex(first)? << 4) | pack_hex(second)?,
        };
        out.put_u8(byte);
    }

    Ok(())
}

fn is_nibble(value: &str) -> bool {
    value.len() <= PACKED_MAX
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == '-' || ch == '.')
}

fn is_hex(value: &str) -> bool {
    value.len() <= PACKED_MAX
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('A'..='F').contains(&ch))
}

fn pack_nibble(ch: char) -> Result<u8, BinaryEncodeError> {
    match ch {
        '-' => Ok(10),
        '.' => Ok(11),
        '\0' => Ok(15),
        '0'..='9' => Ok(ch as u8 - b'0'),
        _ => Err(BinaryEncodeError::InvalidNibble(ch)),
    }
}

fn pack_hex(ch: char) -> Result<u8, BinaryEncodeError> {
    match ch {
        '0'..='9' => Ok(ch as u8 - b'0'),
        'A'..='F' => Ok(10 + ch as u8 - b'A'),
        'a'..='f' => Ok(10 + ch as u8 - b'a'),
        '\0' => Ok(15),
        _ => Err(BinaryEncodeError::InvalidHex(ch)),
    }
}

fn decode_node_inner(cursor: &mut Cursor<'_>) -> Result<BinaryNode, BinaryDecodeError> {
    let list_tag = cursor.read_u8()?;
    let list_size = cursor.read_list_size(list_tag)?;
    let tag_tag = cursor.read_u8()?;
    let tag = cursor.read_string(tag_tag)?;
    if list_size == 0 || tag.is_empty() {
        return Err(BinaryDecodeError::InvalidNode);
    }

    let mut attrs = BTreeMap::new();
    let attr_count = (list_size - 1) >> 1;
    for _ in 0..attr_count {
        let key_tag = cursor.read_u8()?;
        let key = cursor.read_string(key_tag)?;
        let value_tag = cursor.read_u8()?;
        let value = cursor.read_string(value_tag)?;
        attrs.insert(key, value);
    }

    let content = if list_size % 2 == 0 {
        let content_tag = cursor.read_u8()?;
        if cursor.is_list_tag(content_tag) {
            let child_count = cursor.read_list_size(content_tag)?;
            let mut children = Vec::with_capacity(child_count);
            for _ in 0..child_count {
                children.push(decode_node_inner(cursor)?);
            }
            Some(BinaryNodeContent::Nodes(children))
        } else if cursor.is_binary_tag(content_tag) {
            let bytes = cursor.read_binary_for_tag(content_tag)?;
            Some(BinaryNodeContent::Bytes(bytes))
        } else {
            Some(BinaryNodeContent::Text(cursor.read_string(content_tag)?))
        }
    } else {
        None
    };

    Ok(BinaryNode {
        tag,
        attrs,
        content,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, BinaryDecodeError> {
        let byte = *self
            .bytes
            .get(self.index)
            .ok_or(BinaryDecodeError::EndOfStream)?;
        self.index += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Bytes, BinaryDecodeError> {
        let end = self
            .index
            .checked_add(len)
            .ok_or(BinaryDecodeError::EndOfStream)?;
        let bytes = self
            .bytes
            .get(self.index..end)
            .ok_or(BinaryDecodeError::EndOfStream)?;
        self.index = end;
        Ok(Bytes::copy_from_slice(bytes))
    }

    fn read_int(&mut self, len: usize) -> Result<usize, BinaryDecodeError> {
        let mut value = 0usize;
        for _ in 0..len {
            value = (value << 8) | usize::from(self.read_u8()?);
        }
        Ok(value)
    }

    fn read_int20(&mut self) -> Result<usize, BinaryDecodeError> {
        let b1 = usize::from(self.read_u8()? & 0x0f);
        let b2 = usize::from(self.read_u8()?);
        let b3 = usize::from(self.read_u8()?);
        Ok((b1 << 16) | (b2 << 8) | b3)
    }

    fn is_list_tag(&self, tag: u8) -> bool {
        matches!(tag, LIST_EMPTY | LIST_8 | LIST_16)
    }

    fn is_binary_tag(&self, tag: u8) -> bool {
        matches!(tag, BINARY_8 | BINARY_20 | BINARY_32)
    }

    fn read_list_size(&mut self, tag: u8) -> Result<usize, BinaryDecodeError> {
        match tag {
            LIST_EMPTY => Ok(0),
            LIST_8 => Ok(usize::from(self.read_u8()?)),
            LIST_16 => self.read_int(2),
            _ => Err(BinaryDecodeError::InvalidListTag(tag)),
        }
    }

    fn read_binary_for_tag(&mut self, tag: u8) -> Result<Bytes, BinaryDecodeError> {
        let len = match tag {
            BINARY_8 => usize::from(self.read_u8()?),
            BINARY_20 => self.read_int20()?,
            BINARY_32 => self.read_int(4)?,
            _ => return Err(BinaryDecodeError::InvalidStringTag(tag)),
        };
        self.read_bytes(len)
    }

    fn read_string(&mut self, tag: u8) -> Result<String, BinaryDecodeError> {
        if tag >= 1
            && let Some(token) = single_token(tag)
        {
            return Ok(token.to_owned());
        }

        match tag {
            DICTIONARY_0..=DICTIONARY_3 => {
                let index = self.read_u8()?;
                double_token(tag - DICTIONARY_0, index)
                    .map(str::to_owned)
                    .ok_or(BinaryDecodeError::InvalidStringTag(tag))
            }
            LIST_EMPTY => Ok(String::new()),
            BINARY_8 | BINARY_20 | BINARY_32 => {
                let bytes = self.read_binary_for_tag(tag)?;
                Ok(std::str::from_utf8(&bytes)?.to_owned())
            }
            JID_PAIR => self.read_jid_pair(),
            247 => self.read_ad_jid(),
            HEX_8 | NIBBLE_8 => self.read_packed(tag),
            _ => Err(BinaryDecodeError::InvalidStringTag(tag)),
        }
    }

    fn read_jid_pair(&mut self) -> Result<String, BinaryDecodeError> {
        let user_tag = self.read_u8()?;
        let user = self.read_string(user_tag)?;
        let server_tag = self.read_u8()?;
        let server = self.read_string(server_tag)?;
        if server.is_empty() {
            return Err(BinaryDecodeError::InvalidJidPair);
        }
        Ok(format!("{user}@{server}"))
    }

    fn read_ad_jid(&mut self) -> Result<String, BinaryDecodeError> {
        let domain = self.read_u8()?;
        let device = self.read_u8()?;
        let user_tag = self.read_u8()?;
        let user = self.read_string(user_tag)?;
        let domain = match domain {
            1 => WaJidDomain::Lid,
            128 => WaJidDomain::Hosted,
            129 => WaJidDomain::HostedLid,
            _ => WaJidDomain::WhatsApp,
        };
        let server = domain.server(JidServer::SWhatsAppNet);
        Ok(jid_encode(user, server, Some(u16::from(device)), None))
    }

    fn read_packed(&mut self, tag: u8) -> Result<String, BinaryDecodeError> {
        let start = self.read_u8()?;
        let byte_count = usize::from(start & 127);
        let trim_last = start >> 7 != 0;
        let mut out = String::with_capacity(byte_count * 2);
        for _ in 0..byte_count {
            let byte = self.read_u8()?;
            out.push(unpack_byte(tag, (byte & 0xf0) >> 4)?);
            out.push(unpack_byte(tag, byte & 0x0f)?);
        }
        if trim_last {
            out.pop();
        }
        Ok(out)
    }
}

fn unpack_byte(tag: u8, value: u8) -> Result<char, BinaryDecodeError> {
    match tag {
        NIBBLE_8 => match value {
            0..=9 => Ok((b'0' + value) as char),
            10 => Ok('-'),
            11 => Ok('.'),
            15 => Ok('\0'),
            _ => Err(BinaryDecodeError::InvalidPackedByte),
        },
        HEX_8 => match value {
            0..=9 => Ok((b'0' + value) as char),
            10..=15 => Ok((b'A' + value - 10) as char),
            _ => Err(BinaryDecodeError::InvalidPackedByte),
        },
        _ => Err(BinaryDecodeError::InvalidPackedByte),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_simple_node() {
        let node = BinaryNode::new("iq")
            .with_attr("type", "get")
            .with_attr("to", "s.whatsapp.net")
            .with_content(vec![BinaryNode::new("ping")]);

        let encoded = encode_binary_node(&node).unwrap();
        let decoded = decode_binary_node(&encoded).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn round_trips_bytes_content() {
        let node = BinaryNode::new("data").with_content(Bytes::from_static(b"hello"));
        let encoded = encode_binary_node(&node).unwrap();
        let decoded = decode_binary_node(&encoded).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn round_trips_jid_attribute() {
        let node = BinaryNode::new("presence").with_attr("to", "12345@s.whatsapp.net");
        let encoded = encode_binary_node(&node).unwrap();
        let decoded = decode_binary_node(&encoded).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn uses_dictionary_tokens_for_common_protocol_strings() {
        let node = BinaryNode::new("iq").with_attr("type", "get");
        let encoded = encode_binary_node(&node).unwrap();
        let token = token_for("iq").unwrap();
        assert!(encoded.contains(&token.index));
        let decoded = decode_binary_node(&encoded).unwrap();
        assert_eq!(decoded, node);
    }
}
