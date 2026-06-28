#![no_main]

use bytes::Bytes;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use wa_binary::{BinaryNode, decode_binary_node, encode_binary_node};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    drive_raw_compressed_frame(data);
    drive_malformed_compressed_frame(data);
    drive_compressed_round_trip(data);
    drive_structured_compressed_nodes(data);
});

fn drive_raw_compressed_frame(data: &[u8]) {
    let mut frame = Vec::with_capacity(data.len() + 1);
    frame.push(2);
    frame.extend_from_slice(data);
    let _ = decode_binary_node(&frame);
}

fn drive_malformed_compressed_frame(data: &[u8]) {
    let mut frame = Vec::with_capacity(data.len() + 1);
    frame.push(data.first().copied().unwrap_or(2) | 2);
    frame.extend_from_slice(&data[data.len().min(1)..]);
    let _ = decode_binary_node(&frame);
}

fn drive_compressed_round_trip(data: &[u8]) {
    let Ok(node) = decode_binary_node(data) else {
        return;
    };
    let Ok(encoded) = encode_binary_node(&node) else {
        return;
    };
    if let Some(frame) = compressed_binary_frame(&encoded[1..])
        && let Ok(decoded) = decode_binary_node(&frame)
    {
        let _ = encode_binary_node(&decoded);
    }
}

fn drive_structured_compressed_nodes(data: &[u8]) {
    for node in structured_nodes(data) {
        let Ok(encoded) = encode_binary_node(&node) else {
            continue;
        };
        if let Some(frame) = compressed_binary_frame(&encoded[1..]) {
            let _ = decode_binary_node(&frame);
        }
    }
}

fn compressed_binary_frame(payload: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(payload).ok()?;
    let compressed = encoder.finish().ok()?;
    let mut frame = Vec::with_capacity(compressed.len() + 1);
    frame.push(2);
    frame.extend_from_slice(&compressed);
    Some(frame)
}

fn structured_nodes(data: &[u8]) -> [BinaryNode; 4] {
    [
        BinaryNode::new("iq")
            .with_attr(
                "id",
                fuzz_id("query", data.first().copied().unwrap_or_default()),
            )
            .with_attr("to", "s.whatsapp.net")
            .with_attr("type", "get")
            .with_content(vec![BinaryNode::new("ping")]),
        BinaryNode::new("message")
            .with_attr("from", user_jid(data.get(1).copied().unwrap_or_default()))
            .with_attr(
                "id",
                fuzz_id("msg", data.get(2).copied().unwrap_or_default()),
            )
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("enc")
                    .with_attr("type", "msg")
                    .with_content(token_bytes(data, 3, 48)),
            ]),
        BinaryNode::new("receipt")
            .with_attr("from", user_jid(data.get(4).copied().unwrap_or_default()))
            .with_attr(
                "id",
                fuzz_id("receipt", data.get(5).copied().unwrap_or_default()),
            )
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("retry")
                    .with_attr(
                        "count",
                        retry_count(data.get(6).copied().unwrap_or_default()),
                    )
                    .with_attr(
                        "error",
                        retry_error(data.get(7).copied().unwrap_or_default()),
                    ),
                BinaryNode::new("registration").with_content(token_bytes(data, 8, 4)),
            ]),
        BinaryNode::new("notification")
            .with_attr("from", "s.whatsapp.net")
            .with_attr(
                "id",
                fuzz_id("hist", data.get(9).copied().unwrap_or_default()),
            )
            .with_attr("type", "server_sync")
            .with_content(vec![
                BinaryNode::new("history")
                    .with_attr("chunk-order", "1")
                    .with_attr(
                        "progress",
                        progress(data.get(10).copied().unwrap_or_default()),
                    )
                    .with_content(token_bytes(data, 11, 64)),
            ]),
    ]
}

fn token_bytes(data: &[u8], offset: usize, len: usize) -> Bytes {
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        out.push(
            data.get(offset + index)
                .copied()
                .unwrap_or((offset + index) as u8),
        );
    }
    Bytes::from(out)
}

fn user_jid(byte: u8) -> String {
    format!("{}@s.whatsapp.net", 10_000 + u32::from(byte))
}

fn retry_count(byte: u8) -> String {
    (u16::from(byte % 5) + 1).to_string()
}

fn retry_error(byte: u8) -> String {
    (u16::from(byte % 16)).to_string()
}

fn progress(byte: u8) -> String {
    (u16::from(byte % 101)).to_string()
}

fn fuzz_id(prefix: &str, byte: u8) -> String {
    format!("{prefix}-{byte}")
}
