#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use prost::Message as _;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    AppStateCollection, AppStateQueryKind, parse_app_state_query_result,
    parse_app_state_sync_response, parse_dirty_notification_node, parse_dirty_notification_nodes,
};
use wa_proto::proto::{ExternalBlobReference, SyncdPatch, SyncdVersion};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_app_state_node(&node);
    }

    for node in structured_app_state_nodes(data) {
        drive_app_state_node(&node);
    }
});

fn drive_app_state_node(node: &BinaryNode) {
    let _ = parse_dirty_notification_node(node);
    let _ = parse_dirty_notification_nodes(node);
    let _ = parse_app_state_sync_response(node);
    let _ = parse_app_state_query_result(node, AppStateQueryKind::Sync);
    let _ = parse_app_state_query_result(node, AppStateQueryKind::PatchUpload);
}

fn structured_app_state_nodes(data: &[u8]) -> Vec<BinaryNode> {
    vec![
        structured_dirty_node(data),
        malformed_dirty_node(data),
        structured_sync_result_node(data),
        missing_version_patch_node(data),
        raw_patch_bytes_node(data),
        query_result_node(data),
        query_attr_error_node(data),
        query_child_error_node(data),
        invalid_query_result_node(data),
    ]
}

fn structured_dirty_node(data: &[u8]) -> BinaryNode {
    BinaryNode::new("ib").with_content(vec![
        BinaryNode::new("dirty")
            .with_attr(
                "type",
                dirty_type(data.first().copied().unwrap_or_default()),
            )
            .with_attr(
                "timestamp",
                timestamp(data.get(1).copied().unwrap_or_default()),
            ),
        BinaryNode::new("dirty")
            .with_attr("type", dirty_type(data.get(2).copied().unwrap_or_default()))
            .with_attr("t", timestamp(data.get(3).copied().unwrap_or_default())),
    ])
}

fn malformed_dirty_node(data: &[u8]) -> BinaryNode {
    let mut dirty = BinaryNode::new("dirty");
    if data.first().copied().unwrap_or_default().is_multiple_of(2) {
        dirty = dirty.with_attr("timestamp", "not-a-number");
    }
    BinaryNode::new("ib").with_content(vec![dirty])
}

fn structured_sync_result_node(data: &[u8]) -> BinaryNode {
    let collection = collection(data.get(4).copied().unwrap_or_default());
    let version = u64::from(data.get(5).copied().unwrap_or_default());
    BinaryNode::new("iq")
        .with_attr("type", "result")
        .with_content(vec![BinaryNode::new("sync").with_content(vec![
            BinaryNode::new("collection")
                .with_attr("name", collection.name())
                .with_attr("version", version.to_string())
                .with_attr(
                    "has_more_patches",
                    bool_text(data.get(6).copied().unwrap_or_default()),
                )
                .with_content(vec![
                    BinaryNode::new("snapshot").with_content(snapshot_reference_bytes(data)),
                    BinaryNode::new("patches").with_content(vec![
                        BinaryNode::new("patch").with_content(syncd_patch_bytes(
                            Some(version.saturating_add(1)),
                            data,
                        )),
                    ]),
                ]),
        ])])
}

fn missing_version_patch_node(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("type", "result")
        .with_content(vec![BinaryNode::new("sync").with_content(vec![
            BinaryNode::new("collection")
                .with_attr("name", collection(data.get(7).copied().unwrap_or_default()).name())
                .with_content(vec![
                    BinaryNode::new("patch").with_content(syncd_patch_bytes(None, data)),
                ]),
        ])])
}

fn raw_patch_bytes_node(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("type", "result")
        .with_content(vec![BinaryNode::new("sync").with_content(vec![
            BinaryNode::new("collection")
                .with_attr("name", collection(data.get(8).copied().unwrap_or_default()).name())
                .with_attr(
                    "version",
                    u64::from(data.get(9).copied().unwrap_or_default()).to_string(),
                )
                .with_content(vec![
                    BinaryNode::new("patch").with_content(token_bytes(data, 10, 64)),
                ]),
        ])])
}

fn query_result_node(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr(
            "id",
            fuzz_id("app-state", data.get(11).copied().unwrap_or_default()),
        )
        .with_attr("type", "result")
}

fn query_attr_error_node(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("type", "error")
        .with_attr(
            "code",
            error_code(data.get(12).copied().unwrap_or_default()),
        )
        .with_attr(
            "text",
            error_text(data.get(13).copied().unwrap_or_default()),
        )
}

fn query_child_error_node(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("type", "result")
        .with_content(vec![
            BinaryNode::new("error")
                .with_attr(
                    "code",
                    error_code(data.get(14).copied().unwrap_or_default()),
                )
                .with_attr(
                    "text",
                    error_text(data.get(15).copied().unwrap_or_default()),
                ),
        ])
}

fn invalid_query_result_node(data: &[u8]) -> BinaryNode {
    BinaryNode::new(
        if data.get(16).copied().unwrap_or_default().is_multiple_of(2) {
            "message"
        } else {
            "notification"
        },
    )
    .with_attr("type", "result")
}

fn snapshot_reference_bytes(data: &[u8]) -> Bytes {
    Bytes::from(
        ExternalBlobReference {
            media_key: Some(token_bytes(data, 17, 32)),
            direct_path: Some(format!(
                "/app-state/{}",
                fuzz_id("snapshot", data.get(18).copied().unwrap_or_default())
            )),
            handle: Some(fuzz_id("handle", data.get(19).copied().unwrap_or_default())),
            file_size_bytes: Some(u64::from(data.get(20).copied().unwrap_or_default())),
            file_sha256: Some(token_bytes(data, 21, 32)),
            file_enc_sha256: Some(token_bytes(data, 22, 32)),
        }
        .encode_to_vec(),
    )
}

fn syncd_patch_bytes(version: Option<u64>, data: &[u8]) -> Bytes {
    Bytes::from(
        SyncdPatch {
            version: version.map(|version| SyncdVersion {
                version: Some(version),
            }),
            mutations: Vec::new(),
            external_mutations: None,
            snapshot_mac: None,
            patch_mac: None,
            key_id: None,
            exit_code: None,
            device_index: data.get(24).copied().map(u32::from),
            client_debug_data: data
                .get(25)
                .copied()
                .map(|byte| Bytes::copy_from_slice(&[byte])),
        }
        .encode_to_vec(),
    )
}

fn collection(byte: u8) -> AppStateCollection {
    let collections = AppStateCollection::all();
    collections[usize::from(byte) % collections.len()]
}

fn dirty_type(byte: u8) -> &'static str {
    match byte % 6 {
        0 => "account_sync",
        1 => "groups",
        2 => "status",
        3 => "communities",
        4 => "regular_high",
        _ => "critical_block",
    }
}

fn bool_text(byte: u8) -> &'static str {
    if byte.is_multiple_of(2) {
        "true"
    } else {
        "false"
    }
}

fn timestamp(byte: u8) -> String {
    u64::from(byte).saturating_mul(1_000).to_string()
}

fn error_code(byte: u8) -> String {
    match byte % 5 {
        0 => "400",
        1 => "401",
        2 => "409",
        3 => "500",
        _ => "503",
    }
    .to_owned()
}

fn error_text(byte: u8) -> &'static str {
    match byte % 5 {
        0 => "collection conflict",
        1 => "patch rejected",
        2 => "missing key",
        3 => "resync required",
        _ => "server unavailable",
    }
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

fn fuzz_id(prefix: &str, byte: u8) -> String {
    format!("{prefix}-{byte}")
}
