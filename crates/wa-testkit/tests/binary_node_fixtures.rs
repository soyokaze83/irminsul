use std::path::PathBuf;

use wa_binary::{BinaryNodeContent, JidServer, decode_binary_node, encode_binary_node, jid_decode};
use wa_testkit::BinaryNodeFixtureManifest;

#[test]
fn binary_node_fixtures_match_codec() {
    let manifest_path = workspace_fixture_path("binary_nodes/manifest.json");
    let manifest = BinaryNodeFixtureManifest::load(&manifest_path).unwrap();

    assert_eq!(manifest.schema, "wa-binary-node-fixture-v1");
    assert!(
        !manifest.fixtures.is_empty(),
        "fixture manifest should contain at least one fixture"
    );

    let fixture_names = manifest
        .fixtures
        .iter()
        .map(|fixture| fixture.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        fixture_names,
        [
            "iq_ping",
            "message_enc",
            "retry_receipt",
            "presence_device",
            "app_state_sync_query",
            "history_sync_notification",
            "media_message_attrs",
            "group_participant_notification",
            "usync_query",
            "jid_device_domains",
            "stream_error_text",
            "receipt_list_items",
            "call_offer",
        ],
        "fixture manifest should preserve the expanded protocol-shaped seed set",
    );
    assert_eq!(manifest.fixtures.len(), 13);

    let mut saw_bytes = false;
    let mut saw_text = false;
    let mut saw_nested_children = false;
    let mut device_jid_coverage = DeviceJidCoverage::default();

    for fixture in manifest.fixtures {
        let expected_bytes = fixture.encoded_bytes().unwrap();
        let expected_node = fixture.binary_node().unwrap();
        record_fixture_coverage(
            &expected_node,
            &mut saw_bytes,
            &mut saw_text,
            &mut saw_nested_children,
            &mut device_jid_coverage,
        );
        let decoded = decode_binary_node(&expected_bytes)
            .unwrap_or_else(|err| panic!("fixture {} failed to decode: {err}", fixture.name));
        assert_eq!(decoded, expected_node, "fixture {} decode", fixture.name);

        let encoded = encode_binary_node(&expected_node)
            .unwrap_or_else(|err| panic!("fixture {} failed to encode: {err}", fixture.name));
        assert_eq!(
            encoded, expected_bytes,
            "fixture {} encode bytes",
            fixture.name
        );
    }

    assert!(saw_bytes, "fixtures should cover raw byte node content");
    assert!(saw_text, "fixtures should cover text node content");
    assert!(
        saw_nested_children,
        "fixtures should cover nested child-node content"
    );
    assert!(
        device_jid_coverage.saw_whatsapp,
        "fixtures should cover WhatsApp device JID encoding"
    );
    assert!(
        device_jid_coverage.saw_lid,
        "fixtures should cover LID device JID encoding"
    );
    assert!(
        device_jid_coverage.saw_hosted,
        "fixtures should cover hosted device JID encoding"
    );
    assert!(
        device_jid_coverage.saw_hosted_lid,
        "fixtures should cover hosted LID device JID encoding"
    );
}

fn workspace_fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures")
        .join(relative)
}

fn record_fixture_coverage(
    node: &wa_binary::BinaryNode,
    saw_bytes: &mut bool,
    saw_text: &mut bool,
    saw_nested_children: &mut bool,
    device_jid_coverage: &mut DeviceJidCoverage,
) {
    for value in node.attrs.values() {
        device_jid_coverage.record(value);
    }

    match node.content.as_ref() {
        Some(BinaryNodeContent::Bytes(_)) => *saw_bytes = true,
        Some(BinaryNodeContent::Text(_)) => *saw_text = true,
        Some(BinaryNodeContent::Nodes(children)) => {
            if children
                .iter()
                .any(|child| matches!(child.content, Some(BinaryNodeContent::Nodes(_))))
            {
                *saw_nested_children = true;
            }
            for child in children {
                record_fixture_coverage(
                    child,
                    saw_bytes,
                    saw_text,
                    saw_nested_children,
                    device_jid_coverage,
                );
            }
        }
        None => {}
    }
}

#[derive(Default)]
struct DeviceJidCoverage {
    saw_whatsapp: bool,
    saw_lid: bool,
    saw_hosted: bool,
    saw_hosted_lid: bool,
}

impl DeviceJidCoverage {
    fn record(&mut self, value: &str) {
        let Some(jid) = jid_decode(value) else {
            return;
        };
        if jid.device.is_none() {
            return;
        }
        match jid.server {
            JidServer::CUs | JidServer::SWhatsAppNet => self.saw_whatsapp = true,
            JidServer::Lid => self.saw_lid = true,
            JidServer::Hosted => self.saw_hosted = true,
            JidServer::HostedLid => self.saw_hosted_lid = true,
            JidServer::GUs
            | JidServer::Broadcast
            | JidServer::Call
            | JidServer::Newsletter
            | JidServer::Bot
            | JidServer::Other => {}
        }
    }
}
