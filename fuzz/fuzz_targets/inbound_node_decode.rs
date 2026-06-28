#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_core::{
    EventHub, QueryManager, account_update_event_from_notification_node, call_events_from_node,
    decode_inbound_binary_node, dispatch_binary_node, event_batch_from_inbound_ack,
    event_batch_from_inbound_receipt_node, group_update_event_from_notification_node,
    lid_mapping_events_from_newsletter_notification_node,
    newsletter_mex_update_events_from_notification_node,
    newsletter_update_events_from_notification_node, parse_inbound_ack, parse_inbound_notification,
    parse_inbound_receipt,
};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let Ok(inbound) = decode_inbound_binary_node(data) else {
        return;
    };
    let node = inbound.node.clone();

    let queries = QueryManager::new(None);
    let events = EventHub::new(8);
    let _ = dispatch_binary_node(&queries, &events, inbound);

    match node.tag.as_str() {
        "ack" => {
            if let Ok(ack) = parse_inbound_ack(&node) {
                let _ = event_batch_from_inbound_ack(&ack);
            }
        }
        "receipt" => {
            if let Ok(receipt) = parse_inbound_receipt(&node) {
                let _ = event_batch_from_inbound_receipt_node(&node, &receipt);
            }
        }
        "notification" => {
            if let Ok(notification) = parse_inbound_notification(&node) {
                let _ = group_update_event_from_notification_node(&node, &notification);
                let _ = newsletter_update_events_from_notification_node(&node, &notification);
                let _ = newsletter_mex_update_events_from_notification_node(&node, &notification);
                let _ = account_update_event_from_notification_node(&node, 0);
                let _ = lid_mapping_events_from_newsletter_notification_node(&node);
            }
        }
        "call" => {
            let _ = call_events_from_node(&node);
        }
        _ => {}
    }
});
