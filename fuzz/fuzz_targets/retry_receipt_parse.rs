#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::decode_binary_node;
use wa_core::{MessageRetryManager, RetrySessionSnapshot, parse_retry_receipt};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let Ok(node) = decode_binary_node(data) else {
        return;
    };

    let Ok(Some(receipt)) = parse_retry_receipt(&node) else {
        return;
    };

    let _ = receipt.requester_jid();
    let mut manager = MessageRetryManager::default();
    if let Ok(plan) = manager.plan_retry_resend(&receipt, RetrySessionSnapshot::missing(), 0) {
        let _ = manager.prepare_retry_resends(&plan, 0);
    }
});
