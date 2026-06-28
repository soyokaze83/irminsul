#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::{decode_binary_node, encode_binary_node};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let Ok(node) = decode_binary_node(data) else {
        return;
    };
    if let Ok(encoded) = encode_binary_node(&node) {
        let _ = decode_binary_node(&encoded);
    }
});
