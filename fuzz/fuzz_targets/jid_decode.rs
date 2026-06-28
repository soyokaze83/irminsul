#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::{jid_decode, jid_encode, jid_normalized_user};

const MAX_JID_LEN: usize = 512;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if input.len() > MAX_JID_LEN {
        return;
    }

    let Some(decoded) = jid_decode(input) else {
        return;
    };
    let encoded = jid_encode(&decoded.user, decoded.server, decoded.device, decoded.agent);
    let _ = jid_decode(&encoded);
    let _ = jid_normalized_user(input);
});
