#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use wa_crypto::{NoiseFrameCodec, NoiseTransport};

const MAX_INPUT_LEN: usize = 64 * 1024;
const MAX_STRUCTURED_PAYLOAD_LEN: usize = 512;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let max_frame_len = usize::from(data.first().copied().unwrap_or_default()) * 257;
    drive_raw_frame_chunks(data, max_frame_len);
    drive_structured_frames(data, max_frame_len);
    drive_oversized_frame(data, max_frame_len);
    drive_transport(data);
});

fn drive_raw_frame_chunks(data: &[u8], max_frame_len: usize) {
    let mut codec = NoiseFrameCodec::new(max_frame_len);
    for chunk in split_chunks(data, data.get(1).copied().unwrap_or_default()) {
        let Ok(frames) = codec.push(chunk) else {
            return;
        };
        for frame in frames {
            round_trip_codec_frame(&frame, max_frame_len);
        }
    }
}

fn drive_structured_frames(data: &[u8], max_frame_len: usize) {
    let payload = bounded_payload(data, max_frame_len);
    let codec = NoiseFrameCodec::new(max_frame_len);
    let Ok(encoded) = codec.encode_frame(&payload) else {
        return;
    };

    let second_payload = bounded_payload(&data[data.len().min(3)..], max_frame_len);
    let mut encoded_pair = encoded.to_vec();
    if let Ok(second) = codec.encode_frame(&second_payload) {
        encoded_pair.extend_from_slice(&second);
    }

    let mut decoder = NoiseFrameCodec::new(max_frame_len);
    for chunk in split_chunks(&encoded_pair, data.get(2).copied().unwrap_or_default()) {
        if let Ok(frames) = decoder.push(chunk) {
            for frame in frames {
                round_trip_codec_frame(&frame, max_frame_len);
            }
        }
    }
}

fn drive_oversized_frame(data: &[u8], max_frame_len: usize) {
    if max_frame_len >= 0x00ff_ffff {
        return;
    }
    let oversized = max_frame_len + 1;
    let frame = [
        ((oversized >> 16) & 0xff) as u8,
        ((oversized >> 8) & 0xff) as u8,
        (oversized & 0xff) as u8,
        data.get(3).copied().unwrap_or_default(),
    ];
    let mut codec = NoiseFrameCodec::new(max_frame_len);
    let _ = codec.push(&frame);
}

fn drive_transport(data: &[u8]) {
    let key = fixed_key(data, 4);
    let mut sender = NoiseTransport::new(key, key);
    let mut receiver = NoiseTransport::new(key, key);
    let plaintext = bounded_payload(data, MAX_STRUCTURED_PAYLOAD_LEN);

    if let Ok(ciphertext) = sender.encrypt(&plaintext) {
        let _ = receiver.decrypt(&ciphertext);

        if !ciphertext.is_empty() {
            let mut tampered = ciphertext;
            if let Some(last) = tampered.last_mut() {
                *last ^= 1;
            }
            let _ = receiver.decrypt(&tampered);
        }
    }

    let mut raw_receiver = NoiseTransport::new(key, key);
    let _ = raw_receiver.decrypt(data);
}

fn round_trip_codec_frame(frame: &Bytes, max_frame_len: usize) {
    let codec = NoiseFrameCodec::new(max_frame_len);
    let Ok(encoded) = codec.encode_frame(frame) else {
        return;
    };
    let mut decoder = NoiseFrameCodec::new(max_frame_len);
    let _ = decoder.push(&encoded[..encoded.len().min(2)]);
    let _ = decoder.push(&encoded[encoded.len().min(2)..]);
}

fn split_chunks(data: &[u8], seed: u8) -> Vec<&[u8]> {
    if data.is_empty() {
        return vec![data];
    }
    let mut chunks = Vec::new();
    let mut offset = 0;
    let mut step = usize::from(seed % 31) + 1;
    while offset < data.len() {
        let end = (offset + step).min(data.len());
        chunks.push(&data[offset..end]);
        offset = end;
        step = (step * 5 % 31) + 1;
    }
    chunks
}

fn bounded_payload(data: &[u8], max_frame_len: usize) -> Bytes {
    let cap = max_frame_len.min(MAX_STRUCTURED_PAYLOAD_LEN);
    let len = if cap == 0 {
        0
    } else {
        usize::from(data.get(2).copied().unwrap_or_default()) % (cap + 1)
    };
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        out.push(data.get(index).copied().unwrap_or(index as u8));
    }
    Bytes::from(out)
}

fn fixed_key(data: &[u8], offset: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = data
            .get(offset + index)
            .copied()
            .unwrap_or((offset + index) as u8);
    }
    key
}
