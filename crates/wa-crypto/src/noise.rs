use crate::{
    CryptoError, KeyPair, aes_256_gcm_decrypt, aes_256_gcm_encrypt, hkdf_sha256, sha256_hash,
    shared_key,
};
use bytes::{BufMut, Bytes, BytesMut};
use prost::Message;
use wa_proto::proto::cert_chain::noise_certificate::Details as CertificateDetails;
use wa_proto::proto::handshake_message::{ClientFinish, ClientHello, ServerHello};
use wa_proto::proto::{CertChain, HandshakeMessage};
use xeddsa::Verify;
use zeroize::Zeroize;

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const DEFAULT_MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
pub const DEFAULT_NOISE_HEADER: [u8; 4] = [87, 65, 6, 3];
pub const ROOT_CERT_SERIAL: u32 = 0;
pub const ROOT_CERT_PUBLIC_KEY: [u8; 32] = [
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
    0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
];
const NOISE_MODE: &[u8] = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0";

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NoiseFrameError {
    #[error("frame is too large: {actual} > {max}")]
    FrameTooLarge { actual: usize, max: usize },
    #[error("encrypted frame is too short")]
    FrameTooShort,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, thiserror::Error)]
pub enum NoiseHandshakeError {
    #[error("missing handshake field: {0}")]
    MissingField(&'static str),
    #[error("invalid key length: expected 32 bytes for {0}")]
    InvalidKeyLength(&'static str),
    #[error("invalid all-zero shared secret")]
    InvalidSharedSecret,
    #[error("invalid certificate chain: {0}")]
    InvalidCertificate(&'static str),
    #[error("certificate verification failed: {0}")]
    CertificateRejected(&'static str),
    #[error("unexpected certificate issuer serial: {0}")]
    UnexpectedIssuerSerial(u32),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("frame error: {0}")]
    Frame(#[from] NoiseFrameError),
    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),
}

pub trait NoiseCertificateVerifier {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

impl<F> NoiseCertificateVerifier for F
where
    F: Fn(&[u8], &[u8], &[u8]) -> bool,
{
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        self(public_key, message, signature)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct XEdDsaNoiseCertificateVerifier;

impl NoiseCertificateVerifier for XEdDsaNoiseCertificateVerifier {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(public_key) = <[u8; 32]>::try_from(public_key) else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        xeddsa::xed25519::PublicKey(public_key)
            .verify(message, &signature)
            .is_ok()
    }
}

pub struct NoiseHandshake {
    local_ephemeral: KeyPair,
    hash: [u8; 32],
    salt: [u8; 32],
    enc_key: [u8; 32],
    dec_key: [u8; 32],
    counter: u32,
    intro_header: Vec<u8>,
    sent_intro: bool,
    max_frame_len: usize,
    frame_codec: NoiseFrameCodec,
    transport: Option<NoiseTransport>,
}

impl NoiseHandshake {
    #[must_use]
    pub fn new(local_ephemeral: KeyPair) -> Self {
        Self::with_header(
            local_ephemeral,
            DEFAULT_NOISE_HEADER,
            None,
            DEFAULT_MAX_FRAME_LEN,
        )
    }

    #[must_use]
    pub fn with_header(
        local_ephemeral: KeyPair,
        noise_header: [u8; 4],
        routing_info: Option<&[u8]>,
        max_frame_len: usize,
    ) -> Self {
        let mut hash = mode_hash();
        let salt = hash;
        let enc_key = hash;
        let dec_key = hash;
        let intro_header = intro_header(noise_header, routing_info);

        authenticate_hash(&mut hash, &noise_header);
        authenticate_hash(&mut hash, &local_ephemeral.public);

        Self {
            local_ephemeral,
            hash,
            salt,
            enc_key,
            dec_key,
            counter: 0,
            intro_header,
            sent_intro: false,
            max_frame_len,
            frame_codec: NoiseFrameCodec::new(max_frame_len),
            transport: None,
        }
    }

    #[must_use]
    pub fn client_hello(&self) -> HandshakeMessage {
        HandshakeMessage {
            client_hello: Some(ClientHello {
                ephemeral: Some(Bytes::copy_from_slice(&self.local_ephemeral.public)),
                r#static: None,
                payload: None,
                use_extended: None,
                extended_ciphertext: None,
            }),
            server_hello: None,
            client_finish: None,
        }
    }

    #[must_use]
    pub fn client_hello_bytes(&self) -> Bytes {
        self.client_hello().encode_to_vec().into()
    }

    pub fn build_client_finish<V>(
        &mut self,
        server_hello: &ServerHello,
        static_key_pair: &KeyPair,
        client_payload: &[u8],
        verifier: &V,
    ) -> Result<HandshakeMessage, NoiseHandshakeError>
    where
        V: NoiseCertificateVerifier,
    {
        let encrypted_static =
            self.process_server_hello(server_hello, static_key_pair, verifier)?;
        let encrypted_payload = self.encrypt_handshake_payload(client_payload)?;

        Ok(HandshakeMessage {
            client_hello: None,
            server_hello: None,
            client_finish: Some(ClientFinish {
                r#static: Some(encrypted_static),
                payload: Some(encrypted_payload),
                extended_ciphertext: None,
            }),
        })
    }

    pub fn process_server_hello<V>(
        &mut self,
        server_hello: &ServerHello,
        static_key_pair: &KeyPair,
        verifier: &V,
    ) -> Result<Bytes, NoiseHandshakeError>
    where
        V: NoiseCertificateVerifier,
    {
        let server_ephemeral = key_array(
            server_hello
                .ephemeral
                .as_deref()
                .ok_or(NoiseHandshakeError::MissingField("server hello ephemeral"))?,
            "server hello ephemeral",
        )?;
        self.authenticate(&server_ephemeral);

        let local_ephemeral_private = key_array(
            self.local_ephemeral.private.expose(),
            "local ephemeral private key",
        )?;
        self.mix_shared_secret(&local_ephemeral_private, &server_ephemeral)?;

        let encrypted_static = server_hello
            .r#static
            .as_deref()
            .ok_or(NoiseHandshakeError::MissingField("server static key"))?;
        let server_static = self.decrypt_handshake_payload(encrypted_static)?;
        let server_static = key_array(&server_static, "server static key")?;
        self.mix_shared_secret(&local_ephemeral_private, &server_static)?;

        let encrypted_cert =
            server_hello
                .payload
                .as_deref()
                .ok_or(NoiseHandshakeError::MissingField(
                    "server certificate payload",
                ))?;
        let cert_plaintext = self.decrypt_handshake_payload(encrypted_cert)?;
        validate_noise_certificate_chain(&cert_plaintext, verifier)?;

        let encrypted_client_static = self.encrypt_handshake_payload(&static_key_pair.public)?;
        let local_static_private = key_array(static_key_pair.private.expose(), "local static key")?;
        self.mix_shared_secret(&local_static_private, &server_ephemeral)?;

        Ok(encrypted_client_static)
    }

    pub fn encrypt_handshake_payload(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Bytes, NoiseHandshakeError> {
        Ok(self.encrypt_pre_transport(plaintext)?.into())
    }

    pub fn finish_transport(&mut self) -> Result<(), NoiseHandshakeError> {
        let mut key = hkdf_sha256(&[], 64, &self.salt, &[])?;
        let mut enc_key = [0u8; 32];
        let mut dec_key = [0u8; 32];
        enc_key.copy_from_slice(&key[..32]);
        dec_key.copy_from_slice(&key[32..]);
        key.zeroize();

        self.enc_key.zeroize();
        self.dec_key.zeroize();
        self.transport = Some(NoiseTransport::new(enc_key, dec_key));
        Ok(())
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> Option<&mut NoiseTransport> {
        self.transport.as_mut()
    }

    pub fn encode_frame(&mut self, plaintext: &[u8]) -> Result<Bytes, NoiseHandshakeError> {
        if plaintext.len() > self.max_frame_len {
            return Err(NoiseFrameError::FrameTooLarge {
                actual: plaintext.len(),
                max: self.max_frame_len,
            }
            .into());
        }

        let payload = if let Some(transport) = self.transport.as_mut() {
            Bytes::from(transport.encrypt(plaintext)?)
        } else {
            Bytes::copy_from_slice(plaintext)
        };

        let intro_len = if self.sent_intro {
            0
        } else {
            self.intro_header.len()
        };
        let mut out = BytesMut::with_capacity(intro_len + 3 + payload.len());
        if !self.sent_intro {
            out.put_slice(&self.intro_header);
            self.sent_intro = true;
        }
        put_frame_len(payload.len(), &mut out);
        out.put_slice(&payload);
        Ok(out.freeze())
    }

    pub fn push_frame_bytes(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, NoiseHandshakeError> {
        let frames = self.frame_codec.push(chunk)?;
        let mut out = Vec::with_capacity(frames.len());
        for frame in frames {
            if let Some(transport) = self.transport.as_mut() {
                out.push(Bytes::from(transport.decrypt(&frame)?));
            } else {
                out.push(frame);
            }
        }
        Ok(out)
    }

    fn authenticate(&mut self, data: &[u8]) {
        authenticate_hash(&mut self.hash, data);
    }

    fn mix_shared_secret(
        &mut self,
        private_key: &[u8; 32],
        public_key: &[u8; 32],
    ) -> Result<(), NoiseHandshakeError> {
        let mut secret = shared_key(private_key, public_key);
        if secret.iter().all(|byte| *byte == 0) {
            secret.zeroize();
            return Err(NoiseHandshakeError::InvalidSharedSecret);
        }
        self.mix_into_key(&secret)?;
        secret.zeroize();
        Ok(())
    }

    fn mix_into_key(&mut self, input_key_material: &[u8]) -> Result<(), NoiseHandshakeError> {
        let mut key = hkdf_sha256(input_key_material, 64, &self.salt, &[])?;
        self.salt.zeroize();
        self.enc_key.zeroize();
        self.dec_key.zeroize();
        self.salt.copy_from_slice(&key[..32]);
        self.enc_key.copy_from_slice(&key[32..]);
        self.dec_key.copy_from_slice(&key[32..]);
        self.counter = 0;
        key.zeroize();
        Ok(())
    }

    fn encrypt_pre_transport(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseHandshakeError> {
        let iv = counter_iv(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let ciphertext = aes_256_gcm_encrypt(plaintext, &self.enc_key, &iv, &self.hash)?;
        self.authenticate(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_handshake_payload(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseHandshakeError> {
        self.decrypt_pre_transport(ciphertext)
    }

    fn decrypt_pre_transport(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseHandshakeError> {
        let iv = counter_iv(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let plaintext = aes_256_gcm_decrypt(ciphertext, &self.dec_key, &iv, &self.hash)?;
        self.authenticate(ciphertext);
        Ok(plaintext)
    }
}

impl Drop for NoiseHandshake {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.salt.zeroize();
        self.enc_key.zeroize();
        self.dec_key.zeroize();
    }
}

pub struct NoiseTransport {
    enc_key: [u8; 32],
    dec_key: [u8; 32],
    read_counter: u32,
    write_counter: u32,
}

impl NoiseTransport {
    #[must_use]
    pub fn new(enc_key: [u8; 32], dec_key: [u8; 32]) -> Self {
        Self {
            enc_key,
            dec_key,
            read_counter: 0,
            write_counter: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseFrameError> {
        let iv = counter_iv(self.write_counter);
        self.write_counter = self.write_counter.wrapping_add(1);
        Ok(aes_256_gcm_encrypt(plaintext, &self.enc_key, &iv, &[])?)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseFrameError> {
        if ciphertext.len() < TAG_LEN {
            return Err(NoiseFrameError::FrameTooShort);
        }
        let iv = counter_iv(self.read_counter);
        self.read_counter = self.read_counter.wrapping_add(1);
        Ok(aes_256_gcm_decrypt(ciphertext, &self.dec_key, &iv, &[])?)
    }
}

impl Drop for NoiseTransport {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.dec_key.zeroize();
    }
}

pub struct NoiseFrameCodec {
    max_frame_len: usize,
    buffer: BytesMut,
}

impl NoiseFrameCodec {
    #[must_use]
    pub fn new(max_frame_len: usize) -> Self {
        Self {
            max_frame_len,
            buffer: BytesMut::new(),
        }
    }

    pub fn encode_frame(&self, payload: &[u8]) -> Result<Bytes, NoiseFrameError> {
        if payload.len() > self.max_frame_len {
            return Err(NoiseFrameError::FrameTooLarge {
                actual: payload.len(),
                max: self.max_frame_len,
            });
        }

        let mut out = BytesMut::with_capacity(3 + payload.len());
        out.put_u8(((payload.len() >> 16) & 0xff) as u8);
        out.put_u8(((payload.len() >> 8) & 0xff) as u8);
        out.put_u8((payload.len() & 0xff) as u8);
        out.put_slice(payload);
        Ok(out.freeze())
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, NoiseFrameError> {
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();

        loop {
            if self.buffer.len() < 3 {
                break;
            }

            let len = ((usize::from(self.buffer[0])) << 16)
                | ((usize::from(self.buffer[1])) << 8)
                | usize::from(self.buffer[2]);

            if len > self.max_frame_len {
                return Err(NoiseFrameError::FrameTooLarge {
                    actual: len,
                    max: self.max_frame_len,
                });
            }

            if self.buffer.len() < len + 3 {
                break;
            }

            self.buffer.advance(3);
            frames.push(self.buffer.split_to(len).freeze());
        }

        Ok(frames)
    }
}

fn counter_iv(counter: u32) -> [u8; IV_LEN] {
    let mut iv = [0u8; IV_LEN];
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

pub fn validate_noise_certificate_chain<V>(
    certificate_payload: &[u8],
    verifier: &V,
) -> Result<(), NoiseHandshakeError>
where
    V: NoiseCertificateVerifier,
{
    let cert_chain = CertChain::decode(certificate_payload)?;
    let leaf = cert_chain
        .leaf
        .ok_or(NoiseHandshakeError::InvalidCertificate("missing leaf"))?;
    let intermediate = cert_chain
        .intermediate
        .ok_or(NoiseHandshakeError::InvalidCertificate(
            "missing intermediate",
        ))?;

    let leaf_details = leaf.details.ok_or(NoiseHandshakeError::InvalidCertificate(
        "missing leaf details",
    ))?;
    let leaf_signature = leaf
        .signature
        .ok_or(NoiseHandshakeError::InvalidCertificate(
            "missing leaf signature",
        ))?;
    let intermediate_details =
        intermediate
            .details
            .ok_or(NoiseHandshakeError::InvalidCertificate(
                "missing intermediate details",
            ))?;
    let intermediate_signature =
        intermediate
            .signature
            .ok_or(NoiseHandshakeError::InvalidCertificate(
                "missing intermediate signature",
            ))?;

    let details = CertificateDetails::decode(intermediate_details.clone())?;
    let issuer_serial = details.issuer_serial.unwrap_or_default();
    if issuer_serial != ROOT_CERT_SERIAL {
        return Err(NoiseHandshakeError::UnexpectedIssuerSerial(issuer_serial));
    }
    let intermediate_key = details.key.ok_or(NoiseHandshakeError::InvalidCertificate(
        "missing intermediate key",
    ))?;

    if !verifier.verify_signature(&intermediate_key, &leaf_details, &leaf_signature) {
        return Err(NoiseHandshakeError::CertificateRejected("leaf"));
    }
    if !verifier.verify_signature(
        &ROOT_CERT_PUBLIC_KEY,
        &intermediate_details,
        &intermediate_signature,
    ) {
        return Err(NoiseHandshakeError::CertificateRejected("intermediate"));
    }

    Ok(())
}

fn mode_hash() -> [u8; 32] {
    if NOISE_MODE.len() == 32 {
        NOISE_MODE.try_into().expect("mode is 32 bytes")
    } else {
        sha256_hash(NOISE_MODE)
    }
}

fn authenticate_hash(hash: &mut [u8; 32], data: &[u8]) {
    let mut combined = Vec::with_capacity(hash.len() + data.len());
    combined.extend_from_slice(hash);
    combined.extend_from_slice(data);
    *hash = sha256_hash(&combined);
}

fn intro_header(noise_header: [u8; 4], routing_info: Option<&[u8]>) -> Vec<u8> {
    if let Some(routing_info) = routing_info {
        let mut out = Vec::with_capacity(7 + routing_info.len() + noise_header.len());
        out.extend_from_slice(b"ED");
        out.push(0);
        out.push(1);
        out.push(((routing_info.len() >> 16) & 0xff) as u8);
        out.push(((routing_info.len() >> 8) & 0xff) as u8);
        out.push((routing_info.len() & 0xff) as u8);
        out.extend_from_slice(routing_info);
        out.extend_from_slice(&noise_header);
        out
    } else {
        noise_header.to_vec()
    }
}

fn put_frame_len(len: usize, out: &mut BytesMut) {
    out.put_u8(((len >> 16) & 0xff) as u8);
    out.put_u8(((len >> 8) & 0xff) as u8);
    out.put_u8((len & 0xff) as u8);
}

fn key_array(input: &[u8], label: &'static str) -> Result<[u8; 32], NoiseHandshakeError> {
    input
        .try_into()
        .map_err(|_| NoiseHandshakeError::InvalidKeyLength(label))
}

trait Advance {
    fn advance(&mut self, count: usize);
}

impl Advance for BytesMut {
    fn advance(&mut self, count: usize) {
        let _ = self.split_to(count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wa_proto::proto::cert_chain::NoiseCertificate;
    use xeddsa::Sign;

    #[test]
    fn transport_round_trips() {
        let key = [9u8; 32];
        let mut sender = NoiseTransport::new(key, key);
        let mut receiver = NoiseTransport::new(key, key);
        let ciphertext = sender.encrypt(b"frame").unwrap();
        assert_ne!(ciphertext, b"frame");
        assert_eq!(receiver.decrypt(&ciphertext).unwrap(), b"frame");
    }

    #[test]
    fn codec_handles_fragmented_frames() {
        let mut codec = NoiseFrameCodec::new(1024);
        let encoded = codec.encode_frame(b"hello").unwrap();
        assert!(codec.push(&encoded[..2]).unwrap().is_empty());
        let frames = codec.push(&encoded[2..]).unwrap();
        assert_eq!(frames, vec![Bytes::from_static(b"hello")]);
    }

    #[test]
    fn codec_rejects_oversized_frames() {
        let codec = NoiseFrameCodec::new(2);
        assert!(matches!(
            codec.encode_frame(b"abc"),
            Err(NoiseFrameError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn client_hello_contains_ephemeral_public_key() {
        let local = generate_test_key(1);
        let handshake = NoiseHandshake::new(local.clone());
        let hello = handshake.client_hello();

        assert_eq!(
            hello
                .client_hello
                .and_then(|client_hello| client_hello.ephemeral)
                .unwrap(),
            Bytes::copy_from_slice(&local.public)
        );
    }

    #[test]
    fn frame_encoder_prepends_intro_once() {
        let local = generate_test_key(2);
        let mut handshake = NoiseHandshake::new(local);

        let first = handshake.encode_frame(b"hello").unwrap();
        assert!(first.starts_with(&DEFAULT_NOISE_HEADER));
        assert_eq!(
            &first[DEFAULT_NOISE_HEADER.len()..],
            &[0, 0, 5, b'h', b'e', b'l', b'l', b'o']
        );

        let second = handshake.encode_frame(b"again").unwrap();
        assert_eq!(&second[..3], &[0, 0, 5]);
        assert!(!second.starts_with(&DEFAULT_NOISE_HEADER));
    }

    #[test]
    fn frame_encoder_includes_routing_intro_when_present() {
        let local = generate_test_key(3);
        let mut handshake =
            NoiseHandshake::with_header(local, DEFAULT_NOISE_HEADER, Some(b"route"), 1024);

        let first = handshake.encode_frame(b"x").unwrap();
        assert_eq!(&first[..2], b"ED");
        assert_eq!(&first[2..7], &[0, 1, 0, 0, 5]);
        assert_eq!(&first[7..12], b"route");
        assert_eq!(&first[12..16], &DEFAULT_NOISE_HEADER);
    }

    #[test]
    fn validates_certificate_chain_through_verifier() {
        let signer = [8u8; 32];
        let cert_payload = test_cert_chain(signer);
        let verifier = TrackingVerifier::new(true, signer);

        validate_noise_certificate_chain(&cert_payload, &verifier).unwrap();

        assert_eq!(verifier.calls.load(Ordering::Acquire), 2);
    }

    #[test]
    fn rejects_certificate_when_verifier_rejects() {
        let signer = [8u8; 32];
        let cert_payload = test_cert_chain(signer);
        let verifier = TrackingVerifier::new(false, signer);

        assert!(matches!(
            validate_noise_certificate_chain(&cert_payload, &verifier),
            Err(NoiseHandshakeError::CertificateRejected("leaf"))
        ));
    }

    #[test]
    fn concrete_certificate_verifier_rejects_invalid_inputs() {
        let verifier = XEdDsaNoiseCertificateVerifier;

        assert!(!verifier.verify_signature(&[1u8; 31], b"message", &[2u8; 64]));
        assert!(!verifier.verify_signature(&[1u8; 32], b"message", &[2u8; 63]));
        assert!(!verifier.verify_signature(&[1u8; 32], b"message", &[2u8; 64]));
    }

    #[test]
    fn concrete_certificate_verifier_accepts_valid_xeddsa_signature() {
        let private = [
            0xf8, 0xce, 0xd4, 0x2b, 0x07, 0xe7, 0x81, 0x0a, 0x04, 0xcc, 0x85, 0x4b, 0x03, 0x57,
            0x6d, 0xf1, 0xe4, 0xc0, 0xfe, 0xb1, 0x6d, 0x68, 0x5e, 0x0a, 0xc0, 0x42, 0x5e, 0x1c,
            0x3c, 0x5e, 0xb2, 0x47,
        ];
        let message = b"certificate-details";
        let private_key = xeddsa::xed25519::PrivateKey::from(&private);
        let public_key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
        let signature: [u8; 64] = private_key.sign(message, rand_xeddsa::rng());

        assert!(XEdDsaNoiseCertificateVerifier.verify_signature(
            public_key.as_bytes(),
            message,
            &signature
        ));
    }

    #[test]
    fn processes_server_hello_and_builds_client_finish() {
        let client_ephemeral = generate_test_key(4);
        let client_static = generate_test_key(5);
        let server_ephemeral = generate_test_key(6);
        let server_static = generate_test_key(7);
        let signer = [9u8; 32];
        let mut client = NoiseHandshake::new(client_ephemeral.clone());
        let (server_hello, mut server) =
            server_hello_fixture(&client, &server_ephemeral, &server_static, signer);
        let verifier = TrackingVerifier::new(true, signer);

        let finish = client
            .build_client_finish(&server_hello, &client_static, b"payload", &verifier)
            .unwrap();
        let finish = finish.client_finish.unwrap();
        assert!(client.transport_mut().is_none());

        let encrypted_static = finish.r#static.unwrap();
        let decrypted_static = server.decrypt_pre_transport(&encrypted_static).unwrap();
        assert_eq!(decrypted_static, client_static.public);

        let server_ephemeral_private: [u8; 32] =
            server_ephemeral.private.expose().try_into().unwrap();
        server
            .mix_shared_secret(&server_ephemeral_private, &client_static.public)
            .unwrap();

        let encrypted_payload = finish.payload.unwrap();
        let decrypted_payload = server.decrypt_pre_transport(&encrypted_payload).unwrap();
        assert_eq!(decrypted_payload, b"payload");
        assert_eq!(verifier.calls.load(Ordering::Acquire), 2);

        client.finish_transport().unwrap();
        assert!(client.transport_mut().is_some());
    }

    #[test]
    fn finish_transport_uses_hkdf_halves_for_transport_keys() {
        let local = generate_test_key(10);
        let mut handshake = NoiseHandshake::new(local);
        handshake.salt = [3u8; 32];
        let expected = hkdf_sha256(&[], 64, &[3u8; 32], &[]).unwrap();

        handshake.finish_transport().unwrap();
        let transport = handshake.transport_mut().unwrap();

        assert_eq!(transport.enc_key, expected[..32]);
        assert_eq!(transport.dec_key, expected[32..]);
    }

    fn server_hello_fixture(
        client: &NoiseHandshake,
        server_ephemeral: &KeyPair,
        server_static: &KeyPair,
        signer: [u8; 32],
    ) -> (ServerHello, NoiseHandshake) {
        let mut server = NoiseHandshake {
            local_ephemeral: server_ephemeral.clone(),
            hash: client.hash,
            salt: client.salt,
            enc_key: client.enc_key,
            dec_key: client.dec_key,
            counter: client.counter,
            intro_header: Vec::new(),
            sent_intro: false,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            frame_codec: NoiseFrameCodec::new(DEFAULT_MAX_FRAME_LEN),
            transport: None,
        };

        server.authenticate(&server_ephemeral.public);
        let server_ephemeral_private: [u8; 32] =
            server_ephemeral.private.expose().try_into().unwrap();
        server
            .mix_shared_secret(&server_ephemeral_private, &client.local_ephemeral.public)
            .unwrap();
        let encrypted_static = server.encrypt_pre_transport(&server_static.public).unwrap();

        let server_static_private: [u8; 32] = server_static.private.expose().try_into().unwrap();
        server
            .mix_shared_secret(&server_static_private, &client.local_ephemeral.public)
            .unwrap();
        let encrypted_payload = server
            .encrypt_pre_transport(&test_cert_chain(signer))
            .unwrap();

        (
            ServerHello {
                ephemeral: Some(Bytes::copy_from_slice(&server_ephemeral.public)),
                r#static: Some(Bytes::from(encrypted_static)),
                payload: Some(Bytes::from(encrypted_payload)),
                extended_static: None,
            },
            server,
        )
    }

    fn test_cert_chain(signer: [u8; 32]) -> Vec<u8> {
        let leaf_details = CertificateDetails {
            serial: Some(2),
            issuer_serial: Some(1),
            key: Some(Bytes::from_static(b"leaf-key")),
            not_before: Some(1),
            not_after: Some(2),
        }
        .encode_to_vec();
        let intermediate_details = CertificateDetails {
            serial: Some(1),
            issuer_serial: Some(ROOT_CERT_SERIAL),
            key: Some(Bytes::copy_from_slice(&signer)),
            not_before: Some(1),
            not_after: Some(2),
        }
        .encode_to_vec();

        CertChain {
            leaf: Some(NoiseCertificate {
                details: Some(Bytes::from(leaf_details)),
                signature: Some(Bytes::from_static(b"leaf-signature")),
            }),
            intermediate: Some(NoiseCertificate {
                details: Some(Bytes::from(intermediate_details)),
                signature: Some(Bytes::from_static(b"intermediate-signature")),
            }),
        }
        .encode_to_vec()
    }

    fn generate_test_key(seed: u8) -> KeyPair {
        let mut private = [0u8; 32];
        private[0] = seed;
        let secret = x25519_dalek::StaticSecret::from(private);
        let public = x25519_dalek::PublicKey::from(&secret);
        KeyPair {
            public: public.to_bytes(),
            private: private.into(),
        }
    }

    struct TrackingVerifier {
        allow: bool,
        signer: [u8; 32],
        calls: Arc<AtomicUsize>,
    }

    impl TrackingVerifier {
        fn new(allow: bool, signer: [u8; 32]) -> Self {
            Self {
                allow,
                signer,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl NoiseCertificateVerifier for TrackingVerifier {
        fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.allow
                && !message.is_empty()
                && !signature.is_empty()
                && (public_key == self.signer || public_key == ROOT_CERT_PUBLIC_KEY)
        }
    }
}
