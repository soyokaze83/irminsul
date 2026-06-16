use crate::{
    AuthCredentials, ClientConfig, Connection, ConnectionState, CoreError, CoreResult, Event,
    EventHub, FrameSink, FrameStream, QueryManager, RegistrationPayloadKeys, build_login_payload,
    build_registration_payload, shared_noise_handshake,
};
use bytes::Bytes;
use prost::Message;
use wa_crypto::{
    DEFAULT_MAX_FRAME_LEN, DEFAULT_NOISE_HEADER, KeyPair, NoiseCertificateVerifier, NoiseHandshake,
    generate_key_pair,
};
use wa_proto::proto::HandshakeMessage;
use wa_proto::proto::handshake_message::ServerHello;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationPayload {
    Login { user_jid: String },
    Registration { keys: RegistrationPayloadKeys },
}

#[derive(Clone, Debug)]
pub struct ConnectionValidation {
    pub config: ClientConfig,
    pub local_ephemeral: KeyPair,
    pub static_key_pair: KeyPair,
    pub payload: ValidationPayload,
    pub routing_info: Option<Bytes>,
    pub max_frame_len: usize,
}

impl ConnectionValidation {
    #[must_use]
    pub fn new(
        config: ClientConfig,
        local_ephemeral: KeyPair,
        static_key_pair: KeyPair,
        payload: ValidationPayload,
    ) -> Self {
        Self {
            config,
            local_ephemeral,
            static_key_pair,
            payload,
            routing_info: None,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
        }
    }

    #[must_use]
    pub fn with_routing_info(mut self, routing_info: Bytes) -> Self {
        self.routing_info = Some(routing_info);
        self
    }

    #[must_use]
    pub fn with_max_frame_len(mut self, max_frame_len: usize) -> Self {
        self.max_frame_len = max_frame_len;
        self
    }

    pub fn from_credentials(
        config: ClientConfig,
        credentials: &AuthCredentials,
    ) -> CoreResult<Self> {
        Self::from_credentials_with_ephemeral(config, credentials, generate_key_pair())
    }

    pub fn from_credentials_with_ephemeral(
        config: ClientConfig,
        credentials: &AuthCredentials,
        local_ephemeral: KeyPair,
    ) -> CoreResult<Self> {
        let payload = if credentials.registered {
            ValidationPayload::Login {
                user_jid: credentials.account_jid.clone().ok_or_else(|| {
                    CoreError::Payload("registered credentials are missing account JID".to_owned())
                })?,
            }
        } else {
            ValidationPayload::Registration {
                keys: credentials.registration_payload_keys(),
            }
        };

        let mut request = Self::new(
            config,
            local_ephemeral,
            credentials.noise_key.clone(),
            payload,
        );
        request.routing_info.clone_from(&credentials.routing_info);
        Ok(request)
    }
}

#[derive(Clone)]
pub struct ValidatedConnection {
    connection: Connection,
    noise: crate::SharedNoiseHandshake,
}

impl ValidatedConnection {
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    #[must_use]
    pub fn noise(&self) -> &crate::SharedNoiseHandshake {
        &self.noise
    }

    #[must_use]
    pub fn into_connection(self) -> Connection {
        self.connection
    }
}

pub async fn validate_connection<S, R, V>(
    sink: S,
    stream: R,
    request: ConnectionValidation,
    events: EventHub,
    queries: QueryManager,
    verifier: &V,
    outbound_capacity: usize,
) -> CoreResult<ValidatedConnection>
where
    S: FrameSink,
    R: FrameStream,
    V: NoiseCertificateVerifier,
{
    events.emit(Event::ConnectionUpdate(ConnectionState::Connecting));

    let result = validate_connection_inner(
        sink,
        stream,
        request,
        events.clone(),
        queries,
        verifier,
        outbound_capacity,
    )
    .await;

    if result.is_err() {
        events.emit(Event::ConnectionUpdate(ConnectionState::Closed));
    }

    result
}

async fn validate_connection_inner<S, R, V>(
    mut sink: S,
    mut stream: R,
    request: ConnectionValidation,
    events: EventHub,
    queries: QueryManager,
    verifier: &V,
    outbound_capacity: usize,
) -> CoreResult<ValidatedConnection>
where
    S: FrameSink,
    R: FrameStream,
    V: NoiseCertificateVerifier,
{
    if outbound_capacity == 0 {
        return Err(CoreError::Protocol(
            "outbound capacity must be greater than zero".to_owned(),
        ));
    }

    let mut handshake = NoiseHandshake::with_header(
        request.local_ephemeral,
        DEFAULT_NOISE_HEADER,
        request.routing_info.as_deref(),
        request.max_frame_len,
    );

    let client_hello = handshake.client_hello_bytes();
    let client_hello_frame = handshake.encode_frame(&client_hello)?;
    sink.send(client_hello_frame).await?;

    let server_hello = read_server_hello(&mut stream, &mut handshake).await?;
    let client_payload = match request.payload {
        ValidationPayload::Login { user_jid } => build_login_payload(&user_jid, &request.config)?,
        ValidationPayload::Registration { keys } => {
            build_registration_payload(keys, &request.config)?
        }
    };
    let client_payload = client_payload.encode_to_vec();
    let client_finish = handshake.build_client_finish(
        &server_hello,
        &request.static_key_pair,
        &client_payload,
        verifier,
    )?;
    let client_finish_frame = handshake.encode_frame(&client_finish.encode_to_vec())?;
    sink.send(client_finish_frame).await?;

    handshake.finish_transport()?;
    let noise = shared_noise_handshake(handshake);
    let connection = Connection::spawn(
        crate::NoiseFrameSink::new(sink, noise.clone()),
        crate::NoiseFrameStream::new(stream, noise.clone()),
        queries,
        events,
        outbound_capacity,
    );

    Ok(ValidatedConnection { connection, noise })
}

async fn read_server_hello<R>(
    stream: &mut R,
    handshake: &mut NoiseHandshake,
) -> CoreResult<ServerHello>
where
    R: FrameStream,
{
    loop {
        let chunk = stream.recv().await?.ok_or(CoreError::ConnectionClosed)?;
        let mut frames = handshake.push_frame_bytes(&chunk.payload)?;
        if frames.is_empty() {
            continue;
        }
        if frames.len() > 1 {
            return Err(CoreError::Protocol(
                "server hello contained extra frames".to_owned(),
            ));
        }

        let handshake_message = HandshakeMessage::decode(frames.remove(0))?;
        return handshake_message
            .server_hello
            .ok_or_else(|| CoreError::Protocol("missing server hello".to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InboundFrame;
    use crate::create_initial_credentials;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;
    use wa_crypto::{
        NoiseFrameCodec, ROOT_CERT_PUBLIC_KEY, ROOT_CERT_SERIAL, aes_256_gcm_decrypt,
        aes_256_gcm_encrypt, generate_key_pair, hkdf_sha256, sha256_hash, shared_key,
    };
    use wa_proto::proto::cert_chain::NoiseCertificate;
    use wa_proto::proto::cert_chain::noise_certificate::Details as CertificateDetails;
    use wa_proto::proto::handshake_message::{ClientFinish, ClientHello};
    use wa_proto::proto::{CertChain, ClientPayload};
    use zeroize::Zeroize;

    const TEST_NOISE_MODE: &[u8] = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0";

    #[tokio::test]
    async fn validates_login_connection_and_payload() {
        let client_ephemeral = generate_key_pair();
        let client_static = generate_key_pair();
        let request = ConnectionValidation::new(
            ClientConfig::default(),
            client_ephemeral,
            client_static,
            ValidationPayload::Login {
                user_jid: "12345:7@s.whatsapp.net".to_owned(),
            },
        );

        let (sink, stream, mut client_rx, server_tx) = mock_transport();
        let events = EventHub::new(16);
        let mut events_rx = events.subscribe();
        let server_task = tokio::spawn(async move {
            let payload = run_mock_server(&mut client_rx, server_tx).await;
            ClientPayload::decode(payload).unwrap()
        });

        let validated = validate_connection(
            sink,
            stream,
            request,
            events,
            QueryManager::new(None),
            &AllowVerifier,
            4,
        )
        .await
        .unwrap();

        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::ConnectionUpdate(ConnectionState::Connecting)
        ));
        assert!(event_stream_reaches_open(&mut events_rx).await);

        let payload = server_task.await.unwrap();
        assert_eq!(payload.passive, Some(true));
        assert_eq!(payload.pull, Some(true));
        assert_eq!(payload.username, Some(12345));
        assert_eq!(payload.device, Some(7));
        assert_eq!(payload.lid_db_migrated, Some(false));

        validated.connection().close().await.unwrap();
    }

    #[tokio::test]
    async fn validates_registration_connection_and_payload() {
        let request = ConnectionValidation::new(
            ClientConfig::default(),
            generate_key_pair(),
            generate_key_pair(),
            ValidationPayload::Registration {
                keys: RegistrationPayloadKeys {
                    registration_id: 0x0102_0304,
                    signed_identity_public: Bytes::from_static(b"identity"),
                    signed_pre_key_id: 0x0001_0203,
                    signed_pre_key_public: Bytes::from_static(b"pre-key"),
                    signed_pre_key_signature: Bytes::from_static(b"signature"),
                },
            },
        );

        let (sink, stream, mut client_rx, server_tx) = mock_transport();
        let events = EventHub::new(16);
        let mut events_rx = events.subscribe();
        let server_task = tokio::spawn(async move {
            let payload = run_mock_server(&mut client_rx, server_tx).await;
            ClientPayload::decode(payload).unwrap()
        });

        let validated = validate_connection(
            sink,
            stream,
            request,
            events,
            QueryManager::new(None),
            &AllowVerifier,
            4,
        )
        .await
        .unwrap();

        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::ConnectionUpdate(ConnectionState::Connecting)
        ));
        assert!(event_stream_reaches_open(&mut events_rx).await);

        let payload = server_task.await.unwrap();
        assert_eq!(payload.passive, Some(false));
        assert_eq!(payload.pull, Some(false));
        let pairing = payload.device_pairing_data.unwrap();
        assert_eq!(pairing.e_regid.unwrap(), Bytes::from_static(&[1, 2, 3, 4]));
        assert_eq!(pairing.e_ident.unwrap(), Bytes::from_static(b"identity"));
        assert_eq!(pairing.e_skey_id.unwrap(), Bytes::from_static(&[1, 2, 3]));
        assert_eq!(pairing.e_skey_val.unwrap(), Bytes::from_static(b"pre-key"));
        assert_eq!(
            pairing.e_skey_sig.unwrap(),
            Bytes::from_static(b"signature")
        );

        validated.connection().close().await.unwrap();
    }

    #[tokio::test]
    async fn validation_failure_emits_closed() {
        let (sink, stream, _client_rx, server_tx) = mock_transport();
        drop(server_tx);
        let events = EventHub::new(16);
        let mut events_rx = events.subscribe();

        let result = validate_connection(
            sink,
            stream,
            ConnectionValidation::new(
                ClientConfig::default(),
                generate_key_pair(),
                generate_key_pair(),
                ValidationPayload::Login {
                    user_jid: "12345@s.whatsapp.net".to_owned(),
                },
            ),
            events,
            QueryManager::new(None),
            &AllowVerifier,
            4,
        )
        .await;

        assert!(matches!(result, Err(CoreError::ConnectionClosed)));
        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::ConnectionUpdate(ConnectionState::Connecting)
        ));
        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::ConnectionUpdate(ConnectionState::Closed)
        ));
    }

    #[test]
    fn builds_registration_validation_from_credentials() {
        let mut credentials = create_initial_credentials().unwrap();
        credentials.routing_info = Some(Bytes::from_static(b"route"));
        let local_ephemeral = generate_key_pair();
        let request = ConnectionValidation::from_credentials_with_ephemeral(
            ClientConfig::default(),
            &credentials,
            local_ephemeral.clone(),
        )
        .unwrap();

        assert_eq!(request.local_ephemeral, local_ephemeral);
        assert_eq!(request.static_key_pair, credentials.noise_key);
        assert_eq!(request.routing_info, Some(Bytes::from_static(b"route")));
        assert!(matches!(
            request.payload,
            ValidationPayload::Registration { .. }
        ));
    }

    #[test]
    fn builds_login_validation_from_registered_credentials() {
        let mut credentials = create_initial_credentials().unwrap();
        credentials.registered = true;
        credentials.account_jid = Some("12345:7@s.whatsapp.net".to_owned());
        let request =
            ConnectionValidation::from_credentials(ClientConfig::default(), &credentials).unwrap();

        assert!(matches!(
            request.payload,
            ValidationPayload::Login { user_jid } if user_jid == "12345:7@s.whatsapp.net"
        ));

        credentials.account_jid = None;
        assert!(
            ConnectionValidation::from_credentials(ClientConfig::default(), &credentials).is_err()
        );
    }

    async fn run_mock_server(
        client_rx: &mut mpsc::Receiver<Bytes>,
        server_tx: mpsc::Sender<InboundFrame>,
    ) -> Bytes {
        let client_hello_frame = client_rx.recv().await.unwrap();
        let client_ephemeral = parse_client_hello(&client_hello_frame);
        let mut server = TestServerHandshake::new(client_ephemeral);
        let server_ephemeral = generate_key_pair();
        let server_static = generate_key_pair();
        let server_hello = server.server_hello_frame(&server_ephemeral, &server_static);

        server_tx
            .send(InboundFrame::new(server_hello))
            .await
            .unwrap();

        let client_finish_frame = client_rx.recv().await.unwrap();
        server.decrypt_client_payload(&server_ephemeral, &client_finish_frame)
    }

    fn mock_transport() -> (
        MockSink,
        MockStream,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<InboundFrame>,
    ) {
        let (client_tx, client_rx) = mpsc::channel(4);
        let (server_tx, server_rx) = mpsc::channel(4);
        (
            MockSink {
                tx: client_tx,
                close_count: Arc::new(AtomicUsize::new(0)),
            },
            MockStream { rx: server_rx },
            client_rx,
            server_tx,
        )
    }

    async fn event_stream_reaches_open(
        events_rx: &mut tokio::sync::broadcast::Receiver<Event>,
    ) -> bool {
        for _ in 0..4 {
            match events_rx.recv().await.unwrap() {
                Event::ConnectionUpdate(ConnectionState::Open) => return true,
                Event::ConnectionUpdate(ConnectionState::Closed) => return false,
                _ => {}
            }
        }
        false
    }

    struct MockSink {
        tx: mpsc::Sender<Bytes>,
        close_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl FrameSink for MockSink {
        async fn send(&mut self, frame: Bytes) -> CoreResult<()> {
            self.tx
                .send(frame)
                .await
                .map_err(|err| CoreError::Task(err.to_string()))
        }

        async fn close(&mut self) -> CoreResult<()> {
            self.close_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct MockStream {
        rx: mpsc::Receiver<InboundFrame>,
    }

    #[async_trait]
    impl FrameStream for MockStream {
        async fn recv(&mut self) -> CoreResult<Option<InboundFrame>> {
            Ok(self.rx.recv().await)
        }
    }

    struct AllowVerifier;

    impl NoiseCertificateVerifier for AllowVerifier {
        fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
            !public_key.is_empty() && !message.is_empty() && !signature.is_empty()
        }
    }

    struct TestServerHandshake {
        client_ephemeral: [u8; 32],
        hash: [u8; 32],
        salt: [u8; 32],
        enc_key: [u8; 32],
        dec_key: [u8; 32],
        counter: u32,
    }

    impl TestServerHandshake {
        fn new(client_ephemeral: [u8; 32]) -> Self {
            let mut hash = mode_hash();
            let salt = hash;
            let enc_key = hash;
            let dec_key = hash;
            authenticate_hash(&mut hash, &DEFAULT_NOISE_HEADER);
            authenticate_hash(&mut hash, &client_ephemeral);
            Self {
                client_ephemeral,
                hash,
                salt,
                enc_key,
                dec_key,
                counter: 0,
            }
        }

        fn server_hello_frame(
            &mut self,
            server_ephemeral: &KeyPair,
            server_static: &KeyPair,
        ) -> Bytes {
            let client_ephemeral = self.client_ephemeral;
            self.authenticate(&server_ephemeral.public);
            let server_ephemeral_private: [u8; 32] =
                server_ephemeral.private.expose().try_into().unwrap();
            self.mix_shared_secret(&server_ephemeral_private, &client_ephemeral);
            let encrypted_static = self.encrypt_pre_transport(&server_static.public);

            let server_static_private: [u8; 32] =
                server_static.private.expose().try_into().unwrap();
            self.mix_shared_secret(&server_static_private, &client_ephemeral);
            let encrypted_cert = self.encrypt_pre_transport(&test_cert_chain());

            let server_hello = HandshakeMessage {
                client_hello: None,
                server_hello: Some(ServerHello {
                    ephemeral: Some(Bytes::copy_from_slice(&server_ephemeral.public)),
                    r#static: Some(encrypted_static),
                    payload: Some(encrypted_cert),
                    extended_static: None,
                }),
                client_finish: None,
            };

            NoiseFrameCodec::new(DEFAULT_MAX_FRAME_LEN)
                .encode_frame(&server_hello.encode_to_vec())
                .unwrap()
        }

        fn decrypt_client_payload(
            &mut self,
            server_ephemeral: &KeyPair,
            client_finish_frame: &[u8],
        ) -> Bytes {
            let finish = parse_client_finish(client_finish_frame);
            let encrypted_static = finish.r#static.unwrap();
            let client_static = self.decrypt_pre_transport(&encrypted_static);
            let client_static: [u8; 32] = client_static.as_ref().try_into().unwrap();

            let server_ephemeral_private: [u8; 32] =
                server_ephemeral.private.expose().try_into().unwrap();
            self.mix_shared_secret(&server_ephemeral_private, &client_static);

            let encrypted_payload = finish.payload.unwrap();
            self.decrypt_pre_transport(&encrypted_payload)
        }

        fn authenticate(&mut self, data: &[u8]) {
            authenticate_hash(&mut self.hash, data);
        }

        fn mix_shared_secret(&mut self, private_key: &[u8; 32], public_key: &[u8; 32]) {
            let mut secret = shared_key(private_key, public_key);
            self.mix_into_key(&secret);
            secret.zeroize();
        }

        fn mix_into_key(&mut self, input_key_material: &[u8]) {
            let mut key = hkdf_sha256(input_key_material, 64, &self.salt, &[]).unwrap();
            self.salt.zeroize();
            self.enc_key.zeroize();
            self.dec_key.zeroize();
            self.salt.copy_from_slice(&key[..32]);
            self.enc_key.copy_from_slice(&key[32..]);
            self.dec_key.copy_from_slice(&key[32..]);
            self.counter = 0;
            key.zeroize();
        }

        fn encrypt_pre_transport(&mut self, plaintext: &[u8]) -> Bytes {
            let iv = counter_iv(self.counter);
            self.counter = self.counter.wrapping_add(1);
            let ciphertext =
                aes_256_gcm_encrypt(plaintext, &self.enc_key, &iv, &self.hash).unwrap();
            self.authenticate(&ciphertext);
            ciphertext.into()
        }

        fn decrypt_pre_transport(&mut self, ciphertext: &[u8]) -> Bytes {
            let iv = counter_iv(self.counter);
            self.counter = self.counter.wrapping_add(1);
            let plaintext =
                aes_256_gcm_decrypt(ciphertext, &self.dec_key, &iv, &self.hash).unwrap();
            self.authenticate(ciphertext);
            plaintext.into()
        }
    }

    fn parse_client_hello(frame: &[u8]) -> [u8; 32] {
        assert!(frame.starts_with(&DEFAULT_NOISE_HEADER));
        let payload = single_frame_payload(&frame[DEFAULT_NOISE_HEADER.len()..]);
        let message = HandshakeMessage::decode(payload).unwrap();
        let hello: ClientHello = message.client_hello.unwrap();
        hello.ephemeral.unwrap().as_ref().try_into().unwrap()
    }

    fn parse_client_finish(frame: &[u8]) -> ClientFinish {
        let payload = single_frame_payload(frame);
        let message = HandshakeMessage::decode(payload).unwrap();
        message.client_finish.unwrap()
    }

    fn single_frame_payload(frame: &[u8]) -> &[u8] {
        assert!(frame.len() >= 3);
        let len = ((usize::from(frame[0])) << 16)
            | ((usize::from(frame[1])) << 8)
            | usize::from(frame[2]);
        assert_eq!(frame.len(), len + 3);
        &frame[3..]
    }

    fn mode_hash() -> [u8; 32] {
        if TEST_NOISE_MODE.len() == 32 {
            TEST_NOISE_MODE.try_into().unwrap()
        } else {
            sha256_hash(TEST_NOISE_MODE)
        }
    }

    fn authenticate_hash(hash: &mut [u8; 32], data: &[u8]) {
        let mut combined = Vec::with_capacity(hash.len() + data.len());
        combined.extend_from_slice(hash);
        combined.extend_from_slice(data);
        *hash = sha256_hash(&combined);
    }

    fn counter_iv(counter: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&counter.to_be_bytes());
        iv
    }

    fn test_cert_chain() -> Vec<u8> {
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
            key: Some(Bytes::from_static(b"intermediate-key")),
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
                signature: Some(Bytes::copy_from_slice(&ROOT_CERT_PUBLIC_KEY)),
            }),
        }
        .encode_to_vec()
    }
}
