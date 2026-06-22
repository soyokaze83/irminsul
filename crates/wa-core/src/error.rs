pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("store error: {0}")]
    Store(#[from] wa_store::StoreError),
    #[error("binary decode error: {0}")]
    BinaryDecode(#[from] wa_binary::BinaryDecodeError),
    #[error("binary encode error: {0}")]
    BinaryEncode(#[from] wa_binary::BinaryEncodeError),
    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),
    #[error("connection is closed")]
    ConnectionClosed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("duplicate query tag: {0}")]
    DuplicateQueryTag(String),
    #[error("operation timed out")]
    TimedOut,
    #[error("payload error: {0}")]
    Payload(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[cfg(feature = "noise")]
    #[error("crypto error: {0}")]
    Crypto(wa_crypto::CryptoError),
    #[error("task failed: {0}")]
    Task(String),
    #[cfg(any(feature = "http-media", feature = "link-preview"))]
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[cfg(feature = "noise")]
    #[error("noise error: {0}")]
    Noise(#[from] wa_crypto::NoiseHandshakeError),
    #[cfg(feature = "websocket")]
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}
