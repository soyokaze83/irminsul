#[cfg(feature = "noise")]
use crate::event::{EventBatch, MediaRetryEvent, MessageEventKey, message_event_store_key};
#[cfg(feature = "link-preview")]
use crate::message::LinkPreviewThumbnail;
#[cfg(feature = "noise")]
use crate::message::{RemoteMediaThumbnail, UploadedMedia};
use crate::{CoreError, CoreResult};
#[cfg(feature = "noise")]
use async_trait::async_trait;
#[cfg(all(feature = "noise", feature = "http-media"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "noise")]
use bytes::{Buf, BufMut, Bytes, BytesMut};
#[cfg(any(
    feature = "link-preview",
    all(feature = "noise", feature = "http-media")
))]
use futures::StreamExt as _;
use sha2::{Digest, Sha256};
#[cfg(feature = "link-preview")]
use std::time::Duration;
#[cfg(feature = "noise")]
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "noise")]
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};
use wa_binary::{BinaryNode, BinaryNodeContent, jid::S_WHATSAPP_NET};
#[cfg(feature = "noise")]
use wa_proto::proto::media_retry_notification::ResultType as ProtoMediaRetryResult;

pub const DEFAULT_MEDIA_HOST: &str = "mmg.whatsapp.net";
pub const DEFAULT_MEDIA_ORIGIN: &str = "https://web.whatsapp.com";
#[cfg(feature = "noise")]
pub const DEFAULT_MEDIA_UPLOAD_CACHE_CAPACITY: usize = 128;
#[cfg(feature = "noise")]
pub const DEFAULT_MEDIA_UPLOAD_CACHE_TTL_MS: u64 = 60 * 60 * 1000;
#[cfg(feature = "noise")]
pub const DEFAULT_MEDIA_FILE_CHUNK_BYTES: usize = 64 * 1024;
#[cfg(feature = "noise")]
pub const DEFAULT_MEDIA_RETRY_COORDINATOR_CAPACITY: usize = 256;
#[cfg(feature = "noise")]
pub const DEFAULT_MEDIA_RETRY_COORDINATOR_TTL_MS: u64 = 5 * 60 * 1000;
#[cfg(feature = "noise")]
const STORED_PENDING_MEDIA_RETRY_MAGIC: &[u8; 4] = b"pmr1";
#[cfg(feature = "noise")]
const STORED_PENDING_MEDIA_RETRY_VERSION: u8 = 1;
#[cfg(feature = "noise")]
const MAX_STORED_PENDING_MEDIA_RETRY_RECORD_BYTES: usize = 8 * 1024 * 1024;
#[cfg(feature = "noise")]
const MAX_STORED_PENDING_MEDIA_RETRY_FIELD_BYTES: usize = 64 * 1024;
#[cfg(feature = "link-preview")]
pub const DEFAULT_LINK_PREVIEW_FETCH_MAX_HTML_BYTES: usize = 512 * 1024;
#[cfg(feature = "link-preview")]
pub const DEFAULT_LINK_PREVIEW_FETCH_TIMEOUT_MS: u64 = 10_000;
#[cfg(feature = "link-preview")]
pub const DEFAULT_LINK_PREVIEW_FETCH_USER_AGENT: &str = "Mozilla/5.0 (WhatsAppAgent link-preview)";
#[cfg(feature = "link-preview")]
pub const DEFAULT_LINK_PREVIEW_IMAGE_FETCH_MAX_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "link-preview")]
pub const DEFAULT_LINK_PREVIEW_IMAGE_FETCH_TIMEOUT_MS: u64 = DEFAULT_LINK_PREVIEW_FETCH_TIMEOUT_MS;

#[cfg(feature = "link-preview")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkPreviewFetchOptions {
    pub max_html_bytes: usize,
    pub timeout: Duration,
    pub user_agent: Option<String>,
    pub max_redirects: usize,
}

#[cfg(feature = "link-preview")]
impl Default for LinkPreviewFetchOptions {
    fn default() -> Self {
        Self {
            max_html_bytes: DEFAULT_LINK_PREVIEW_FETCH_MAX_HTML_BYTES,
            timeout: Duration::from_millis(DEFAULT_LINK_PREVIEW_FETCH_TIMEOUT_MS),
            user_agent: Some(DEFAULT_LINK_PREVIEW_FETCH_USER_AGENT.to_owned()),
            max_redirects: 5,
        }
    }
}

#[cfg(feature = "link-preview")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkPreviewImageFetchOptions {
    pub max_image_bytes: usize,
    pub timeout: Duration,
    pub user_agent: Option<String>,
    pub max_redirects: usize,
}

#[cfg(feature = "link-preview")]
impl Default for LinkPreviewImageFetchOptions {
    fn default() -> Self {
        Self {
            max_image_bytes: DEFAULT_LINK_PREVIEW_IMAGE_FETCH_MAX_BYTES,
            timeout: Duration::from_millis(DEFAULT_LINK_PREVIEW_IMAGE_FETCH_TIMEOUT_MS),
            user_agent: Some(DEFAULT_LINK_PREVIEW_FETCH_USER_AGENT.to_owned()),
            max_redirects: 5,
        }
    }
}

#[cfg(all(feature = "link-preview", feature = "image"))]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinkPreviewThumbnailFetchOptions {
    pub metadata: LinkPreviewFetchOptions,
    pub image: LinkPreviewImageFetchOptions,
    pub image_processing: crate::LinkPreviewImageOptions,
}

#[cfg(feature = "link-preview")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedLinkPreview {
    pub content: crate::LinkPreviewContent,
    pub final_url: String,
    pub image_url: Option<String>,
}

#[cfg(all(feature = "link-preview", feature = "image"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedLinkPreviewWithThumbnail {
    pub preview: FetchedLinkPreview,
    pub thumbnail_upload: GeneratedLinkPreviewThumbnailUpload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaUploadHost {
    pub hostname: String,
    pub max_content_length_bytes: Option<usize>,
    pub scheme: Option<String>,
}

impl MediaUploadHost {
    #[must_use]
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            max_content_length_bytes: None,
            scheme: None,
        }
    }

    #[must_use]
    pub fn with_max_content_length_bytes(mut self, max_content_length_bytes: usize) -> Self {
        self.max_content_length_bytes = Some(max_content_length_bytes);
        self
    }

    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = Some(scheme.into());
        self
    }

    #[must_use]
    pub fn upload_scheme(&self) -> &str {
        self.scheme.as_deref().unwrap_or("https")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaConnectionInfo {
    pub hosts: Vec<MediaUploadHost>,
    pub auth: String,
    pub ttl_seconds: u64,
}

impl MediaConnectionInfo {
    #[must_use]
    pub fn new(auth: impl Into<String>, ttl_seconds: u64) -> Self {
        Self {
            hosts: Vec::new(),
            auth: auth.into(),
            ttl_seconds,
        }
    }

    #[must_use]
    pub fn with_hosts<I>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = MediaUploadHost>,
    {
        self.hosts = hosts.into_iter().collect();
        self
    }
}

#[must_use]
pub fn build_media_connection_query(tag: impl Into<String>) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("type", "set")
        .with_attr("xmlns", "w:m")
        .with_attr("to", S_WHATSAPP_NET)
        .with_content(vec![BinaryNode::new("media_conn")])
}

pub fn parse_media_connection_info(node: &BinaryNode) -> CoreResult<MediaConnectionInfo> {
    if let Some(error) = media_connection_error_from_result(node) {
        return Err(error);
    }

    let media_conn = if node.tag == "media_conn" {
        node
    } else {
        child_node(node, "media_conn").ok_or_else(|| {
            CoreError::Protocol("media connection response missing media_conn node".to_owned())
        })?
    };
    let auth = required_attr(media_conn, "auth")?.to_owned();
    let ttl_seconds = required_attr(media_conn, "ttl")?
        .parse::<u64>()
        .map_err(|_| CoreError::Protocol("media connection ttl is not a number".to_owned()))?;

    let mut hosts = Vec::new();
    for host in child_nodes(media_conn, "host") {
        let hostname = required_attr(host, "hostname")?;
        let mut upload_host = MediaUploadHost::new(hostname);
        if let Some(max) = host.attrs.get("maxContentLengthBytes") {
            upload_host.max_content_length_bytes = Some(max.parse::<usize>().map_err(|_| {
                CoreError::Protocol(
                    "media connection host maxContentLengthBytes is not a number".to_owned(),
                )
            })?);
        }
        hosts.push(upload_host);
    }

    if hosts.is_empty() {
        return Err(CoreError::Protocol(
            "media connection response has no upload hosts".to_owned(),
        ));
    }

    Ok(MediaConnectionInfo {
        hosts,
        auth,
        ttl_seconds,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadedMediaLocation {
    pub url: Option<String>,
    pub direct_path: Option<String>,
    pub media_key_timestamp: Option<i64>,
    pub upload_id: Option<String>,
    pub upload_token: Option<String>,
}

impl UploadedMediaLocation {
    #[must_use]
    pub fn new() -> Self {
        Self {
            url: None,
            direct_path: None,
            media_key_timestamp: None,
            upload_id: None,
            upload_token: None,
        }
    }

    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    #[must_use]
    pub fn with_direct_path(mut self, direct_path: impl Into<String>) -> Self {
        self.direct_path = Some(direct_path.into());
        self
    }

    #[must_use]
    pub fn with_media_key_timestamp(mut self, timestamp: i64) -> Self {
        self.media_key_timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_upload_id(mut self, upload_id: impl Into<String>) -> Self {
        self.upload_id = Some(upload_id.into());
        self
    }

    #[must_use]
    pub fn with_upload_token(mut self, upload_token: impl Into<String>) -> Self {
        self.upload_token = Some(upload_token.into());
        self
    }
}

impl Default for UploadedMediaLocation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaUploadCacheKey {
    pub kind: wa_crypto::MediaKind,
    pub file_sha256: [u8; 32],
    pub file_length: u64,
}

#[cfg(feature = "noise")]
impl MediaUploadCacheKey {
    pub fn new(
        kind: wa_crypto::MediaKind,
        file_sha256: impl AsRef<[u8]>,
        file_length: u64,
    ) -> CoreResult<Self> {
        let file_sha256 = file_sha256.as_ref();
        let file_sha256 = file_sha256.try_into().map_err(|_| {
            CoreError::Payload(format!(
                "media upload cache key SHA-256 must be 32 bytes, got {}",
                file_sha256.len()
            ))
        })?;
        Ok(Self {
            kind,
            file_sha256,
            file_length,
        })
    }

    #[must_use]
    pub fn from_plaintext(kind: wa_crypto::MediaKind, plaintext: &[u8]) -> Self {
        Self {
            kind,
            file_sha256: Sha256::digest(plaintext).into(),
            file_length: plaintext.len() as u64,
        }
    }
}

#[cfg(feature = "noise")]
impl Ord for MediaUploadCacheKey {
    fn cmp(&self, other: &Self) -> Ordering {
        media_kind_cache_id(self.kind)
            .cmp(&media_kind_cache_id(other.kind))
            .then_with(|| self.file_sha256.cmp(&other.file_sha256))
            .then_with(|| self.file_length.cmp(&other.file_length))
    }
}

#[cfg(feature = "noise")]
impl PartialOrd for MediaUploadCacheKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "noise")]
#[async_trait]
pub trait MediaUploadCache: Send + Sync {
    async fn get_media_upload(
        &self,
        key: &MediaUploadCacheKey,
    ) -> CoreResult<Option<UploadedMedia>>;

    async fn store_media_upload(
        &self,
        key: MediaUploadCacheKey,
        media: UploadedMedia,
    ) -> CoreResult<()>;
}

#[cfg(feature = "noise")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryMediaUploadCacheConfig {
    pub capacity: usize,
    pub ttl_ms: u64,
}

#[cfg(feature = "noise")]
impl Default for MemoryMediaUploadCacheConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_MEDIA_UPLOAD_CACHE_CAPACITY,
            ttl_ms: DEFAULT_MEDIA_UPLOAD_CACHE_TTL_MS,
        }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone)]
pub struct MemoryMediaUploadCache {
    inner: Arc<Mutex<MemoryMediaUploadCacheInner>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

#[cfg(feature = "noise")]
impl MemoryMediaUploadCache {
    #[must_use]
    pub fn new(config: MemoryMediaUploadCacheConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryMediaUploadCacheInner {
                config,
                entries: BTreeMap::new(),
            })),
            clock: Arc::new(system_time_ms),
        }
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(MemoryMediaUploadCacheConfig {
            capacity,
            ..MemoryMediaUploadCacheConfig::default()
        })
    }

    pub fn len(&self) -> CoreResult<usize> {
        Ok(self.lock()?.entries.len())
    }

    pub fn is_empty(&self) -> CoreResult<bool> {
        Ok(self.lock()?.entries.is_empty())
    }

    #[cfg(test)]
    fn with_clock<F>(config: MemoryMediaUploadCacheConfig, clock: F) -> Self
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(Mutex::new(MemoryMediaUploadCacheInner {
                config,
                entries: BTreeMap::new(),
            })),
            clock: Arc::new(clock),
        }
    }

    fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    fn lock(&self) -> CoreResult<MutexGuard<'_, MemoryMediaUploadCacheInner>> {
        self.inner
            .lock()
            .map_err(|_| CoreError::Task("media upload cache mutex poisoned".to_owned()))
    }
}

#[cfg(feature = "noise")]
impl Default for MemoryMediaUploadCache {
    fn default() -> Self {
        Self::new(MemoryMediaUploadCacheConfig::default())
    }
}

#[cfg(feature = "noise")]
#[async_trait]
impl MediaUploadCache for MemoryMediaUploadCache {
    async fn get_media_upload(
        &self,
        key: &MediaUploadCacheKey,
    ) -> CoreResult<Option<UploadedMedia>> {
        let now_ms = self.now_ms();
        let mut inner = self.lock()?;
        inner.prune_expired(now_ms);
        let Some(entry) = inner.entries.get_mut(key) else {
            return Ok(None);
        };
        entry.last_accessed_ms = now_ms;
        Ok(Some(entry.media.clone()))
    }

    async fn store_media_upload(
        &self,
        key: MediaUploadCacheKey,
        media: UploadedMedia,
    ) -> CoreResult<()> {
        validate_cached_media_matches_key(&key, &media)?;
        let now_ms = self.now_ms();
        let mut inner = self.lock()?;
        inner.prune_expired(now_ms);
        if inner.config.capacity == 0 {
            return Ok(());
        }
        inner.entries.insert(
            key,
            MemoryMediaUploadCacheEntry {
                media,
                stored_at_ms: now_ms,
                last_accessed_ms: now_ms,
            },
        );
        inner.evict_to_capacity();
        Ok(())
    }
}

#[cfg(feature = "noise")]
struct MemoryMediaUploadCacheInner {
    config: MemoryMediaUploadCacheConfig,
    entries: BTreeMap<MediaUploadCacheKey, MemoryMediaUploadCacheEntry>,
}

#[cfg(feature = "noise")]
impl MemoryMediaUploadCacheInner {
    fn prune_expired(&mut self, now_ms: u64) {
        let ttl_ms = self.config.ttl_ms;
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.stored_at_ms) < ttl_ms);
    }

    fn evict_to_capacity(&mut self) {
        while self.entries.len() > self.config.capacity {
            let Some(key) = self
                .entries
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.last_accessed_ms
                        .cmp(&right.last_accessed_ms)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&key);
        }
    }
}

#[cfg(feature = "noise")]
struct MemoryMediaUploadCacheEntry {
    media: UploadedMedia,
    stored_at_ms: u64,
    last_accessed_ms: u64,
}

#[cfg(feature = "noise")]
#[must_use]
pub fn media_upload_path(kind: wa_crypto::MediaKind) -> Option<&'static str> {
    match kind {
        wa_crypto::MediaKind::Audio | wa_crypto::MediaKind::PushToTalk => Some("/mms/audio"),
        wa_crypto::MediaKind::Document => Some("/mms/document"),
        wa_crypto::MediaKind::Gif
        | wa_crypto::MediaKind::Video
        | wa_crypto::MediaKind::VideoNote => Some("/mms/video"),
        wa_crypto::MediaKind::Image
        | wa_crypto::MediaKind::Sticker
        | wa_crypto::MediaKind::ThumbnailImage
        | wa_crypto::MediaKind::ThumbnailVideo
        | wa_crypto::MediaKind::ThumbnailLink => Some("/mms/image"),
        wa_crypto::MediaKind::HistorySync => Some("/mms/md-app-state"),
        wa_crypto::MediaKind::ProductCatalogImage => Some("/product/image"),
        wa_crypto::MediaKind::BusinessCoverPhoto => Some("/pps/biz-cover-photo"),
        wa_crypto::MediaKind::AppState
        | wa_crypto::MediaKind::PaymentBackgroundImage
        | wa_crypto::MediaKind::Product
        | wa_crypto::MediaKind::ProfilePicture
        | wa_crypto::MediaKind::ThumbnailDocument => None,
    }
}

#[cfg(all(feature = "noise", feature = "http-media"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpMediaTransportConfig {
    pub media_connection: MediaConnectionInfo,
    pub custom_upload_hosts: Vec<MediaUploadHost>,
    pub origin: String,
}

#[cfg(all(feature = "noise", feature = "http-media"))]
impl HttpMediaTransportConfig {
    #[must_use]
    pub fn new(media_connection: MediaConnectionInfo) -> Self {
        Self {
            media_connection,
            custom_upload_hosts: Vec::new(),
            origin: DEFAULT_MEDIA_ORIGIN.to_owned(),
        }
    }

    #[must_use]
    pub fn with_custom_upload_hosts<I>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = MediaUploadHost>,
    {
        self.custom_upload_hosts = hosts.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = origin.into();
        self
    }
}

#[cfg(all(feature = "noise", feature = "http-media"))]
#[derive(Clone)]
pub struct HttpMediaTransport {
    client: reqwest::Client,
    config: HttpMediaTransportConfig,
}

#[cfg(all(feature = "noise", feature = "http-media"))]
impl HttpMediaTransport {
    #[must_use]
    pub fn new(media_connection: MediaConnectionInfo) -> Self {
        Self::with_config(HttpMediaTransportConfig::new(media_connection))
    }

    #[must_use]
    pub fn with_config(config: HttpMediaTransportConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    #[must_use]
    pub fn with_client(client: reqwest::Client, config: HttpMediaTransportConfig) -> Self {
        Self { client, config }
    }

    #[must_use]
    pub fn config(&self) -> &HttpMediaTransportConfig {
        &self.config
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaTransferConfig {
    pub max_upload_plaintext_bytes: usize,
    pub max_download_ciphertext_bytes: usize,
}

#[cfg(feature = "noise")]
impl Default for MediaTransferConfig {
    fn default() -> Self {
        Self {
            max_upload_plaintext_bytes: 100 * 1024 * 1024,
            max_download_ciphertext_bytes: 128 * 1024 * 1024,
        }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadedMediaUpload {
    pub media: UploadedMedia,
    pub location: UploadedMediaLocation,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaUploadRequest {
    pub kind: wa_crypto::MediaKind,
    pub ciphertext_with_mac: Bytes,
    pub file_sha256: Bytes,
    pub file_enc_sha256: Bytes,
    pub file_length: u64,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaUploadStreamRequest {
    pub kind: wa_crypto::MediaKind,
    pub ciphertext_path: PathBuf,
    pub ciphertext_len: u64,
    pub file_sha256: Bytes,
    pub file_enc_sha256: Bytes,
    pub file_length: u64,
}

#[cfg(feature = "noise")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaRetryResult {
    GeneralError,
    Success,
    NotFound,
    DecryptionError,
}

#[cfg(feature = "noise")]
impl MediaRetryResult {
    #[must_use]
    pub fn status_code(self) -> u16 {
        match self {
            Self::Success => 200,
            Self::DecryptionError => 412,
            Self::NotFound => 404,
            Self::GeneralError => 418,
        }
    }

    fn from_proto(result: ProtoMediaRetryResult) -> Self {
        match result {
            ProtoMediaRetryResult::Success => Self::Success,
            ProtoMediaRetryResult::NotFound => Self::NotFound,
            ProtoMediaRetryResult::DecryptionError => Self::DecryptionError,
            ProtoMediaRetryResult::GeneralError => Self::GeneralError,
        }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryApplication {
    pub result: MediaRetryResult,
    pub status_code: u16,
    pub media: UploadedMedia,
    pub direct_path: Option<String>,
    pub message_secret: Option<Bytes>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryDownload {
    pub application: MediaRetryApplication,
    pub plaintext: Vec<u8>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryBatchError {
    pub key: MessageEventKey,
    pub error_code: Option<u16>,
    pub status_code: Option<u16>,
    pub reason: String,
}

#[cfg(feature = "noise")]
impl MediaRetryBatchError {
    #[must_use]
    pub fn from_retry_event(retry: &MediaRetryEvent, reason: impl Into<String>) -> Self {
        Self {
            key: retry.key.clone(),
            error_code: retry.error_code,
            status_code: retry.status_code,
            reason: reason.into(),
        }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MediaRetryBatchOutcome {
    pub downloads: Vec<MediaRetryDownload>,
    pub errors: Vec<MediaRetryBatchError>,
    pub ignored_without_pending: usize,
    pub malformed_stored_records: usize,
}

#[cfg(feature = "noise")]
impl MediaRetryBatchOutcome {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.downloads.is_empty()
            && self.errors.is_empty()
            && self.ignored_without_pending == 0
            && self.malformed_stored_records == 0
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaRetryCoordinatorConfig {
    pub capacity: usize,
    pub ttl_ms: u64,
}

#[cfg(feature = "noise")]
impl Default for MediaRetryCoordinatorConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_MEDIA_RETRY_COORDINATOR_CAPACITY,
            ttl_ms: DEFAULT_MEDIA_RETRY_COORDINATOR_TTL_MS,
        }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingMediaRetry {
    pub media: UploadedMedia,
    pub kind: wa_crypto::MediaKind,
    pub fallback_host: Option<String>,
}

#[cfg(feature = "noise")]
impl PendingMediaRetry {
    #[must_use]
    pub fn new(media: UploadedMedia, kind: wa_crypto::MediaKind) -> Self {
        Self {
            media,
            kind,
            fallback_host: None,
        }
    }

    #[must_use]
    pub fn with_fallback_host(mut self, fallback_host: impl Into<String>) -> Self {
        self.fallback_host = Some(fallback_host.into());
        self
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryPendingEntry {
    pub key: MessageEventKey,
    pub pending: PendingMediaRetry,
}

#[cfg(feature = "noise")]
impl MediaRetryPendingEntry {
    #[must_use]
    pub fn new(key: MessageEventKey, pending: PendingMediaRetry) -> Self {
        Self { key, pending }
    }
}

#[cfg(feature = "noise")]
#[derive(Clone)]
pub struct MediaRetryCoordinator {
    inner: Arc<Mutex<MediaRetryCoordinatorInner>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

#[cfg(feature = "noise")]
impl MediaRetryCoordinator {
    #[must_use]
    pub fn new(config: MediaRetryCoordinatorConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MediaRetryCoordinatorInner {
                config,
                entries: BTreeMap::new(),
            })),
            clock: Arc::new(system_time_ms),
        }
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(MediaRetryCoordinatorConfig {
            capacity,
            ..MediaRetryCoordinatorConfig::default()
        })
    }

    #[cfg(test)]
    fn with_clock<F>(config: MediaRetryCoordinatorConfig, clock: F) -> Self
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(Mutex::new(MediaRetryCoordinatorInner {
                config,
                entries: BTreeMap::new(),
            })),
            clock: Arc::new(clock),
        }
    }

    pub fn register(&self, key: MessageEventKey, pending: PendingMediaRetry) -> CoreResult<()> {
        validate_media_retry_key(&key)?;
        validate_pending_media_retry(&pending)?;
        let now_ms = self.now_ms();
        let mut inner = self.lock()?;
        inner.prune_expired(now_ms);
        if inner.config.capacity == 0 {
            return Ok(());
        }
        inner.entries.insert(
            key,
            MediaRetryCoordinatorEntry {
                pending,
                stored_at_ms: now_ms,
                last_accessed_ms: now_ms,
            },
        );
        inner.evict_to_capacity();
        Ok(())
    }

    pub fn pending(&self, key: &MessageEventKey) -> CoreResult<Option<PendingMediaRetry>> {
        let now_ms = self.now_ms();
        let mut inner = self.lock()?;
        inner.prune_expired(now_ms);
        let Some(entry) = inner.entries.get_mut(key) else {
            return Ok(None);
        };
        entry.last_accessed_ms = now_ms;
        Ok(Some(entry.pending.clone()))
    }

    pub fn remove(&self, key: &MessageEventKey) -> CoreResult<Option<PendingMediaRetry>> {
        Ok(self.lock()?.entries.remove(key).map(|entry| entry.pending))
    }

    pub fn pending_entries(&self) -> CoreResult<Vec<MediaRetryPendingEntry>> {
        let now_ms = self.now_ms();
        let mut inner = self.lock()?;
        inner.prune_expired(now_ms);
        Ok(inner
            .entries
            .iter()
            .map(|(key, entry)| MediaRetryPendingEntry::new(key.clone(), entry.pending.clone()))
            .collect())
    }

    pub fn restore_pending_entries<I>(&self, entries: I) -> CoreResult<usize>
    where
        I: IntoIterator<Item = MediaRetryPendingEntry>,
    {
        let mut restored = 0;
        for entry in entries {
            self.register(entry.key, entry.pending)?;
            restored += 1;
        }
        Ok(restored)
    }

    pub fn apply_retry_event(&self, retry: &MediaRetryEvent) -> CoreResult<MediaRetryApplication> {
        let now_ms = self.now_ms();
        let mut inner = self.lock()?;
        inner.prune_expired(now_ms);
        let entry = inner.entries.get_mut(&retry.key).ok_or_else(|| {
            CoreError::Protocol(format!(
                "media retry has no pending media for message {}",
                retry.key.id
            ))
        })?;
        let application = apply_media_retry_event(retry, &entry.pending.media)?;
        entry.pending.media = application.media.clone();
        entry.last_accessed_ms = now_ms;
        Ok(application)
    }

    pub async fn download_after_retry<T>(
        &self,
        transfer: &MediaTransfer<T>,
        retry: &MediaRetryEvent,
    ) -> CoreResult<MediaRetryDownload>
    where
        T: MediaTransport,
    {
        let pending = self.pending(&retry.key)?.ok_or_else(|| {
            CoreError::Protocol(format!(
                "media retry has no pending media for message {}",
                retry.key.id
            ))
        })?;
        let download = transfer
            .download_bytes_after_retry(
                &pending.media,
                pending.kind,
                retry,
                pending.fallback_host.as_deref(),
            )
            .await?;
        self.remove(&retry.key)?;
        Ok(download)
    }

    pub async fn handle_retry_events<T>(
        &self,
        transfer: &MediaTransfer<T>,
        retries: &[MediaRetryEvent],
    ) -> CoreResult<MediaRetryBatchOutcome>
    where
        T: MediaTransport,
    {
        let mut outcome = MediaRetryBatchOutcome::default();
        for retry in retries {
            if self.pending(&retry.key)?.is_none() {
                outcome.ignored_without_pending += 1;
                continue;
            }
            match self.download_after_retry(transfer, retry).await {
                Ok(download) => outcome.downloads.push(download),
                Err(err) => outcome.errors.push(MediaRetryBatchError::from_retry_event(
                    retry,
                    err.to_string(),
                )),
            }
        }
        Ok(outcome)
    }

    pub async fn handle_event_batch<T>(
        &self,
        transfer: &MediaTransfer<T>,
        batch: &EventBatch,
    ) -> CoreResult<MediaRetryBatchOutcome>
    where
        T: MediaTransport,
    {
        self.handle_retry_events(transfer, &batch.media_retry).await
    }

    pub fn len(&self) -> CoreResult<usize> {
        let now_ms = self.now_ms();
        let mut inner = self.lock()?;
        inner.prune_expired(now_ms);
        Ok(inner.entries.len())
    }

    pub fn is_empty(&self) -> CoreResult<bool> {
        Ok(self.len()? == 0)
    }

    fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    fn lock(&self) -> CoreResult<MutexGuard<'_, MediaRetryCoordinatorInner>> {
        self.inner
            .lock()
            .map_err(|_| CoreError::Task("media retry coordinator mutex poisoned".to_owned()))
    }
}

#[cfg(feature = "noise")]
impl Default for MediaRetryCoordinator {
    fn default() -> Self {
        Self::new(MediaRetryCoordinatorConfig::default())
    }
}

#[cfg(feature = "noise")]
struct MediaRetryCoordinatorInner {
    config: MediaRetryCoordinatorConfig,
    entries: BTreeMap<MessageEventKey, MediaRetryCoordinatorEntry>,
}

#[cfg(feature = "noise")]
impl MediaRetryCoordinatorInner {
    fn prune_expired(&mut self, now_ms: u64) {
        let ttl_ms = self.config.ttl_ms;
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.stored_at_ms) < ttl_ms);
    }

    fn evict_to_capacity(&mut self) {
        while self.entries.len() > self.config.capacity {
            let Some(key) = self
                .entries
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.last_accessed_ms
                        .cmp(&right.last_accessed_ms)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&key);
        }
    }
}

#[cfg(feature = "noise")]
struct MediaRetryCoordinatorEntry {
    pending: PendingMediaRetry,
    stored_at_ms: u64,
    last_accessed_ms: u64,
}

#[cfg(feature = "noise")]
#[async_trait]
pub trait MediaTransport: Send + Sync {
    async fn upload_media(&self, request: MediaUploadRequest) -> CoreResult<UploadedMediaLocation>;
    async fn upload_media_stream(
        &self,
        request: MediaUploadStreamRequest,
    ) -> CoreResult<UploadedMediaLocation> {
        let max_bytes = usize::try_from(request.ciphertext_len).map_err(|_| {
            CoreError::Payload(format!(
                "encrypted media upload is too large for this platform: {} bytes",
                request.ciphertext_len
            ))
        })?;
        let ciphertext = read_file_limited(
            &request.ciphertext_path,
            max_bytes,
            "encrypted media upload file",
        )
        .await?;
        if u64::try_from(ciphertext.len()).map_err(|_| {
            CoreError::Payload("encrypted media upload byte count overflow".to_owned())
        })? != request.ciphertext_len
        {
            return Err(CoreError::Payload(format!(
                "encrypted media upload file length changed before upload: expected {}, got {}",
                request.ciphertext_len,
                ciphertext.len()
            )));
        }
        self.upload_media(MediaUploadRequest {
            kind: request.kind,
            ciphertext_with_mac: Bytes::from(ciphertext),
            file_sha256: request.file_sha256,
            file_enc_sha256: request.file_enc_sha256,
            file_length: request.file_length,
        })
        .await
    }
    async fn download_media(&self, url: &str) -> CoreResult<Bytes>;
    async fn download_media_to_file(
        &self,
        url: &str,
        path: &Path,
        max_bytes: usize,
    ) -> CoreResult<u64> {
        let bytes = self.download_media(url).await?;
        validate_media_transfer_limit("encrypted media download", bytes.len(), max_bytes)?;
        write_bytes_to_file(path, &bytes).await
    }
}

#[cfg(all(feature = "noise", feature = "http-media"))]
#[async_trait]
impl MediaTransport for HttpMediaTransport {
    async fn upload_media(&self, request: MediaUploadRequest) -> CoreResult<UploadedMediaLocation> {
        let path = media_upload_path(request.kind).ok_or_else(|| {
            CoreError::Payload(format!(
                "media kind {:?} does not support HTTP upload",
                request.kind
            ))
        })?;
        let token = media_upload_token(&request.file_enc_sha256)?;
        let mut last_error = None;

        for host in self
            .config
            .custom_upload_hosts
            .iter()
            .chain(self.config.media_connection.hosts.iter())
        {
            if let Some(max) = host.max_content_length_bytes
                && request.ciphertext_with_mac.len() > max
            {
                last_error = Some(format!(
                    "host {} rejects {} bytes above max {max}",
                    host.hostname,
                    request.ciphertext_with_mac.len()
                ));
                continue;
            }

            let url = media_upload_url(host, path, &token, &self.config.media_connection.auth)?;
            let response = self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .header(reqwest::header::ORIGIN, self.config.origin.as_str())
                .body(request.ciphertext_with_mac.clone())
                .send()
                .await?;

            let status = response.status();
            let body = response.bytes().await?;
            if !status.is_success() {
                last_error = Some(format!("media upload HTTP status {status}"));
                continue;
            }

            match uploaded_media_location_from_response(&body) {
                Ok(location) => return Ok(location),
                Err(err) => {
                    last_error = Some(err.to_string());
                }
            }
        }

        Err(CoreError::Protocol(format!(
            "media upload failed on all hosts{}",
            last_error.map(|err| format!(": {err}")).unwrap_or_default()
        )))
    }

    async fn upload_media_stream(
        &self,
        request: MediaUploadStreamRequest,
    ) -> CoreResult<UploadedMediaLocation> {
        let path = media_upload_path(request.kind).ok_or_else(|| {
            CoreError::Payload(format!(
                "media kind {:?} does not support HTTP upload",
                request.kind
            ))
        })?;
        let metadata = tokio::fs::metadata(&request.ciphertext_path).await?;
        if !metadata.is_file() {
            return Err(CoreError::Payload(
                "encrypted media upload path is not a regular file".to_owned(),
            ));
        }
        if metadata.len() != request.ciphertext_len {
            return Err(CoreError::Payload(format!(
                "encrypted media upload file length changed before upload: expected {}, got {}",
                request.ciphertext_len,
                metadata.len()
            )));
        }

        let token = media_upload_token(&request.file_enc_sha256)?;
        let mut last_error = None;

        for host in self
            .config
            .custom_upload_hosts
            .iter()
            .chain(self.config.media_connection.hosts.iter())
        {
            if let Some(max) = host.max_content_length_bytes
                && request.ciphertext_len > max as u64
            {
                last_error = Some(format!(
                    "host {} rejects {} bytes above max {max}",
                    host.hostname, request.ciphertext_len
                ));
                continue;
            }

            let file = File::open(&request.ciphertext_path).await?;
            let url = media_upload_url(host, path, &token, &self.config.media_connection.auth)?;
            let response = self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .header(
                    reqwest::header::CONTENT_LENGTH,
                    request.ciphertext_len.to_string(),
                )
                .header(reqwest::header::ORIGIN, self.config.origin.as_str())
                .body(reqwest::Body::from(file))
                .send()
                .await?;

            let status = response.status();
            let body = response.bytes().await?;
            if !status.is_success() {
                last_error = Some(format!("media upload HTTP status {status}"));
                continue;
            }

            match uploaded_media_location_from_response(&body) {
                Ok(location) => return Ok(location),
                Err(err) => {
                    last_error = Some(err.to_string());
                }
            }
        }

        Err(CoreError::Protocol(format!(
            "media upload failed on all hosts{}",
            last_error.map(|err| format!(": {err}")).unwrap_or_default()
        )))
    }

    async fn download_media(&self, url: &str) -> CoreResult<Bytes> {
        let response = self.client.get(url).send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(CoreError::Protocol(format!(
                "media download HTTP status {status}"
            )));
        }
        Ok(body)
    }

    async fn download_media_to_file(
        &self,
        url: &str,
        path: &Path,
        max_bytes: usize,
    ) -> CoreResult<u64> {
        validate_media_transfer_limit("encrypted media download", 0, max_bytes)?;
        let response = self.client.get(url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(CoreError::Protocol(format!(
                "media download HTTP status {status}"
            )));
        }
        if let Some(length) = response.content_length() {
            let length = usize::try_from(length).map_err(|_| {
                CoreError::Payload(format!(
                    "encrypted media download is too large for this platform: {length} bytes"
                ))
            })?;
            validate_media_transfer_limit("encrypted media download", length, max_bytes)?;
        }

        let mut file = File::create(path).await?;
        let mut stream = response.bytes_stream();
        let mut written = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let next_len = usize::try_from(written)
                .ok()
                .and_then(|current| current.checked_add(chunk.len()))
                .ok_or_else(|| {
                    CoreError::Payload("encrypted media download byte count overflow".to_owned())
                })?;
            validate_media_transfer_limit("encrypted media download", next_len, max_bytes)?;
            file.write_all(&chunk).await?;
            written = u64::try_from(next_len).map_err(|_| {
                CoreError::Payload("encrypted media download byte count overflow".to_owned())
            })?;
        }
        file.flush().await?;
        Ok(written)
    }
}

#[cfg(feature = "noise")]
#[derive(Clone)]
pub struct MediaTransfer<T> {
    transport: T,
    config: MediaTransferConfig,
}

#[cfg(feature = "noise")]
impl<T> MediaTransfer<T> {
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            config: MediaTransferConfig::default(),
        }
    }

    #[must_use]
    pub fn with_config(transport: T, config: MediaTransferConfig) -> Self {
        Self { transport, config }
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn config(&self) -> MediaTransferConfig {
        self.config
    }
}

#[cfg(feature = "noise")]
impl<T> MediaTransfer<T>
where
    T: MediaTransport,
{
    pub async fn upload_bytes(
        &self,
        plaintext: &[u8],
        kind: wa_crypto::MediaKind,
    ) -> CoreResult<UploadedMedia> {
        self.upload_bytes_with_location(plaintext, kind)
            .await
            .map(|upload| upload.media)
    }

    pub async fn upload_bytes_with_location(
        &self,
        plaintext: &[u8],
        kind: wa_crypto::MediaKind,
    ) -> CoreResult<UploadedMediaUpload> {
        validate_media_transfer_limit(
            "media upload plaintext",
            plaintext.len(),
            self.config.max_upload_plaintext_bytes,
        )?;
        let encrypted =
            wa_crypto::encrypt_media_bytes(plaintext, kind).map_err(CoreError::Crypto)?;
        validate_media_transfer_limit(
            "encrypted media upload",
            encrypted.ciphertext_with_mac.len(),
            self.config.max_download_ciphertext_bytes,
        )?;
        let location = self
            .transport
            .upload_media(MediaUploadRequest {
                kind,
                ciphertext_with_mac: encrypted.ciphertext_with_mac.clone(),
                file_sha256: encrypted.file_sha256.clone(),
                file_enc_sha256: encrypted.file_enc_sha256.clone(),
                file_length: encrypted.file_length,
            })
            .await?;
        let media = uploaded_media_from_encrypted(&encrypted, location.clone())?;
        Ok(UploadedMediaUpload { media, location })
    }

    pub async fn upload_video_remote_thumbnail(
        &self,
        parent_media: &UploadedMedia,
        jpeg_thumbnail: &[u8],
    ) -> CoreResult<RemoteMediaThumbnail> {
        self.upload_remote_thumbnail_with_parent_key(
            parent_media,
            jpeg_thumbnail,
            wa_crypto::MediaKind::ThumbnailVideo,
            None,
        )
        .await
    }

    pub async fn upload_document_remote_thumbnail(
        &self,
        parent_media: &UploadedMedia,
        jpeg_thumbnail: &[u8],
        dimensions: Option<(u32, u32)>,
    ) -> CoreResult<RemoteMediaThumbnail> {
        self.upload_remote_thumbnail_with_parent_key(
            parent_media,
            jpeg_thumbnail,
            wa_crypto::MediaKind::ThumbnailDocument,
            dimensions,
        )
        .await
    }

    async fn upload_remote_thumbnail_with_parent_key(
        &self,
        parent_media: &UploadedMedia,
        jpeg_thumbnail: &[u8],
        kind: wa_crypto::MediaKind,
        dimensions: Option<(u32, u32)>,
    ) -> CoreResult<RemoteMediaThumbnail> {
        validate_remote_thumbnail_upload(parent_media, jpeg_thumbnail, dimensions)?;
        validate_media_transfer_limit(
            "remote thumbnail upload plaintext",
            jpeg_thumbnail.len(),
            self.config.max_upload_plaintext_bytes,
        )?;
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            jpeg_thumbnail,
            kind,
            parent_media.media_key.as_ref(),
        )
        .map_err(CoreError::Crypto)?;
        validate_media_transfer_limit(
            "encrypted remote thumbnail upload",
            encrypted.ciphertext_with_mac.len(),
            self.config.max_download_ciphertext_bytes,
        )?;
        let location = self
            .transport
            .upload_media(MediaUploadRequest {
                kind,
                ciphertext_with_mac: encrypted.ciphertext_with_mac.clone(),
                file_sha256: encrypted.file_sha256.clone(),
                file_enc_sha256: encrypted.file_enc_sha256.clone(),
                file_length: encrypted.file_length,
            })
            .await?;
        remote_thumbnail_from_encrypted(&encrypted, location, dimensions)
    }

    pub async fn upload_bytes_cached<C>(
        &self,
        plaintext: &[u8],
        kind: wa_crypto::MediaKind,
        cache: &C,
    ) -> CoreResult<UploadedMedia>
    where
        C: MediaUploadCache,
    {
        validate_media_transfer_limit(
            "media upload plaintext",
            plaintext.len(),
            self.config.max_upload_plaintext_bytes,
        )?;
        let cache_key = MediaUploadCacheKey::from_plaintext(kind, plaintext);
        if let Some(media) = cache.get_media_upload(&cache_key).await? {
            validate_cached_media_matches_key(&cache_key, &media)?;
            return Ok(media);
        }

        let media = self.upload_bytes(plaintext, kind).await?;
        cache.store_media_upload(cache_key, media.clone()).await?;
        Ok(media)
    }

    pub async fn upload_file(
        &self,
        path: impl AsRef<Path>,
        kind: wa_crypto::MediaKind,
    ) -> CoreResult<UploadedMedia> {
        self.upload_file_with_location(path, kind)
            .await
            .map(|upload| upload.media)
    }

    pub async fn upload_file_with_location(
        &self,
        path: impl AsRef<Path>,
        kind: wa_crypto::MediaKind,
    ) -> CoreResult<UploadedMediaUpload> {
        let path = path.as_ref();
        let temp_path = temp_media_path(path);
        let encrypted = encrypt_file_to_temp_limited(
            path,
            kind,
            self.config.max_upload_plaintext_bytes,
            self.config.max_download_ciphertext_bytes,
            "media upload file",
            &temp_path,
        )
        .await;
        let (metadata, ciphertext_len) = match encrypted {
            Ok(encrypted) => encrypted,
            Err(err) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(err);
            }
        };

        let upload = self
            .transport
            .upload_media_stream(MediaUploadStreamRequest {
                kind,
                ciphertext_path: temp_path.clone(),
                ciphertext_len,
                file_sha256: metadata.file_sha256.clone(),
                file_enc_sha256: metadata.file_enc_sha256.clone(),
                file_length: metadata.file_length,
            })
            .await;
        let _ = tokio::fs::remove_file(&temp_path).await;
        let location = upload?;
        let media = uploaded_media_from_metadata(&metadata, location.clone())?;
        Ok(UploadedMediaUpload { media, location })
    }

    pub async fn upload_file_cached<C>(
        &self,
        path: impl AsRef<Path>,
        kind: wa_crypto::MediaKind,
        cache: &C,
    ) -> CoreResult<UploadedMedia>
    where
        C: MediaUploadCache,
    {
        let plaintext = read_file_limited(
            path.as_ref(),
            self.config.max_upload_plaintext_bytes,
            "media upload file",
        )
        .await?;
        self.upload_bytes_cached(&plaintext, kind, cache).await
    }

    pub async fn download_bytes(
        &self,
        media: &UploadedMedia,
        kind: wa_crypto::MediaKind,
        fallback_host: Option<&str>,
    ) -> CoreResult<Vec<u8>> {
        let url = media_download_url(
            media.direct_path.as_deref(),
            media.url.as_deref(),
            fallback_host,
        )?;
        let ciphertext = self.transport.download_media(&url).await?;
        validate_media_transfer_limit(
            "encrypted media download",
            ciphertext.len(),
            self.config.max_download_ciphertext_bytes,
        )?;
        decrypt_and_verify_media_bytes(&ciphertext, kind, media)
    }

    pub async fn download_bytes_after_retry(
        &self,
        media: &UploadedMedia,
        kind: wa_crypto::MediaKind,
        retry: &MediaRetryEvent,
        fallback_host: Option<&str>,
    ) -> CoreResult<MediaRetryDownload> {
        let application = apply_media_retry_event(retry, media)?;
        if application.result != MediaRetryResult::Success {
            return Err(CoreError::Protocol(format!(
                "media retry did not succeed: {:?}",
                application.result
            )));
        }
        let plaintext = self
            .download_bytes(&application.media, kind, fallback_host)
            .await?;
        Ok(MediaRetryDownload {
            application,
            plaintext,
        })
    }

    pub async fn download_to_file(
        &self,
        media: &UploadedMedia,
        kind: wa_crypto::MediaKind,
        fallback_host: Option<&str>,
        path: impl AsRef<Path>,
    ) -> CoreResult<u64> {
        let url = media_download_url(
            media.direct_path.as_deref(),
            media.url.as_deref(),
            fallback_host,
        )?;
        let path = path.as_ref();
        let encrypted_path = temp_media_path(path);
        let download = self
            .transport
            .download_media_to_file(
                &url,
                &encrypted_path,
                self.config.max_download_ciphertext_bytes,
            )
            .await;
        if let Err(err) = download {
            let _ = tokio::fs::remove_file(&encrypted_path).await;
            return Err(err);
        }
        let decrypted = decrypt_media_file_to_file(&encrypted_path, kind, media, path).await;
        let _ = tokio::fs::remove_file(&encrypted_path).await;
        decrypted
    }
}

#[must_use]
pub fn media_url_from_direct_path(direct_path: &str, host: Option<&str>) -> String {
    let host = host
        .filter(|host| !host.is_empty())
        .unwrap_or(DEFAULT_MEDIA_HOST);
    format!("https://{host}{direct_path}")
}

pub fn media_download_url(
    direct_path: Option<&str>,
    url: Option<&str>,
    fallback_host: Option<&str>,
) -> CoreResult<String> {
    if let Some(direct_path) = direct_path
        && !direct_path.is_empty()
    {
        return Ok(media_url_from_direct_path(direct_path, fallback_host));
    }
    if let Some(url) = url
        && !url.is_empty()
    {
        return Ok(url.to_owned());
    }
    Err(CoreError::Payload(
        "media download requires a direct path or URL".to_owned(),
    ))
}

#[cfg(all(feature = "noise", feature = "http-media"))]
pub fn media_upload_token(file_enc_sha256: &[u8]) -> CoreResult<String> {
    if file_enc_sha256.len() != 32 {
        return Err(CoreError::Payload(format!(
            "media encrypted SHA-256 must be 32 bytes, got {}",
            file_enc_sha256.len()
        )));
    }
    Ok(URL_SAFE_NO_PAD.encode(file_enc_sha256))
}

#[cfg(all(feature = "noise", feature = "http-media"))]
pub fn media_upload_url(
    host: &MediaUploadHost,
    path: &str,
    token: &str,
    auth: &str,
) -> CoreResult<String> {
    if host.hostname.is_empty() {
        return Err(CoreError::Payload(
            "media upload host must not be empty".to_owned(),
        ));
    }
    if auth.is_empty() {
        return Err(CoreError::Payload(
            "media upload auth token must not be empty".to_owned(),
        ));
    }
    let base = format!("{}://{}{}", host.upload_scheme(), host.hostname, path);
    let mut url = reqwest::Url::parse(&base)
        .map_err(|err| CoreError::Payload(format!("invalid media upload URL: {err}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| CoreError::Payload("media upload URL cannot be a base".to_owned()))?;
        segments.pop_if_empty().push(token);
    }
    url.query_pairs_mut()
        .append_pair("auth", auth)
        .append_pair("token", token);
    Ok(url.to_string())
}

#[cfg(all(feature = "noise", feature = "http-media"))]
fn uploaded_media_location_from_response(body: &[u8]) -> CoreResult<UploadedMediaLocation> {
    let value = serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|err| CoreError::Protocol(format!("media upload returned invalid JSON: {err}")))?;
    let mut location = UploadedMediaLocation::new();
    if let Some(url) = value.get("url").and_then(serde_json::Value::as_str)
        && !url.is_empty()
    {
        location = location.with_url(url);
    }
    if let Some(direct_path) = value.get("direct_path").and_then(serde_json::Value::as_str)
        && !direct_path.is_empty()
    {
        location = location.with_direct_path(direct_path);
    }
    if let Some(timestamp) = value.get("ts").and_then(serde_json::Value::as_i64) {
        location = location.with_media_key_timestamp(timestamp);
    }
    if let Some(upload_id) = value.get("fbid").and_then(json_string_or_number)
        && !upload_id.is_empty()
    {
        location = location.with_upload_id(upload_id);
    }
    if let Some(upload_token) = value.get("meta_hmac").and_then(serde_json::Value::as_str)
        && !upload_token.is_empty()
    {
        location = location.with_upload_token(upload_token);
    }
    if location.url.as_deref().is_none_or(str::is_empty)
        && location.direct_path.as_deref().is_none_or(str::is_empty)
    {
        return Err(CoreError::Protocol(
            "media upload response missing URL and direct path".to_owned(),
        ));
    }
    Ok(location)
}

#[cfg(all(feature = "noise", feature = "http-media"))]
fn json_string_or_number(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_i64().map(|value| value.to_string()))
        .or_else(|| value.as_u64().map(|value| value.to_string()))
}

pub fn verify_media_plaintext_hash(
    plaintext: &[u8],
    expected_file_sha256: &[u8],
) -> CoreResult<()> {
    verify_sha256(
        plaintext,
        expected_file_sha256,
        "media plaintext SHA-256 mismatch",
    )
}

pub fn verify_media_ciphertext_hash(
    ciphertext_with_mac: &[u8],
    expected_file_enc_sha256: &[u8],
) -> CoreResult<()> {
    verify_sha256(
        ciphertext_with_mac,
        expected_file_enc_sha256,
        "media encrypted SHA-256 mismatch",
    )
}

#[cfg(feature = "noise")]
pub fn uploaded_media_from_encrypted(
    encrypted: &wa_crypto::EncryptedMedia,
    location: UploadedMediaLocation,
) -> CoreResult<UploadedMedia> {
    uploaded_media_from_metadata(&encrypted.metadata(), location)
}

#[cfg(feature = "noise")]
pub fn uploaded_media_from_metadata(
    metadata: &wa_crypto::MediaEncryptionMetadata,
    location: UploadedMediaLocation,
) -> CoreResult<UploadedMedia> {
    if location.url.as_deref().is_none_or(str::is_empty)
        && location.direct_path.as_deref().is_none_or(str::is_empty)
    {
        return Err(CoreError::Payload(
            "uploaded media location requires a URL or direct path".to_owned(),
        ));
    }

    let mut media = UploadedMedia::new(
        Bytes::copy_from_slice(metadata.media_key.expose()),
        metadata.file_sha256.clone(),
        metadata.file_enc_sha256.clone(),
        metadata.file_length,
    );
    if let Some(url) = location.url {
        media = media.with_url(url);
    }
    if let Some(direct_path) = location.direct_path {
        media = media.with_direct_path(direct_path);
    }
    if let Some(timestamp) = location.media_key_timestamp {
        media = media.with_media_key_timestamp(timestamp);
    }
    Ok(media)
}

#[cfg(feature = "noise")]
pub fn remote_thumbnail_from_encrypted(
    encrypted: &wa_crypto::EncryptedMedia,
    location: UploadedMediaLocation,
    dimensions: Option<(u32, u32)>,
) -> CoreResult<RemoteMediaThumbnail> {
    let direct_path = location
        .direct_path
        .filter(|direct_path| !direct_path.is_empty())
        .ok_or_else(|| {
            CoreError::Payload("remote thumbnail upload requires a direct path".to_owned())
        })?;
    validate_remote_thumbnail_dimensions(dimensions)?;
    let mut thumbnail = RemoteMediaThumbnail::new(
        direct_path,
        encrypted.file_sha256.clone(),
        encrypted.file_enc_sha256.clone(),
    );
    if let Some((width, height)) = dimensions {
        thumbnail = thumbnail.with_dimensions(width, height);
    }
    Ok(thumbnail)
}

#[cfg(feature = "link-preview")]
pub fn link_preview_thumbnail_from_uploaded_media(
    media: &UploadedMedia,
    dimensions: Option<(u32, u32)>,
) -> CoreResult<LinkPreviewThumbnail> {
    let direct_path = media.direct_path.as_deref().ok_or_else(|| {
        CoreError::Payload("link preview thumbnail upload requires a direct path".to_owned())
    })?;
    if direct_path.is_empty() {
        return Err(CoreError::Payload(
            "link preview thumbnail direct path must not be empty".to_owned(),
        ));
    }
    validate_media_bytes_len("link preview thumbnail media key", &media.media_key, 32)?;
    validate_media_bytes_len(
        "link preview thumbnail plaintext SHA-256",
        &media.file_sha256,
        32,
    )?;
    validate_media_bytes_len(
        "link preview thumbnail encrypted SHA-256",
        &media.file_enc_sha256,
        32,
    )?;

    let mut thumbnail = LinkPreviewThumbnail::new(
        direct_path.to_owned(),
        media.media_key.clone(),
        media.file_sha256.clone(),
        media.file_enc_sha256.clone(),
    );
    if let Some(timestamp) = media.media_key_timestamp {
        thumbnail = thumbnail.with_media_key_timestamp(timestamp);
    }
    if let Some((width, height)) = dimensions {
        if width == 0 || height == 0 {
            return Err(CoreError::Payload(
                "link preview thumbnail dimensions must be greater than zero".to_owned(),
            ));
        }
        thumbnail = thumbnail.with_dimensions(width, height);
    }
    Ok(thumbnail)
}

#[cfg(feature = "link-preview")]
pub async fn fetch_link_preview(
    url: &str,
    options: LinkPreviewFetchOptions,
) -> CoreResult<FetchedLinkPreview> {
    let parsed = parse_link_preview_fetch_url(url)?;
    validate_link_preview_fetch_options(&options)?;

    let mut client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(options.max_redirects))
        .timeout(options.timeout);
    if let Some(user_agent) = options.user_agent.as_deref()
        && !user_agent.trim().is_empty()
    {
        client = client.user_agent(user_agent);
    }
    let response = client.build()?.get(parsed).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(CoreError::Protocol(format!(
            "link preview fetch failed with HTTP status {status}"
        )));
    }
    if let Some(length) = response.content_length()
        && length > options.max_html_bytes as u64
    {
        return Err(CoreError::Payload(format!(
            "link preview HTML exceeds {} bytes",
            options.max_html_bytes
        )));
    }
    if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
        let content_type = content_type.to_str().map_err(|_| {
            CoreError::Protocol("link preview content-type is not valid UTF-8".to_owned())
        })?;
        let content_type = content_type.to_ascii_lowercase();
        if !content_type.contains("text/html") && !content_type.contains("application/xhtml+xml") {
            return Err(CoreError::Protocol(format!(
                "link preview fetch returned unsupported content-type {content_type}"
            )));
        }
    }

    let final_url = response.url().clone();
    let body =
        read_bounded_link_preview_body(response, options.max_html_bytes, "link preview HTML")
            .await?;
    let html = String::from_utf8_lossy(&body);
    link_preview_from_html(url, final_url.as_str(), &html)
}

#[cfg(feature = "link-preview")]
pub async fn fetch_link_preview_image(
    url: &str,
    options: LinkPreviewImageFetchOptions,
) -> CoreResult<Bytes> {
    let parsed = parse_link_preview_fetch_url(url)?;
    validate_link_preview_image_fetch_options(&options)?;

    let mut client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(options.max_redirects))
        .timeout(options.timeout);
    if let Some(user_agent) = options.user_agent.as_deref()
        && !user_agent.trim().is_empty()
    {
        client = client.user_agent(user_agent);
    }
    let response = client.build()?.get(parsed).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(CoreError::Protocol(format!(
            "link preview image fetch failed with HTTP status {status}"
        )));
    }
    if let Some(length) = response.content_length()
        && length > options.max_image_bytes as u64
    {
        return Err(CoreError::Payload(format!(
            "link preview image exceeds {} bytes",
            options.max_image_bytes
        )));
    }
    if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE) {
        let content_type = content_type.to_str().map_err(|_| {
            CoreError::Protocol("link preview image content-type is not valid UTF-8".to_owned())
        })?;
        validate_link_preview_image_content_type(content_type)?;
    }

    read_bounded_link_preview_body(response, options.max_image_bytes, "link preview image").await
}

#[cfg(feature = "link-preview")]
pub async fn upload_link_preview_thumbnail<T>(
    transfer: &MediaTransfer<T>,
    jpeg_thumbnail: &[u8],
    dimensions: Option<(u32, u32)>,
) -> CoreResult<LinkPreviewThumbnail>
where
    T: MediaTransport,
{
    validate_link_preview_thumbnail_plaintext(jpeg_thumbnail)?;
    let media = transfer
        .upload_bytes(jpeg_thumbnail, wa_crypto::MediaKind::ThumbnailLink)
        .await?;
    link_preview_thumbnail_from_uploaded_media(&media, dimensions)
}

#[cfg(feature = "link-preview")]
fn validate_link_preview_fetch_options(options: &LinkPreviewFetchOptions) -> CoreResult<()> {
    if options.max_html_bytes == 0 {
        return Err(CoreError::Payload(
            "link preview max HTML bytes must be greater than zero".to_owned(),
        ));
    }
    if options.timeout.is_zero() {
        return Err(CoreError::Payload(
            "link preview fetch timeout must be non-zero".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "link-preview")]
fn validate_link_preview_image_fetch_options(
    options: &LinkPreviewImageFetchOptions,
) -> CoreResult<()> {
    if options.max_image_bytes == 0 {
        return Err(CoreError::Payload(
            "link preview max image bytes must be greater than zero".to_owned(),
        ));
    }
    if options.timeout.is_zero() {
        return Err(CoreError::Payload(
            "link preview image fetch timeout must be non-zero".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "link-preview")]
fn validate_link_preview_image_content_type(content_type: &str) -> CoreResult<()> {
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if content_type.starts_with("image/") && content_type != "image/svg+xml" {
        return Ok(());
    }
    Err(CoreError::Protocol(format!(
        "link preview image fetch returned unsupported content-type {content_type}"
    )))
}

#[cfg(feature = "link-preview")]
fn parse_link_preview_fetch_url(url: &str) -> CoreResult<reqwest::Url> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|err| CoreError::Payload(format!("invalid link preview URL: {err}")))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        scheme => Err(CoreError::Payload(format!(
            "unsupported link preview URL scheme: {scheme}"
        ))),
    }
}

#[cfg(feature = "link-preview")]
async fn read_bounded_link_preview_body(
    response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> CoreResult<Bytes> {
    let mut body = bytes::BytesMut::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(CoreError::Payload(format!(
                "{label} exceeds {max_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

#[cfg(feature = "link-preview")]
fn link_preview_from_html(
    matched_text: &str,
    final_url: &str,
    html: &str,
) -> CoreResult<FetchedLinkPreview> {
    let title = find_meta_content(html, "property", "og:title")
        .or_else(|| find_meta_content(html, "name", "twitter:title"))
        .or_else(|| find_title_text(html))
        .ok_or_else(|| CoreError::Payload("link preview HTML missing title".to_owned()))?;
    let description = find_meta_content(html, "property", "og:description")
        .or_else(|| find_meta_content(html, "name", "description"))
        .or_else(|| find_meta_content(html, "name", "twitter:description"));
    let image_url = find_meta_content(html, "property", "og:image")
        .or_else(|| find_meta_content(html, "name", "twitter:image"))
        .and_then(|image| resolve_link_preview_url(final_url, &image));

    let mut content = crate::LinkPreviewContent::new(matched_text, title);
    if let Some(description) = description {
        content = content.with_description(description);
    }
    Ok(FetchedLinkPreview {
        content,
        final_url: final_url.to_owned(),
        image_url,
    })
}

#[cfg(feature = "link-preview")]
fn find_meta_content(html: &str, key_attr: &str, key_value: &str) -> Option<String> {
    html_tag_segments(html, "meta").into_iter().find_map(|tag| {
        let value = html_attr_value(tag, key_attr)?;
        if !value.eq_ignore_ascii_case(key_value) {
            return None;
        }
        normalize_html_text(&html_attr_value(tag, "content")?)
    })
}

#[cfg(feature = "link-preview")]
fn find_title_text(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let title_open_end = lower[start..].find('>')? + start + 1;
    let title_close = lower[title_open_end..].find("</title>")? + title_open_end;
    normalize_html_text(&html[title_open_end..title_close])
}

#[cfg(feature = "link-preview")]
fn html_tag_segments<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    let lower = html.to_ascii_lowercase();
    let pattern = format!("<{tag}");
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(found) = lower[offset..].find(&pattern) {
        let start = offset + found;
        let next = lower.as_bytes().get(start + pattern.len()).copied();
        if next.is_some_and(is_attr_name_byte) {
            offset = start + pattern.len();
            continue;
        }
        let Some(end) = lower[start..].find('>').map(|end| start + end + 1) else {
            break;
        };
        out.push(&html[start..end]);
        offset = end;
    }
    out
}

#[cfg(feature = "link-preview")]
fn html_attr_value(tag: &str, attr: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && !is_attr_name_byte(bytes[index]) {
            index += 1;
        }
        let name_start = index;
        while index < bytes.len() && is_attr_name_byte(bytes[index]) {
            index += 1;
        }
        if name_start == index {
            break;
        }
        let name = &tag[name_start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let value = if matches!(bytes[index], b'"' | b'\'') {
            let quote = bytes[index];
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            let value = tag[value_start..index].to_owned();
            if index < bytes.len() {
                index += 1;
            }
            value
        } else {
            let value_start = index;
            while index < bytes.len()
                && !bytes[index].is_ascii_whitespace()
                && !matches!(bytes[index], b'>')
            {
                index += 1;
            }
            tag[value_start..index].trim_end_matches('/').to_owned()
        };
        if name.eq_ignore_ascii_case(attr) {
            return Some(decode_html_entities(&value));
        }
    }
    None
}

#[cfg(feature = "link-preview")]
fn is_attr_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-')
}

#[cfg(feature = "link-preview")]
fn normalize_html_text(value: &str) -> Option<String> {
    let decoded = decode_html_entities(value);
    let normalized = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(feature = "link-preview")]
fn decode_html_entities(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(entity_start) = rest.find('&') {
        out.push_str(&rest[..entity_start]);
        let entity_rest = &rest[entity_start + 1..];
        let Some(entity_end) = entity_rest.find(';') else {
            out.push_str(&rest[entity_start..]);
            return out;
        };
        let entity = &entity_rest[..entity_end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            value if value.starts_with("#x") || value.starts_with("#X") => {
                u32::from_str_radix(&value[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            value if value.starts_with('#') => {
                value[1..].parse::<u32>().ok().and_then(char::from_u32)
            }
            _ => None,
        };
        if let Some(decoded) = decoded {
            out.push(decoded);
        } else {
            out.push('&');
            out.push_str(entity);
            out.push(';');
        }
        rest = &entity_rest[entity_end + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(feature = "link-preview")]
fn resolve_link_preview_url(base_url: &str, raw_url: &str) -> Option<String> {
    let raw_url = normalize_html_text(raw_url)?;
    let base = reqwest::Url::parse(base_url).ok()?;
    let resolved = base
        .join(&raw_url)
        .or_else(|_| reqwest::Url::parse(&raw_url))
        .ok()?;
    match resolved.scheme() {
        "http" | "https" => Some(resolved.to_string()),
        _ => None,
    }
}

#[cfg(feature = "link-preview")]
pub async fn upload_link_preview_thumbnail_cached<T, C>(
    transfer: &MediaTransfer<T>,
    jpeg_thumbnail: &[u8],
    dimensions: Option<(u32, u32)>,
    cache: &C,
) -> CoreResult<LinkPreviewThumbnail>
where
    T: MediaTransport,
    C: MediaUploadCache,
{
    validate_link_preview_thumbnail_plaintext(jpeg_thumbnail)?;
    let media = transfer
        .upload_bytes_cached(jpeg_thumbnail, wa_crypto::MediaKind::ThumbnailLink, cache)
        .await?;
    link_preview_thumbnail_from_uploaded_media(&media, dimensions)
}

#[cfg(feature = "link-preview")]
pub async fn upload_link_preview_thumbnail_file<T>(
    transfer: &MediaTransfer<T>,
    path: impl AsRef<Path>,
    dimensions: Option<(u32, u32)>,
) -> CoreResult<LinkPreviewThumbnail>
where
    T: MediaTransport,
{
    let media = transfer
        .upload_file(path, wa_crypto::MediaKind::ThumbnailLink)
        .await?;
    link_preview_thumbnail_from_uploaded_media(&media, dimensions)
}

#[cfg(feature = "link-preview")]
pub async fn upload_link_preview_thumbnail_file_cached<T, C>(
    transfer: &MediaTransfer<T>,
    path: impl AsRef<Path>,
    dimensions: Option<(u32, u32)>,
    cache: &C,
) -> CoreResult<LinkPreviewThumbnail>
where
    T: MediaTransport,
    C: MediaUploadCache,
{
    let media = transfer
        .upload_file_cached(path, wa_crypto::MediaKind::ThumbnailLink, cache)
        .await?;
    link_preview_thumbnail_from_uploaded_media(&media, dimensions)
}

#[cfg(all(feature = "link-preview", feature = "image"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedLinkPreviewThumbnailUpload {
    pub jpeg_thumbnail: Bytes,
    pub high_quality_thumbnail: LinkPreviewThumbnail,
    pub source_width: u32,
    pub source_height: u32,
    pub thumbnail_width: u32,
    pub thumbnail_height: u32,
    pub high_quality_width: u32,
    pub high_quality_height: u32,
}

#[cfg(all(feature = "noise", feature = "image"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedRemoteMediaThumbnailUpload {
    pub jpeg_thumbnail: Bytes,
    pub remote_thumbnail: RemoteMediaThumbnail,
    pub source_width: u32,
    pub source_height: u32,
    pub thumbnail_width: u32,
    pub thumbnail_height: u32,
}

#[cfg(all(feature = "noise", feature = "image"))]
pub async fn upload_generated_video_remote_thumbnail_file<T>(
    transfer: &MediaTransfer<T>,
    parent_media: &UploadedMedia,
    path: impl AsRef<Path>,
    options: crate::VideoThumbnailOptions,
) -> CoreResult<GeneratedRemoteMediaThumbnailUpload>
where
    T: MediaTransport,
{
    let generated = crate::generate_video_thumbnail_from_file(path, options)?;
    let remote_thumbnail = transfer
        .upload_video_remote_thumbnail(parent_media, &generated.jpeg)
        .await?
        .with_dimensions(generated.width, generated.height);
    Ok(generated_remote_media_thumbnail_upload(
        generated,
        remote_thumbnail,
    ))
}

#[cfg(all(feature = "noise", feature = "image"))]
pub async fn upload_generated_document_remote_thumbnail_file<T>(
    transfer: &MediaTransfer<T>,
    parent_media: &UploadedMedia,
    path: impl AsRef<Path>,
    options: crate::PdfThumbnailOptions,
) -> CoreResult<GeneratedRemoteMediaThumbnailUpload>
where
    T: MediaTransport,
{
    let generated = crate::generate_pdf_thumbnail_from_file(path, options)?;
    let remote_thumbnail = transfer
        .upload_document_remote_thumbnail(
            parent_media,
            &generated.jpeg,
            Some((generated.width, generated.height)),
        )
        .await?;
    Ok(generated_remote_media_thumbnail_upload(
        generated,
        remote_thumbnail,
    ))
}

#[cfg(all(feature = "link-preview", feature = "image"))]
pub async fn upload_generated_link_preview_thumbnail<T>(
    transfer: &MediaTransfer<T>,
    input: &[u8],
    options: crate::LinkPreviewImageOptions,
) -> CoreResult<GeneratedLinkPreviewThumbnailUpload>
where
    T: MediaTransport,
{
    let generated = crate::generate_link_preview_images(input, options)?;
    let high_quality_thumbnail = upload_link_preview_thumbnail(
        transfer,
        &generated.high_quality_jpeg,
        Some((generated.high_quality_width, generated.high_quality_height)),
    )
    .await?;
    Ok(generated_link_preview_thumbnail_upload(
        generated,
        high_quality_thumbnail,
    ))
}

#[cfg(all(feature = "link-preview", feature = "image"))]
pub async fn upload_generated_link_preview_thumbnail_cached<T, C>(
    transfer: &MediaTransfer<T>,
    input: &[u8],
    options: crate::LinkPreviewImageOptions,
    cache: &C,
) -> CoreResult<GeneratedLinkPreviewThumbnailUpload>
where
    T: MediaTransport,
    C: MediaUploadCache,
{
    let generated = crate::generate_link_preview_images(input, options)?;
    let high_quality_thumbnail = upload_link_preview_thumbnail_cached(
        transfer,
        &generated.high_quality_jpeg,
        Some((generated.high_quality_width, generated.high_quality_height)),
        cache,
    )
    .await?;
    Ok(generated_link_preview_thumbnail_upload(
        generated,
        high_quality_thumbnail,
    ))
}

#[cfg(all(feature = "link-preview", feature = "image"))]
pub async fn fetch_link_preview_with_thumbnail<T>(
    transfer: &MediaTransfer<T>,
    url: &str,
    options: LinkPreviewThumbnailFetchOptions,
) -> CoreResult<FetchedLinkPreviewWithThumbnail>
where
    T: MediaTransport,
{
    let mut preview = fetch_link_preview(url, options.metadata).await?;
    let image_url = preview
        .image_url
        .clone()
        .ok_or_else(|| CoreError::Payload("link preview HTML missing preview image".to_owned()))?;
    let image = fetch_link_preview_image(&image_url, options.image).await?;
    let thumbnail_upload =
        upload_generated_link_preview_thumbnail(transfer, &image, options.image_processing).await?;
    preview.content = preview
        .content
        .with_jpeg_thumbnail(thumbnail_upload.jpeg_thumbnail.clone())
        .with_high_quality_thumbnail(thumbnail_upload.high_quality_thumbnail.clone());
    Ok(FetchedLinkPreviewWithThumbnail {
        preview,
        thumbnail_upload,
    })
}

#[cfg(all(feature = "link-preview", feature = "image"))]
pub async fn fetch_link_preview_with_thumbnail_cached<T, C>(
    transfer: &MediaTransfer<T>,
    url: &str,
    options: LinkPreviewThumbnailFetchOptions,
    cache: &C,
) -> CoreResult<FetchedLinkPreviewWithThumbnail>
where
    T: MediaTransport,
    C: MediaUploadCache,
{
    let mut preview = fetch_link_preview(url, options.metadata).await?;
    let image_url = preview
        .image_url
        .clone()
        .ok_or_else(|| CoreError::Payload("link preview HTML missing preview image".to_owned()))?;
    let image = fetch_link_preview_image(&image_url, options.image).await?;
    let thumbnail_upload = upload_generated_link_preview_thumbnail_cached(
        transfer,
        &image,
        options.image_processing,
        cache,
    )
    .await?;
    preview.content = preview
        .content
        .with_jpeg_thumbnail(thumbnail_upload.jpeg_thumbnail.clone())
        .with_high_quality_thumbnail(thumbnail_upload.high_quality_thumbnail.clone());
    Ok(FetchedLinkPreviewWithThumbnail {
        preview,
        thumbnail_upload,
    })
}

#[cfg(all(feature = "link-preview", feature = "image"))]
fn generated_link_preview_thumbnail_upload(
    generated: crate::GeneratedLinkPreviewImages,
    high_quality_thumbnail: LinkPreviewThumbnail,
) -> GeneratedLinkPreviewThumbnailUpload {
    GeneratedLinkPreviewThumbnailUpload {
        jpeg_thumbnail: generated.jpeg_thumbnail,
        high_quality_thumbnail,
        source_width: generated.source_width,
        source_height: generated.source_height,
        thumbnail_width: generated.thumbnail_width,
        thumbnail_height: generated.thumbnail_height,
        high_quality_width: generated.high_quality_width,
        high_quality_height: generated.high_quality_height,
    }
}

#[cfg(all(feature = "noise", feature = "image"))]
fn generated_remote_media_thumbnail_upload(
    generated: crate::GeneratedJpegThumbnail,
    remote_thumbnail: RemoteMediaThumbnail,
) -> GeneratedRemoteMediaThumbnailUpload {
    GeneratedRemoteMediaThumbnailUpload {
        jpeg_thumbnail: generated.jpeg,
        remote_thumbnail,
        source_width: generated.source_width,
        source_height: generated.source_height,
        thumbnail_width: generated.width,
        thumbnail_height: generated.height,
    }
}

#[cfg(feature = "link-preview")]
fn validate_link_preview_thumbnail_plaintext(jpeg_thumbnail: &[u8]) -> CoreResult<()> {
    if jpeg_thumbnail.is_empty() {
        return Err(CoreError::Payload(
            "link preview thumbnail upload must not be empty".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "link-preview", feature = "noise"))]
fn validate_media_bytes_len(label: &str, bytes: &Bytes, expected: usize) -> CoreResult<()> {
    if bytes.len() != expected {
        return Err(CoreError::Payload(format!(
            "{label} must be {expected} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn validate_remote_thumbnail_upload(
    parent_media: &UploadedMedia,
    jpeg_thumbnail: &[u8],
    dimensions: Option<(u32, u32)>,
) -> CoreResult<()> {
    validate_media_bytes_len(
        "remote thumbnail parent media key",
        &parent_media.media_key,
        32,
    )?;
    if jpeg_thumbnail.is_empty() {
        return Err(CoreError::Payload(
            "remote thumbnail upload must not be empty".to_owned(),
        ));
    }
    validate_remote_thumbnail_dimensions(dimensions)
}

#[cfg(feature = "noise")]
fn validate_remote_thumbnail_dimensions(dimensions: Option<(u32, u32)>) -> CoreResult<()> {
    if let Some((width, height)) = dimensions
        && (width == 0 || height == 0)
    {
        return Err(CoreError::Payload(
            "remote thumbnail dimensions must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "noise")]
#[must_use]
pub fn pending_media_retry_store_key(key: &MessageEventKey) -> String {
    message_event_store_key(key)
}

#[cfg(feature = "noise")]
pub fn encode_stored_pending_media_retry(entry: &MediaRetryPendingEntry) -> CoreResult<Vec<u8>> {
    validate_media_retry_key(&entry.key)?;
    validate_pending_media_retry(&entry.pending)?;

    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_PENDING_MEDIA_RETRY_MAGIC);
    out.put_u8(STORED_PENDING_MEDIA_RETRY_VERSION);
    put_media_retry_key(&mut out, &entry.key)?;
    put_uploaded_media(&mut out, &entry.pending.media)?;
    out.put_u8(media_kind_cache_id(entry.pending.kind));
    put_optional_string(&mut out, entry.pending.fallback_host.as_deref())?;
    Ok(out.to_vec())
}

#[cfg(feature = "noise")]
pub fn decode_stored_pending_media_retry(value: &[u8]) -> CoreResult<MediaRetryPendingEntry> {
    validate_stored_pending_media_retry_len(value)?;
    let mut input = value;
    read_stored_pending_media_retry_magic(&mut input)?;
    let key = read_media_retry_key(&mut input)?;
    let media = read_uploaded_media(&mut input)?;
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored pending media retry missing media kind".to_owned(),
        ));
    }
    let kind = media_kind_from_cache_id(input.get_u8())?;
    let fallback_host = read_optional_string(&mut input)?;
    reject_trailing_pending_media_retry_bytes(input)?;

    let pending = PendingMediaRetry {
        media,
        kind,
        fallback_host,
    };
    validate_media_retry_key(&key)?;
    validate_pending_media_retry(&pending)?;
    Ok(MediaRetryPendingEntry { key, pending })
}

#[cfg(feature = "noise")]
pub fn apply_media_retry_event(
    retry: &MediaRetryEvent,
    media: &UploadedMedia,
) -> CoreResult<MediaRetryApplication> {
    if let Some(code) = retry.error_code {
        return Err(CoreError::Protocol(format!(
            "media retry returned error code {code} with status {}",
            retry.status_code.unwrap_or_default()
        )));
    }
    if retry.key.id.is_empty() {
        return Err(CoreError::Protocol(
            "media retry event missing stanza id".to_owned(),
        ));
    }

    let ciphertext = retry.encrypted_payload.as_ref().ok_or_else(|| {
        CoreError::Protocol("media retry event missing encrypted payload".to_owned())
    })?;
    let iv = retry
        .iv
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("media retry event missing IV".to_owned()))?;
    let payload = wa_crypto::MediaRetryPayload {
        ciphertext: ciphertext.clone(),
        iv: iv.clone(),
    };
    let notification =
        wa_crypto::decrypt_media_retry_notification(&payload, &media.media_key, &retry.key.id)
            .map_err(CoreError::Crypto)?;
    let stanza_id = notification.stanza_id.as_deref().ok_or_else(|| {
        CoreError::Protocol("media retry notification missing stanza id".to_owned())
    })?;
    if stanza_id != retry.key.id {
        return Err(CoreError::Protocol(format!(
            "media retry notification stanza id mismatch: expected {}, got {stanza_id}",
            retry.key.id
        )));
    }

    let proto_result = notification
        .result
        .and_then(|result| ProtoMediaRetryResult::try_from(result).ok())
        .ok_or_else(|| CoreError::Protocol("media retry notification missing result".to_owned()))?;
    let result = MediaRetryResult::from_proto(proto_result);
    let direct_path = notification
        .direct_path
        .filter(|direct_path| !direct_path.is_empty());
    let mut updated_media = media.clone();
    if result == MediaRetryResult::Success {
        let direct_path = direct_path.as_deref().ok_or_else(|| {
            CoreError::Protocol(
                "successful media retry notification missing direct path".to_owned(),
            )
        })?;
        updated_media.direct_path = Some(direct_path.to_owned());
    }

    Ok(MediaRetryApplication {
        result,
        status_code: result.status_code(),
        media: updated_media,
        direct_path,
        message_secret: notification.message_secret,
    })
}

#[cfg(feature = "noise")]
pub fn decrypt_and_verify_media_bytes(
    ciphertext_with_mac: &[u8],
    kind: wa_crypto::MediaKind,
    media: &UploadedMedia,
) -> CoreResult<Vec<u8>> {
    verify_media_ciphertext_hash(ciphertext_with_mac, &media.file_enc_sha256)?;
    let plaintext = wa_crypto::decrypt_media_bytes(ciphertext_with_mac, kind, &media.media_key)
        .map_err(CoreError::Crypto)?;
    verify_media_plaintext_hash(&plaintext, &media.file_sha256)?;
    Ok(plaintext)
}

#[cfg(feature = "noise")]
fn validate_media_transfer_limit(label: &str, len: usize, max: usize) -> CoreResult<()> {
    if max == 0 {
        return Err(CoreError::Payload(format!(
            "{label} size limit must be greater than zero"
        )));
    }
    if len > max {
        return Err(CoreError::Payload(format!(
            "{label} exceeds configured limit: {len} bytes exceeds {max}"
        )));
    }
    Ok(())
}

fn verify_sha256(input: &[u8], expected: &[u8], message: &str) -> CoreResult<()> {
    if expected.len() != 32 {
        return Err(CoreError::Payload(format!(
            "expected media SHA-256 must be 32 bytes, got {}",
            expected.len()
        )));
    }
    let digest: [u8; 32] = Sha256::digest(input).into();
    if !constant_time_eq(&digest, expected) {
        return Err(CoreError::Payload(message.to_owned()));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

#[cfg(feature = "noise")]
fn validate_cached_media_matches_key(
    key: &MediaUploadCacheKey,
    media: &UploadedMedia,
) -> CoreResult<()> {
    if media.url.as_deref().is_none_or(str::is_empty)
        && media.direct_path.as_deref().is_none_or(str::is_empty)
    {
        return Err(CoreError::Payload(
            "cached media requires a URL or direct path".to_owned(),
        ));
    }
    if media.file_length != key.file_length {
        return Err(CoreError::Payload(format!(
            "cached media length mismatch: expected {}, got {}",
            key.file_length, media.file_length
        )));
    }
    if !constant_time_eq(&key.file_sha256, &media.file_sha256) {
        return Err(CoreError::Payload(
            "cached media plaintext SHA-256 mismatch".to_owned(),
        ));
    }
    if media.media_key.len() != 32 {
        return Err(CoreError::Payload(format!(
            "cached media key must be 32 bytes, got {}",
            media.media_key.len()
        )));
    }
    if media.file_enc_sha256.len() != 32 {
        return Err(CoreError::Payload(format!(
            "cached media encrypted SHA-256 must be 32 bytes, got {}",
            media.file_enc_sha256.len()
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn validate_media_retry_key(key: &MessageEventKey) -> CoreResult<()> {
    if key.remote_jid.is_empty() {
        return Err(CoreError::Payload(
            "media retry key remote JID must not be empty".to_owned(),
        ));
    }
    if key.id.is_empty() {
        return Err(CoreError::Payload(
            "media retry key id must not be empty".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn validate_pending_media_retry(pending: &PendingMediaRetry) -> CoreResult<()> {
    if pending.media.media_key.len() != 32 {
        return Err(CoreError::Payload(format!(
            "pending media retry key must be 32 bytes, got {}",
            pending.media.media_key.len()
        )));
    }
    if pending.media.file_sha256.len() != 32 {
        return Err(CoreError::Payload(format!(
            "pending media retry plaintext SHA-256 must be 32 bytes, got {}",
            pending.media.file_sha256.len()
        )));
    }
    if pending.media.file_enc_sha256.len() != 32 {
        return Err(CoreError::Payload(format!(
            "pending media retry encrypted SHA-256 must be 32 bytes, got {}",
            pending.media.file_enc_sha256.len()
        )));
    }
    if let Some(host) = pending.fallback_host.as_deref()
        && host.is_empty()
    {
        return Err(CoreError::Payload(
            "pending media retry fallback host must not be empty".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn put_media_retry_key(out: &mut BytesMut, key: &MessageEventKey) -> CoreResult<()> {
    put_string(out, &key.remote_jid)?;
    put_string(out, &key.id)?;
    put_optional_string(out, key.participant.as_deref())
}

#[cfg(feature = "noise")]
fn read_media_retry_key(input: &mut &[u8]) -> CoreResult<MessageEventKey> {
    let remote_jid = read_string(input)?;
    let id = read_string(input)?;
    let participant = read_optional_string(input)?;
    Ok(MessageEventKey {
        remote_jid,
        id,
        participant,
    })
}

#[cfg(feature = "noise")]
fn put_uploaded_media(out: &mut BytesMut, media: &UploadedMedia) -> CoreResult<()> {
    put_optional_string(out, media.url.as_deref())?;
    put_optional_string(out, media.direct_path.as_deref())?;
    put_bytes(out, &media.media_key)?;
    put_bytes(out, &media.file_sha256)?;
    put_bytes(out, &media.file_enc_sha256)?;
    out.put_u64(media.file_length);
    put_optional_i64(out, media.media_key_timestamp);
    Ok(())
}

#[cfg(feature = "noise")]
fn read_uploaded_media(input: &mut &[u8]) -> CoreResult<UploadedMedia> {
    let url = read_optional_string(input)?;
    let direct_path = read_optional_string(input)?;
    let media_key = Bytes::from(read_bytes(input)?);
    let file_sha256 = Bytes::from(read_bytes(input)?);
    let file_enc_sha256 = Bytes::from(read_bytes(input)?);
    if input.remaining() < 8 {
        return Err(CoreError::Protocol(
            "stored pending media retry has truncated file length".to_owned(),
        ));
    }
    let file_length = input.get_u64();
    let media_key_timestamp = read_optional_i64(input)?;
    Ok(UploadedMedia {
        url,
        direct_path,
        media_key,
        file_sha256,
        file_enc_sha256,
        file_length,
        media_key_timestamp,
    })
}

#[cfg(feature = "noise")]
fn put_optional_i64(out: &mut BytesMut, value: Option<i64>) {
    match value {
        Some(value) => {
            out.put_u8(1);
            out.put_i64(value);
        }
        None => out.put_u8(0),
    }
}

#[cfg(feature = "noise")]
fn read_optional_i64(input: &mut &[u8]) -> CoreResult<Option<i64>> {
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored pending media retry missing optional i64 tag".to_owned(),
        ));
    }
    match input.get_u8() {
        0 => Ok(None),
        1 => {
            if input.remaining() < 8 {
                return Err(CoreError::Protocol(
                    "stored pending media retry has truncated i64".to_owned(),
                ));
            }
            Ok(Some(input.get_i64()))
        }
        tag => Err(CoreError::Protocol(format!(
            "stored pending media retry has invalid optional i64 tag {tag}"
        ))),
    }
}

#[cfg(feature = "noise")]
fn put_optional_string(out: &mut BytesMut, value: Option<&str>) -> CoreResult<()> {
    match value {
        Some(value) => {
            out.put_u8(1);
            put_string(out, value)
        }
        None => {
            out.put_u8(0);
            Ok(())
        }
    }
}

#[cfg(feature = "noise")]
fn read_optional_string(input: &mut &[u8]) -> CoreResult<Option<String>> {
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored pending media retry missing optional string tag".to_owned(),
        ));
    }
    match input.get_u8() {
        0 => Ok(None),
        1 => read_string(input).map(Some),
        tag => Err(CoreError::Protocol(format!(
            "stored pending media retry has invalid optional string tag {tag}"
        ))),
    }
}

#[cfg(feature = "noise")]
fn put_string(out: &mut BytesMut, value: &str) -> CoreResult<()> {
    put_bytes(out, value.as_bytes())
}

#[cfg(feature = "noise")]
fn read_string(input: &mut &[u8]) -> CoreResult<String> {
    let value = read_bytes(input)?;
    String::from_utf8(value).map_err(|_| {
        CoreError::Protocol("stored pending media retry contains invalid UTF-8".to_owned())
    })
}

#[cfg(feature = "noise")]
fn put_bytes(out: &mut BytesMut, value: &[u8]) -> CoreResult<()> {
    if value.len() > MAX_STORED_PENDING_MEDIA_RETRY_FIELD_BYTES {
        return Err(CoreError::Protocol(format!(
            "stored pending media retry field exceeds {MAX_STORED_PENDING_MEDIA_RETRY_FIELD_BYTES} bytes"
        )));
    }
    out.put_u32(u32::try_from(value.len()).map_err(|_| {
        CoreError::Protocol("stored pending media retry field length does not fit u32".to_owned())
    })?);
    out.extend_from_slice(value);
    Ok(())
}

#[cfg(feature = "noise")]
fn read_bytes(input: &mut &[u8]) -> CoreResult<Vec<u8>> {
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored pending media retry missing byte length".to_owned(),
        ));
    }
    let len = input.get_u32() as usize;
    if len > MAX_STORED_PENDING_MEDIA_RETRY_FIELD_BYTES {
        return Err(CoreError::Protocol(format!(
            "stored pending media retry field exceeds {MAX_STORED_PENDING_MEDIA_RETRY_FIELD_BYTES} bytes"
        )));
    }
    if input.remaining() < len {
        return Err(CoreError::Protocol(
            "stored pending media retry field is truncated".to_owned(),
        ));
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value.to_vec())
}

#[cfg(feature = "noise")]
fn validate_stored_pending_media_retry_len(value: &[u8]) -> CoreResult<()> {
    if value.len() > MAX_STORED_PENDING_MEDIA_RETRY_RECORD_BYTES {
        return Err(CoreError::Protocol(format!(
            "stored pending media retry record exceeds {MAX_STORED_PENDING_MEDIA_RETRY_RECORD_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn read_stored_pending_media_retry_magic(input: &mut &[u8]) -> CoreResult<()> {
    if input.len() < STORED_PENDING_MEDIA_RETRY_MAGIC.len() + 1 {
        return Err(CoreError::Protocol(
            "stored pending media retry record is truncated".to_owned(),
        ));
    }
    let (magic, rest) = input.split_at(STORED_PENDING_MEDIA_RETRY_MAGIC.len());
    if magic != STORED_PENDING_MEDIA_RETRY_MAGIC {
        return Err(CoreError::Protocol(
            "stored pending media retry record has invalid magic".to_owned(),
        ));
    }
    *input = rest;
    let version = input.get_u8();
    if version != STORED_PENDING_MEDIA_RETRY_VERSION {
        return Err(CoreError::Protocol(format!(
            "unsupported stored pending media retry version: {version}"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn reject_trailing_pending_media_retry_bytes(input: &[u8]) -> CoreResult<()> {
    if input.is_empty() {
        return Ok(());
    }
    Err(CoreError::Protocol(format!(
        "stored pending media retry has {} trailing bytes",
        input.len()
    )))
}

#[cfg(feature = "noise")]
fn media_kind_cache_id(kind: wa_crypto::MediaKind) -> u8 {
    match kind {
        wa_crypto::MediaKind::Audio => 0,
        wa_crypto::MediaKind::Document => 1,
        wa_crypto::MediaKind::Gif => 2,
        wa_crypto::MediaKind::Image => 3,
        wa_crypto::MediaKind::ProfilePicture => 4,
        wa_crypto::MediaKind::Product => 5,
        wa_crypto::MediaKind::PushToTalk => 6,
        wa_crypto::MediaKind::Sticker => 7,
        wa_crypto::MediaKind::Video => 8,
        wa_crypto::MediaKind::ThumbnailDocument => 9,
        wa_crypto::MediaKind::ThumbnailImage => 10,
        wa_crypto::MediaKind::ThumbnailVideo => 11,
        wa_crypto::MediaKind::ThumbnailLink => 12,
        wa_crypto::MediaKind::HistorySync => 13,
        wa_crypto::MediaKind::AppState => 14,
        wa_crypto::MediaKind::ProductCatalogImage => 15,
        wa_crypto::MediaKind::PaymentBackgroundImage => 16,
        wa_crypto::MediaKind::VideoNote => 17,
        wa_crypto::MediaKind::BusinessCoverPhoto => 18,
    }
}

#[cfg(feature = "noise")]
fn media_kind_from_cache_id(value: u8) -> CoreResult<wa_crypto::MediaKind> {
    match value {
        0 => Ok(wa_crypto::MediaKind::Audio),
        1 => Ok(wa_crypto::MediaKind::Document),
        2 => Ok(wa_crypto::MediaKind::Gif),
        3 => Ok(wa_crypto::MediaKind::Image),
        4 => Ok(wa_crypto::MediaKind::ProfilePicture),
        5 => Ok(wa_crypto::MediaKind::Product),
        6 => Ok(wa_crypto::MediaKind::PushToTalk),
        7 => Ok(wa_crypto::MediaKind::Sticker),
        8 => Ok(wa_crypto::MediaKind::Video),
        9 => Ok(wa_crypto::MediaKind::ThumbnailDocument),
        10 => Ok(wa_crypto::MediaKind::ThumbnailImage),
        11 => Ok(wa_crypto::MediaKind::ThumbnailVideo),
        12 => Ok(wa_crypto::MediaKind::ThumbnailLink),
        13 => Ok(wa_crypto::MediaKind::HistorySync),
        14 => Ok(wa_crypto::MediaKind::AppState),
        15 => Ok(wa_crypto::MediaKind::ProductCatalogImage),
        16 => Ok(wa_crypto::MediaKind::PaymentBackgroundImage),
        17 => Ok(wa_crypto::MediaKind::VideoNote),
        18 => Ok(wa_crypto::MediaKind::BusinessCoverPhoto),
        value => Err(CoreError::Protocol(format!(
            "stored pending media retry has invalid media kind {value}"
        ))),
    }
}

#[cfg(feature = "noise")]
fn system_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(feature = "noise")]
async fn read_file_limited(path: &Path, max_bytes: usize, label: &str) -> CoreResult<Vec<u8>> {
    validate_media_transfer_limit(label, 0, max_bytes)?;
    let metadata = tokio::fs::metadata(path).await?;
    if !metadata.is_file() {
        return Err(CoreError::Payload(format!(
            "{label} path is not a regular file"
        )));
    }
    let file_len = usize::try_from(metadata.len()).map_err(|_| {
        CoreError::Payload(format!(
            "{label} is too large for this platform: {} bytes",
            metadata.len()
        ))
    })?;
    validate_media_transfer_limit(label, file_len, max_bytes)?;

    let mut file = File::open(path).await?;
    let mut out = Vec::with_capacity(file_len);
    let mut buffer = vec![0u8; DEFAULT_MEDIA_FILE_CHUNK_BYTES.min(max_bytes.max(1))];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        if out.len().saturating_add(read) > max_bytes {
            return Err(CoreError::Payload(format!(
                "{label} exceeds configured limit while reading: {} bytes exceeds {max_bytes}",
                out.len().saturating_add(read)
            )));
        }
        out.extend_from_slice(&buffer[..read]);
    }
    Ok(out)
}

#[cfg(feature = "noise")]
async fn write_bytes_to_file(path: &Path, bytes: &[u8]) -> CoreResult<u64> {
    let mut file = File::create(path).await?;
    for chunk in bytes.chunks(DEFAULT_MEDIA_FILE_CHUNK_BYTES) {
        file.write_all(chunk).await?;
    }
    file.flush().await?;
    u64::try_from(bytes.len())
        .map_err(|_| CoreError::Payload("file byte count overflow".to_owned()))
}

#[cfg(feature = "noise")]
async fn encrypt_file_to_temp_limited(
    path: &Path,
    kind: wa_crypto::MediaKind,
    max_plaintext_bytes: usize,
    max_ciphertext_bytes: usize,
    label: &str,
    temp_path: &Path,
) -> CoreResult<(wa_crypto::MediaEncryptionMetadata, u64)> {
    validate_media_transfer_limit(label, 0, max_plaintext_bytes)?;
    validate_media_transfer_limit("encrypted media upload", 0, max_ciphertext_bytes)?;
    let metadata = tokio::fs::metadata(path).await?;
    if !metadata.is_file() {
        return Err(CoreError::Payload(format!(
            "{label} path is not a regular file"
        )));
    }
    let file_len = usize::try_from(metadata.len()).map_err(|_| {
        CoreError::Payload(format!(
            "{label} is too large for this platform: {} bytes",
            metadata.len()
        ))
    })?;
    validate_media_transfer_limit(label, file_len, max_plaintext_bytes)?;

    let padded_len = file_len
        .checked_add(16 - (file_len % 16))
        .and_then(|len| len.checked_add(10))
        .ok_or_else(|| CoreError::Payload(format!("{label} encrypted length overflow")))?;
    validate_media_transfer_limit("encrypted media upload", padded_len, max_ciphertext_bytes)?;

    let mut file = File::open(path).await?;
    let mut encryptor = wa_crypto::MediaStreamEncryptor::new(kind).map_err(CoreError::Crypto)?;
    let mut encrypted_file = File::create(temp_path).await?;
    let mut encrypted_hash = Sha256::new();
    let mut written = 0usize;
    let mut buffer = vec![0u8; DEFAULT_MEDIA_FILE_CHUNK_BYTES.min(max_plaintext_bytes.max(1))];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let chunk = encryptor
            .update(&buffer[..read])
            .map_err(CoreError::Crypto)?;
        if written.saturating_add(chunk.len()) > max_ciphertext_bytes {
            return Err(CoreError::Payload(format!(
                "encrypted media upload exceeds configured limit while encrypting: {} bytes exceeds {max_ciphertext_bytes}",
                written.saturating_add(chunk.len())
            )));
        }
        if !chunk.is_empty() {
            encrypted_hash.update(&chunk);
            encrypted_file.write_all(&chunk).await?;
            written = written.saturating_add(chunk.len());
        }
    }

    let final_chunk = encryptor.finalize().map_err(CoreError::Crypto)?;
    if written.saturating_add(final_chunk.final_bytes.len()) > max_ciphertext_bytes {
        return Err(CoreError::Payload(format!(
            "encrypted media upload exceeds configured limit while finalizing: {} bytes exceeds {max_ciphertext_bytes}",
            written.saturating_add(final_chunk.final_bytes.len())
        )));
    }
    encrypted_hash.update(&final_chunk.final_bytes);
    encrypted_file.write_all(&final_chunk.final_bytes).await?;
    encrypted_file.flush().await?;
    written = written.saturating_add(final_chunk.final_bytes.len());
    let actual_hash = encrypted_hash.finalize();
    if !constant_time_eq(&actual_hash, &final_chunk.metadata.file_enc_sha256) {
        return Err(CoreError::Payload(
            "media encrypted SHA-256 mismatch".to_owned(),
        ));
    }
    let written = u64::try_from(written)
        .map_err(|_| CoreError::Payload("encrypted media byte count overflow".to_owned()))?;
    Ok((final_chunk.metadata, written))
}

#[cfg(feature = "noise")]
async fn decrypt_media_file_to_file(
    ciphertext_path: &Path,
    kind: wa_crypto::MediaKind,
    media: &UploadedMedia,
    path: &Path,
) -> CoreResult<u64> {
    let temp_path = temp_media_path(path);
    let result = decrypt_media_file_to_temp_file(ciphertext_path, kind, media, &temp_path).await;
    match result {
        Ok(written) => {
            tokio::fs::rename(&temp_path, path).await?;
            Ok(written)
        }
        Err(err) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            Err(err)
        }
    }
}

#[cfg(feature = "noise")]
async fn decrypt_media_file_to_temp_file(
    ciphertext_path: &Path,
    kind: wa_crypto::MediaKind,
    media: &UploadedMedia,
    temp_path: &Path,
) -> CoreResult<u64> {
    let metadata = tokio::fs::metadata(ciphertext_path).await?;
    if !metadata.is_file() {
        return Err(CoreError::Payload(
            "encrypted media download path is not a regular file".to_owned(),
        ));
    }
    if metadata.len() <= 10 {
        return Err(CoreError::Crypto(
            wa_crypto::CryptoError::CiphertextTooShort,
        ));
    }

    let mut encrypted_file = File::open(ciphertext_path).await?;
    let mut decryptor =
        wa_crypto::MediaStreamDecryptor::new(kind, &media.media_key).map_err(CoreError::Crypto)?;
    let mut encrypted_hash = Sha256::new();
    let mut plaintext_hash = Sha256::new();
    let mut written = 0u64;
    let mut file = File::create(temp_path).await?;

    let mut buffer = vec![0u8; DEFAULT_MEDIA_FILE_CHUNK_BYTES];
    loop {
        let read = encrypted_file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        encrypted_hash.update(chunk);
        let plaintext = decryptor.update(chunk).map_err(CoreError::Crypto)?;
        if !plaintext.is_empty() {
            plaintext_hash.update(&plaintext);
            file.write_all(&plaintext).await?;
            written = written
                .checked_add(u64::try_from(plaintext.len()).map_err(|_| {
                    CoreError::Payload("downloaded media byte count overflow".to_owned())
                })?)
                .ok_or_else(|| {
                    CoreError::Payload("downloaded media byte count overflow".to_owned())
                })?;
        }
    }
    let final_plaintext = decryptor.finalize().map_err(CoreError::Crypto)?;
    if !final_plaintext.is_empty() {
        plaintext_hash.update(&final_plaintext);
        file.write_all(&final_plaintext).await?;
        written = written
            .checked_add(u64::try_from(final_plaintext.len()).map_err(|_| {
                CoreError::Payload("downloaded media byte count overflow".to_owned())
            })?)
            .ok_or_else(|| CoreError::Payload("downloaded media byte count overflow".to_owned()))?;
    }
    file.flush().await?;
    let actual_encrypted_hash = encrypted_hash.finalize();
    if !constant_time_eq(&actual_encrypted_hash, &media.file_enc_sha256) {
        return Err(CoreError::Payload(
            "media encrypted SHA-256 mismatch".to_owned(),
        ));
    }
    let actual_hash = plaintext_hash.finalize();
    if !constant_time_eq(&actual_hash, &media.file_sha256) {
        return Err(CoreError::Payload(
            "media plaintext SHA-256 mismatch".to_owned(),
        ));
    }
    Ok(written)
}

#[cfg(feature = "noise")]
fn temp_media_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_else(|| std::ffi::OsString::from("media-download"));
    file_name.push(format!(".{}.tmp", rand::random::<u128>()));
    path.with_file_name(file_name)
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    child_nodes(node, tag).into_iter().next()
}

fn child_nodes<'a>(node: &'a BinaryNode, tag: &str) -> Vec<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return Vec::new();
    };
    children.iter().filter(|child| child.tag == tag).collect()
}

fn required_attr<'a>(node: &'a BinaryNode, name: &str) -> CoreResult<&'a str> {
    node.attrs.get(name).map(String::as_str).ok_or_else(|| {
        CoreError::Protocol(format!(
            "node {} missing required attribute {name}",
            node.tag
        ))
    })
}

fn media_connection_error_from_result(node: &BinaryNode) -> Option<CoreError> {
    let error_node = child_node(node, "error");
    if node.attrs.get("type").is_none_or(|value| value != "error") && error_node.is_none() {
        return None;
    }
    let code = error_node
        .and_then(|error| error.attrs.get("code"))
        .or_else(|| node.attrs.get("code"))
        .or_else(|| node.attrs.get("error"))
        .map(String::as_str)
        .unwrap_or("500");
    let text = error_node
        .and_then(|error| error.attrs.get("text"))
        .or_else(|| node.attrs.get("text"))
        .or_else(|| node.attrs.get("reason"))
        .map(String::as_str)
        .unwrap_or("media connection query failed");
    Some(CoreError::Protocol(format!(
        "media connection query failed ({code}): {text}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "noise")]
    use async_trait::async_trait;
    #[cfg(feature = "noise")]
    use std::collections::BTreeMap;
    #[cfg(feature = "noise")]
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    #[cfg(feature = "noise")]
    use std::sync::{Arc, Mutex};
    #[cfg(all(feature = "noise", feature = "http-media"))]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(all(feature = "noise", feature = "http-media"))]
    use tokio::net::TcpListener;

    #[test]
    fn builds_media_download_urls() {
        assert_eq!(
            media_url_from_direct_path("/v/t62/file", None),
            "https://mmg.whatsapp.net/v/t62/file"
        );
        assert_eq!(
            media_download_url(
                Some("/v/t62/file"),
                Some("https://fallback"),
                Some("cdn.example")
            )
            .unwrap(),
            "https://cdn.example/v/t62/file"
        );
        assert_eq!(
            media_download_url(None, Some("https://media.example/file"), None).unwrap(),
            "https://media.example/file"
        );
        assert!(media_download_url(None, None, None).is_err());
    }

    #[test]
    fn builds_and_parses_media_connection_query() {
        let query = build_media_connection_query("media-1");
        assert_eq!(query.tag, "iq");
        assert_eq!(query.attrs["id"], "media-1");
        assert_eq!(query.attrs["type"], "set");
        assert_eq!(query.attrs["xmlns"], "w:m");
        assert_eq!(query.attrs["to"], S_WHATSAPP_NET);

        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("media_conn")
                .with_attr("auth", "auth-token")
                .with_attr("ttl", "120")
                .with_content(vec![
                    BinaryNode::new("host")
                        .with_attr("hostname", "media-a.example")
                        .with_attr("maxContentLengthBytes", "1024"),
                    BinaryNode::new("host").with_attr("hostname", "media-b.example"),
                ]),
        ]);
        let parsed = parse_media_connection_info(&response).unwrap();

        assert_eq!(parsed.auth, "auth-token");
        assert_eq!(parsed.ttl_seconds, 120);
        assert_eq!(parsed.hosts.len(), 2);
        assert_eq!(parsed.hosts[0].hostname, "media-a.example");
        assert_eq!(parsed.hosts[0].max_content_length_bytes, Some(1024));
        assert_eq!(parsed.hosts[1].hostname, "media-b.example");
        assert!(parse_media_connection_info(&BinaryNode::new("iq")).is_err());

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "401")
            .with_attr("text", "media denied");
        let err = parse_media_connection_info(&attr_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("media connection query failed (401): media denied")
        );

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "503")
                    .with_attr("text", "try later"),
            ]);
        let err = parse_media_connection_info(&child_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("media connection query failed (503): try later")
        );
    }

    #[test]
    fn verifies_media_hashes() {
        let plaintext = b"media";
        let digest: [u8; 32] = Sha256::digest(plaintext).into();
        verify_media_plaintext_hash(plaintext, &digest).unwrap();
        assert!(verify_media_plaintext_hash(b"changed", &digest).is_err());
        assert!(verify_media_ciphertext_hash(b"ciphertext", &[1u8; 31]).is_err());
    }

    #[cfg(feature = "noise")]
    #[test]
    fn converts_encrypted_media_to_upload_metadata_and_decrypts() {
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"plaintext",
            wa_crypto::MediaKind::Image,
            &[9u8; 32],
        )
        .unwrap();
        let metadata = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new()
                .with_direct_path("/v/t62/file")
                .with_media_key_timestamp(1_700_000_000),
        )
        .unwrap();

        assert_eq!(metadata.direct_path.as_deref(), Some("/v/t62/file"));
        assert_eq!(metadata.media_key, Bytes::from(vec![9u8; 32]));
        assert_eq!(metadata.file_length, 9);

        let plaintext = decrypt_and_verify_media_bytes(
            &encrypted.ciphertext_with_mac,
            wa_crypto::MediaKind::Image,
            &metadata,
        )
        .unwrap();
        assert_eq!(plaintext, b"plaintext");

        let mut tampered = metadata.clone();
        tampered.file_sha256 = Bytes::from(vec![1u8; 32]);
        assert!(
            decrypt_and_verify_media_bytes(
                &encrypted.ciphertext_with_mac,
                wa_crypto::MediaKind::Image,
                &tampered,
            )
            .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn uploads_remote_media_thumbnails_with_parent_media_key() {
        let parent_key = [9u8; 32];
        let encrypted_parent = wa_crypto::encrypt_media_bytes_with_key(
            b"parent video",
            wa_crypto::MediaKind::Video,
            &parent_key,
        )
        .unwrap();
        let parent_media = uploaded_media_from_encrypted(
            &encrypted_parent,
            UploadedMediaLocation::new().with_direct_path("/v/t62/parent"),
        )
        .unwrap();
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let video_thumbnail = transfer
            .upload_video_remote_thumbnail(&parent_media, b"video thumbnail")
            .await
            .unwrap();
        let document_thumbnail = transfer
            .upload_document_remote_thumbnail(&parent_media, b"document thumbnail", Some((64, 32)))
            .await
            .unwrap();

        assert_eq!(video_thumbnail.direct_path, "/v/t62/upload");
        assert_eq!(video_thumbnail.sha256.len(), 32);
        assert_eq!(video_thumbnail.enc_sha256.len(), 32);
        assert_eq!(document_thumbnail.width, Some(64));
        assert_eq!(document_thumbnail.height, Some(32));

        {
            let uploads = transport.uploads.lock().unwrap();
            assert_eq!(uploads.len(), 2);
            assert_eq!(uploads[0].kind, wa_crypto::MediaKind::ThumbnailVideo);
            assert_eq!(uploads[0].file_sha256, video_thumbnail.sha256);
            assert_eq!(uploads[0].file_enc_sha256, video_thumbnail.enc_sha256);
            assert_eq!(
                wa_crypto::decrypt_media_bytes(
                    &uploads[0].ciphertext_with_mac,
                    wa_crypto::MediaKind::ThumbnailVideo,
                    &parent_media.media_key,
                )
                .unwrap(),
                b"video thumbnail"
            );
            assert_eq!(uploads[1].kind, wa_crypto::MediaKind::ThumbnailDocument);
            assert_eq!(uploads[1].file_sha256, document_thumbnail.sha256);
            assert_eq!(uploads[1].file_enc_sha256, document_thumbnail.enc_sha256);
            assert_eq!(
                wa_crypto::decrypt_media_bytes(
                    &uploads[1].ciphertext_with_mac,
                    wa_crypto::MediaKind::ThumbnailDocument,
                    &parent_media.media_key,
                )
                .unwrap(),
                b"document thumbnail"
            );
        }

        assert!(
            transfer
                .upload_document_remote_thumbnail(
                    &parent_media,
                    b"document thumbnail",
                    Some((0, 1))
                )
                .await
                .is_err()
        );
    }

    #[cfg(all(feature = "noise", feature = "image", unix))]
    #[tokio::test]
    async fn uploads_generated_remote_media_thumbnails_from_extractors() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = test_media_path("generated-remote-thumbnails");
        std::fs::create_dir_all(&dir).unwrap();
        let frame_path = dir.join("frame.jpg");
        let video_path = dir.join("video.mp4");
        let pdf_path = dir.join("document.pdf");
        let ffmpeg_path = dir.join("fake-ffmpeg");
        let renderer_path = dir.join("fake-pdftoppm");
        std::fs::write(&frame_path, sample_media_jpeg(96, 48)).unwrap();
        std::fs::write(&video_path, b"fake video").unwrap();
        std::fs::write(&pdf_path, b"%PDF-1.7\n").unwrap();
        std::fs::write(
            &ffmpeg_path,
            format!(
                "#!/bin/sh\nset -eu\nout=\"\"\nfor arg do out=\"$arg\"; done\ncp {} \"$out\"\n",
                shell_quote(&frame_path),
            ),
        )
        .unwrap();
        std::fs::write(
            &renderer_path,
            format!(
                "#!/bin/sh\nset -eu\nout=\"\"\nfor arg do out=\"$arg\"; done\ncp {} \"$out.jpg\"\n",
                shell_quote(&frame_path),
            ),
        )
        .unwrap();
        for command_path in [&ffmpeg_path, &renderer_path] {
            let mut permissions = std::fs::metadata(command_path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(command_path, permissions).unwrap();
        }

        let video_key = [9u8; 32];
        let document_key = [10u8; 32];
        let video_parent = uploaded_media_from_encrypted(
            &wa_crypto::encrypt_media_bytes_with_key(
                b"parent video",
                wa_crypto::MediaKind::Video,
                &video_key,
            )
            .unwrap(),
            UploadedMediaLocation::new().with_direct_path("/generated/video"),
        )
        .unwrap();
        let document_parent = uploaded_media_from_encrypted(
            &wa_crypto::encrypt_media_bytes_with_key(
                b"parent document",
                wa_crypto::MediaKind::Document,
                &document_key,
            )
            .unwrap(),
            UploadedMediaLocation::new().with_direct_path("/generated/document"),
        )
        .unwrap();
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let video_upload = upload_generated_video_remote_thumbnail_file(
            &transfer,
            &video_parent,
            &video_path,
            crate::VideoThumbnailOptions {
                ffmpeg_path,
                temp_dir: Some(dir.clone()),
                ..crate::VideoThumbnailOptions::default()
            },
        )
        .await
        .unwrap();
        let document_upload = upload_generated_document_remote_thumbnail_file(
            &transfer,
            &document_parent,
            &pdf_path,
            crate::PdfThumbnailOptions {
                pdftoppm_path: renderer_path,
                temp_dir: Some(dir.clone()),
                ..crate::PdfThumbnailOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(video_upload.source_width, 96);
        assert_eq!(video_upload.source_height, 48);
        assert_eq!(video_upload.thumbnail_width, 32);
        assert_eq!(video_upload.thumbnail_height, 16);
        assert_eq!(video_upload.remote_thumbnail.width, Some(32));
        assert_eq!(video_upload.remote_thumbnail.height, Some(16));
        assert_eq!(document_upload.remote_thumbnail.width, Some(32));
        assert_eq!(document_upload.remote_thumbnail.height, Some(16));

        let uploads = transport.uploads.lock().unwrap();
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[0].kind, wa_crypto::MediaKind::ThumbnailVideo);
        assert_eq!(uploads[0].file_sha256, video_upload.remote_thumbnail.sha256);
        assert_eq!(
            wa_crypto::decrypt_media_bytes(
                &uploads[0].ciphertext_with_mac,
                wa_crypto::MediaKind::ThumbnailVideo,
                &video_parent.media_key,
            )
            .unwrap(),
            video_upload.jpeg_thumbnail
        );
        assert_eq!(uploads[1].kind, wa_crypto::MediaKind::ThumbnailDocument);
        assert_eq!(
            uploads[1].file_enc_sha256,
            document_upload.remote_thumbnail.enc_sha256
        );
        assert_eq!(
            wa_crypto::decrypt_media_bytes(
                &uploads[1].ciphertext_with_mac,
                wa_crypto::MediaKind::ThumbnailDocument,
                &document_parent.media_key,
            )
            .unwrap(),
            document_upload.jpeg_thumbnail
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "link-preview")]
    #[tokio::test]
    async fn uploads_link_preview_thumbnail_with_thumbnail_link_kind() {
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let thumbnail = upload_link_preview_thumbnail(&transfer, b"preview jpeg", Some((320, 180)))
            .await
            .unwrap();

        assert_eq!(thumbnail.direct_path, "/v/t62/upload");
        assert_eq!(thumbnail.media_key.len(), 32);
        assert_eq!(thumbnail.sha256.len(), 32);
        assert_eq!(thumbnail.enc_sha256.len(), 32);
        assert_eq!(thumbnail.width, Some(320));
        assert_eq!(thumbnail.height, Some(180));
        assert_eq!(
            transport.uploads.lock().unwrap()[0].kind,
            wa_crypto::MediaKind::ThumbnailLink
        );

        let message = crate::build_text_message(
            crate::TextMessage::new("See https://example.invalid").with_link_preview(
                crate::LinkPreviewContent::new("https://example.invalid", "Example")
                    .with_jpeg_thumbnail(Bytes::from_static(b"tiny"))
                    .with_high_quality_thumbnail(thumbnail),
            ),
        )
        .unwrap();
        let extended = message.extended_text_message.unwrap();
        assert_eq!(
            extended.thumbnail_direct_path.as_deref(),
            Some("/v/t62/upload")
        );
        assert_eq!(extended.thumbnail_width, Some(320));
        assert_eq!(extended.thumbnail_height, Some(180));
    }

    #[cfg(feature = "link-preview")]
    #[tokio::test]
    async fn fetches_link_preview_metadata_from_html() {
        let base = serve_link_preview_response(
            r#"<!doctype html>
            <html>
              <head>
                <meta property="og:title" content="Example &amp; Preview">
                <meta name="description" content="A compact description">
                <meta property="og:image" content="/images/card.jpg">
              </head>
            </html>"#
                .to_owned(),
            "text/html; charset=utf-8",
        )
        .await;
        let url = format!("{base}/post");

        let fetched = fetch_link_preview(&url, LinkPreviewFetchOptions::default())
            .await
            .unwrap();

        assert_eq!(fetched.final_url, url);
        assert_eq!(fetched.image_url, Some(format!("{base}/images/card.jpg")));
        assert_eq!(fetched.content.matched_text, url);
        assert_eq!(fetched.content.title, "Example & Preview");
        assert_eq!(
            fetched.content.description.as_deref(),
            Some("A compact description")
        );
        let message = crate::build_text_message(
            crate::TextMessage::new("see link").with_link_preview(fetched.content),
        )
        .unwrap();
        let extended = message.extended_text_message.unwrap();
        assert_eq!(extended.title.as_deref(), Some("Example & Preview"));
        assert_eq!(
            extended.description.as_deref(),
            Some("A compact description")
        );
    }

    #[cfg(feature = "link-preview")]
    #[tokio::test]
    async fn fetch_link_preview_rejects_oversized_html() {
        let base = serve_link_preview_response(
            "<html><title>Too Large</title></html>".to_owned(),
            "text/html",
        )
        .await;
        let options = LinkPreviewFetchOptions {
            max_html_bytes: 8,
            ..LinkPreviewFetchOptions::default()
        };

        assert!(fetch_link_preview(&base, options).await.is_err());
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    #[tokio::test]
    async fn fetches_link_preview_image_and_uploads_thumbnail() {
        use image::codecs::jpeg::JpegEncoder;
        use image::{Rgb, RgbImage};

        let source_image = RgbImage::from_fn(240, 120, |x, y| {
            Rgb([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8])
        });
        let mut source = Vec::new();
        JpegEncoder::new_with_quality(&mut source, 90)
            .encode_image(&source_image)
            .unwrap();

        let base = serve_link_preview_routes(vec![
            LinkPreviewTestRoute::new(
                "/post",
                r#"<!doctype html>
                <html>
                  <head>
                    <meta property="og:title" content="Image Preview">
                    <meta property="og:image" content="/card.jpg">
                  </head>
                </html>"#
                    .as_bytes()
                    .to_vec(),
                "text/html; charset=utf-8",
            ),
            LinkPreviewTestRoute::new("/card.jpg", source, "image/jpeg"),
        ])
        .await;
        let url = format!("{base}/post");
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let fetched = fetch_link_preview_with_thumbnail(
            &transfer,
            &url,
            LinkPreviewThumbnailFetchOptions {
                image_processing: crate::LinkPreviewImageOptions {
                    high_quality_max_width: 120,
                    high_quality_max_height: 120,
                    ..crate::LinkPreviewImageOptions::default()
                },
                ..LinkPreviewThumbnailFetchOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(fetched.preview.final_url, url);
        assert_eq!(fetched.preview.image_url, Some(format!("{base}/card.jpg")));
        assert_eq!(fetched.preview.content.title, "Image Preview");
        assert_eq!(fetched.thumbnail_upload.source_width, 240);
        assert_eq!(fetched.thumbnail_upload.source_height, 120);
        assert_eq!(fetched.thumbnail_upload.thumbnail_width, 32);
        assert_eq!(fetched.thumbnail_upload.thumbnail_height, 16);
        assert_eq!(fetched.thumbnail_upload.high_quality_width, 120);
        assert_eq!(fetched.thumbnail_upload.high_quality_height, 60);
        assert!(
            fetched
                .preview
                .content
                .jpeg_thumbnail
                .as_ref()
                .unwrap()
                .starts_with(&[0xff, 0xd8])
        );
        let high_quality = fetched
            .preview
            .content
            .high_quality_thumbnail
            .as_ref()
            .unwrap();
        assert_eq!(high_quality.direct_path, "/v/t62/upload");
        assert_eq!(high_quality.width, Some(120));
        assert_eq!(high_quality.height, Some(60));
        assert_eq!(
            transport.uploads.lock().unwrap()[0].kind,
            wa_crypto::MediaKind::ThumbnailLink
        );

        let message = crate::build_text_message(
            crate::TextMessage::new("see link").with_link_preview(fetched.preview.content),
        )
        .unwrap();
        let extended = message.extended_text_message.unwrap();
        assert!(extended.jpeg_thumbnail.unwrap().starts_with(&[0xff, 0xd8]));
        assert_eq!(
            extended.thumbnail_direct_path.as_deref(),
            Some("/v/t62/upload")
        );
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    #[tokio::test]
    async fn fetch_link_preview_with_thumbnail_rejects_oversized_image() {
        let base = serve_link_preview_routes(vec![
            LinkPreviewTestRoute::new(
                "/post",
                br#"<html><head><title>Large Image</title><meta property="og:image" content="/card.jpg"></head></html>"#.to_vec(),
                "text/html",
            ),
            LinkPreviewTestRoute::new("/card.jpg", vec![7u8; 32], "image/jpeg"),
        ])
        .await;
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let result = fetch_link_preview_with_thumbnail(
            &transfer,
            &format!("{base}/post"),
            LinkPreviewThumbnailFetchOptions {
                image: LinkPreviewImageFetchOptions {
                    max_image_bytes: 8,
                    ..LinkPreviewImageFetchOptions::default()
                },
                ..LinkPreviewThumbnailFetchOptions::default()
            },
        )
        .await;

        assert_eq!(
            result.unwrap_err().to_string(),
            "payload error: link preview image exceeds 8 bytes"
        );
        assert!(transport.uploads.lock().unwrap().is_empty());
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    #[tokio::test]
    async fn fetch_link_preview_with_thumbnail_cached_reuses_high_quality_upload() {
        use image::codecs::jpeg::JpegEncoder;
        use image::{Rgb, RgbImage};

        let source_image = RgbImage::from_fn(240, 120, |x, y| {
            Rgb([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8])
        });
        let mut source = Vec::new();
        JpegEncoder::new_with_quality(&mut source, 90)
            .encode_image(&source_image)
            .unwrap();

        let html = r#"<!doctype html>
            <html>
              <head>
                <meta property="og:title" content="Cached Image Preview">
                <meta property="og:image" content="/card.jpg">
              </head>
            </html>"#;
        let base = serve_link_preview_routes(vec![
            LinkPreviewTestRoute::new("/post", html.as_bytes().to_vec(), "text/html"),
            LinkPreviewTestRoute::new("/card.jpg", source.clone(), "image/jpeg"),
            LinkPreviewTestRoute::new("/post", html.as_bytes().to_vec(), "text/html"),
            LinkPreviewTestRoute::new("/card.jpg", source, "image/jpeg"),
        ])
        .await;
        let url = format!("{base}/post");
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());
        let cache = MemoryMediaUploadCache::default();
        let options = LinkPreviewThumbnailFetchOptions {
            image_processing: crate::LinkPreviewImageOptions {
                high_quality_max_width: 120,
                high_quality_max_height: 120,
                ..crate::LinkPreviewImageOptions::default()
            },
            ..LinkPreviewThumbnailFetchOptions::default()
        };

        let first =
            fetch_link_preview_with_thumbnail_cached(&transfer, &url, options.clone(), &cache)
                .await
                .unwrap();
        let second = fetch_link_preview_with_thumbnail_cached(&transfer, &url, options, &cache)
            .await
            .unwrap();

        assert_eq!(first.preview.content.title, "Cached Image Preview");
        assert_eq!(second.preview.content.title, "Cached Image Preview");
        assert_eq!(
            first.thumbnail_upload.jpeg_thumbnail,
            second.thumbnail_upload.jpeg_thumbnail
        );
        assert_eq!(
            first.thumbnail_upload.high_quality_thumbnail,
            second.thumbnail_upload.high_quality_thumbnail
        );
        assert_eq!(first.thumbnail_upload.high_quality_width, 120);
        assert_eq!(first.thumbnail_upload.high_quality_height, 60);
        assert_eq!(
            first.preview.content.high_quality_thumbnail.as_ref(),
            Some(&first.thumbnail_upload.high_quality_thumbnail)
        );
        assert_eq!(
            second.preview.content.high_quality_thumbnail.as_ref(),
            Some(&first.thumbnail_upload.high_quality_thumbnail)
        );
        assert!(
            second
                .preview
                .content
                .jpeg_thumbnail
                .as_ref()
                .unwrap()
                .starts_with(&[0xff, 0xd8])
        );
        let uploads = transport.uploads.lock().unwrap();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].kind, wa_crypto::MediaKind::ThumbnailLink);
        assert_eq!(cache.len().unwrap(), 1);
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    #[tokio::test]
    async fn uploads_generated_link_preview_thumbnail_images() {
        use image::codecs::jpeg::JpegEncoder;
        use image::{Rgb, RgbImage};

        let image = RgbImage::from_fn(240, 120, |x, y| {
            Rgb([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8])
        });
        let mut source = Vec::new();
        JpegEncoder::new_with_quality(&mut source, 90)
            .encode_image(&image)
            .unwrap();

        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());
        let uploaded = upload_generated_link_preview_thumbnail(
            &transfer,
            &source,
            crate::LinkPreviewImageOptions {
                high_quality_max_width: 120,
                high_quality_max_height: 120,
                ..crate::LinkPreviewImageOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(uploaded.source_width, 240);
        assert_eq!(uploaded.source_height, 120);
        assert_eq!(uploaded.thumbnail_width, 32);
        assert_eq!(uploaded.thumbnail_height, 16);
        assert_eq!(uploaded.high_quality_width, 120);
        assert_eq!(uploaded.high_quality_height, 60);
        assert!(uploaded.jpeg_thumbnail.starts_with(&[0xff, 0xd8]));
        assert_eq!(uploaded.high_quality_thumbnail.direct_path, "/v/t62/upload");
        assert_eq!(uploaded.high_quality_thumbnail.width, Some(120));
        assert_eq!(uploaded.high_quality_thumbnail.height, Some(60));
        assert_eq!(
            transport.uploads.lock().unwrap()[0].kind,
            wa_crypto::MediaKind::ThumbnailLink
        );
    }

    #[cfg(feature = "link-preview")]
    async fn serve_link_preview_response(body: String, content_type: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}")
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    struct LinkPreviewTestRoute {
        path: &'static str,
        body: Vec<u8>,
        content_type: &'static str,
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    impl LinkPreviewTestRoute {
        fn new(path: &'static str, body: Vec<u8>, content_type: &'static str) -> Self {
            Self {
                path,
                body,
                content_type,
            }
        }
    }

    #[cfg(all(feature = "link-preview", feature = "image"))]
    async fn serve_link_preview_routes(routes: Vec<LinkPreviewTestRoute>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..routes.len() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let read = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let route = routes.iter().find(|route| route.path == path);
                let (status, content_type, body) = if let Some(route) = route {
                    ("200 OK", route.content_type, route.body.as_slice())
                } else {
                    ("404 Not Found", "text/plain", b"not found".as_slice())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            }
        });
        format!("http://{address}")
    }

    #[cfg(feature = "link-preview")]
    #[test]
    fn rejects_invalid_link_preview_thumbnail_upload_metadata() {
        let media = UploadedMedia::new(
            Bytes::from(vec![1u8; 31]),
            Bytes::from(vec![2u8; 32]),
            Bytes::from(vec![3u8; 32]),
            1,
        )
        .with_direct_path("/thumb");

        assert!(link_preview_thumbnail_from_uploaded_media(&media, None).is_err());
        assert!(
            link_preview_thumbnail_from_uploaded_media(
                &UploadedMedia::new(
                    Bytes::from(vec![1u8; 32]),
                    Bytes::from(vec![2u8; 32]),
                    Bytes::from(vec![3u8; 32]),
                    1,
                ),
                None,
            )
            .is_err()
        );
        assert!(
            link_preview_thumbnail_from_uploaded_media(
                &media.with_direct_path("/thumb"),
                Some((0, 10)),
            )
            .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn applies_media_retry_event_and_downloads_refreshed_media() {
        let media_key = [8u8; 32];
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"retried plaintext",
            wa_crypto::MediaKind::Image,
            &media_key,
        )
        .unwrap();
        let media = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new().with_direct_path("/old/path"),
        )
        .unwrap();
        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some("msg-1".to_owned()),
            direct_path: Some("/new/path".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: Some(Bytes::from_static(b"secret")),
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            "msg-1",
            &[4u8; 12],
        )
        .unwrap();
        let retry = MediaRetryEvent::new(
            crate::event::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None),
            false,
        )
        .with_encrypted_payload(payload.ciphertext, payload.iv);

        let application = apply_media_retry_event(&retry, &media).unwrap();
        assert_eq!(application.result, MediaRetryResult::Success);
        assert_eq!(application.status_code, 200);
        assert_eq!(application.direct_path.as_deref(), Some("/new/path"));
        assert_eq!(application.media.direct_path.as_deref(), Some("/new/path"));
        assert_eq!(application.media.file_sha256, media.file_sha256);
        assert_eq!(
            application.message_secret.as_deref(),
            Some(b"secret".as_slice())
        );

        let transport = RecordingMediaTransport::default();
        transport.add_download(
            "https://media.test/new/path",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = MediaTransfer::new(transport.clone());
        let download = transfer
            .download_bytes_after_retry(
                &media,
                wa_crypto::MediaKind::Image,
                &retry,
                Some("media.test"),
            )
            .await
            .unwrap();

        assert_eq!(download.plaintext, b"retried plaintext");
        assert_eq!(
            download.application.media.direct_path.as_deref(),
            Some("/new/path")
        );
        assert_eq!(
            transport.download_urls.lock().unwrap().as_slice(),
            &["https://media.test/new/path".to_owned()]
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn rejects_invalid_media_retry_applications() {
        let media = UploadedMedia::new(
            Bytes::from(vec![8u8; 32]),
            Bytes::from(vec![1u8; 32]),
            Bytes::from(vec![2u8; 32]),
            1,
        )
        .with_direct_path("/old/path");
        let error_retry = MediaRetryEvent::new(
            crate::event::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None),
            false,
        )
        .with_error(2, Some("missing".to_owned()), 404);
        assert_eq!(
            apply_media_retry_event(&error_retry, &media)
                .unwrap_err()
                .to_string(),
            "protocol error: media retry returned error code 2 with status 404"
        );

        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some("different".to_owned()),
            direct_path: Some("/new/path".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &[8u8; 32],
            "msg-1",
            &[4u8; 12],
        )
        .unwrap();
        let retry = MediaRetryEvent::new(
            crate::event::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None),
            false,
        )
        .with_encrypted_payload(payload.ciphertext, payload.iv);

        assert_eq!(
            apply_media_retry_event(&retry, &media)
                .unwrap_err()
                .to_string(),
            "protocol error: media retry notification stanza id mismatch: expected msg-1, got different"
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn download_after_retry_rejects_non_success_without_download() {
        let media_key = [8u8; 32];
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"retry not found",
            wa_crypto::MediaKind::Image,
            &media_key,
        )
        .unwrap();
        let media = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new().with_direct_path("/old/path"),
        )
        .unwrap();
        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some("msg-1".to_owned()),
            direct_path: Some("/new/path".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::NotFound as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            "msg-1",
            &[4u8; 12],
        )
        .unwrap();
        let retry = MediaRetryEvent::new(
            crate::event::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None),
            false,
        )
        .with_encrypted_payload(payload.ciphertext, payload.iv);
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let err = transfer
            .download_bytes_after_retry(
                &media,
                wa_crypto::MediaKind::Image,
                &retry,
                Some("media.test"),
            )
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "protocol error: media retry did not succeed: NotFound"
        );
        assert!(transport.download_urls.lock().unwrap().is_empty());
    }

    #[cfg(feature = "noise")]
    #[test]
    fn media_retry_coordinator_enforces_capacity_ttl_and_validation() {
        let now = Arc::new(AtomicU64::new(1_000));
        let clock_now = now.clone();
        let coordinator = MediaRetryCoordinator::with_clock(
            MediaRetryCoordinatorConfig {
                capacity: 2,
                ttl_ms: 10,
            },
            move || clock_now.load(AtomicOrdering::SeqCst),
        );
        let key_a = crate::event::MessageEventKey::new("123@s.whatsapp.net", "a", None);
        let key_b = crate::event::MessageEventKey::new("123@s.whatsapp.net", "b", None);
        let key_c = crate::event::MessageEventKey::new("123@s.whatsapp.net", "c", None);

        coordinator
            .register(
                key_a.clone(),
                PendingMediaRetry::new(
                    pending_retry_media([1u8; 32], "/old/a"),
                    wa_crypto::MediaKind::Image,
                ),
            )
            .unwrap();
        coordinator
            .register(
                key_b.clone(),
                PendingMediaRetry::new(
                    pending_retry_media([2u8; 32], "/old/b"),
                    wa_crypto::MediaKind::Image,
                ),
            )
            .unwrap();
        now.store(1_001, AtomicOrdering::SeqCst);
        assert!(coordinator.pending(&key_a).unwrap().is_some());
        now.store(1_002, AtomicOrdering::SeqCst);
        coordinator
            .register(
                key_c.clone(),
                PendingMediaRetry::new(
                    pending_retry_media([3u8; 32], "/old/c"),
                    wa_crypto::MediaKind::Image,
                ),
            )
            .unwrap();

        assert!(coordinator.pending(&key_a).unwrap().is_some());
        assert!(coordinator.pending(&key_b).unwrap().is_none());
        assert!(coordinator.pending(&key_c).unwrap().is_some());

        now.store(1_020, AtomicOrdering::SeqCst);
        assert!(coordinator.pending(&key_a).unwrap().is_none());
        assert!(coordinator.is_empty().unwrap());

        assert!(
            coordinator
                .register(
                    crate::event::MessageEventKey::new("123@s.whatsapp.net", "", None),
                    PendingMediaRetry::new(
                        pending_retry_media([4u8; 32], "/old/d"),
                        wa_crypto::MediaKind::Image,
                    ),
                )
                .is_err()
        );
        assert!(
            coordinator
                .register(
                    crate::event::MessageEventKey::new("123@s.whatsapp.net", "d", None),
                    PendingMediaRetry::new(
                        UploadedMedia::new(
                            Bytes::from(vec![1u8; 31]),
                            Bytes::from(vec![2u8; 32]),
                            Bytes::from(vec![3u8; 32]),
                            1,
                        ),
                        wa_crypto::MediaKind::Image,
                    ),
                )
                .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn stores_and_restores_pending_media_retry_descriptors() {
        let key = crate::event::MessageEventKey::new(
            "123@g.us",
            "msg-1",
            Some("456@s.whatsapp.net".to_owned()),
        );
        let pending = PendingMediaRetry::new(
            pending_retry_media([7u8; 32], "/old/path").with_media_key_timestamp(1_700_000),
            wa_crypto::MediaKind::Video,
        )
        .with_fallback_host("media.test");
        let entry = MediaRetryPendingEntry::new(key.clone(), pending.clone());

        assert_eq!(
            pending_media_retry_store_key(&key),
            "123@g.us|msg-1|456@s.whatsapp.net"
        );
        let encoded = encode_stored_pending_media_retry(&entry).unwrap();
        let decoded = decode_stored_pending_media_retry(&encoded).unwrap();
        assert_eq!(decoded, entry);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_stored_pending_media_retry(&trailing).is_err());

        let coordinator = MediaRetryCoordinator::default();
        coordinator.register(key.clone(), pending.clone()).unwrap();
        let entries = coordinator.pending_entries().unwrap();
        assert_eq!(entries, vec![entry]);

        let restored = MediaRetryCoordinator::default();
        assert_eq!(restored.restore_pending_entries(entries).unwrap(), 1);
        assert_eq!(restored.pending(&key).unwrap(), Some(pending));
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_retry_coordinator_downloads_pending_media_and_removes_entry() {
        let key = crate::event::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None);
        let media_key = [8u8; 32];
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"coordinated retry",
            wa_crypto::MediaKind::Image,
            &media_key,
        )
        .unwrap();
        let media = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new().with_direct_path("/old/path"),
        )
        .unwrap();
        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(key.id.clone()),
            direct_path: Some("/new/path".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            &key.id,
            &[4u8; 12],
        )
        .unwrap();
        let retry = MediaRetryEvent::new(key.clone(), false)
            .with_encrypted_payload(payload.ciphertext, payload.iv);
        let coordinator = MediaRetryCoordinator::default();
        coordinator
            .register(
                key.clone(),
                PendingMediaRetry::new(media, wa_crypto::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .unwrap();

        let transport = RecordingMediaTransport::default();
        transport.add_download(
            "https://media.test/new/path",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = MediaTransfer::new(transport);
        let download = coordinator
            .download_after_retry(&transfer, &retry)
            .await
            .unwrap();

        assert_eq!(download.plaintext, b"coordinated retry");
        assert_eq!(
            download.application.direct_path.as_deref(),
            Some("/new/path")
        );
        assert!(coordinator.pending(&key).unwrap().is_none());
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_retry_coordinator_handles_event_batches() {
        let key = crate::event::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None);
        let missing_key = crate::event::MessageEventKey::new("456@s.whatsapp.net", "msg-2", None);
        let media_key = [8u8; 32];
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"batch retried media",
            wa_crypto::MediaKind::Image,
            &media_key,
        )
        .unwrap();
        let media = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new().with_direct_path("/old/path"),
        )
        .unwrap();
        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(key.id.clone()),
            direct_path: Some("/batch/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            &key.id,
            &[5u8; 12],
        )
        .unwrap();
        let retry = MediaRetryEvent::new(key.clone(), false)
            .with_encrypted_payload(payload.ciphertext, payload.iv);
        let missing_retry = MediaRetryEvent::new(missing_key, false);
        let coordinator = MediaRetryCoordinator::default();
        coordinator
            .register(
                key.clone(),
                PendingMediaRetry::new(media, wa_crypto::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .unwrap();

        let transport = RecordingMediaTransport::default();
        transport.add_download(
            "https://media.test/batch/new",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = MediaTransfer::new(transport);
        let batch = EventBatch {
            media_retry: vec![retry, missing_retry],
            ..EventBatch::default()
        };
        let outcome = coordinator
            .handle_event_batch(&transfer, &batch)
            .await
            .unwrap();

        assert_eq!(outcome.downloads.len(), 1);
        assert_eq!(outcome.downloads[0].plaintext, b"batch retried media");
        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.ignored_without_pending, 1);
        assert!(coordinator.pending(&key).unwrap().is_none());
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_retry_coordinator_collects_batch_errors() {
        let key = crate::event::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None);
        let retry =
            MediaRetryEvent::new(key.clone(), false).with_error(2, Some("missing".to_owned()), 404);
        let coordinator = MediaRetryCoordinator::default();
        coordinator
            .register(
                key.clone(),
                PendingMediaRetry::new(
                    pending_retry_media([8u8; 32], "/old/path"),
                    wa_crypto::MediaKind::Image,
                ),
            )
            .unwrap();

        let transfer = MediaTransfer::new(RecordingMediaTransport::default());
        let outcome = coordinator
            .handle_retry_events(&transfer, &[retry])
            .await
            .unwrap();

        assert!(outcome.downloads.is_empty());
        assert_eq!(outcome.errors.len(), 1);
        assert_eq!(outcome.errors[0].key, key);
        assert_eq!(outcome.errors[0].error_code, Some(2));
        assert_eq!(outcome.errors[0].status_code, Some(404));
        assert_eq!(
            outcome.errors[0].reason,
            "protocol error: media retry returned error code 2 with status 404"
        );
        assert_eq!(outcome.ignored_without_pending, 0);
        assert!(coordinator.pending(&key).unwrap().is_some());
    }

    #[cfg(all(feature = "noise", feature = "http-media"))]
    #[test]
    fn builds_media_upload_paths_tokens_and_urls() {
        assert_eq!(
            media_upload_path(wa_crypto::MediaKind::Image),
            Some("/mms/image")
        );
        assert_eq!(
            media_upload_path(wa_crypto::MediaKind::HistorySync),
            Some("/mms/md-app-state")
        );
        assert_eq!(media_upload_path(wa_crypto::MediaKind::AppState), None);

        let token = media_upload_token(&[251u8; 32]).unwrap();
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
        assert!(!token.contains('='));

        let host = MediaUploadHost::new("media.example:8443").with_scheme("http");
        let url = media_upload_url(&host, "/mms/image", &token, "auth token").unwrap();
        assert!(url.starts_with("http://media.example:8443/mms/image/"));
        assert!(url.contains("auth=auth+token"));
        assert!(url.contains(&format!("token={token}")));
        assert!(media_upload_token(&[1u8; 31]).is_err());
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_transfer_uploads_encrypted_bytes_and_downloads_plaintext() {
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let media = transfer
            .upload_bytes(b"media plaintext", wa_crypto::MediaKind::Image)
            .await
            .unwrap();

        assert_eq!(media.direct_path.as_deref(), Some("/v/t62/upload"));
        assert_eq!(media.media_key.len(), 32);
        assert_eq!(media.file_length, 15);
        {
            let uploads = transport.uploads.lock().unwrap();
            assert_eq!(uploads.len(), 1);
            assert_eq!(uploads[0].kind, wa_crypto::MediaKind::Image);
            assert_eq!(uploads[0].file_length, 15);
            assert_eq!(uploads[0].file_sha256, media.file_sha256);
            assert_eq!(uploads[0].file_enc_sha256, media.file_enc_sha256);
            assert_ne!(uploads[0].ciphertext_with_mac.as_ref(), b"media plaintext");
        }

        let plaintext = transfer
            .download_bytes(&media, wa_crypto::MediaKind::Image, Some("media.test"))
            .await
            .unwrap();

        assert_eq!(plaintext, b"media plaintext");
        assert_eq!(
            transport.download_urls.lock().unwrap().as_slice(),
            &["https://media.test/v/t62/upload".to_owned()]
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_upload_cache_reuses_uploaded_media_and_skips_transport() {
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());
        let cache = MemoryMediaUploadCache::default();

        let first = transfer
            .upload_bytes_cached(b"cached plaintext", wa_crypto::MediaKind::Image, &cache)
            .await
            .unwrap();
        let second = transfer
            .upload_bytes_cached(b"cached plaintext", wa_crypto::MediaKind::Image, &cache)
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(transport.uploads.lock().unwrap().len(), 1);
        assert_eq!(cache.len().unwrap(), 1);

        let third = transfer
            .upload_bytes_cached(b"cached plaintext", wa_crypto::MediaKind::Video, &cache)
            .await
            .unwrap();
        assert_ne!(third.media_key, first.media_key);
        assert_eq!(transport.uploads.lock().unwrap().len(), 2);
        assert_eq!(cache.len().unwrap(), 2);
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_transfer_uploads_and_downloads_files_with_limits_and_cache() {
        let input = test_media_path("upload-input");
        let output = test_media_path("download-output");
        tokio::fs::write(&input, b"file media plaintext")
            .await
            .unwrap();
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::new(transport.clone());

        let media = transfer
            .upload_file(&input, wa_crypto::MediaKind::Image)
            .await
            .unwrap();
        assert_eq!(media.file_length, 20);
        assert_eq!(transport.uploads.lock().unwrap().len(), 1);
        assert_eq!(transport.stream_uploads.lock().unwrap().len(), 1);

        let written = transfer
            .download_to_file(
                &media,
                wa_crypto::MediaKind::Image,
                Some("media.test"),
                &output,
            )
            .await
            .unwrap();
        assert_eq!(written, 20);
        assert_eq!(
            tokio::fs::read(&output).await.unwrap(),
            b"file media plaintext"
        );

        let limited_transport = RecordingMediaTransport::default();
        let limited = MediaTransfer::with_config(
            limited_transport.clone(),
            MediaTransferConfig {
                max_upload_plaintext_bytes: 4,
                max_download_ciphertext_bytes: 1024,
            },
        );
        assert!(
            limited
                .upload_file(&input, wa_crypto::MediaKind::Image)
                .await
                .is_err()
        );
        assert!(limited_transport.uploads.lock().unwrap().is_empty());

        let cache = MemoryMediaUploadCache::default();
        let cached_first = transfer
            .upload_file_cached(&input, wa_crypto::MediaKind::Image, &cache)
            .await
            .unwrap();
        let cached_second = transfer
            .upload_file_cached(&input, wa_crypto::MediaKind::Image, &cache)
            .await
            .unwrap();
        assert_eq!(cached_first, cached_second);
        assert_eq!(transport.uploads.lock().unwrap().len(), 2);
        assert_eq!(transport.stream_uploads.lock().unwrap().len(), 1);

        let _ = tokio::fs::remove_file(&input).await;
        let _ = tokio::fs::remove_file(&output).await;
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_transfer_streams_large_file_upload_and_download_to_file() {
        let input = test_media_path("large-upload-input");
        let output = test_media_path("large-download-output");
        let plaintext = (0..(DEFAULT_MEDIA_FILE_CHUNK_BYTES * 3 + 333))
            .map(|idx| u8::try_from((idx * 31) % 251).unwrap())
            .collect::<Vec<_>>();
        tokio::fs::write(&input, &plaintext).await.unwrap();
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::with_config(
            transport.clone(),
            MediaTransferConfig {
                max_upload_plaintext_bytes: plaintext.len() + 1024,
                max_download_ciphertext_bytes: plaintext.len() + 4096,
            },
        );

        let media = transfer
            .upload_file(&input, wa_crypto::MediaKind::Video)
            .await
            .unwrap();
        assert_eq!(media.file_length, plaintext.len() as u64);
        {
            let stream_uploads = transport.stream_uploads.lock().unwrap();
            assert_eq!(stream_uploads.len(), 1);
            assert!(stream_uploads[0].ciphertext_len > DEFAULT_MEDIA_FILE_CHUNK_BYTES as u64);
        }

        let written = transfer
            .download_to_file(
                &media,
                wa_crypto::MediaKind::Video,
                Some("media.test"),
                &output,
            )
            .await
            .unwrap();
        assert_eq!(written, plaintext.len() as u64);
        assert_eq!(tokio::fs::read(&output).await.unwrap(), plaintext);

        let _ = tokio::fs::remove_file(&input).await;
        let _ = tokio::fs::remove_file(&output).await;
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_transfer_streams_e2e_sized_file_without_in_memory_ciphertext_transport() {
        let dir = test_media_path("file-backed-large-media");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let input = dir.join("input.bin");
        let output = dir.join("output.bin");
        let plaintext = (0..(DEFAULT_MEDIA_FILE_CHUNK_BYTES * 16 + 777))
            .map(|idx| u8::try_from((idx * 17 + 23) % 251).unwrap())
            .collect::<Vec<_>>();
        tokio::fs::write(&input, &plaintext).await.unwrap();
        let transport = FileBackedMediaTransport::new(dir.join("transport"));
        let transfer = MediaTransfer::with_config(
            transport.clone(),
            MediaTransferConfig {
                max_upload_plaintext_bytes: plaintext.len() + DEFAULT_MEDIA_FILE_CHUNK_BYTES,
                max_download_ciphertext_bytes: plaintext.len() + DEFAULT_MEDIA_FILE_CHUNK_BYTES,
            },
        );

        let media = transfer
            .upload_file(&input, wa_crypto::MediaKind::Video)
            .await
            .unwrap();
        assert_eq!(media.file_length, plaintext.len() as u64);
        assert_eq!(transport.non_stream_uploads.lock().unwrap().len(), 0);
        let uploaded_path = transport.uploaded_path().unwrap();
        let uploaded_encrypted_len = tokio::fs::metadata(&uploaded_path).await.unwrap().len();
        assert_eq!(
            transport.stream_upload_lengths.lock().unwrap().as_slice(),
            &[uploaded_encrypted_len]
        );
        let upload_chunks = transport.upload_chunks.lock().unwrap().clone();
        assert_chunk_profile(
            &upload_chunks,
            uploaded_encrypted_len,
            DEFAULT_MEDIA_FILE_CHUNK_BYTES,
        );

        let written = transfer
            .download_to_file(
                &media,
                wa_crypto::MediaKind::Video,
                Some("media.test"),
                &output,
            )
            .await
            .unwrap();
        assert_eq!(written, plaintext.len() as u64);
        assert_eq!(tokio::fs::read(&output).await.unwrap(), plaintext);
        let download_chunks = transport.download_chunks.lock().unwrap().clone();
        assert_chunk_profile(
            &download_chunks,
            uploaded_encrypted_len,
            DEFAULT_MEDIA_FILE_CHUNK_BYTES / 2,
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_transfer_download_to_file_keeps_target_on_failed_mac() {
        let output = test_media_path("download-bad-mac-output");
        tokio::fs::write(&output, b"existing target").await.unwrap();
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"file media plaintext",
            wa_crypto::MediaKind::Image,
            &[7u8; 32],
        )
        .unwrap();
        let mut tampered = encrypted.ciphertext_with_mac.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        let mut media = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new().with_url("https://media.test/bad-mac"),
        )
        .unwrap();
        media.file_enc_sha256 = Bytes::copy_from_slice(&wa_crypto::sha256_hash(&tampered));

        let transport = RecordingMediaTransport::default();
        transport.add_download("https://media.test/bad-mac", Bytes::from(tampered));
        let transfer = MediaTransfer::new(transport);

        assert!(
            transfer
                .download_to_file(&media, wa_crypto::MediaKind::Image, None, &output)
                .await
                .is_err()
        );
        assert_eq!(tokio::fs::read(&output).await.unwrap(), b"existing target");

        let _ = tokio::fs::remove_file(&output).await;
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn memory_media_upload_cache_enforces_capacity_ttl_and_validation() {
        let now = Arc::new(AtomicU64::new(1_000));
        let clock_now = now.clone();
        let cache = MemoryMediaUploadCache::with_clock(
            MemoryMediaUploadCacheConfig {
                capacity: 2,
                ttl_ms: 10,
            },
            move || clock_now.load(AtomicOrdering::SeqCst),
        );
        let key_a = MediaUploadCacheKey::from_plaintext(wa_crypto::MediaKind::Image, b"a");
        let key_b = MediaUploadCacheKey::from_plaintext(wa_crypto::MediaKind::Image, b"b");
        let key_c = MediaUploadCacheKey::from_plaintext(wa_crypto::MediaKind::Image, b"c");

        cache
            .store_media_upload(key_a.clone(), cached_media_for_key(&key_a, "/a"))
            .await
            .unwrap();
        cache
            .store_media_upload(key_b.clone(), cached_media_for_key(&key_b, "/b"))
            .await
            .unwrap();
        now.store(1_001, AtomicOrdering::SeqCst);
        assert!(cache.get_media_upload(&key_a).await.unwrap().is_some());
        now.store(1_002, AtomicOrdering::SeqCst);
        cache
            .store_media_upload(key_c.clone(), cached_media_for_key(&key_c, "/c"))
            .await
            .unwrap();

        assert!(cache.get_media_upload(&key_a).await.unwrap().is_some());
        assert!(cache.get_media_upload(&key_b).await.unwrap().is_none());
        assert!(cache.get_media_upload(&key_c).await.unwrap().is_some());

        now.store(1_020, AtomicOrdering::SeqCst);
        assert!(cache.get_media_upload(&key_a).await.unwrap().is_none());
        assert!(cache.is_empty().unwrap());

        let mut invalid = cached_media_for_key(&key_a, "/bad");
        invalid.file_length += 1;
        assert!(
            cache
                .store_media_upload(key_a.clone(), invalid)
                .await
                .is_err()
        );
        assert!(MediaUploadCacheKey::new(wa_crypto::MediaKind::Image, [1u8; 31], 1).is_err());
    }

    #[cfg(all(feature = "noise", feature = "http-media"))]
    #[tokio::test]
    async fn http_media_transport_uploads_and_downloads_with_local_server() {
        let uploaded_ciphertext = Arc::new(Mutex::new(None::<Bytes>));
        let uploaded_for_server = uploaded_ciphertext.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_http_request(&mut socket).await;
                if request.path.starts_with("/mms/image/") {
                    assert_eq!(request.method, "POST");
                    assert_eq!(
                        request.headers.get("content-type").map(String::as_str),
                        Some("application/octet-stream")
                    );
                    assert_eq!(
                        request.headers.get("origin").map(String::as_str),
                        Some(DEFAULT_MEDIA_ORIGIN)
                    );
                    assert!(request.path.contains("auth=auth-token"));
                    *uploaded_for_server.lock().unwrap() = Some(request.body);
                    let body = format!(
                        r#"{{"url":"http://{addr}/download/file","ts":1700000000,"fbid":12345,"meta_hmac":"token-1"}}"#
                    );
                    write_http_response(&mut socket, "200 OK", "application/json", body.as_bytes())
                        .await;
                } else if request.path == "/download/file" {
                    assert_eq!(request.method, "GET");
                    let body = uploaded_for_server
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("upload request should run before download");
                    write_http_response(&mut socket, "200 OK", "application/octet-stream", &body)
                        .await;
                } else {
                    write_http_response(&mut socket, "404 Not Found", "text/plain", b"missing")
                        .await;
                }
            }
        });

        let connection =
            MediaConnectionInfo::new("auth-token", 60).with_hosts([MediaUploadHost::new(
                addr.to_string(),
            )
            .with_scheme("http")
            .with_max_content_length_bytes(1024 * 1024)]);
        let transport = HttpMediaTransport::new(connection);
        let transfer = MediaTransfer::new(transport);
        let input = test_media_path("http-upload-input");
        let output = test_media_path("http-download-output");
        tokio::fs::write(&input, b"http media plaintext")
            .await
            .unwrap();

        let upload = transfer
            .upload_file_with_location(&input, wa_crypto::MediaKind::Image)
            .await
            .unwrap();
        assert_eq!(upload.location.upload_id.as_deref(), Some("12345"));
        assert_eq!(upload.location.upload_token.as_deref(), Some("token-1"));
        let media = upload.media;
        let download_url = format!("http://{addr}/download/file");
        assert_eq!(media.url.as_deref(), Some(download_url.as_str()));
        assert_eq!(media.media_key_timestamp, Some(1_700_000_000));
        assert!(uploaded_ciphertext.lock().unwrap().is_some());

        let written = transfer
            .download_to_file(&media, wa_crypto::MediaKind::Image, None, &output)
            .await
            .unwrap();
        assert_eq!(written, 20);
        assert_eq!(
            tokio::fs::read(&output).await.unwrap(),
            b"http media plaintext"
        );
        let _ = tokio::fs::remove_file(&input).await;
        let _ = tokio::fs::remove_file(&output).await;
        server.await.unwrap();
    }

    #[cfg(all(feature = "noise", feature = "http-media"))]
    #[tokio::test]
    async fn http_media_download_to_file_enforces_stream_limit_without_replacing_target() {
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &vec![17u8; DEFAULT_MEDIA_FILE_CHUNK_BYTES + 257],
            wa_crypto::MediaKind::Image,
            &[8u8; 32],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ciphertext = encrypted.ciphertext_with_mac.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut socket).await;
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/download/too-large");
            write_http_response_without_length(
                &mut socket,
                "200 OK",
                "application/octet-stream",
                &ciphertext,
                1024,
            )
            .await;
        });

        let media = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new().with_url(format!("http://{addr}/download/too-large")),
        )
        .unwrap();
        let output = test_media_path("http-download-limit-output");
        tokio::fs::write(&output, b"existing target").await.unwrap();
        let connection = MediaConnectionInfo::new("auth-token", 60)
            .with_hosts([MediaUploadHost::new(addr.to_string()).with_scheme("http")]);
        let transfer = MediaTransfer::with_config(
            HttpMediaTransport::new(connection),
            MediaTransferConfig {
                max_upload_plaintext_bytes: 1024,
                max_download_ciphertext_bytes: encrypted.ciphertext_with_mac.len() - 1,
            },
        );

        assert!(
            transfer
                .download_to_file(&media, wa_crypto::MediaKind::Image, None, &output)
                .await
                .is_err()
        );
        assert_eq!(tokio::fs::read(&output).await.unwrap(), b"existing target");

        let _ = tokio::fs::remove_file(&output).await;
        server.await.unwrap();
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn media_transfer_enforces_configured_size_limits() {
        let transport = RecordingMediaTransport::default();
        let transfer = MediaTransfer::with_config(
            transport.clone(),
            MediaTransferConfig {
                max_upload_plaintext_bytes: 4,
                max_download_ciphertext_bytes: 1024,
            },
        );

        assert!(
            transfer
                .upload_bytes(b"media", wa_crypto::MediaKind::Image)
                .await
                .is_err()
        );
        assert!(transport.uploads.lock().unwrap().is_empty());

        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            b"media",
            wa_crypto::MediaKind::Image,
            &[7u8; 32],
        )
        .unwrap();
        let media = uploaded_media_from_encrypted(
            &encrypted,
            UploadedMediaLocation::new().with_url("https://media.test/file"),
        )
        .unwrap();
        transport.add_download(
            "https://media.test/file",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = MediaTransfer::with_config(
            transport,
            MediaTransferConfig {
                max_upload_plaintext_bytes: 1024,
                max_download_ciphertext_bytes: encrypted.ciphertext_with_mac.len() - 1,
            },
        );

        assert!(
            transfer
                .download_bytes(&media, wa_crypto::MediaKind::Image, None)
                .await
                .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[derive(Clone, Default)]
    struct RecordingMediaTransport {
        uploads: Arc<Mutex<Vec<MediaUploadRequest>>>,
        stream_uploads: Arc<Mutex<Vec<MediaUploadStreamRequest>>>,
        downloads: Arc<Mutex<BTreeMap<String, Bytes>>>,
        download_urls: Arc<Mutex<Vec<String>>>,
    }

    #[cfg(feature = "noise")]
    impl RecordingMediaTransport {
        fn add_download(&self, url: impl Into<String>, bytes: Bytes) {
            self.downloads.lock().unwrap().insert(url.into(), bytes);
        }
    }

    #[cfg(feature = "noise")]
    #[async_trait]
    impl MediaTransport for RecordingMediaTransport {
        async fn upload_media(
            &self,
            request: MediaUploadRequest,
        ) -> CoreResult<UploadedMediaLocation> {
            self.add_download(
                "https://media.test/v/t62/upload",
                request.ciphertext_with_mac.clone(),
            );
            self.uploads.lock().unwrap().push(request);
            Ok(UploadedMediaLocation::new()
                .with_direct_path("/v/t62/upload")
                .with_media_key_timestamp(1_700_000_000))
        }

        async fn upload_media_stream(
            &self,
            request: MediaUploadStreamRequest,
        ) -> CoreResult<UploadedMediaLocation> {
            self.stream_uploads.lock().unwrap().push(request.clone());
            let max_bytes = usize::try_from(request.ciphertext_len).map_err(|_| {
                CoreError::Payload(format!(
                    "encrypted media upload is too large for this platform: {} bytes",
                    request.ciphertext_len
                ))
            })?;
            let ciphertext = read_file_limited(
                &request.ciphertext_path,
                max_bytes,
                "encrypted media upload file",
            )
            .await?;
            if u64::try_from(ciphertext.len()).map_err(|_| {
                CoreError::Payload("encrypted media upload byte count overflow".to_owned())
            })? != request.ciphertext_len
            {
                return Err(CoreError::Payload(format!(
                    "encrypted media upload file length changed before upload: expected {}, got {}",
                    request.ciphertext_len,
                    ciphertext.len()
                )));
            }
            self.upload_media(MediaUploadRequest {
                kind: request.kind,
                ciphertext_with_mac: Bytes::from(ciphertext),
                file_sha256: request.file_sha256,
                file_enc_sha256: request.file_enc_sha256,
                file_length: request.file_length,
            })
            .await
        }

        async fn download_media(&self, url: &str) -> CoreResult<Bytes> {
            self.download_urls.lock().unwrap().push(url.to_owned());
            self.downloads
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .ok_or_else(|| CoreError::Payload(format!("missing download fixture: {url}")))
        }
    }

    #[cfg(feature = "noise")]
    #[derive(Clone)]
    struct FileBackedMediaTransport {
        dir: PathBuf,
        uploaded_path: Arc<Mutex<Option<PathBuf>>>,
        non_stream_uploads: Arc<Mutex<Vec<usize>>>,
        stream_upload_lengths: Arc<Mutex<Vec<u64>>>,
        upload_chunks: Arc<Mutex<Vec<usize>>>,
        download_chunks: Arc<Mutex<Vec<usize>>>,
    }

    #[cfg(feature = "noise")]
    impl FileBackedMediaTransport {
        fn new(dir: PathBuf) -> Self {
            Self {
                dir,
                uploaded_path: Arc::new(Mutex::new(None)),
                non_stream_uploads: Arc::new(Mutex::new(Vec::new())),
                stream_upload_lengths: Arc::new(Mutex::new(Vec::new())),
                upload_chunks: Arc::new(Mutex::new(Vec::new())),
                download_chunks: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn uploaded_path(&self) -> CoreResult<PathBuf> {
            self.uploaded_path
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| CoreError::Payload("missing file-backed upload".to_owned()))
        }
    }

    #[cfg(feature = "noise")]
    #[async_trait]
    impl MediaTransport for FileBackedMediaTransport {
        async fn upload_media(
            &self,
            request: MediaUploadRequest,
        ) -> CoreResult<UploadedMediaLocation> {
            self.non_stream_uploads
                .lock()
                .unwrap()
                .push(request.ciphertext_with_mac.len());
            tokio::fs::create_dir_all(&self.dir).await?;
            let path = self.dir.join("upload.enc");
            tokio::fs::write(&path, &request.ciphertext_with_mac).await?;
            *self.uploaded_path.lock().unwrap() = Some(path);
            Ok(UploadedMediaLocation::new().with_direct_path("/file-backed/upload"))
        }

        async fn upload_media_stream(
            &self,
            request: MediaUploadStreamRequest,
        ) -> CoreResult<UploadedMediaLocation> {
            tokio::fs::create_dir_all(&self.dir).await?;
            let path = self.dir.join("upload.enc");
            let mut input = File::open(&request.ciphertext_path).await?;
            let mut output = File::create(&path).await?;
            let mut written = 0u64;
            let mut buffer = vec![0u8; DEFAULT_MEDIA_FILE_CHUNK_BYTES];
            self.stream_upload_lengths
                .lock()
                .unwrap()
                .push(request.ciphertext_len);
            loop {
                let read = read_file_backed_chunk(&mut input, &mut buffer).await?;
                if read == 0 {
                    break;
                }
                self.upload_chunks.lock().unwrap().push(read);
                output.write_all(&buffer[..read]).await?;
                written = written
                    .checked_add(u64::try_from(read).map_err(|_| {
                        CoreError::Payload("file-backed upload byte count overflow".to_owned())
                    })?)
                    .ok_or_else(|| {
                        CoreError::Payload("file-backed upload byte count overflow".to_owned())
                    })?;
            }
            output.flush().await?;
            if written != request.ciphertext_len {
                return Err(CoreError::Payload(format!(
                    "file-backed upload length mismatch: expected {}, got {written}",
                    request.ciphertext_len
                )));
            }
            *self.uploaded_path.lock().unwrap() = Some(path);
            Ok(UploadedMediaLocation::new().with_direct_path("/file-backed/upload"))
        }

        async fn download_media(&self, _url: &str) -> CoreResult<Bytes> {
            Err(CoreError::Payload(
                "file-backed media transport requires download_media_to_file".to_owned(),
            ))
        }

        async fn download_media_to_file(
            &self,
            _url: &str,
            path: &Path,
            max_bytes: usize,
        ) -> CoreResult<u64> {
            let source = self.uploaded_path()?;
            let metadata = tokio::fs::metadata(&source).await?;
            let len = usize::try_from(metadata.len()).map_err(|_| {
                CoreError::Payload(format!(
                    "encrypted media download is too large for this platform: {} bytes",
                    metadata.len()
                ))
            })?;
            validate_media_transfer_limit("encrypted media download", len, max_bytes)?;

            let mut input = File::open(source).await?;
            let mut output = File::create(path).await?;
            let mut written = 0u64;
            let mut buffer = vec![0u8; DEFAULT_MEDIA_FILE_CHUNK_BYTES / 2];
            loop {
                let read = read_file_backed_chunk(&mut input, &mut buffer).await?;
                if read == 0 {
                    break;
                }
                self.download_chunks.lock().unwrap().push(read);
                output.write_all(&buffer[..read]).await?;
                written = written
                    .checked_add(u64::try_from(read).map_err(|_| {
                        CoreError::Payload("file-backed download byte count overflow".to_owned())
                    })?)
                    .ok_or_else(|| {
                        CoreError::Payload("file-backed download byte count overflow".to_owned())
                    })?;
            }
            output.flush().await?;
            Ok(written)
        }
    }

    #[cfg(feature = "noise")]
    async fn read_file_backed_chunk(file: &mut File, buffer: &mut [u8]) -> CoreResult<usize> {
        let mut filled = 0usize;
        while filled < buffer.len() {
            let read = file.read(&mut buffer[filled..]).await?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        Ok(filled)
    }

    #[cfg(feature = "noise")]
    fn assert_chunk_profile(chunks: &[usize], total_bytes: u64, chunk_bytes: usize) {
        assert!(chunk_bytes > 0);
        assert!(!chunks.is_empty());
        let chunk_bytes_u64 = u64::try_from(chunk_bytes).unwrap();
        let observed_total = chunks
            .iter()
            .fold(0u64, |total, chunk| total + u64::try_from(*chunk).unwrap());
        assert_eq!(observed_total, total_bytes);
        assert_eq!(
            chunks.len(),
            usize::try_from(total_bytes.div_ceil(chunk_bytes_u64)).unwrap()
        );
        assert!(
            chunks
                .iter()
                .all(|chunk| *chunk > 0 && *chunk <= chunk_bytes)
        );
        assert_eq!(
            chunks.iter().copied().max(),
            Some(
                usize::try_from(total_bytes)
                    .unwrap_or(usize::MAX)
                    .min(chunk_bytes)
            )
        );
        let remainder = total_bytes % chunk_bytes_u64;
        if remainder == 0 {
            assert_eq!(chunks.last().copied(), Some(chunk_bytes));
        } else {
            assert_eq!(
                chunks.last().copied(),
                Some(usize::try_from(remainder).unwrap())
            );
        }
    }

    #[cfg(feature = "noise")]
    fn cached_media_for_key(key: &MediaUploadCacheKey, direct_path: &str) -> UploadedMedia {
        UploadedMedia::new(
            Bytes::from(vec![9u8; 32]),
            Bytes::copy_from_slice(&key.file_sha256),
            Bytes::from(vec![8u8; 32]),
            key.file_length,
        )
        .with_direct_path(direct_path)
    }

    #[cfg(feature = "noise")]
    fn pending_retry_media(media_key: [u8; 32], direct_path: &str) -> UploadedMedia {
        UploadedMedia::new(
            Bytes::copy_from_slice(&media_key),
            Bytes::from(vec![2u8; 32]),
            Bytes::from(vec![3u8; 32]),
            1,
        )
        .with_direct_path(direct_path)
    }

    #[cfg(feature = "noise")]
    fn test_media_path(label: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("wa-core-media-{label}-{suffix}"))
    }

    #[cfg(all(feature = "noise", feature = "image", unix))]
    fn sample_media_jpeg(width: u32, height: u32) -> Bytes {
        use image::codecs::jpeg::JpegEncoder;
        use image::{Rgb, RgbImage};

        let image = RgbImage::from_fn(width, height, |x, y| {
            Rgb([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8])
        });
        let mut bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut bytes, 90)
            .encode_image(&image)
            .unwrap();
        Bytes::from(bytes)
    }

    #[cfg(all(feature = "noise", feature = "image", unix))]
    fn shell_quote(path: &std::path::Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    #[cfg(all(feature = "noise", feature = "http-media"))]
    struct TestHttpRequest {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Bytes,
    }

    #[cfg(all(feature = "noise", feature = "http-media"))]
    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> TestHttpRequest {
        let mut data = Vec::new();
        let mut buffer = [0u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "connection closed before headers");
            data.extend_from_slice(&buffer[..read]);
            if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(data[..header_end].to_vec()).unwrap();
        let mut lines = headers.split("\r\n");
        let request_line = lines.next().unwrap();
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap().to_owned();
        let path = request_parts.next().unwrap().to_owned();
        let mut parsed_headers = BTreeMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            parsed_headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
        let content_length = parsed_headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while data.len() < header_end + content_length {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "connection closed before body");
            data.extend_from_slice(&buffer[..read]);
        }
        TestHttpRequest {
            method,
            path,
            headers: parsed_headers,
            body: Bytes::copy_from_slice(&data[header_end..header_end + content_length]),
        }
    }

    #[cfg(all(feature = "noise", feature = "http-media"))]
    async fn write_http_response(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        content_type: &str,
        body: &[u8],
    ) {
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    }

    #[cfg(all(feature = "noise", feature = "http-media"))]
    async fn write_http_response_without_length(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        content_type: &str,
        body: &[u8],
        chunk_size: usize,
    ) {
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\nconnection: close\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        for chunk in body.chunks(chunk_size) {
            stream.write_all(chunk).await.unwrap();
        }
    }
}
