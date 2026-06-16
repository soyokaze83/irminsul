#[cfg(feature = "noise")]
use crate::event::{EventBatch, MediaRetryEvent, MessageEventKey};
#[cfg(feature = "noise")]
use crate::message::UploadedMedia;
use crate::{CoreError, CoreResult};
#[cfg(feature = "noise")]
use async_trait::async_trait;
#[cfg(all(feature = "noise", feature = "http-media"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "noise")]
use bytes::Bytes;
use sha2::{Digest, Sha256};
#[cfg(feature = "noise")]
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    path::Path,
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
}

#[cfg(feature = "noise")]
impl MediaRetryBatchOutcome {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.downloads.is_empty() && self.errors.is_empty() && self.ignored_without_pending == 0
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
    async fn download_media(&self, url: &str) -> CoreResult<Bytes>;
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
        let plaintext = read_file_limited(
            path.as_ref(),
            self.config.max_upload_plaintext_bytes,
            "media upload file",
        )
        .await?;
        self.upload_bytes_with_location(&plaintext, kind).await
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
        let plaintext = self.download_bytes(media, kind, fallback_host).await?;
        write_file_chunked(path.as_ref(), &plaintext).await
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
    if location.url.as_deref().is_none_or(str::is_empty)
        && location.direct_path.as_deref().is_none_or(str::is_empty)
    {
        return Err(CoreError::Payload(
            "uploaded media location requires a URL or direct path".to_owned(),
        ));
    }

    let mut media = UploadedMedia::new(
        Bytes::copy_from_slice(encrypted.media_key.expose()),
        encrypted.file_sha256.clone(),
        encrypted.file_enc_sha256.clone(),
        encrypted.file_length,
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
async fn write_file_chunked(path: &Path, bytes: &[u8]) -> CoreResult<u64> {
    let mut file = File::create(path).await?;
    for chunk in bytes.chunks(DEFAULT_MEDIA_FILE_CHUNK_BYTES) {
        file.write_all(chunk).await?;
    }
    file.flush().await?;
    u64::try_from(bytes.len()).map_err(|_| {
        CoreError::Payload(format!(
            "downloaded media is too large for byte count: {}",
            bytes.len()
        ))
    })
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
        assert!(apply_media_retry_event(&error_retry, &media).is_err());

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

        assert!(apply_media_retry_event(&retry, &media).is_err());
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
        assert!(outcome.errors[0].reason.contains("media retry returned"));
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

        let _ = tokio::fs::remove_file(&input).await;
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

        let upload = transfer
            .upload_bytes_with_location(b"http media plaintext", wa_crypto::MediaKind::Image)
            .await
            .unwrap();
        assert_eq!(upload.location.upload_id.as_deref(), Some("12345"));
        assert_eq!(upload.location.upload_token.as_deref(), Some("token-1"));
        let media = upload.media;
        let download_url = format!("http://{addr}/download/file");
        assert_eq!(media.url.as_deref(), Some(download_url.as_str()));
        assert_eq!(media.media_key_timestamp, Some(1_700_000_000));
        assert!(uploaded_ciphertext.lock().unwrap().is_some());

        let plaintext = transfer
            .download_bytes(&media, wa_crypto::MediaKind::Image, None)
            .await
            .unwrap();
        assert_eq!(plaintext, b"http media plaintext");
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
}
