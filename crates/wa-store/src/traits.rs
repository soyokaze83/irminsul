use async_trait::async_trait;

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    #[cfg(feature = "sqlite")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store task failed: {0}")]
    Join(String),
    #[error("store path has no parent directory")]
    MissingParent,
    #[error("invalid store data: {0}")]
    InvalidData(String),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyNamespace {
    Credentials,
    PreKey,
    Session,
    SenderKey,
    SenderKeyMemory,
    AppStateSyncKey,
    AppStateSyncBlocked,
    AppStateSyncVersion,
    AccountSettingsEvent,
    AccountReachoutTimelock,
    DefaultDisappearingMode,
    BusinessNotificationEvent,
    CallEvent,
    ChatEvent,
    ContactEvent,
    GroupEvent,
    LabelAssociation,
    LabelEvent,
    LidMapping,
    DeviceList,
    PendingMediaRetry,
    MediaRetryEvent,
    MessageCappingInfo,
    MessageEvent,
    MessageUpdate,
    NewsletterParticipantEvent,
    NewsletterReactionEvent,
    NewsletterSettingsEvent,
    NewsletterViewEvent,
    QuickReplyEvent,
    PresenceEvent,
    RecentStickerEvent,
    ReceiptEvent,
    ReactionEvent,
    SignalProviderIdentity,
    SignalProviderPreKey,
    SignalProviderSenderKey,
    SignalProviderSenderKeyMemory,
    SignalProviderSession,
    SignalProviderSignedPreKey,
    TcToken,
    IdentityKey,
}

impl KeyNamespace {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::PreKey => "pre-key",
            Self::Session => "session",
            Self::SenderKey => "sender-key",
            Self::SenderKeyMemory => "sender-key-memory",
            Self::AppStateSyncKey => "app-state-sync-key",
            Self::AppStateSyncBlocked => "app-state-sync-blocked",
            Self::AppStateSyncVersion => "app-state-sync-version",
            Self::AccountSettingsEvent => "account-settings-event",
            Self::AccountReachoutTimelock => "account-reachout-timelock",
            Self::DefaultDisappearingMode => "default-disappearing-mode",
            Self::BusinessNotificationEvent => "business-notification-event",
            Self::CallEvent => "call-event",
            Self::ChatEvent => "chat-event",
            Self::ContactEvent => "contact-event",
            Self::GroupEvent => "group-event",
            Self::LabelAssociation => "label-association",
            Self::LabelEvent => "label-event",
            Self::LidMapping => "lid-mapping",
            Self::DeviceList => "device-list",
            Self::PendingMediaRetry => "pending-media-retry",
            Self::MediaRetryEvent => "media-retry-event",
            Self::MessageCappingInfo => "message-capping-info",
            Self::MessageEvent => "message-event",
            Self::MessageUpdate => "message-update",
            Self::NewsletterParticipantEvent => "newsletter-participant-event",
            Self::NewsletterReactionEvent => "newsletter-reaction-event",
            Self::NewsletterSettingsEvent => "newsletter-settings-event",
            Self::NewsletterViewEvent => "newsletter-view-event",
            Self::QuickReplyEvent => "quick-reply-event",
            Self::PresenceEvent => "presence-event",
            Self::RecentStickerEvent => "recent-sticker-event",
            Self::ReceiptEvent => "receipt-event",
            Self::ReactionEvent => "reaction-event",
            Self::SignalProviderIdentity => "signal-provider-identity",
            Self::SignalProviderPreKey => "signal-provider-pre-key",
            Self::SignalProviderSenderKey => "signal-provider-sender-key",
            Self::SignalProviderSenderKeyMemory => "signal-provider-sender-key-memory",
            Self::SignalProviderSession => "signal-provider-session",
            Self::SignalProviderSignedPreKey => "signal-provider-signed-pre-key",
            Self::TcToken => "tctoken",
            Self::IdentityKey => "identity-key",
        }
    }
}

pub trait StoreTransaction {
    fn get(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>>;
    fn set(&mut self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()>;
    fn delete(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<()>;
}

#[async_trait]
pub trait AuthStore: Send + Sync {
    async fn get(&self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>>;
    async fn set(&self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()>;
    async fn delete(&self, namespace: KeyNamespace, key: &str) -> StoreResult<()>;
    async fn list_keys(
        &self,
        namespace: KeyNamespace,
        after: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<String>>;

    async fn transaction<F, R>(&self, label: &str, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut dyn StoreTransaction) -> StoreResult<R> + Send + 'static,
        R: Send + 'static;
}

#[async_trait]
pub trait SignalKeyStore: Send + Sync {
    async fn get_signal_key(
        &self,
        namespace: KeyNamespace,
        key: &str,
    ) -> StoreResult<Option<Vec<u8>>>;
    async fn set_signal_key(
        &self,
        namespace: KeyNamespace,
        key: &str,
        value: &[u8],
    ) -> StoreResult<()>;
    async fn delete_signal_key(&self, namespace: KeyNamespace, key: &str) -> StoreResult<()>;

    async fn signal_transaction<F, R>(&self, label: &str, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut dyn StoreTransaction) -> StoreResult<R> + Send + 'static,
        R: Send + 'static;
}

#[async_trait]
impl<T> SignalKeyStore for T
where
    T: AuthStore,
{
    async fn get_signal_key(
        &self,
        namespace: KeyNamespace,
        key: &str,
    ) -> StoreResult<Option<Vec<u8>>> {
        self.get(namespace, key).await
    }

    async fn set_signal_key(
        &self,
        namespace: KeyNamespace,
        key: &str,
        value: &[u8],
    ) -> StoreResult<()> {
        self.set(namespace, key, value).await
    }

    async fn delete_signal_key(&self, namespace: KeyNamespace, key: &str) -> StoreResult<()> {
        self.delete(namespace, key).await
    }

    async fn signal_transaction<F, R>(&self, label: &str, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut dyn StoreTransaction) -> StoreResult<R> + Send + 'static,
        R: Send + 'static,
    {
        self.transaction(label, exec).await
    }
}
