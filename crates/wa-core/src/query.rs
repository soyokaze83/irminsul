use crate::{CoreError, CoreResult};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct QueryManager {
    inner: Arc<QueryInner>,
}

impl QueryManager {
    #[must_use]
    pub fn new(default_timeout: Option<Duration>) -> Self {
        Self::with_prefix("q", default_timeout)
    }

    #[must_use]
    pub fn with_prefix(prefix: impl Into<String>, default_timeout: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(QueryInner {
                prefix: prefix.into(),
                next_id: AtomicU64::new(1),
                default_timeout,
                waiters: Mutex::new(HashMap::new()),
            }),
        }
    }

    #[must_use]
    pub fn next_tag(&self) -> String {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        format!("{}-{id}", self.inner.prefix)
    }

    pub fn register(&self, tag: impl Into<String>) -> CoreResult<QueryWaiter> {
        self.register_with_timeout(tag, self.inner.default_timeout)
    }

    pub fn register_with_timeout(
        &self,
        tag: impl Into<String>,
        timeout: Option<Duration>,
    ) -> CoreResult<QueryWaiter> {
        let tag = tag.into();
        let (tx, rx) = oneshot::channel();
        let mut waiters = self
            .inner
            .waiters
            .lock()
            .map_err(|err| CoreError::Task(err.to_string()))?;

        if waiters.insert(tag.clone(), tx).is_some() {
            return Err(CoreError::DuplicateQueryTag(tag));
        }

        Ok(QueryWaiter {
            tag,
            timeout,
            rx,
            inner: Arc::downgrade(&self.inner),
            completed: false,
        })
    }

    pub fn resolve(&self, tag: &str, payload: Bytes) -> CoreResult<bool> {
        let sender = self
            .inner
            .waiters
            .lock()
            .map_err(|err| CoreError::Task(err.to_string()))?
            .remove(tag);

        Ok(sender.is_some_and(|tx| tx.send(payload).is_ok()))
    }

    pub fn close_pending(&self) -> CoreResult<usize> {
        let mut waiters = self
            .inner
            .waiters
            .lock()
            .map_err(|err| CoreError::Task(err.to_string()))?;
        let count = waiters.len();
        waiters.clear();
        Ok(count)
    }

    pub fn pending_len(&self) -> CoreResult<usize> {
        Ok(self
            .inner
            .waiters
            .lock()
            .map_err(|err| CoreError::Task(err.to_string()))?
            .len())
    }
}

struct QueryInner {
    prefix: String,
    next_id: AtomicU64,
    default_timeout: Option<Duration>,
    waiters: Mutex<HashMap<String, oneshot::Sender<Bytes>>>,
}

pub struct QueryWaiter {
    tag: String,
    timeout: Option<Duration>,
    rx: oneshot::Receiver<Bytes>,
    inner: Weak<QueryInner>,
    completed: bool,
}

impl QueryWaiter {
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub async fn wait(mut self) -> CoreResult<Bytes> {
        let result = if let Some(timeout) = self.timeout {
            match tokio::time::timeout(timeout, &mut self.rx).await {
                Ok(Ok(payload)) => Ok(payload),
                Ok(Err(_closed)) => Err(CoreError::ConnectionClosed),
                Err(_elapsed) => {
                    self.remove_waiter();
                    Err(CoreError::TimedOut)
                }
            }
        } else {
            (&mut self.rx)
                .await
                .map_err(|_closed| CoreError::ConnectionClosed)
        };

        self.completed = true;
        result
    }

    fn remove_waiter(&self) {
        if let Some(inner) = self.inner.upgrade()
            && let Ok(mut waiters) = inner.waiters.lock()
        {
            waiters.remove(&self.tag);
        }
    }
}

impl Drop for QueryWaiter {
    fn drop(&mut self) {
        if !self.completed {
            self.remove_waiter();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_tags() {
        let manager = QueryManager::with_prefix("test", None);
        assert_eq!(manager.next_tag(), "test-1");
        assert_eq!(manager.next_tag(), "test-2");
    }

    #[tokio::test]
    async fn resolves_registered_waiter() {
        let manager = QueryManager::new(None);
        let waiter = manager.register("abc").unwrap();

        assert!(manager.resolve("abc", Bytes::from_static(b"ok")).unwrap());
        assert_eq!(waiter.wait().await.unwrap(), Bytes::from_static(b"ok"));
        assert_eq!(manager.pending_len().unwrap(), 0);
    }

    #[tokio::test]
    async fn rejects_duplicate_tags() {
        let manager = QueryManager::new(None);
        let _waiter = manager.register("abc").unwrap();

        assert!(matches!(
            manager.register("abc"),
            Err(CoreError::DuplicateQueryTag(tag)) if tag == "abc"
        ));
    }

    #[tokio::test]
    async fn times_out_and_removes_waiter() {
        let manager = QueryManager::new(Some(Duration::from_millis(1)));
        let waiter = manager.register("abc").unwrap();

        assert!(matches!(waiter.wait().await, Err(CoreError::TimedOut)));
        assert_eq!(manager.pending_len().unwrap(), 0);
        assert!(!manager.resolve("abc", Bytes::new()).unwrap());
    }

    #[tokio::test]
    async fn closes_pending_waiters() {
        let manager = QueryManager::new(None);
        let waiter = manager.register("abc").unwrap();

        assert_eq!(manager.close_pending().unwrap(), 1);
        assert!(matches!(
            waiter.wait().await,
            Err(CoreError::ConnectionClosed)
        ));
        assert_eq!(manager.pending_len().unwrap(), 0);
    }

    #[tokio::test]
    async fn dropping_waiter_removes_pending_entry() {
        let manager = QueryManager::new(None);
        let waiter = manager.register("abc").unwrap();
        assert_eq!(manager.pending_len().unwrap(), 1);

        drop(waiter);
        assert_eq!(manager.pending_len().unwrap(), 0);
        assert!(!manager.resolve("abc", Bytes::new()).unwrap());
    }
}
