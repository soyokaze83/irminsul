use crate::{AuthStore, KeyNamespace, StoreError, StoreResult, StoreTransaction};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

type StoreKey = (KeyNamespace, String);
type StoreMap = HashMap<StoreKey, SecretValue>;

#[derive(Clone, Default)]
pub struct MemoryAuthStore {
    entries: Arc<Mutex<StoreMap>>,
}

impl MemoryAuthStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with_entries<F, R>(&self, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut StoreMap) -> StoreResult<R>,
    {
        let mut guard = self
            .entries
            .lock()
            .map_err(|err| StoreError::Join(err.to_string()))?;
        exec(&mut guard)
    }
}

#[async_trait]
impl AuthStore for MemoryAuthStore {
    async fn get(&self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>> {
        self.with_entries(|entries| {
            Ok(entries
                .get(&(namespace, key.to_owned()))
                .map(SecretValue::expose)
                .map(ToOwned::to_owned))
        })
    }

    async fn set(&self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()> {
        let key = key.to_owned();
        let value = SecretValue::new(value.to_vec());
        self.with_entries(move |entries| {
            entries.insert((namespace, key), value);
            Ok(())
        })
    }

    async fn delete(&self, namespace: KeyNamespace, key: &str) -> StoreResult<()> {
        let key = key.to_owned();
        self.with_entries(move |entries| {
            entries.remove(&(namespace, key));
            Ok(())
        })
    }

    async fn list_keys(
        &self,
        namespace: KeyNamespace,
        after: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<String>> {
        let after = after.map(ToOwned::to_owned);
        self.with_entries(move |entries| {
            if limit == 0 {
                return Ok(Vec::new());
            }
            let mut keys = entries
                .keys()
                .filter(|(entry_namespace, key)| {
                    *entry_namespace == namespace
                        && after
                            .as_ref()
                            .is_none_or(|after| key.as_str() > after.as_str())
                })
                .map(|(_, key)| key.clone())
                .collect::<Vec<_>>();
            keys.sort_unstable();
            keys.truncate(limit);
            Ok(keys)
        })
    }

    async fn transaction<F, R>(&self, _label: &str, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut dyn StoreTransaction) -> StoreResult<R> + Send + 'static,
        R: Send + 'static,
    {
        self.with_entries(move |entries| {
            let mut snapshot = entries.clone();
            let mut tx = MemoryTransaction {
                entries: &mut snapshot,
            };
            let result = exec(&mut tx)?;
            *entries = snapshot;
            Ok(result)
        })
    }
}

struct MemoryTransaction<'a> {
    entries: &'a mut StoreMap,
}

impl StoreTransaction for MemoryTransaction<'_> {
    fn get(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .entries
            .get(&(namespace, key.to_owned()))
            .map(SecretValue::expose)
            .map(ToOwned::to_owned))
    }

    fn set(&mut self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()> {
        self.entries.insert(
            (namespace, key.to_owned()),
            SecretValue::new(value.to_vec()),
        );
        Ok(())
    }

    fn delete(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<()> {
        self.entries.remove(&(namespace, key.to_owned()));
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SecretValue(Vec<u8>);

impl SecretValue {
    fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignalKeyStore;

    #[tokio::test]
    async fn stores_and_deletes_values() {
        let store = MemoryAuthStore::new();
        store
            .set(KeyNamespace::Credentials, "auth", b"secret")
            .await
            .unwrap();

        assert_eq!(
            store.get(KeyNamespace::Credentials, "auth").await.unwrap(),
            Some(b"secret".to_vec())
        );

        store
            .delete(KeyNamespace::Credentials, "auth")
            .await
            .unwrap();
        assert_eq!(
            store.get(KeyNamespace::Credentials, "auth").await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn rolls_back_failed_transaction() {
        let store = MemoryAuthStore::new();
        let result: StoreResult<()> = store
            .transaction("rollback", |tx| {
                tx.set(KeyNamespace::Session, "jid:device", b"record")?;
                Err(StoreError::Join("fail".to_owned()))
            })
            .await;

        assert!(result.is_err());
        assert_eq!(
            store
                .get(KeyNamespace::Session, "jid:device")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn commits_successful_transaction() {
        let store = MemoryAuthStore::new();
        store
            .transaction("commit", |tx| {
                tx.set(KeyNamespace::PreKey, "1", b"pre-key")?;
                Ok(())
            })
            .await
            .unwrap();

        assert_eq!(
            store.get(KeyNamespace::PreKey, "1").await.unwrap(),
            Some(b"pre-key".to_vec())
        );
    }

    #[tokio::test]
    async fn supports_signal_key_trait() {
        let store = MemoryAuthStore::new();
        store
            .set_signal_key(KeyNamespace::IdentityKey, "device", b"identity")
            .await
            .unwrap();

        assert_eq!(
            store
                .get_signal_key(KeyNamespace::IdentityKey, "device")
                .await
                .unwrap(),
            Some(b"identity".to_vec())
        );
    }

    #[tokio::test]
    async fn lists_keys_by_namespace_with_pagination() {
        let store = MemoryAuthStore::new();
        store.set(KeyNamespace::TcToken, "b", b"2").await.unwrap();
        store.set(KeyNamespace::TcToken, "a", b"1").await.unwrap();
        store
            .set(KeyNamespace::Credentials, "ignored", b"x")
            .await
            .unwrap();
        store.set(KeyNamespace::TcToken, "c", b"3").await.unwrap();

        assert_eq!(
            store
                .list_keys(KeyNamespace::TcToken, None, 2)
                .await
                .unwrap(),
            vec!["a".to_owned(), "b".to_owned()]
        );
        assert_eq!(
            store
                .list_keys(KeyNamespace::TcToken, Some("b"), 10)
                .await
                .unwrap(),
            vec!["c".to_owned()]
        );
        assert!(
            store
                .list_keys(KeyNamespace::TcToken, None, 0)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
