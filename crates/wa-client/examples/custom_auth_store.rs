use async_trait::async_trait;
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
};
use wa_client::prelude::Client;
use wa_store::{AuthStore, KeyNamespace, StoreError, StoreResult, StoreTransaction};

type StoreKey = (KeyNamespace, String);
type StoreMap = HashMap<StoreKey, Vec<u8>>;

#[derive(Clone, Default)]
struct ExampleAuthStore {
    entries: Arc<Mutex<StoreMap>>,
}

impl ExampleAuthStore {
    fn with_entries<F, R>(&self, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut StoreMap) -> StoreResult<R>,
    {
        let mut entries = self
            .entries
            .lock()
            .map_err(|error| StoreError::Join(error.to_string()))?;
        exec(&mut entries)
    }
}

#[async_trait]
impl AuthStore for ExampleAuthStore {
    async fn get(&self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>> {
        self.with_entries(|entries| Ok(entries.get(&(namespace, key.to_owned())).cloned()))
    }

    async fn set(&self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()> {
        let key = key.to_owned();
        let value = value.to_vec();
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
            let mut tx = ExampleTransaction {
                entries: &mut snapshot,
            };
            let result = exec(&mut tx)?;
            *entries = snapshot;
            Ok(result)
        })
    }
}

struct ExampleTransaction<'a> {
    entries: &'a mut StoreMap,
}

impl StoreTransaction for ExampleTransaction<'_> {
    fn get(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self.entries.get(&(namespace, key.to_owned())).cloned())
    }

    fn set(&mut self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()> {
        self.entries
            .insert((namespace, key.to_owned()), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<()> {
        self.entries.remove(&(namespace, key.to_owned()));
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let store = ExampleAuthStore::default();
    let client = Client::builder(store).connect().await?;
    let _events = client.subscribe();
    println!("client initialized with a custom auth store");
    Ok(())
}
