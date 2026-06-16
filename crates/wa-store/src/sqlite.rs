use crate::{AuthStore, KeyNamespace, StoreError, StoreResult, StoreTransaction};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct SqliteAuthStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
}

impl SqliteAuthStore {
    pub async fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let path = path.as_ref().to_owned();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| StoreError::Join(err.to_string()))?;
        } else {
            return Err(StoreError::MissingParent);
        }

        let connection = Connection::open(&path)?;
        configure_connection(&connection)?;
        migrate(&connection)?;

        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn with_connection<F, R>(&self, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut Connection) -> StoreResult<R>,
    {
        let mut guard = self
            .connection
            .lock()
            .map_err(|err| StoreError::Join(err.to_string()))?;
        exec(&mut guard)
    }
}

fn configure_connection(connection: &Connection) -> StoreResult<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

fn migrate(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY NOT NULL,
            value INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS kv_store (
            namespace TEXT NOT NULL,
            key TEXT NOT NULL,
            value BLOB NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
            PRIMARY KEY (namespace, key)
        );

        INSERT INTO schema_meta(key, value)
        VALUES ('schema_version', 1)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        "#,
    )?;
    Ok(())
}

#[async_trait]
impl AuthStore for SqliteAuthStore {
    async fn get(&self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>> {
        let key = key.to_owned();
        self.with_connection(move |connection| {
            connection
                .query_row(
                    "SELECT value FROM kv_store WHERE namespace = ?1 AND key = ?2",
                    params![namespace.as_str(), key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(StoreError::from)
        })
    }

    async fn set(&self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()> {
        let key = key.to_owned();
        let value = value.to_vec();
        self.with_connection(move |connection| {
            connection.execute(
                r#"
                INSERT INTO kv_store(namespace, key, value, updated_at)
                VALUES (?1, ?2, ?3, unixepoch())
                ON CONFLICT(namespace, key)
                DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                "#,
                params![namespace.as_str(), key, value],
            )?;
            Ok(())
        })
    }

    async fn delete(&self, namespace: KeyNamespace, key: &str) -> StoreResult<()> {
        let key = key.to_owned();
        self.with_connection(move |connection| {
            connection.execute(
                "DELETE FROM kv_store WHERE namespace = ?1 AND key = ?2",
                params![namespace.as_str(), key],
            )?;
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
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_connection(move |connection| {
            if limit <= 0 {
                return Ok(Vec::new());
            }
            let mut statement = connection.prepare(
                r#"
                SELECT key FROM kv_store
                WHERE namespace = ?1
                  AND (?2 IS NULL OR key > ?2)
                ORDER BY key ASC
                LIMIT ?3
                "#,
            )?;
            let rows = statement.query_map(
                params![namespace.as_str(), after.as_deref(), limit],
                |row| row.get::<_, String>(0),
            )?;
            let mut keys = Vec::new();
            for row in rows {
                keys.push(row?);
            }
            Ok(keys)
        })
    }

    async fn transaction<F, R>(&self, _label: &str, exec: F) -> StoreResult<R>
    where
        F: FnOnce(&mut dyn StoreTransaction) -> StoreResult<R> + Send + 'static,
        R: Send + 'static,
    {
        self.with_connection(move |connection| {
            let tx = connection.transaction()?;
            let mut wrapper = SqliteTransaction { tx };
            let result = exec(&mut wrapper)?;
            wrapper.tx.commit()?;
            Ok(result)
        })
    }
}

struct SqliteTransaction<'a> {
    tx: rusqlite::Transaction<'a>,
}

impl StoreTransaction for SqliteTransaction<'_> {
    fn get(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<Option<Vec<u8>>> {
        self.tx
            .query_row(
                "SELECT value FROM kv_store WHERE namespace = ?1 AND key = ?2",
                params![namespace.as_str(), key],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    fn set(&mut self, namespace: KeyNamespace, key: &str, value: &[u8]) -> StoreResult<()> {
        self.tx.execute(
            r#"
            INSERT INTO kv_store(namespace, key, value, updated_at)
            VALUES (?1, ?2, ?3, unixepoch())
            ON CONFLICT(namespace, key)
            DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            "#,
            params![namespace.as_str(), key, value],
        )?;
        Ok(())
    }

    fn delete(&mut self, namespace: KeyNamespace, key: &str) -> StoreResult<()> {
        self.tx.execute(
            "DELETE FROM kv_store WHERE namespace = ?1 AND key = ?2",
            params![namespace.as_str(), key],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn persists_values() {
        let dir = std::env::temp_dir().join(format!("wa-store-{}", rand_suffix()));
        let path = dir.join("session.db");
        let store = SqliteAuthStore::open(&path).await.unwrap();
        store
            .set(KeyNamespace::Credentials, "me", b"hello")
            .await
            .unwrap();
        assert_eq!(
            store.get(KeyNamespace::Credentials, "me").await.unwrap(),
            Some(b"hello".to_vec())
        );
    }

    #[tokio::test]
    async fn rolls_back_failed_transaction() {
        let dir = std::env::temp_dir().join(format!("wa-store-{}", rand_suffix()));
        let path = dir.join("session.db");
        let store = SqliteAuthStore::open(&path).await.unwrap();

        let result: StoreResult<()> = store
            .transaction("test", |tx| {
                tx.set(KeyNamespace::PreKey, "1", b"one")?;
                Err(StoreError::Join("boom".to_owned()))
            })
            .await;

        assert!(result.is_err());
        assert_eq!(store.get(KeyNamespace::PreKey, "1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn lists_keys_by_namespace_with_pagination() {
        let dir = std::env::temp_dir().join(format!("wa-store-{}", rand_suffix()));
        let path = dir.join("session.db");
        let store = SqliteAuthStore::open(&path).await.unwrap();
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

    fn rand_suffix() -> u128 {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = u128::from(TEST_DB_COUNTER.fetch_add(1, Ordering::AcqRel));
        let process_id = u128::from(std::process::id());
        timestamp ^ (process_id << 32) ^ counter
    }
}
