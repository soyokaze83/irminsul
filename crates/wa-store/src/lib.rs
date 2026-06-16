#![forbid(unsafe_code)]

mod traits;

#[cfg(feature = "memory")]
mod memory;

#[cfg(feature = "sqlite")]
mod sqlite;

pub use traits::{
    AuthStore, KeyNamespace, SignalKeyStore, StoreError, StoreResult, StoreTransaction,
};

#[cfg(feature = "memory")]
pub use memory::MemoryAuthStore;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteAuthStore;
