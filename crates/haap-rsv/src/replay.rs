//! Two-tier replay store: in-process LRU + Redis SETNX with TTL.

use lru::LruCache;
use redis::aio::ConnectionManager;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("jti already consumed (in-process LRU)")]
    AlreadySeenLocally,
    #[error("jti already consumed (Redis SETNX returned 0)")]
    AlreadySeenDistributed,
    #[error("redis transport: {0}")]
    Redis(String),
}

#[derive(Clone)]
pub struct ReplayStore {
    lru: Arc<Mutex<LruCache<[u8; 22], ()>>>,
    redis: ConnectionManager,
}

impl ReplayStore {
    pub fn new(redis: ConnectionManager, lru_capacity: usize) -> Self {
        Self {
            lru: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(lru_capacity).unwrap_or(NonZeroUsize::new(1024).unwrap()),
            ))),
            redis,
        }
    }

    /// Try to atomically consume a jti. Returns Ok if the jti is fresh;
    /// returns AlreadySeen* if previously consumed.
    pub async fn try_consume(&self, jti: &[u8; 22], ttl: Duration) -> Result<(), ReplayError> {
        {
            let lru = self.lru.lock().await;
            if lru.contains(jti) {
                return Err(ReplayError::AlreadySeenLocally);
            }
        }

        let key = format!("haap:jti:{}", std::str::from_utf8(jti).unwrap_or("?"));
        let mut conn = self.redis.clone();
        let setnx: redis::Value = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("EX")
            .arg(ttl.as_secs())
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(|e| ReplayError::Redis(e.to_string()))?;

        if !matches!(setnx, redis::Value::Okay) {
            return Err(ReplayError::AlreadySeenDistributed);
        }

        let mut lru = self.lru.lock().await;
        lru.put(*jti, ());
        Ok(())
    }
}
