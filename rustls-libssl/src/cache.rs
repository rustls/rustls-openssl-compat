use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::SslSession;

/// A container for session caches that can live inside
/// an `SSL_CTX` but outlive a rustls `ServerConfig`/`ClientConfig`
pub struct SessionCaches {
    max_size: usize,

    /// the underlying server store. This outlives any given connection.
    server: Arc<ServerSessionStorage>,
}

impl SessionCaches {
    pub fn with_size(max_size: usize) -> Self {
        // a user who has one `SSL_CTX` for both clients and servers will end
        // up with twice as many sessions as this, since rustls caches
        // client and server sessions separately.
        //
        // the common case is to have those separate (it is, for example,
        // impossible to configure certs/keys separately for client and
        // servers in a given `SSL_CTX`) so this should be ok.
        Self {
            max_size,
            server: Arc::new(ServerSessionStorage::new(max_size)),
        }
    }

    pub fn set_mode(&mut self, mode: u32) -> u32 {
        self.server.set_mode(mode)
    }

    pub fn size(&self) -> usize {
        self.max_size
    }

    pub fn set_size(&mut self, size: usize) -> usize {
        let old_size = self.max_size;
        self.max_size = size;
        self.server.set_size(size);
        old_size
    }
}

impl Default for SessionCaches {
    fn default() -> Self {
        // this is SSL_SESSION_CACHE_MAX_SIZE_DEFAULT
        Self::with_size(1024 * 20)
    }
}

#[derive(Debug)]
pub struct ServerSessionStorage {
    items: Mutex<BTreeSet<Arc<SslSession>>>,
    parameters: Mutex<CacheParameters>,
}

impl ServerSessionStorage {
    fn new(max_size: usize) -> Self {
        Self {
            items: Mutex::new(BTreeSet::new()),
            parameters: Mutex::new(CacheParameters::new(max_size)),
        }
    }

    fn set_mode(&self, mode: u32) -> u32 {
        if let Ok(mut inner) = self.parameters.lock() {
            let old = inner.mode;
            inner.mode = mode;
            old
        } else {
            0
        }
    }

    fn set_size(&self, size: usize) {
        if let Ok(mut inner) = self.parameters.lock() {
            inner.max_size = size;
        }
    }
}

#[derive(Debug)]
struct CacheParameters {
    mode: u32,
    max_size: usize,
}

impl CacheParameters {
    fn new(max_size: usize) -> Self {
        Self {
            mode: CACHE_MODE_SERVER,
            max_size,
        }
    }
}

const CACHE_MODE_SERVER: u32 = 0x02;

#[derive(Debug, Clone, Copy)]
pub struct ExpiryTime(pub u64);

impl ExpiryTime {
    fn calculate(now: TimeBase, life_time_secs: u64) -> ExpiryTime {
        ExpiryTime(now.0.saturating_add(life_time_secs))
    }

    pub fn in_past(&self, time: TimeBase) -> bool {
        self.0 < time.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TimeBase(u64);

impl TimeBase {
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|n| n.as_secs())
                .unwrap_or_default(),
        )
    }
}
