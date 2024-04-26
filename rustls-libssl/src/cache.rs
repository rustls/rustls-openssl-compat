use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rustls::client::ClientSessionMemoryCache;
use rustls::client::ClientSessionStore;

use crate::SslSession;

/// A container for session caches that can live inside
/// an `SSL_CTX` but outlive a rustls `ServerConfig`/`ClientConfig`
pub struct SessionCaches {
    max_size: usize,

    /// the underlying client store. This outlives any given connection.
    client: Option<Arc<dyn ClientSessionStore + Send + Sync>>,

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
            client: None,
            server: Arc::new(ServerSessionStorage::new(max_size)),
        }
    }

    /// Get a cache that can be used for an in-construction `ClientConnection`
    pub fn get_client(&mut self) -> Arc<dyn ClientSessionStore + Send + Sync> {
        Arc::clone(
            self.client
                .get_or_insert_with(|| Arc::new(ClientSessionMemoryCache::new(self.max_size))),
        )
    }

    pub fn set_mode(&mut self, mode: u32) -> u32 {
        self.server.set_mode(mode)
    }

    pub fn get_timeout(&self) -> u64 {
        self.server.get_timeout()
    }

    pub fn set_timeout(&mut self, timeout: u64) -> u64 {
        self.server.set_timeout(timeout)
    }

    pub fn size(&self) -> usize {
        self.max_size
    }

    pub fn set_size(&mut self, size: usize) -> usize {
        let old_size = self.max_size;
        self.max_size = size;
        self.server.set_size(size);
        // divergence: openssl can change the size without emptying the (client) cache
        self.client.take();
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

    fn get_timeout(&self) -> u64 {
        self.parameters
            .lock()
            .map(|inner| inner.time_out)
            .unwrap_or_default()
    }

    fn set_timeout(&self, time_out: u64) -> u64 {
        self.parameters
            .lock()
            .map(|mut inner| {
                let old = inner.time_out;
                inner.time_out = time_out;
                old
            })
            .unwrap_or_default()
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
    time_out: u64,
}

impl CacheParameters {
    fn new(max_size: usize) -> Self {
        Self {
            mode: CACHE_MODE_SERVER,
            max_size,
            // See <https://www.openssl.org/docs/manmaster/man3/SSL_get_default_timeout.html>
            time_out: 300,
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
