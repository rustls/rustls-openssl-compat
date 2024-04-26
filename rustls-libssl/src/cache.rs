use core::ptr;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rustls::client::ClientSessionMemoryCache;
use rustls::client::ClientSessionStore;
use rustls::server::StoresServerSessions;

use crate::entry::{
    SSL_CTX_new_session_cb, SSL_CTX_sess_get_cb, SSL_CTX_sess_remove_cb, SSL_CTX, SSL_SESSION,
};
use crate::{callbacks, SslSession, SslSessionLookup};

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

    pub fn set_pointer_to_owning_ssl_ctx(&mut self, ptr: *mut SSL_CTX) {
        self.server.set_ssl_ctx(ptr);
    }

    /// Get a cache that can be used for an in-construction `ClientConnection`
    pub fn get_client(&mut self) -> Arc<dyn ClientSessionStore + Send + Sync> {
        Arc::clone(
            self.client
                .get_or_insert_with(|| Arc::new(ClientSessionMemoryCache::new(self.max_size))),
        )
    }

    /// Get a cache that can be used for a single `ServerConnection`
    pub fn get_server(&mut self) -> Arc<SingleServerCache> {
        Arc::new(SingleServerCache::new(self.server.clone()))
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

    pub fn set_new_callback(&mut self, callback: SSL_CTX_new_session_cb) {
        self.server.set_new_callback(callback)
    }

    pub fn set_remove_callback(&mut self, callback: SSL_CTX_sess_remove_cb) {
        self.server.set_remove_callback(callback)
    }

    pub fn set_get_callback(&mut self, callback: SSL_CTX_sess_get_cb) {
        self.server.set_get_callback(callback);
    }

    pub fn set_context(&mut self, context: &[u8]) {
        self.server.set_context(context);
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

    fn set_new_callback(&self, callback: SSL_CTX_new_session_cb) {
        if let Ok(mut inner) = self.parameters.lock() {
            inner.callbacks.new_callback = callback;
        }
    }

    fn set_remove_callback(&self, callback: SSL_CTX_sess_remove_cb) {
        if let Ok(mut inner) = self.parameters.lock() {
            inner.callbacks.remove_callback = callback;
        }
    }

    fn set_get_callback(&self, callback: SSL_CTX_sess_get_cb) {
        if let Ok(mut inner) = self.parameters.lock() {
            inner.callbacks.get_callback = callback;
        }
    }

    fn set_ssl_ctx(&self, ssl_ctx: *mut SSL_CTX) {
        if let Ok(mut inner) = self.parameters.lock() {
            inner.callbacks.ssl_ctx = ssl_ctx;
        }
    }

    fn set_context(&self, context: &[u8]) {
        if let Ok(mut inner) = self.parameters.lock() {
            context.clone_into(&mut inner.context);
        }
    }

    fn get_context(&self) -> Vec<u8> {
        self.parameters
            .lock()
            .ok()
            .map(|inner| inner.context.clone())
            .unwrap_or_default()
    }

    fn mode(&self) -> u32 {
        self.parameters
            .lock()
            .map(|inner| inner.mode)
            .unwrap_or_default()
    }

    fn callbacks(&self) -> CacheCallbacks {
        self.parameters
            .lock()
            .map(|inner| inner.callbacks)
            .unwrap_or_default()
    }

    fn invoke_new_callback(&self, sess: Arc<SslSession>) -> bool {
        callbacks::invoke_session_new_callback(self.callbacks().new_callback, sess)
    }

    fn invoke_remove_callback(&self, sess: Arc<SslSession>) {
        let callbacks = self.callbacks();
        callbacks::invoke_session_remove_callback(
            callbacks.remove_callback,
            callbacks.ssl_ctx,
            sess,
        );
    }

    fn invoke_get_callback(&self, id: &[u8]) -> Option<Arc<SslSession>> {
        callbacks::invoke_session_get_callback(self.callbacks().get_callback, id)
    }

    fn build_new_session(&self, id: Vec<u8>, value: Vec<u8>) -> Arc<SslSession> {
        let context = self.get_context();
        let time_out = ExpiryTime::calculate(TimeBase::now(), self.get_timeout());
        Arc::new(SslSession::new(id, value, context, time_out))
    }

    fn insert(&self, new: Arc<SslSession>) -> bool {
        if let Ok(mut items) = self.items.lock() {
            items.insert(new)
        } else {
            false
        }
    }

    fn take(&self, id: &[u8]) -> Option<Arc<SslSession>> {
        if let Ok(mut items) = self.items.lock() {
            items.take(&SslSessionLookup::for_id(id))
        } else {
            None
        }
    }

    fn find_by_id(&self, id: &[u8]) -> Option<Arc<SslSession>> {
        if let Ok(items) = self.items.lock() {
            items.get(&SslSessionLookup::for_id(id)).cloned()
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct CacheParameters {
    callbacks: CacheCallbacks,
    mode: u32,
    context: Vec<u8>,
    max_size: usize,
    time_out: u64,
}

impl CacheParameters {
    fn new(max_size: usize) -> Self {
        Self {
            callbacks: CacheCallbacks::default(),
            mode: CACHE_MODE_SERVER,
            context: vec![],
            max_size,
            // See <https://www.openssl.org/docs/manmaster/man3/SSL_get_default_timeout.html>
            time_out: 300,
        }
    }
}

/// A `StoresServerSessions` implementor that is bound to a single `SSL`,
/// and tracks which `SSL_SESSION` was most recently used, to allow
/// `SSL_get_session` to work.
#[derive(Debug)]
pub struct SingleServerCache {
    parent: Arc<ServerSessionStorage>,
    most_recent_session: Mutex<Option<Arc<SslSession>>>,
}

impl SingleServerCache {
    fn new(parent: Arc<ServerSessionStorage>) -> Self {
        Self {
            parent,
            most_recent_session: Mutex::new(None),
        }
    }

    fn is_enabled(&self) -> bool {
        self.parent.mode() & CACHE_MODE_SERVER == CACHE_MODE_SERVER
    }

    fn save_most_recent_session(&self, sess: Arc<SslSession>) {
        if let Ok(mut old) = self.most_recent_session.lock() {
            *old = Some(sess);
        }
    }

    pub fn get_most_recent_session(&self) -> Option<Arc<SslSession>> {
        self.most_recent_session
            .lock()
            .ok()
            .and_then(|inner| inner.clone())
    }

    pub fn borrow_most_recent_session(&self) -> *mut SSL_SESSION {
        if let Ok(inner) = self.most_recent_session.lock() {
            inner
                .as_ref()
                .map(|sess| Arc::as_ptr(sess) as *mut SSL_SESSION)
                .unwrap_or_else(ptr::null_mut)
        } else {
            ptr::null_mut()
        }
    }
}

impl StoresServerSessions for SingleServerCache {
    fn put(&self, id: Vec<u8>, value: Vec<u8>) -> bool {
        if !self.is_enabled() {
            return false;
        }

        let sess = self.parent.build_new_session(id, value);

        self.save_most_recent_session(sess.clone());

        let possibly_stored_elsewhere = self.parent.invoke_new_callback(sess.clone());

        if self.parent.mode() & CACHE_MODE_NO_INTERNAL_STORE == 0 {
            self.parent.insert(sess) || possibly_stored_elsewhere
        } else {
            possibly_stored_elsewhere
        }
    }

    fn get(&self, id: &[u8]) -> Option<Vec<u8>> {
        if !self.is_enabled() {
            return None;
        }

        if self.parent.mode() & CACHE_MODE_NO_INTERNAL_LOOKUP == 0 {
            let sess = self.parent.find_by_id(id);
            if let Some(sess) = sess {
                self.save_most_recent_session(sess.clone());
                return Some(sess.value.clone());
            }
        }

        if let Some(sess) = self.parent.invoke_get_callback(id) {
            return Some(sess.value.clone());
        }

        None
    }

    fn take(&self, id: &[u8]) -> Option<Vec<u8>> {
        if !self.is_enabled() {
            return None;
        }

        if self.parent.mode() & CACHE_MODE_NO_INTERNAL_LOOKUP == 0 {
            let sess = self.parent.take(id);

            if let Some(sess) = sess {
                // inform external cache that this session is being consumed
                self.parent.invoke_remove_callback(sess.clone());

                self.save_most_recent_session(sess.clone());
                return Some(sess.value.clone());
            }
        }

        // look up in external cache
        if let Some(sess) = self.parent.invoke_get_callback(id) {
            self.save_most_recent_session(sess.clone());
            self.parent.invoke_remove_callback(sess.clone());
            return Some(sess.value.clone());
        }

        None
    }

    fn can_cache(&self) -> bool {
        self.is_enabled()
    }
}

const CACHE_MODE_SERVER: u32 = 0x02;
const CACHE_MODE_NO_AUTO_CLEAR: u32 = 0x080;
const CACHE_MODE_NO_INTERNAL_LOOKUP: u32 = 0x100;
const CACHE_MODE_NO_INTERNAL_STORE: u32 = 0x200;

#[derive(Clone, Copy, Debug)]
struct CacheCallbacks {
    new_callback: SSL_CTX_new_session_cb,
    remove_callback: SSL_CTX_sess_remove_cb,
    get_callback: SSL_CTX_sess_get_cb,
    ssl_ctx: *mut SSL_CTX,
}

impl Default for CacheCallbacks {
    fn default() -> Self {
        Self {
            new_callback: None,
            remove_callback: None,
            get_callback: None,
            ssl_ctx: ptr::null_mut(),
        }
    }
}
// `ssl_ctx` is not Send, but we don't dereference it (could
// equally be an integer).
unsafe impl Send for CacheCallbacks {}

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
