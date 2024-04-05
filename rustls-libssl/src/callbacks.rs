use core::ffi::{c_uchar, c_void};
use core::ptr;
use std::collections::VecDeque;

use openssl_sys::SSL_TLSEXT_ERR_OK;

use crate::entry::{
    SSL_CTX_alpn_select_cb_func, SSL_CTX_cert_cb_func, _internal_SSL_complete_accept,
    _internal_SSL_set_alpn_choice, SSL,
};
use crate::error::Error;

/// Collects pending callbacks during a critical section.
///
/// Callback objects must be self-contained and own any neccessary data.
///
/// Callbacks are called in the same order they were `add()`ed.
///
/// This is because (eg) `SSL_accept` takes a lock on the `crate::Ssl`
/// it dispatches to, but this object knows when callbacks need to
/// happen.  It therefore adds an item to this object, and then
/// `SSL_accept` execute these once the lock has been dropped.
/// This means the callbacks are free to call further functions that
/// themselves take locks.
pub struct Callbacks {
    pending: VecDeque<Box<dyn PendingCallback>>,
    ssl: *mut SSL,
}

impl Callbacks {
    /// Make a new, empty callback collection.
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            ssl: ptr::null_mut(),
        }
    }

    /// Smuggle the original SSL* pointer via this object
    pub fn with_ssl(mut self, ssl: *mut SSL) -> Self {
        self.ssl = ssl;
        self
    }

    /// Get the original SSL* pointer, or else `NULL`
    pub fn ssl_ptr(&self) -> *mut SSL {
        self.ssl
    }

    /// Add a pending callback.
    pub fn add(&mut self, cb: Box<dyn PendingCallback>) {
        self.pending.push_back(cb);
    }

    /// Call the callbacks, in order.
    ///
    /// If one fails, the remainder are not called.
    pub fn dispatch(&mut self) -> Result<(), Error> {
        while let Some(callback) = self.pending.pop_front() {
            callback.call()?;
        }
        Ok(())
    }
}

/// A callback that should be called later.
pub trait PendingCallback {
    fn call(self: Box<Self>) -> Result<(), Error>;
}

/// Configuration needed to create a `AlpnPendingCallback` later
#[derive(Debug, Clone)]
pub struct AlpnCallbackConfig {
    pub cb: SSL_CTX_alpn_select_cb_func,
    pub context: *mut c_void,
}

impl Default for AlpnCallbackConfig {
    fn default() -> Self {
        Self {
            cb: None,
            context: ptr::null_mut(),
        }
    }
}

pub struct AlpnPendingCallback {
    pub config: AlpnCallbackConfig,
    pub ssl: *mut SSL,
    pub offer: Vec<u8>,
}

impl PendingCallback for AlpnPendingCallback {
    fn call(self: Box<Self>) -> Result<(), Error> {
        let callback = match self.config.cb {
            Some(callback) => callback,
            None => {
                return Ok(());
            }
        };

        let mut output_ptr: *const c_uchar = ptr::null();
        let mut output_len = 0u8;
        let result = unsafe {
            callback(
                self.ssl,
                &mut output_ptr as *mut *const c_uchar,
                &mut output_len as *mut u8,
                self.offer.as_ptr(),
                self.offer.len() as u32,
                self.config.context,
            )
        };

        if result == SSL_TLSEXT_ERR_OK {
            _internal_SSL_set_alpn_choice(self.ssl, output_ptr, output_len);
        }

        Ok(())
    }
}

/// Configuration needed to create a `CertPendingCallback` later
#[derive(Debug, Clone)]
pub struct CertCallbackConfig {
    pub cb: SSL_CTX_cert_cb_func,
    pub context: *mut c_void,
}

impl Default for CertCallbackConfig {
    fn default() -> Self {
        Self {
            cb: None,
            context: ptr::null_mut(),
        }
    }
}

pub struct CertPendingCallback {
    pub config: CertCallbackConfig,
    pub ssl: *mut SSL,
}

impl PendingCallback for CertPendingCallback {
    fn call(self: Box<Self>) -> Result<(), Error> {
        let callback = match self.config.cb {
            Some(callback) => callback,
            None => {
                return Ok(());
            }
        };

        let result = unsafe { callback(self.ssl, self.config.context) };

        match result {
            1 => Ok(()),
            _ => Err(Error::not_supported("SSL_CTX_cert_cb_func returned != 1")),
        }
    }
}

/// The last callback during acceptance of a connection by a server.
///
/// This completes the creation of the `ServerConfig` and `ServerConnection`.
///
/// It doesn't actually call into a user-supplied callback, but instead runs
/// after them.
pub struct CompleteAcceptPendingCallback {
    pub ssl: *mut SSL,
}

impl PendingCallback for CompleteAcceptPendingCallback {
    fn call(self: Box<Self>) -> Result<(), Error> {
        _internal_SSL_complete_accept(self.ssl)
    }
}
