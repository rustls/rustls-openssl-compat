use core::cell::RefCell;
use core::ffi::{c_uchar, c_void};
use core::{ptr, slice};

use openssl_sys::{SSL_TLSEXT_ERR_NOACK, SSL_TLSEXT_ERR_OK};

use crate::entry::{SSL_CTX_alpn_select_cb_func, SSL_CTX_cert_cb_func, SSL};
use crate::error::Error;

/// Smuggling SSL* pointers from the outer entrypoint into the
/// callback call site.
pub struct SslCallbackContext;

impl SslCallbackContext {
    /// Register the original SSL* pointer for use in later callbacks.
    ///
    /// The returned object de-registers itself when dropped.
    pub fn new(ssl: *mut SSL) -> Self {
        SSL_CALLBACK_CONTEXT.set(Some(ssl));
        Self
    }

    /// Get the original SSL* pointer, or else `NULL`
    ///
    /// This has thread-local semantics: it uses the most recent
    /// object of this type created on this thread.
    pub fn ssl_ptr() -> *mut SSL {
        SSL_CALLBACK_CONTEXT.with_borrow(|holder| {
            holder
                .as_ref()
                .map(|inner| *inner)
                .unwrap_or_else(ptr::null_mut)
        })
    }
}

impl Drop for SslCallbackContext {
    fn drop(&mut self) {
        SSL_CALLBACK_CONTEXT.set(None);
    }
}

thread_local! {
    static SSL_CALLBACK_CONTEXT: RefCell<Option<*mut SSL>> = const { RefCell::new(None) };
}

/// Configuration needed to call [`invoke_alpn_callback`] later
#[derive(Debug, Clone)]
pub struct AlpnCallbackConfig {
    pub cb: SSL_CTX_alpn_select_cb_func,
    pub context: *mut c_void,
}

impl AlpnCallbackConfig {
    /// Call a `SSL_CTX_alpn_select_cb_func` callback
    ///
    /// Returns the selected ALPN, or None, or an error.
    pub fn invoke(&self, offer: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let callback = match self.cb {
            Some(callback) => callback,
            None => {
                return Ok(None);
            }
        };

        let ssl = SslCallbackContext::ssl_ptr();

        let mut output_ptr: *const c_uchar = ptr::null();
        let mut output_len = 0u8;
        let result = unsafe {
            callback(
                ssl,
                &mut output_ptr as *mut *const c_uchar,
                &mut output_len as *mut u8,
                offer.as_ptr(),
                offer.len() as u32,
                self.context,
            )
        };

        if result == SSL_TLSEXT_ERR_OK && !output_ptr.is_null() {
            let chosen = unsafe { slice::from_raw_parts(output_ptr, output_len as usize) };
            Ok(Some(chosen.to_vec()))
        } else if result == SSL_TLSEXT_ERR_NOACK {
            Ok(None)
        } else {
            Err(Error::bad_data("alpn not chosen"))
        }
    }
}

impl Default for AlpnCallbackConfig {
    fn default() -> Self {
        Self {
            cb: None,
            context: ptr::null_mut(),
        }
    }
}

/// Configuration needed to call [`invoke_cert_callback`] later
#[derive(Debug, Clone)]
pub struct CertCallbackConfig {
    pub cb: SSL_CTX_cert_cb_func,
    pub context: *mut c_void,
}

impl CertCallbackConfig {
    pub fn invoke(&self) -> Result<(), Error> {
        let callback = match self.cb {
            Some(callback) => callback,
            None => {
                return Ok(());
            }
        };
        let ssl = SslCallbackContext::ssl_ptr();

        let result = unsafe { callback(ssl, self.context) };

        match result {
            1 => Ok(()),
            _ => Err(Error::not_supported("SSL_CTX_cert_cb_func returned != 1")),
        }
    }
}

impl Default for CertCallbackConfig {
    fn default() -> Self {
        Self {
            cb: None,
            context: ptr::null_mut(),
        }
    }
}
