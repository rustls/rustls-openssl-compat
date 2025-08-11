use core::cell::RefCell;
use core::ffi::{c_int, c_uchar, c_void};
use core::{ptr, slice};
use std::sync::Arc;

use openssl_sys::{SSL_TLSEXT_ERR_NOACK, SSL_TLSEXT_ERR_OK};
use rustls::AlertDescription;

use crate::entry::{
    SSL_CTX_alpn_select_cb_func, SSL_CTX_cert_cb_func, SSL_CTX_info_callback_func,
    SSL_CTX_new_session_cb, SSL_CTX_servername_callback_func, SSL_CTX_sess_get_cb,
    SSL_CTX_sess_remove_cb, SSL_client_hello_cb_func, _SSL_SESSION_free, SSL, SSL_CTX, SSL_SESSION,
};
use crate::error::Error;
use crate::ffi;
use crate::not_thread_safe::NotThreadSafe;

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
        let Some(callback) = self.cb else {
            return Ok(None);
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
        let Some(callback) = self.cb else {
            return Ok(());
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

/// Configuration needed to call [`invoke_servername_callback`] later
#[derive(Debug, Clone)]
pub struct ServerNameCallbackConfig {
    pub cb: SSL_CTX_servername_callback_func,
    pub context: *mut c_void,
}

impl ServerNameCallbackConfig {
    pub fn invoke(&self) -> Result<(), Error> {
        let Some(callback) = self.cb else {
            return Ok(());
        };

        let ssl = SslCallbackContext::ssl_ptr();

        let unrecognised_name = u8::from(AlertDescription::UnrecognisedName) as c_int;
        let mut alert = unrecognised_name;
        let result = unsafe { callback(ssl, &mut alert as *mut c_int, self.context) };

        if alert != unrecognised_name {
            log::trace!("NYI: customised alert during servername callback");
        }

        match result {
            SSL_TLSEXT_ERR_OK => Ok(()),
            // in practice no client does anything if SNI is not acked, and rustls
            // acks any syntactically valid extension (and ignores invalid ones, because OpenSSL)
            SSL_TLSEXT_ERR_NOACK => {
                log::trace!("NYI: SSL_TLSEXT_ERR_NOACK returned from SSL_CTX_servername_callback_func (acking the extension anyway)");
                Ok(())
            }
            _ => Err(Error::not_supported(
                "SSL_CTX_servername_callback_func return error",
            )),
        }
    }
}

impl Default for ServerNameCallbackConfig {
    fn default() -> Self {
        Self {
            cb: None,
            context: ptr::null_mut(),
        }
    }
}

/// Returns true if a callback was actually called.
///
/// It is unknowable if this means something was stored externally.
pub fn invoke_session_new_callback(
    callback: SSL_CTX_new_session_cb,
    sess: Arc<NotThreadSafe<SSL_SESSION>>,
) -> bool {
    let Some(callback) = callback else {
        return false;
    };

    let ssl = SslCallbackContext::ssl_ptr();
    let sess_ptr = Arc::into_raw(sess) as *mut SSL_SESSION;

    let result = unsafe { callback(ssl, sess_ptr) };

    // "If the callback returns 1, the application retains the reference"
    if result == 0 {
        _SSL_SESSION_free(sess_ptr);
    }
    true
}

pub fn invoke_session_get_callback(
    callback: SSL_CTX_sess_get_cb,
    id: &[u8],
) -> Option<Arc<NotThreadSafe<SSL_SESSION>>> {
    let callback = callback?;

    let ssl_ptr = SslCallbackContext::ssl_ptr();
    let mut copy = 1;
    let sess_ptr = unsafe { callback(ssl_ptr, id.as_ptr(), id.len() as c_int, &mut copy) };

    if sess_ptr.is_null() {
        return None;
    }

    let maybe_sess = ffi::clone_arc(sess_ptr);

    if copy > 0 {
        _SSL_SESSION_free(sess_ptr);
    }

    maybe_sess
}

pub fn invoke_session_remove_callback(
    callback: SSL_CTX_sess_remove_cb,
    ssl_ctx: *mut SSL_CTX,
    sess: Arc<NotThreadSafe<SSL_SESSION>>,
) {
    let Some(callback) = callback else {
        return;
    };

    let sess_ptr = Arc::into_raw(sess) as *mut SSL_SESSION;

    unsafe { callback(ssl_ctx, sess_ptr) };

    _SSL_SESSION_free(sess_ptr);
}

/// Configuration needed to call an [`SSL_CTX_info_callback_func`] later
#[derive(Debug, Default, Clone)]
pub struct InfoCallbackConfig {
    pub cb: SSL_CTX_info_callback_func,
}

impl InfoCallbackConfig {
    pub fn invoke(&self, info: Info) {
        let Some(callback) = self.cb else {
            return;
        };

        let ssl = SslCallbackContext::ssl_ptr();
        unsafe { callback(ssl, info.typ(), info.val()) };
    }
}

pub enum Info {
    /// `SSL_CB_ALERT | SSL_CB_READ`
    AlertReceived(AlertDescription),

    /// `SSL_CB_ALERT | SSL_CB_WRITE`
    AlertSent(AlertDescription),
}

impl Info {
    fn typ(&self) -> c_int {
        match self {
            Self::AlertReceived(_) => SSL_CB_ALERT | SSL_CB_READ,
            Self::AlertSent(_) => SSL_CB_ALERT | SSL_CB_WRITE,
        }
    }

    fn val(&self) -> c_int {
        match self {
            Self::AlertReceived(a) | Self::AlertSent(a) => u8::from(*a) as c_int,
        }
    }
}

const SSL_CB_ALERT: c_int = 0x4000;
const SSL_CB_READ: c_int = 0x0004;
const SSL_CB_WRITE: c_int = 0x0008;

/// Configuration needed to call a client hello callback later
#[derive(Debug, Default, Clone)]
pub struct ClientHelloCallbackConfig {
    pub cb: SSL_client_hello_cb_func,
    pub context: *mut c_void,
}

impl ClientHelloCallbackConfig {
    pub fn invoke(&self) -> Result<(), Error> {
        let Some(callback) = self.cb else {
            return Ok(());
        };

        let internal_error = u8::from(AlertDescription::InternalError) as c_int;

        let ssl = SslCallbackContext::ssl_ptr();
        let mut alert = internal_error;
        let result = unsafe { callback(ssl, &mut alert as *mut c_int, self.context) };

        if alert != internal_error {
            log::trace!("NYI: customised alert during client hello callback");
        }

        match result {
            i if i < 0 => Err(Error::not_supported(
                "SSL_client_hello_cb_func requesting suspension",
            )),
            0 => Err(Error::not_supported(
                "SSL_client_hello_cb_func returning error",
            )),
            _ => Ok(()),
        }
    }
}
