//! This file contains all the libssl entrypoints that we implement.
//!
//! It should mainly be concerned with mapping these calls up to
//! the safe APIs implemented elsewhere.

use core::mem;
use std::os::raw::c_int;
use std::sync::Mutex;

use crate::error::{ffi_panic_boundary, Error};
use crate::ffi::{
    free_arc, to_arc_mut_ptr, try_clone_arc, try_ref_from_ptr, Castable, OwnershipArc, OwnershipRef,
};

/// Makes a entry function definition.
///
/// The body is wrapped in `ffi_panic_boundary`, the name is `#[no_mangle]`,
/// and is `extern "C"`.
///
/// See also `build.rs`:
///
/// - the name should start with `_` to support the linker-renaming and symbol
///   versioning happening there,
/// - the name should appear in the list of all entry points there.
macro_rules! entry {
    (pub fn $name:ident($($args:tt)*) $body:block) => {
        #[no_mangle]
        pub extern "C" fn $name($($args)*) { ffi_panic_boundary! { $body } }
    };
    (pub fn $name:ident($($args:tt)*) -> $ret:ty $body:block) => {
        #[no_mangle]
        pub extern "C" fn $name($($args)*) -> $ret { ffi_panic_boundary! { $body } }
    };
}

pub struct OpenSslInitSettings;
type OPENSSL_INIT_SETTINGS = OpenSslInitSettings;

entry! {
    pub fn _OPENSSL_init_ssl(_opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int {
        const VERSION: &str = env!("CARGO_PKG_VERSION");

        if !settings.is_null() {
            return Error::not_supported("settings").raise().into();
        }
        env_logger::init();
        log::trace!("OPENSSL_init_ssl in rustls-libssl {VERSION}");
        C_INT_SUCCESS
    }
}

type SSL_METHOD = crate::SslMethod;

entry! {
    pub fn _TLS_method() -> *const SSL_METHOD {
        &crate::TLS_METHOD
    }
}

entry! {
    pub fn _TLS_server_method() -> *const SSL_METHOD {
        &crate::TLS_SERVER_METHOD
    }
}

entry! {
    pub fn _TLS_client_method() -> *const SSL_METHOD {
        &crate::TLS_CLIENT_METHOD
    }
}

impl Castable for SSL_METHOD {
    type Ownership = OwnershipRef;
    type RustType = SSL_METHOD;
}

type SSL_CTX = crate::SslContext;

entry! {
    pub fn _SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX {
        let method = try_ref_from_ptr!(meth);
        to_arc_mut_ptr(Mutex::new(crate::SslContext::new(method)))
    }
}

entry! {
    pub fn _SSL_CTX_up_ref(ctx: *mut SSL_CTX) -> c_int {
        let ctx = try_clone_arc!(ctx);
        mem::forget(ctx.clone());
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_free(ctx: *mut SSL_CTX) {
        free_arc(ctx);
    }
}

impl Castable for SSL_CTX {
    type Ownership = OwnershipArc;
    type RustType = Mutex<SSL_CTX>;
}

type SSL = crate::Ssl;

entry! {
    pub fn _SSL_new(ctx: *mut SSL_CTX) -> *mut SSL {
        let ctx = try_clone_arc!(ctx);
        to_arc_mut_ptr(Mutex::new(crate::Ssl::new(ctx)))
    }
}

entry! {
    pub fn _SSL_up_ref(ssl: *mut SSL) -> c_int {
        let ssl = try_clone_arc!(ssl);
        mem::forget(ssl.clone());
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_free(ssl: *mut SSL) {
        free_arc(ssl);
    }
}

impl Castable for SSL {
    type Ownership = OwnershipArc;
    type RustType = Mutex<SSL>;
}

/// Normal OpenSSL return value convention success indicator.
const C_INT_SUCCESS: c_int = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn test_SSL_CTX_new_null() {
        assert!(_SSL_CTX_new(ptr::null()).is_null());
    }

    #[test]
    fn test_SSL_new_null() {
        assert!(_SSL_new(ptr::null_mut()).is_null());
    }

    #[test]
    fn test_SSL_up_ref_null() {
        assert_eq!(_SSL_up_ref(ptr::null_mut()), 0);
    }

    #[test]
    fn test_SSL_free() {
        let ctx = _SSL_CTX_new(_TLS_method());
        assert!(!ctx.is_null());
        let ssl = _SSL_new(ctx);
        assert!(!ssl.is_null());
        _SSL_free(ssl);
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_free_after_up_ref() {
        let ctx = _SSL_CTX_new(_TLS_method());
        assert!(!ctx.is_null());
        let ssl = _SSL_new(ctx);
        assert!(!ssl.is_null());
        assert_eq!(_SSL_up_ref(ssl), 1);
        _SSL_free(ssl); // ref 2
        _SSL_free(ssl); // ref 1
        _SSL_CTX_free(ctx);
    }
}
