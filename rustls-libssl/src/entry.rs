//! This file contains all the libssl entrypoints that we implement.
//!
//! It should mainly be concerned with mapping these calls up to
//! the safe APIs implemented elsewhere.

use core::{mem, ptr};
use std::os::raw::{c_char, c_int, c_uchar};
use std::sync::Mutex;

use openssl_sys::OPENSSL_malloc;

use crate::error::{ffi_panic_boundary, Error};
use crate::ffi::{
    free_arc, to_arc_mut_ptr, try_clone_arc, try_from, try_ref_from_ptr, try_slice, Castable,
    OwnershipArc, OwnershipRef,
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

entry! {
    pub fn _SSL_alert_desc_string_long(value: c_int) -> *const c_char {
        crate::constants::alert_desc_to_long_string(value).as_ptr() as *const c_char
    }
}

entry! {
    pub fn _SSL_alert_desc_string(value: c_int) -> *const c_char {
        crate::constants::alert_desc_to_short_string(value).as_ptr() as *const c_char
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

type SSL_CIPHER = crate::SslCipher;

entry! {
    pub fn _SSL_CIPHER_find(_ssl: *const SSL, ptr: *const c_uchar) -> *const SSL_CIPHER {
        let slice = try_slice!(ptr, 2);
        let id = (slice[0] as u16) << 8 | (slice[1] as u16);
        crate::SslCipher::find_by_id(rustls::CipherSuite::from(id))
            .map(|cipher| cipher as *const SSL_CIPHER)
            .unwrap_or_else(ptr::null)
    }
}

entry! {
    pub fn _SSL_CIPHER_get_bits(cipher: *const SSL_CIPHER, alg_bits: *mut c_int) -> c_int {
        let cipher = try_ref_from_ptr!(cipher);
        let bits = cipher.bits as c_int;
        if !alg_bits.is_null() {
            unsafe { ptr::write(alg_bits, bits) };
        }
        bits
    }
}

entry! {
    pub fn _SSL_CIPHER_get_version(cipher: *const SSL_CIPHER) -> *const c_char {
        match try_from(cipher) {
            Some(cipher) => cipher.version,
            None => c"(NONE)",
        }
        .as_ptr()
    }
}

entry! {
    pub fn _SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) -> *const c_char {
        match try_from(cipher) {
            Some(cipher) => cipher.openssl_name,
            None => c"(NONE)",
        }
        .as_ptr()
    }
}

entry! {
    pub fn _SSL_CIPHER_standard_name(cipher: *const SSL_CIPHER) -> *const c_char {
        match try_from(cipher) {
            Some(cipher) => cipher.standard_name,
            None => c"(NONE)",
        }
        .as_ptr()
    }
}

entry! {
    pub fn _SSL_CIPHER_get_id(cipher: *const SSL_CIPHER) -> u32 {
        let cipher = try_ref_from_ptr!(cipher);
        cipher.openssl_id()
    }
}

entry! {
    pub fn _SSL_CIPHER_get_protocol_id(cipher: *const SSL_CIPHER) -> u16 {
        let cipher = try_ref_from_ptr!(cipher);
        cipher.protocol_id()
    }
}

entry! {
    pub fn _SSL_CIPHER_description(
        cipher: *const SSL_CIPHER,
        mut buf: *mut c_char,
        mut size: c_int,
    ) -> *mut c_char {
        let cipher = try_ref_from_ptr!(cipher);
        let required_len = cipher.description.to_bytes_with_nul().len();

        if buf.is_null() {
            // safety: `required_len` is a compile-time constant, and is
            // a reasonable quantity to ask `OPENSSL_malloc` for.
            // In C cast rules, any `*mut c_void` can be viewed as a
            // `*mut c_char`.
            let allocd = unsafe { OPENSSL_malloc(required_len) as *mut c_char };
            if allocd.is_null() {
                return allocd;
            }
            buf = allocd;
            size = required_len as i32;
        } else if size < (required_len as i32) {
            return ptr::null_mut();
        }

        unsafe {
            ptr::copy_nonoverlapping(cipher.description.as_ptr(), buf, required_len as usize);
        };
        buf
    }
}

impl Castable for SSL_CIPHER {
    type Ownership = OwnershipRef;
    type RustType = SSL_CIPHER;
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
