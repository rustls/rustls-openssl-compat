use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use openssl_sys::{
    d2i_X509, stack_st_X509, OPENSSL_sk_new_null, OPENSSL_sk_push, X509_STORE_free, X509_STORE_new,
    X509_free, OPENSSL_STACK, X509, X509_STORE,
};

/// Safe, owning wrapper around an OpenSSL `STACK_OF(X509)` object.
pub struct OwnedX509Stack {
    raw: *mut stack_st_X509,
}

impl OwnedX509Stack {
    pub fn empty() -> Self {
        Self {
            raw: unsafe { OPENSSL_sk_new_null() as *mut stack_st_X509 },
        }
    }

    pub fn push(&mut self, cert: &OwnedX509) {
        unsafe {
            OPENSSL_sk_push(
                self.raw as *mut OPENSSL_STACK,
                cert.up_ref() as *const c_void,
            );
        }
    }

    /// Leaks our pointer to the caller.
    ///
    /// We retain ownership.  The caller could modify the returned
    /// object under our feet; that is an inherent property of the
    /// OpenSSL `SSL_get_peer_cert_chain` API.
    pub fn pointer(&self) -> *mut stack_st_X509 {
        self.raw
    }
}

impl Drop for OwnedX509Stack {
    fn drop(&mut self) {
        unsafe {
            OPENSSL_sk_free(self.raw as *mut OPENSSL_STACK);
        }
    }
}

/// Safe, owning wrapper around an OpenSSL X509 object.
pub struct OwnedX509 {
    raw: *mut X509,
}

impl OwnedX509 {
    /// Create a new one, from parsing DER certificate data.
    pub fn parse_der(data: &[u8]) -> Option<Self> {
        let raw = unsafe {
            d2i_X509(
                ptr::null_mut(),
                &mut data.as_ptr() as *mut *const u8,
                data.len() as c_long,
            )
        };

        if raw.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }

    /// Give out our reference.
    ///
    /// This DOES NOT take a reference.  See `SSL_get0_peer_certificate`.
    pub fn borrow_ref(&self) -> *mut X509 {
        self.raw
    }

    /// Give out a new reference.
    ///
    /// See `SSL_get1_peer_certificate`.
    pub fn up_ref(&self) -> *mut X509 {
        unsafe {
            if !self.raw.is_null() {
                X509_up_ref(self.raw);
            }
        }
        self.raw
    }
}

impl Drop for OwnedX509 {
    fn drop(&mut self) {
        unsafe {
            X509_free(self.raw);
        }
    }
}

pub struct OwnedX509Store {
    raw: *mut X509_STORE,
}

impl OwnedX509Store {
    pub fn new() -> Self {
        Self {
            raw: unsafe { X509_STORE_new() },
        }
    }

    pub fn pointer(&self) -> *mut X509_STORE {
        self.raw
    }
}

impl Drop for OwnedX509Store {
    fn drop(&mut self) {
        unsafe {
            X509_STORE_free(self.raw);
        }
    }
}

extern "C" {
    /// XXX: these missing from openssl-sys(?) investigate why that is.
    fn OPENSSL_sk_free(st: *mut OPENSSL_STACK);
    fn X509_up_ref(x: *mut X509) -> c_int;
}
