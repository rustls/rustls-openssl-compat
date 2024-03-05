use core::ffi::{c_int, c_long, c_void};
use core::{ptr, slice};
use std::path::PathBuf;
use std::{fs, io};

use openssl_sys::{
    d2i_X509, i2d_X509, stack_st_X509, OPENSSL_free, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_push, OPENSSL_sk_value, X509_STORE_free, X509_STORE_new, X509_free, OPENSSL_STACK,
    X509, X509_STORE,
};
use rustls::pki_types::CertificateDer;

use crate::error::Error;

/// Safe, owning wrapper around an OpenSSL `STACK_OF(X509)` object.
///
/// The items are owned by the stack.
pub struct OwnedX509Stack {
    raw: *mut stack_st_X509,
}

impl OwnedX509Stack {
    /// Make an empty stack.
    pub fn empty() -> Self {
        Self {
            raw: unsafe { OPENSSL_sk_new_null() as *mut stack_st_X509 },
        }
    }

    pub fn from_rustls(certs: &Vec<CertificateDer<'static>>) -> Self {
        let mut r = Self::empty();
        for c in certs {
            let item = OwnedX509::parse_der(c.as_ref()).unwrap();
            r.push(&item);
        }
        r
    }

    /// Add the given cert to the top (end) of the stack.
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

    /// Leak the first X509* to the caller.
    ///
    /// null is returned if the stack is empty, or itself null.
    pub fn borrow_top_ref(&self) -> *mut X509 {
        self.borrowed_item(0)
    }

    #[allow(dead_code)] // delete me later if unused
    /// Convert contents to rustls's representation.
    ///
    /// This copies the whole chain.
    pub fn to_rustls(&self) -> Vec<CertificateDer<'static>> {
        let len = self.len();
        let mut r = Vec::with_capacity(len);

        for i in 0..len {
            let item = self.item(i);
            r.push(CertificateDer::from(item.der_bytes()));
        }

        r
    }

    #[allow(dead_code)] // delete me later if unused
    /// Owned reference of item at `index`.
    fn item(&self, index: usize) -> OwnedX509 {
        let donate = self.borrowed_item(index);
        unsafe { X509_up_ref(donate) };
        OwnedX509::new(donate)
    }

    /// Plain, borrowed pointer to the item at `index`.
    fn borrowed_item(&self, index: usize) -> *mut X509 {
        unsafe { OPENSSL_sk_value(self.raw as *const OPENSSL_STACK, index as c_int) as *mut X509 }
    }

    fn len(&self) -> usize {
        match unsafe { OPENSSL_sk_num(self.raw as *const OPENSSL_STACK) } {
            -1 => 0,
            x => x as usize,
        }
    }
}

impl Clone for OwnedX509Stack {
    fn clone(&self) -> Self {
        // up-ref each item
        for i in 0..self.len() {
            unsafe { X509_up_ref(self.borrowed_item(i)) };
        }
        // then shallow copy the stack
        Self {
            raw: unsafe { OPENSSL_sk_dup(self.raw as *const OPENSSL_STACK) as *mut stack_st_X509 },
        }
    }
}

impl Drop for OwnedX509Stack {
    fn drop(&mut self) {
        unsafe {
            OPENSSL_sk_pop_free(self.raw as *mut OPENSSL_STACK, Some(X509_free));
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

    /// Create a new one, from a (donated) existing ref.
    pub fn new(raw: *mut X509) -> Self {
        Self { raw }
    }

    /// Return the DER-encoded bytes for this object.
    pub fn der_bytes(&self) -> Vec<u8> {
        let (ptr, len) = unsafe {
            let mut ptr = ptr::null_mut();
            let len = i2d_X509(self.raw, &mut ptr);
            (ptr, len)
        };

        if len <= 0 {
            return vec![];
        }
        let len = len as usize;

        let mut v = Vec::with_capacity(len);
        v.extend_from_slice(unsafe { slice::from_raw_parts(ptr, len) });

        unsafe { OPENSSL_free(ptr as *mut _) };
        v
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

pub(crate) fn load_certs<'a>(
    file_names: impl Iterator<Item = PathBuf>,
) -> Result<Vec<CertificateDer<'a>>, Error> {
    let mut certs = Vec::new();
    for file_name in file_names {
        let mut file_reader = match fs::File::open(file_name.clone()) {
            Ok(content) => io::BufReader::new(content),
            Err(err) => return Err(Error::from_io(err).raise()),
        };

        for cert in rustls_pemfile::certs(&mut file_reader) {
            match cert {
                Ok(cert) => certs.push(cert),
                Err(err) => {
                    log::trace!("Failed to parse {file_name:?}: {err:?}");
                    return Err(Error::from_io(err).raise());
                }
            };
        }
    }
    Ok(certs)
}

extern "C" {
    /// XXX: these missing from openssl-sys(?) investigate why that is.
    fn OPENSSL_sk_pop_free(
        st: *mut OPENSSL_STACK,
        func: Option<unsafe extern "C" fn(arg1: *mut X509)>,
    );
    fn OPENSSL_sk_dup(st: *const OPENSSL_STACK) -> *mut OPENSSL_STACK;
    fn X509_up_ref(x: *mut X509) -> c_int;
}
