use core::ffi::{c_int, c_void};
use core::ptr;

use crate::entry::{SSL, SSL_CTX};
use crate::error::Error;

/// Safe(ish), owning wrapper around an OpenSSL `CRYPTO_EX_DATA`.
///
/// `ty` and `owner` allow us to drop this object with no extra context.
///
/// Because this refers to the object that contains it, a two-step
/// construction is needed.
pub struct ExData {
    ex_data: CRYPTO_EX_DATA,
    ty: c_int,
    owner: *mut c_void,
}

impl ExData {
    /// Makes a new CRYPTO_EX_DATA for an SSL object.
    pub fn new_ssl(ssl: *mut SSL) -> Option<Self> {
        let mut ex_data = CRYPTO_EX_DATA::default();
        let owner = ssl as *mut c_void;
        let ty = CRYPTO_EX_INDEX_SSL;
        let rc = unsafe { CRYPTO_new_ex_data(ty, owner, &mut ex_data) };
        if rc == 1 {
            Some(Self { ex_data, ty, owner })
        } else {
            None
        }
    }

    /// Makes a new CRYPTO_EX_DATA for an SSL_CTX object.
    pub fn new_ssl_ctx(ctx: *mut SSL_CTX) -> Option<Self> {
        let mut ex_data = CRYPTO_EX_DATA::default();
        let owner = ctx as *mut c_void;
        let ty = CRYPTO_EX_INDEX_SSL_CTX;
        let rc = unsafe { CRYPTO_new_ex_data(ty, owner, &mut ex_data) };
        if rc == 1 {
            Some(Self { ex_data, ty, owner })
        } else {
            None
        }
    }

    pub fn set(&mut self, idx: c_int, data: *mut c_void) -> Result<(), Error> {
        let rc = unsafe { CRYPTO_set_ex_data(&mut self.ex_data, idx, data) };
        if rc == 1 {
            Ok(())
        } else {
            Err(Error::bad_data("CRYPTO_set_ex_data"))
        }
    }

    pub fn get(&self, idx: c_int) -> *mut c_void {
        unsafe { CRYPTO_get_ex_data(&self.ex_data, idx) }
    }
}

impl Drop for ExData {
    fn drop(&mut self) {
        if !self.owner.is_null() {
            unsafe {
                CRYPTO_free_ex_data(self.ty, self.owner, &mut self.ex_data);
            };
            self.owner = ptr::null_mut();
        }
    }
}

impl Default for ExData {
    fn default() -> Self {
        Self {
            ex_data: CRYPTO_EX_DATA::default(),
            ty: -1,
            owner: ptr::null_mut(),
        }
    }
}

/// This has the same layout prefix as `struct crypto_ex_data_st` aka
/// `CRYPTO_EX_DATA` -- just two pointers.  We don't need to know
/// the types of these; the API lets us treat them opaquely.
///
/// This is _not_ owning.
#[repr(C)]
struct CRYPTO_EX_DATA {
    ctx: *mut c_void,
    sk: *mut c_void,
}

impl Default for CRYPTO_EX_DATA {
    fn default() -> Self {
        Self {
            ctx: ptr::null_mut(),
            sk: ptr::null_mut(),
        }
    }
}

// See `crypto.h`
const CRYPTO_EX_INDEX_SSL: c_int = 0;
const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;

extern "C" {
    fn CRYPTO_new_ex_data(class_index: c_int, obj: *mut c_void, ed: *mut CRYPTO_EX_DATA) -> c_int;
    fn CRYPTO_set_ex_data(ed: *mut CRYPTO_EX_DATA, index: c_int, data: *mut c_void) -> c_int;
    fn CRYPTO_get_ex_data(ed: *const CRYPTO_EX_DATA, index: c_int) -> *mut c_void;
    fn CRYPTO_free_ex_data(class_index: c_int, obj: *mut c_void, ed: *mut CRYPTO_EX_DATA);
}
