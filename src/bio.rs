use core::ffi::{c_char, c_int, c_long, c_void, CStr};
use std::io;

// nb. cannot use any BIO types from openssl_sys: it doesn't
// have the internal type for BIO_METHOD, and once we provide
// it here their opaque type doesn't match ours.

/// Safe, owning wrapper around an OpenSSL BIO pair.
///
/// This owns references to both BIOs, even if they
/// are the same pointer.  That means `drop()` can
/// be straight-forward.
pub struct Bio {
    read: *mut BIO,
    write: *mut BIO,
}

impl Bio {
    /// Use a pre-existing file descriptor.
    ///
    /// Does not (and cannot) validate the file descriptor.
    pub fn new_fd_no_close(fd: c_int) -> Self {
        let (read, write) = unsafe {
            let bio = BIO_new_fd(fd, 0);
            BIO_up_ref(bio);
            (bio, bio)
        };
        Self { read, write }
    }

    /// Use a pair of raw BIO pointers.
    ///
    /// Absent pointers are silently replaced with a `BIO_s_null()`.
    /// `Some(ptr::null_mut())` is illegal.
    ///
    /// The caller donates their references, using the rules for `update()`.
    pub fn new_pair(rbio: Option<*mut BIO>, wbio: Option<*mut BIO>) -> Self {
        let null_2 = unsafe { BIO_new(BIO_s_null()) };
        unsafe { BIO_up_ref(null_2) };
        let mut ret = Self {
            read: null_2,
            write: null_2,
        };
        ret.update(rbio, wbio);
        ret
    }

    /// Update this object with a pair of raw BIO pointers.
    ///
    pub fn update(&mut self, rbio: Option<*mut BIO>, wbio: Option<*mut BIO>) {
        match (rbio, wbio) {
            (Some(rbio), Some(wbio)) => {
                // See `SSL_set_bio` for the overcomplex ownership rules when both
                // `rbio` and `wbio` are `Some`:
                //
                // <https://www.openssl.org/docs/man3.2/man3/SSL_set_bio.html>
                //
                // If neither the rbio or wbio have changed from their
                // previous values then nothing is done.
                if rbio == self.read && wbio == self.write {
                    return;
                }

                // If the rbio and wbio parameters are different and both are
                // different to their previously set values then one reference
                // is consumed for the rbio and one reference is consumed for
                // the wbio.
                if rbio != wbio && rbio != self.read && wbio != self.write {
                    self.set_read(rbio);
                    self.set_write(wbio);
                    return;
                }

                // If the rbio and wbio parameters are the same and the rbio
                // is not the same as the previously set value then one reference
                // is consumed for the rbio.
                if rbio == wbio && rbio != self.read {
                    unsafe {
                        BIO_up_ref(rbio);
                    }
                    self.set_read(rbio);
                    self.set_write(wbio);
                    return;
                }

                // If the rbio and wbio parameters are the same and the rbio
                // is the same as the previously set value, then no additional
                // references are consumed.
                if rbio == wbio && rbio == self.read {
                    // (er, what about self.write though?)
                    return;
                }

                // If the rbio and wbio parameters are different and the rbio
                // is the same as the previously set value then one reference
                // is consumed for the wbio and no references are consumed for
                // the rbio.
                if rbio != wbio && rbio == self.read {
                    self.set_write(wbio);
                    return;
                }

                // If the rbio and wbio parameters are different and the wbio
                // is the same as the previously set value and the old rbio and
                // wbio values were the same as each other then one reference
                // is consumed for the rbio and no references are consumed for
                // the wbio.
                if rbio != wbio && wbio == self.write && self.read == self.write {
                    self.set_read(rbio);
                    return;
                }

                // If the rbio and wbio parameters are different and the wbio
                // is the same as the previously set value and the old rbio and
                // wbio values were different to each other, then one reference
                // is consumed for the rbio and one reference is consumed for the wbio.
                if rbio != wbio && wbio == self.write && self.read != self.write {
                    self.set_read(rbio);
                    self.set_write(wbio);
                }
            }
            (Some(rbio), None) => {
                self.set_read(rbio);
            }
            (None, Some(wbio)) => {
                self.set_write(wbio);
            }
            (None, None) => {}
        }
    }

    /// Sets `write` to `wbio`.
    ///
    /// Frees the old `write` if needed.
    /// Consumes the `wbio` reference unconditionally.
    ///
    /// `wbio` must be non-NULL.
    fn set_write(&mut self, wbio: *mut BIO) {
        if wbio != self.write {
            unsafe { BIO_free_all(self.write) };
            self.write = wbio;
        } else {
            unsafe { BIO_free_all(wbio) };
        }
    }

    /// Sets `read` to `rbio`.
    ///
    /// Frees the old `read` if needed.
    /// Consumes the `rbio` reference unconditionally.
    ///
    /// `rbio` must be non-NULL.
    fn set_read(&mut self, rbio: *mut BIO) {
        if rbio != self.read {
            unsafe { BIO_free_all(self.read) };
            self.read = rbio;
        } else {
            unsafe { BIO_free_all(rbio) };
        }
    }

    pub fn read_would_block(&self) -> bool {
        bio_should_retry_read(self.read)
    }

    pub fn write_would_block(&self) -> bool {
        bio_should_retry_write(self.write)
    }

    /// Returns `read`.
    ///
    /// See `SSL_get_rbio` docs for semantics, and confirmation
    /// that this API is const-incorrect.
    pub fn borrow_read(&self) -> *mut BIO {
        self.read
    }

    /// Returns `write`.
    ///
    /// See `SSL_get_wbio` docs for semantics, and confirmation
    /// that this API is const-incorrect.
    pub fn borrow_write(&self) -> *mut BIO {
        self.write
    }
}

impl io::Read for Bio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_bytes = 0;
        let rc = unsafe {
            BIO_read_ex(
                self.read,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut read_bytes,
            )
        };

        match rc {
            1 => Ok(read_bytes),
            _ => {
                if bio_in_eof(self.read) {
                    Ok(0)
                } else if bio_should_retry_read(self.read) {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Err(io::Error::other("BIO_read_ex failed"))
                }
            }
        }
    }
}

impl io::Write for Bio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written_bytes = 0;
        let rc = unsafe {
            BIO_write_ex(
                self.write,
                buf.as_ptr() as *const c_void,
                buf.len(),
                &mut written_bytes,
            )
        };

        match rc {
            1 => Ok(written_bytes),
            _ => {
                if bio_should_retry_write(self.write) {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Err(io::Error::other("BIO_write_ex failed"))
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // nb. BIO_flush "in some cases it is used to signal EOF and
        // that no more data will be written." so is not a good match.
        Ok(())
    }
}

impl Drop for Bio {
    fn drop(&mut self) {
        unsafe {
            BIO_free_all(self.read);
            BIO_free_all(self.write);
        }
    }
}

static NAME: &CStr = c"ssl";
const BIO_TYPE_SSL: i32 = 0x0200 | 7;

pub static SSL_BIO_METHOD: bio_method_st = bio_method_st {
    type_: BIO_TYPE_SSL,
    name: NAME.as_ptr(),
    bwrite: None,
    bwrite_old: None,
    bread: None,
    bread_old: None,
    bputs: None,
    bgets: None,
    ctrl: None,
    create: None,
    destroy: None,
    callback_ctrl: None,
};

// This is a public interface between libcrypto and libssl, but is
// defined in `internal/bio.h`.  Hmm.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bio_method_st {
    pub type_: c_int,
    pub name: *const c_char,
    pub bwrite: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: *const c_char,
            arg3: usize,
            arg4: *mut usize,
        ) -> c_int,
    >,
    pub bwrite_old:
        Option<unsafe extern "C" fn(arg1: *mut BIO, arg2: *const c_char, arg3: c_int) -> c_int>,
    pub bread: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: *mut c_char,
            arg3: usize,
            arg4: *mut usize,
        ) -> c_int,
    >,
    pub bread_old:
        Option<unsafe extern "C" fn(arg1: *mut BIO, arg2: *mut c_char, arg3: c_int) -> c_int>,
    pub bputs: Option<unsafe extern "C" fn(arg1: *mut BIO, arg2: *const c_char) -> c_int>,
    pub bgets:
        Option<unsafe extern "C" fn(arg1: *mut BIO, arg2: *mut c_char, arg3: c_int) -> c_int>,
    pub ctrl: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: c_int,
            arg3: c_long,
            arg4: *mut c_void,
        ) -> c_long,
    >,
    pub create: Option<unsafe extern "C" fn(arg1: *mut BIO) -> c_int>,
    pub destroy: Option<unsafe extern "C" fn(arg1: *mut BIO) -> c_int>,
    pub callback_ctrl:
        Option<unsafe extern "C" fn(arg1: *mut BIO, arg2: c_int, arg3: BIO_info_cb) -> c_long>,
}

unsafe impl Send for bio_method_st {}
unsafe impl Sync for bio_method_st {}

#[allow(non_camel_case_types)]
pub type BIO_info_cb =
    Option<unsafe extern "C" fn(arg1: *mut BIO, arg2: c_int, arg3: c_int) -> c_int>;

#[repr(C)]
pub struct OpaqueBio {
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub type BIO = OpaqueBio;
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub type BIO_METHOD = bio_method_st;

fn bio_should_retry_read(b: *const BIO) -> bool {
    const BIO_FLAGS_READ: c_int = 0x01;
    const BIO_SHOULD_RETRY: c_int = 0x08;
    unsafe { BIO_test_flags(b, BIO_SHOULD_RETRY | BIO_FLAGS_READ) != 0 }
}

fn bio_should_retry_write(b: *const BIO) -> bool {
    const BIO_FLAGS_WRITE: c_int = 0x02;
    const BIO_SHOULD_RETRY: c_int = 0x08;
    unsafe { BIO_test_flags(b, BIO_SHOULD_RETRY | BIO_FLAGS_WRITE) != 0 }
}

fn bio_in_eof(b: *const BIO) -> bool {
    const BIO_IN_EOF: c_int = 0x800;
    unsafe { BIO_test_flags(b, BIO_IN_EOF) != 0 }
}

extern "C" {
    fn BIO_new(meth: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free_all(b: *mut BIO);
    fn BIO_new_fd(fd: c_int, close_flag: c_int) -> *mut BIO;
    fn BIO_read_ex(b: *mut BIO, data: *mut c_void, dlen: usize, readbytes: *mut usize) -> c_int;
    fn BIO_write_ex(b: *mut BIO, data: *const c_void, dlen: usize, written: *mut usize) -> c_int;
    fn BIO_up_ref(b: *mut BIO) -> c_int;
    fn BIO_test_flags(b: *const BIO, flags: c_int) -> c_int;
    fn BIO_s_null() -> *const BIO_METHOD;
}
