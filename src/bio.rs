use core::ffi::{c_char, c_int, c_long, c_void, CStr};
use core::ptr;
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
    record_limit: RecordLimit,
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
        Self {
            read,
            write,
            record_limit: RecordLimit::default(),
        }
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
            record_limit: RecordLimit::default(),
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
                if ptr::eq(rbio, self.read) && ptr::eq(wbio, self.write) {
                    return;
                }

                // If the rbio and wbio parameters are different and both are
                // different to their previously set values then one reference
                // is consumed for the rbio and one reference is consumed for
                // the wbio.
                if !ptr::eq(rbio, wbio) && !ptr::eq(rbio, self.read) && !ptr::eq(wbio, self.write) {
                    self.set_read(rbio);
                    self.set_write(wbio);
                    return;
                }

                // If the rbio and wbio parameters are the same and the rbio
                // is not the same as the previously set value then one reference
                // is consumed for the rbio.
                if ptr::eq(rbio, wbio) && !ptr::eq(rbio, self.read) {
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
                if ptr::eq(rbio, wbio) && ptr::eq(rbio, self.read) {
                    // (er, what about self.write though?)
                    return;
                }

                // If the rbio and wbio parameters are different and the rbio
                // is the same as the previously set value then one reference
                // is consumed for the wbio and no references are consumed for
                // the rbio.
                if !ptr::eq(rbio, wbio) && ptr::eq(rbio, self.read) {
                    self.set_write(wbio);
                    return;
                }

                // If the rbio and wbio parameters are different and the wbio
                // is the same as the previously set value and the old rbio and
                // wbio values were the same as each other then one reference
                // is consumed for the rbio and no references are consumed for
                // the wbio.
                if !ptr::eq(rbio, wbio)
                    && ptr::eq(wbio, self.write)
                    && ptr::eq(self.read, self.write)
                {
                    self.set_read(rbio);
                    return;
                }

                // If the rbio and wbio parameters are different and the wbio
                // is the same as the previously set value and the old rbio and
                // wbio values were different to each other, then one reference
                // is consumed for the rbio and one reference is consumed for the wbio.
                if !ptr::eq(rbio, wbio)
                    && ptr::eq(wbio, self.write)
                    && !ptr::eq(self.read, self.write)
                {
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
        if !ptr::eq(wbio, self.write) {
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
        if !ptr::eq(rbio, self.read) {
            unsafe { BIO_free_all(self.read) };
            self.read = rbio;
            // a different transport means a different record stream
            self.record_limit = RecordLimit::default();
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

/// Tracks where we are in the TLS record currently being read.
///
/// OpenSSL never reads more from a `BIO` than the record it is currently
/// processing needs (read-ahead is off by default, and callers rely on
/// that).  Anything belonging to a later record stays in the underlying
/// socket, so the caller's poll loop still sees it as readable.
///
/// rustls, by contrast, hands `read_tls` a large buffer and takes
/// everything the transport will give it.  Doing that here breaks callers
/// like haproxy: if the client's `Finished` and its first application data
/// arrive in one segment we swallow both, the caller completes the
/// handshake, subscribes for a read event that can never arrive, and the
/// request sits undelivered in our buffer until the caller times out.
///
/// So: read a record header, then no more than that record's body.
#[derive(Default)]
struct RecordLimit {
    /// Bytes of the current record's body still to be read.
    body_remaining: usize,

    /// The record header, while we have less than all of it.
    header: [u8; Self::HEADER_LEN],
    header_used: usize,
}

impl RecordLimit {
    /// How many bytes may be read from the transport right now.
    fn allowance(&self) -> usize {
        match self.body_remaining {
            0 => Self::HEADER_LEN - self.header_used,
            body => body,
        }
    }

    /// Account for `data`, which was just read from the transport.
    fn update(&mut self, data: &[u8]) {
        debug_assert!(data.len() <= self.allowance());
        if self.body_remaining > 0 {
            self.body_remaining -= data.len().min(self.body_remaining);
            return;
        }

        let take = data.len().min(Self::HEADER_LEN - self.header_used);
        self.header[self.header_used..self.header_used + take].copy_from_slice(&data[..take]);
        self.header_used += take;

        if self.header_used == Self::HEADER_LEN {
            self.body_remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            self.header_used = 0;
        }
    }

    const HEADER_LEN: usize = 5;
}

impl io::Read for Bio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let allowance = buf.len().min(self.record_limit.allowance());
        let buf = &mut buf[..allowance];

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
            1 => {
                let read_bytes = read_bytes.min(buf.len());
                self.record_limit.update(&buf[..read_bytes]);
                Ok(read_bytes)
            }
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

#[cfg(test)]
mod tests {
    use super::RecordLimit;

    #[test]
    fn stops_at_record_boundary() {
        let mut limit = RecordLimit::default();
        // header first, then the body: two reads, and never more.
        assert_eq!(drive(&mut limit, &record(64), usize::MAX), 2);
        assert_eq!(limit.allowance(), RecordLimit::HEADER_LEN);
    }

    #[test]
    fn handles_split_header() {
        let mut limit = RecordLimit::default();
        assert_eq!(drive(&mut limit, &record(64), 1), 5 + 64);
        assert_eq!(limit.allowance(), RecordLimit::HEADER_LEN);
    }

    #[test]
    fn handles_consecutive_records() {
        let mut limit = RecordLimit::default();
        for len in [0, 1, 5, 4096, 16384] {
            drive(&mut limit, &record(len), usize::MAX);
            assert_eq!(limit.allowance(), RecordLimit::HEADER_LEN);
        }
    }

    fn drive(limit: &mut RecordLimit, record: &[u8], chunk: usize) -> usize {
        let mut offset = 0;
        let mut reads = 0;
        while offset < record.len() {
            // the limiter must ask for exactly the rest of the header,
            // then exactly the rest of the body
            let expected = match offset < RecordLimit::HEADER_LEN {
                true => RecordLimit::HEADER_LEN - offset,
                false => record.len() - offset,
            };
            assert_eq!(limit.allowance(), expected);

            let take = expected.min(chunk);
            limit.update(&record[offset..offset + take]);
            offset += take;
            reads += 1;
        }
        reads
    }

    fn record(body_len: u16) -> Vec<u8> {
        let mut r = vec![0x17, 0x03, 0x03];
        r.extend_from_slice(&body_len.to_be_bytes());
        r.extend(std::iter::repeat_n(0xab, body_len as usize));
        r
    }
}
