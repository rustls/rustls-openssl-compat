use core::ffi::{c_int, c_long};
use core::ptr;
use std::ffi::CString;

use openssl_sys::{ERR_new, ERR_set_error, ERR_RFLAGS_OFFSET, ERR_RFLAG_FATAL};
use rustls::AlertDescription;

// See openssl/err.h for the source of these magic numbers.

#[derive(Copy, Clone, Debug)]
#[repr(i32)]
enum Lib {
    /// This is `ERR_LIB_SSL`.
    Ssl = 20,

    /// This is `ERR_LIB_USER`.
    User = 128,
}

const ERR_RFLAG_COMMON: i32 = 0x2i32 << ERR_RFLAGS_OFFSET;

#[derive(Copy, Clone, Debug, PartialEq)]
enum Reason {
    PassedNullParameter,
    InternalError,
    OperationFailed,
    Unsupported,
    WouldBlock,
    Alert(AlertDescription),
}

impl From<Reason> for c_int {
    fn from(r: Reason) -> c_int {
        use Reason::*;
        match r {
            // see `err.h.in` for magic numbers.
            PassedNullParameter => (ERR_RFLAG_FATAL as i32) | ERR_RFLAG_COMMON | 258,
            InternalError => (ERR_RFLAG_FATAL as i32) | ERR_RFLAG_COMMON | 259,
            OperationFailed => (ERR_RFLAG_FATAL as i32) | ERR_RFLAG_COMMON | 263,
            Unsupported => ERR_RFLAG_COMMON | 268,
            WouldBlock => 0,
            // `sslerr.h`
            Alert(alert) => 1000 + u8::from(alert) as c_int,
        }
    }
}

#[derive(Debug)]
pub struct Error {
    lib: Lib,
    reason: Reason,
    string: Option<String>,
}

impl Error {
    pub fn unexpected_panic() -> Self {
        Self {
            lib: Lib::Ssl,
            reason: Reason::InternalError,
            string: None,
        }
    }

    pub fn null_pointer() -> Self {
        Self {
            lib: Lib::Ssl,
            reason: Reason::PassedNullParameter,
            string: None,
        }
    }

    pub fn not_supported(hint: &str) -> Self {
        Self {
            lib: Lib::Ssl,
            reason: Reason::Unsupported,
            string: Some(hint.to_string()),
        }
    }

    pub fn bad_data(hint: &str) -> Self {
        Self {
            lib: Lib::Ssl,
            reason: Reason::OperationFailed,
            string: Some(hint.to_string()),
        }
    }

    pub fn from_rustls(err: rustls::Error) -> Self {
        match err {
            rustls::Error::AlertReceived(alert) => Self {
                lib: Lib::Ssl,
                reason: Reason::Alert(alert),
                string: Some(format!("SSL alert number {}", u8::from(alert))),
            },
            _ => Self {
                lib: Lib::User,
                reason: Reason::OperationFailed,
                string: Some(err.to_string()),
            },
        }
    }

    pub fn from_io(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::WouldBlock => Self {
                lib: Lib::User,
                reason: Reason::WouldBlock,
                string: None,
            },
            _ => Self {
                lib: Lib::User,
                reason: Reason::OperationFailed,
                string: Some(err.to_string()),
            },
        }
    }

    /// Add this error to the openssl error stack.
    pub fn raise(self) -> Self {
        if self.quiet() {
            return self;
        }

        log::error!("raising {self:?}");
        let cstr = CString::new(
            self.string
                .clone()
                .unwrap_or_else(|| format!("{:?}", self.reason)),
        )
        .unwrap();
        unsafe {
            ERR_new();
            // nb. miri cannot do variadic functions, so we define a miri-only equivalent
            #[cfg(not(miri))]
            ERR_set_error(
                self.lib as c_int,
                self.reason.into(),
                c"%s".as_ptr(),
                cstr.as_ptr(),
            );
            #[cfg(miri)]
            crate::miri::ERR_set_error(self.lib as c_int, self.reason.into(), cstr.as_ptr());
        }
        self
    }

    /// `WouldBlock` errors never make it on the error stack.
    ///
    /// They are usual in the use of non-blocking BIOs.
    fn quiet(&self) -> bool {
        self.reason == Reason::WouldBlock
    }
}

// These conversions determine how errors are reported from entry point
// functions.

impl<T> From<Error> for *const T {
    fn from(_: Error) -> Self {
        ptr::null()
    }
}

impl<T> From<Error> for *mut T {
    fn from(_: Error) -> Self {
        ptr::null_mut()
    }
}

impl From<Error> for c_int {
    fn from(_: Error) -> Self {
        // for typical OpenSSL functions (return 0 on error)
        0
    }
}

impl From<Error> for usize {
    fn from(_: Error) -> Self {
        // ditto
        0
    }
}

impl From<Error> for MysteriouslyOppositeReturnValue {
    fn from(_: Error) -> Self {
        // for a small subset of OpenSSL functions (return 1 on error)
        MysteriouslyOppositeReturnValue::Error
    }
}

impl From<Error> for c_long {
    fn from(_: Error) -> Self {
        // ditto
        0
    }
}

impl From<Error> for u64 {
    fn from(_: Error) -> Self {
        // for options functions (return 0 on error)
        0
    }
}

impl From<Error> for u32 {
    fn from(_: Error) -> Self {
        // for `SSL_CIPHER_get_id`
        0
    }
}

impl From<Error> for u16 {
    fn from(_: Error) -> Self {
        // for `SSL_CIPHER_get_protocol_id`
        0
    }
}

impl From<Error> for () {
    fn from(_: Error) {
        // for void functions (return early on error)
    }
}

impl From<Error> for crate::entry::SSL_verify_cb {
    fn from(_: Error) -> crate::entry::SSL_verify_cb {
        None
    }
}

#[macro_export]
macro_rules! ffi_panic_boundary {
    ( $($tt:tt)* ) => {
        match ::std::panic::catch_unwind(
            ::std::panic::AssertUnwindSafe(|| {
                $($tt)*
        })) {
            Ok(ret) => ret,
            Err(_) => return $crate::error::Error::unexpected_panic()
                .raise()
                .into(),
        }
    }
}

pub(crate) use ffi_panic_boundary;

/// An entry point that yields this type marks it as one where
/// `0` is returned on success, `1` on error.
///
/// That is opposite to other OpenSSL functions which return 1 on success.
///
/// It has the same representation as `c_int`.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MysteriouslyOppositeReturnValue {
    Success = 0,
    Error = 1,
}
