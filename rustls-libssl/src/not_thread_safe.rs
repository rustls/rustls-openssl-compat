use core::cell::UnsafeCell;

/// An extremely bad and unsafe laundering of pointer-to-references.
///
/// OpenSSL's API is specifically not thread-safe.  `SSL_CTX` and `SSL`
/// instances must not be shared between threads.  See
/// <https://www.openssl.org/blog/blog/2017/02/21/threads/>
///
/// Because the API includes callbacks (that must be called at
/// specific times, and may have side effects) and those callbacks can
/// re-enter the API, just having a `Mutex<T>` here is not workable:
/// `Mutex<T>` is not recursive, and cannot be without being a font of
/// multiple mutable references onto one object.
pub struct NotThreadSafe<T> {
    cell: UnsafeCell<T>,
}

impl<T> NotThreadSafe<T> {
    pub fn new(value: T) -> Self {
        Self {
            cell: UnsafeCell::new(value),
        }
    }

    pub fn get(&self) -> &T {
        // safety: extremely not
        unsafe { &*(self.cell.get() as *const T) }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get_mut(&self) -> &mut T {
        // safety: extremely not
        unsafe { &mut *self.cell.get() }
    }
}
