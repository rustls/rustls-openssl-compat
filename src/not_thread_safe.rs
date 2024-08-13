use core::cell::UnsafeCell;
use core::cmp;
use std::fmt;

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

impl<T: fmt::Debug> fmt::Debug for NotThreadSafe<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.cell.fmt(f)
    }
}

impl<T: Ord + PartialOrd> Ord for NotThreadSafe<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.get().cmp(other.get())
    }
}

impl<T: PartialOrd<T> + Ord> PartialOrd for NotThreadSafe<T> {
    fn partial_cmp(&self, other: &NotThreadSafe<T>) -> Option<cmp::Ordering> {
        Some(self.get().cmp(other.get()))
    }
}

impl<T: Eq> Eq for NotThreadSafe<T> {}

impl<T: PartialEq> PartialEq for NotThreadSafe<T> {
    fn eq(&self, other: &Self) -> bool {
        self.get().eq(other.get())
    }
}

unsafe impl<T> Sync for NotThreadSafe<T> {}
