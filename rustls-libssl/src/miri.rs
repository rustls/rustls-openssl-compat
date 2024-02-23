/// Shims for functions we call, written in rust so they are visible to miri.
use std::ffi::{c_char, c_int, CStr};

pub struct X509_STORE(());

#[no_mangle]
pub extern "C" fn X509_STORE_new() -> *mut X509_STORE {
    Box::into_raw(Box::new(X509_STORE(())))
}

#[no_mangle]
pub extern "C" fn X509_STORE_free(ptr: *mut X509_STORE) {
    if ptr.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(ptr) });
}

#[no_mangle]
pub extern "C" fn ERR_new() {
    eprintln!("ERR_new()");
}

#[no_mangle]
pub extern "C" fn ERR_set_error(lib: c_int, reason: c_int, message: *const c_char) {
    eprintln!("ERR_set_error(0x{lib:x}, 0x{reason:x}, {:?})", unsafe {
        CStr::from_ptr(message)
    });
}
