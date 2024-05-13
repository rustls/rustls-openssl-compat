use core::ptr;
/// Shims for functions we call, written in rust so they are visible to miri.
use std::ffi::{c_char, c_int, c_void, CStr};

pub struct X509_STORE(());

#[no_mangle]
pub extern "C" fn X509_STORE_new() -> *mut X509_STORE {
    Box::into_raw(Box::new(X509_STORE(())))
}

#[no_mangle]
pub extern "C" fn X509_STORE_get0_objects(s: *mut X509_STORE) -> *mut c_void {
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn OPENSSL_sk_num(sk: *mut c_void) -> c_int {
    0
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

#[no_mangle]
pub extern "C" fn CRYPTO_new_ex_data(
    ty: c_int,
    owner: *mut c_void,
    out: *mut [*mut c_void; 2],
) -> c_int {
    eprintln!("CRYPTO_new_ex_data({ty}, {owner:?});");
    let marker = [owner, owner];
    unsafe {
        ptr::write(out, marker);
    };
    1
}

#[no_mangle]
pub extern "C" fn CRYPTO_free_ex_data(ty: c_int, owner: *mut c_void, ed: *mut [*mut c_void; 2]) {
    let marker: [*mut c_void; 2] = unsafe { ptr::read(ed) };
    assert!(marker[0] == owner);
    assert!(marker[1] == owner);
}
