/// Shims for functions we call, written in rust so they are visible to miri.
use std::ffi::{c_char, c_int, CStr};

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
