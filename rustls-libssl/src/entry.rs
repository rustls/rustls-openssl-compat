//! This file contains all the libssl entrypoints that we implement.
//!
//! It should mainly be concerned with mapping these calls up to
//! the safe APIs implemented elsewhere.

use core::{mem, ptr};
use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use std::sync::Mutex;
use std::{fs, io, path::PathBuf};

use openssl_sys::{OPENSSL_malloc, X509_STORE, X509_STORE_CTX};

use crate::bio::{Bio, BIO};
use crate::error::{ffi_panic_boundary, Error, MysteriouslyOppositeReturnValue};
use crate::ffi::{
    free_arc, str_from_cstring, to_arc_mut_ptr, try_clone_arc, try_from, try_ref_from_ptr,
    try_slice, try_str, Castable, OwnershipArc, OwnershipRef,
};

/// Makes a entry function definition.
///
/// The body is wrapped in `ffi_panic_boundary`, the name is `#[no_mangle]`,
/// and is `extern "C"`.
///
/// See also `build.rs`:
///
/// - the name should start with `_` to support the linker-renaming and symbol
///   versioning happening there,
/// - the name should appear in the list of all entry points there.
macro_rules! entry {
    (pub fn $name:ident($($args:tt)*) $body:block) => {
        #[no_mangle]
        pub extern "C" fn $name($($args)*) { ffi_panic_boundary! { $body } }
    };
    (pub fn $name:ident($($args:tt)*) -> $ret:ty $body:block) => {
        #[no_mangle]
        pub extern "C" fn $name($($args)*) -> $ret { ffi_panic_boundary! { $body } }
    };
}

pub struct OpenSslInitSettings;
type OPENSSL_INIT_SETTINGS = OpenSslInitSettings;

entry! {
    pub fn _OPENSSL_init_ssl(_opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int {
        const VERSION: &str = env!("CARGO_PKG_VERSION");

        if !settings.is_null() {
            return Error::not_supported("settings").raise().into();
        }
        env_logger::init();
        log::trace!("OPENSSL_init_ssl in rustls-libssl {VERSION}");
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_alert_desc_string_long(value: c_int) -> *const c_char {
        crate::constants::alert_desc_to_long_string(value).as_ptr() as *const c_char
    }
}

entry! {
    pub fn _SSL_alert_desc_string(value: c_int) -> *const c_char {
        crate::constants::alert_desc_to_short_string(value).as_ptr() as *const c_char
    }
}

type SSL_METHOD = crate::SslMethod;

entry! {
    pub fn _TLS_method() -> *const SSL_METHOD {
        &crate::TLS_METHOD
    }
}

entry! {
    pub fn _TLS_server_method() -> *const SSL_METHOD {
        &crate::TLS_SERVER_METHOD
    }
}

entry! {
    pub fn _TLS_client_method() -> *const SSL_METHOD {
        &crate::TLS_CLIENT_METHOD
    }
}

impl Castable for SSL_METHOD {
    type Ownership = OwnershipRef;
    type RustType = SSL_METHOD;
}

type SSL_CTX = crate::SslContext;

entry! {
    pub fn _SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX {
        let method = try_ref_from_ptr!(meth);
        to_arc_mut_ptr(Mutex::new(crate::SslContext::new(method)))
    }
}

entry! {
    pub fn _SSL_CTX_up_ref(ctx: *mut SSL_CTX) -> c_int {
        let ctx = try_clone_arc!(ctx);
        mem::forget(ctx.clone());
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_free(ctx: *mut SSL_CTX) {
        free_arc(ctx);
    }
}

entry! {
    pub fn _SSL_CTX_get_options(ctx: *const SSL_CTX) -> u64 {
        let ctx = try_clone_arc!(ctx);
        ctx.lock()
            .ok()
            .map(|ctx| ctx.get_options())
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_CTX_clear_options(ctx: *mut SSL_CTX, op: u64) -> u64 {
        let ctx = try_clone_arc!(ctx);
        ctx.lock()
            .ok()
            .map(|mut ctx| ctx.clear_options(op))
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_CTX_set_options(ctx: *mut SSL_CTX, op: u64) -> u64 {
        let ctx = try_clone_arc!(ctx);
        ctx.lock()
            .ok()
            .map(|mut ctx| ctx.set_options(op))
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_CTX_ctrl(
        _ctx: *mut SSL_CTX,
        cmd: c_int,
        larg: c_long,
        _parg: *mut c_void,
    ) -> c_long {
        match SslCtrl::try_from(cmd) {
            Ok(SslCtrl::Mode) => {
                log::warn!("unimplemented SSL_CTX_set_mode()");
                0
            }
            Ok(SslCtrl::SetMsgCallbackArg) => {
                log::warn!("unimplemented SSL_CTX_set_msg_callback_arg()");
                0
            }
            Ok(SslCtrl::SetMaxProtoVersion) => {
                log::warn!("unimplemented SSL_CTX_set_max_proto_version()");
                1
            }
            Ok(SslCtrl::SetTlsExtHostname) => {
                // not a defined operation in the OpenSSL API
                0
            }
            Err(()) => {
                log::warn!("unimplemented _SSL_CTX_ctrl(..., {cmd}, {larg}, ...)");
                0
            }
        }
    }
}

entry! {
    pub fn _SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int, callback: SSL_verify_cb) {
        let ctx = try_clone_arc!(ctx);

        if callback.is_some() {
            // supporting verify callbacks would mean we need to fully use
            // the openssl certificate verifier, because X509_STORE and
            // X509_STORE_CTX are both in libcrypto.
            return Error::not_supported("verify callback").raise().into();
        }

        ctx.lock()
            .ok()
            .map(|mut ctx| ctx.set_verify(crate::VerifyMode::from(mode)))
            .unwrap_or_default();
    }
}

pub type SSL_verify_cb =
    Option<unsafe extern "C" fn(preverify_ok: c_int, x509_ctx: *mut X509_STORE_CTX) -> c_int>;

entry! {
    pub fn _SSL_CTX_get_cert_store(ctx: *const SSL_CTX) -> *mut X509_STORE {
        let ctx = try_clone_arc!(ctx);
        ctx.lock()
            .ok()
            .map(|ctx| ctx.get_x509_store())
            .unwrap_or(ptr::null_mut())
    }
}

fn load_verify_files(ctx: &Mutex<SSL_CTX>, file_names: impl Iterator<Item = PathBuf>) -> c_int {
    let mut certs = Vec::new();
    for file_name in file_names {
        let mut file_reader = match fs::File::open(file_name.clone()) {
            Ok(content) => io::BufReader::new(content),
            Err(err) => return Error::from_io(err).raise().into(),
        };

        for cert in rustls_pemfile::certs(&mut file_reader) {
            match cert {
                Ok(cert) => certs.push(cert),
                Err(err) => {
                    log::trace!("Failed to parse {file_name:?}: {err:?}");
                    return Error::from_io(err).raise().into();
                }
            };
        }
    }

    match ctx
        .lock()
        .map_err(|_| Error::cannot_lock())
        .and_then(|mut ctx| ctx.add_trusted_certs(certs))
    {
        Err(e) => e.raise().into(),
        Ok(()) => C_INT_SUCCESS,
    }
}

entry! {
    pub fn _SSL_CTX_load_verify_file(ctx: *mut SSL_CTX, ca_file: *const c_char) -> c_int {
        let ctx = try_clone_arc!(ctx);
        let ca_file = try_str!(ca_file);
        let path_buf = PathBuf::from(ca_file);
        load_verify_files(ctx.as_ref(), [path_buf].into_iter())
    }
}

entry! {
    pub fn _SSL_CTX_load_verify_dir(ctx: *mut SSL_CTX, ca_dir: *const c_char) -> c_int {
        let ctx = try_clone_arc!(ctx);
        let ca_dir = try_str!(ca_dir);

        let entries = match fs::read_dir(ca_dir) {
            Ok(iter) => iter,
            Err(err) => return Error::from_io(err).raise().into(),
        }
        .filter_map(|entry| entry.ok())
        .map(|dir_entry| dir_entry.path());

        load_verify_files(ctx.as_ref(), entries)
    }
}

entry! {
    pub fn _SSL_CTX_set_alpn_protos(
        ctx: *mut SSL_CTX,
        protos: *const c_uchar,
        protos_len: c_uint,
    ) -> MysteriouslyOppositeReturnValue {
        let ctx = try_clone_arc!(ctx);
        let slice = try_slice!(protos, protos_len);

        let alpn = match crate::parse_alpn(slice) {
            Some(alpn) => alpn,
            None => {
                // nb. openssl doesn't add anything to the error stack
                // in this case.
                return Error::bad_data("invalid alpn protocols").raise().into();
            }
        };

        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ctx| ctx.set_alpn_offer(alpn))
        {
            Err(e) => e.raise().into(),
            Ok(()) => MysteriouslyOppositeReturnValue::Success,
        }
    }
}

impl Castable for SSL_CTX {
    type Ownership = OwnershipArc;
    type RustType = Mutex<SSL_CTX>;
}

type SSL = crate::Ssl;

entry! {
    pub fn _SSL_new(ctx: *mut SSL_CTX) -> *mut SSL {
        let ctx = try_clone_arc!(ctx);

        ctx.lock()
            .ok()
            .map(|c| to_arc_mut_ptr(Mutex::new(crate::Ssl::new(ctx.clone(), &c))))
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_up_ref(ssl: *mut SSL) -> c_int {
        let ssl = try_clone_arc!(ssl);
        mem::forget(ssl.clone());
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_free(ssl: *mut SSL) {
        free_arc(ssl);
    }
}

entry! {
    pub fn _SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
        let ssl = try_clone_arc!(ssl);

        match SslCtrl::try_from(cmd) {
            Ok(SslCtrl::Mode) => {
                log::warn!("unimplemented SSL_set_mode()");
                0
            }
            Ok(SslCtrl::SetMsgCallbackArg) => {
                log::warn!("unimplemented SSL_set_msg_callback_arg()");
                0
            }
            Ok(SslCtrl::SetMaxProtoVersion) => {
                log::warn!("unimplemented SSL_set_max_proto_version()");
                1
            }
            Ok(SslCtrl::SetTlsExtHostname) => {
                let hostname = try_str!(parg as *const c_char);
                ssl.lock()
                    .ok()
                    .map(|mut ssl| ssl.set_sni_hostname(hostname))
                    .unwrap_or_default() as c_long
            }
            Err(()) => {
                log::warn!("unimplemented _SSL_ctrl(..., {cmd}, {larg}, ...)");
                0
            }
        }
    }
}

entry! {
    pub fn _SSL_get_options(ssl: *const SSL) -> u64 {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|ssl| ssl.get_options())
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_clear_options(ssl: *mut SSL, op: u64) -> u64 {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|mut ssl| ssl.clear_options(op))
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_set_options(ssl: *mut SSL, op: u64) -> u64 {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|mut ssl| ssl.set_options(op))
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_set_alpn_protos(
        ssl: *mut SSL,
        protos: *const c_uchar,
        protos_len: c_uint,
    ) -> MysteriouslyOppositeReturnValue {
        let ssl = try_clone_arc!(ssl);
        let slice = try_slice!(protos, protos_len);

        let alpn = match crate::parse_alpn(slice) {
            Some(alpn) => alpn,
            None => {
                // nb. openssl doesn't add anything to the error stack
                // in this case.
                return Error::bad_data("invalid alpn protocols").raise().into();
            }
        };

        match ssl
            .lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ssl| ssl.set_alpn_offer(alpn))
        {
            Err(e) => e.raise().into(),
            Ok(()) => MysteriouslyOppositeReturnValue::Success,
        }
    }
}

entry! {
    pub fn _SSL_set_connect_state(ssl: *mut SSL) {
        let ssl = try_clone_arc!(ssl);
        let _ = ssl.lock().ok().map(|mut ssl| ssl.set_client_mode());
    }
}

entry! {
    pub fn _SSL_set_accept_state(ssl: *mut SSL) {
        let ssl = try_clone_arc!(ssl);
        let _ = ssl.lock().ok().map(|mut ssl| ssl.set_server_mode());
    }
}

entry! {
    pub fn _SSL_is_server(ssl: *const SSL) -> c_int {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|ssl| ssl.is_server())
            .unwrap_or_default() as c_int
    }
}

entry! {
    pub fn _SSL_set1_host(ssl: *mut SSL, hostname: *const c_char) -> c_int {
        let ssl = try_clone_arc!(ssl);
        let maybe_hostname = str_from_cstring(hostname);
        ssl.lock()
            .ok()
            .map(|mut ssl| ssl.set_verify_hostname(maybe_hostname))
            .unwrap_or_default() as c_int
    }
}

entry! {
    pub fn _SSL_set_fd(ssl: *mut SSL, fd: c_int) -> c_int {
        let ssl = try_clone_arc!(ssl);
        let bio = Bio::new_fd_no_close(fd);
        ssl.lock()
            .ok()
            .map(|mut ssl| {
                ssl.set_bio(bio);
                true
            })
            .unwrap_or_default() as c_int
    }
}

entry! {
    pub fn _SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO) {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|mut ssl| ssl.set_bio_pair(Some(rbio), Some(wbio)))
            .unwrap_or_default();
    }
}

entry! {
    pub fn _SSL_set0_rbio(ssl: *mut SSL, rbio: *mut BIO) {
        let ssl = try_clone_arc!(ssl);
        if rbio.is_null() {
            return;
        }
        ssl.lock()
            .ok()
            .map(|mut ssl| ssl.set_bio_pair(Some(rbio), None))
            .unwrap_or_default();
    }
}

entry! {
    pub fn _SSL_set0_wbio(ssl: *mut SSL, wbio: *mut BIO) {
        let ssl = try_clone_arc!(ssl);
        if wbio.is_null() {
            return;
        }
        ssl.lock()
            .ok()
            .map(|mut ssl| ssl.set_bio_pair(None, Some(wbio)))
            .unwrap_or_default();
    }
}

entry! {
    pub fn _SSL_connect(ssl: *mut SSL) -> c_int {
        let ssl = try_clone_arc!(ssl);

        match ssl
            .lock()
            .map_err(|_| Error::cannot_lock())
            .and_then(|mut ssl| ssl.connect())
            .map_err(|err| err.raise())
        {
            Err(e) => e.into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

impl Castable for SSL {
    type Ownership = OwnershipArc;
    type RustType = Mutex<SSL>;
}

type SSL_CIPHER = crate::SslCipher;

entry! {
    pub fn _SSL_CIPHER_find(_ssl: *const SSL, ptr: *const c_uchar) -> *const SSL_CIPHER {
        let slice = try_slice!(ptr, 2);
        let id = (slice[0] as u16) << 8 | (slice[1] as u16);
        crate::SslCipher::find_by_id(rustls::CipherSuite::from(id))
            .map(|cipher| cipher as *const SSL_CIPHER)
            .unwrap_or_else(ptr::null)
    }
}

entry! {
    pub fn _SSL_CIPHER_get_bits(cipher: *const SSL_CIPHER, alg_bits: *mut c_int) -> c_int {
        let cipher = try_ref_from_ptr!(cipher);
        let bits = cipher.bits as c_int;
        if !alg_bits.is_null() {
            unsafe { ptr::write(alg_bits, bits) };
        }
        bits
    }
}

entry! {
    pub fn _SSL_CIPHER_get_version(cipher: *const SSL_CIPHER) -> *const c_char {
        match try_from(cipher) {
            Some(cipher) => cipher.version,
            None => c"(NONE)",
        }
        .as_ptr()
    }
}

entry! {
    pub fn _SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) -> *const c_char {
        match try_from(cipher) {
            Some(cipher) => cipher.openssl_name,
            None => c"(NONE)",
        }
        .as_ptr()
    }
}

entry! {
    pub fn _SSL_CIPHER_standard_name(cipher: *const SSL_CIPHER) -> *const c_char {
        match try_from(cipher) {
            Some(cipher) => cipher.standard_name,
            None => c"(NONE)",
        }
        .as_ptr()
    }
}

entry! {
    pub fn _SSL_CIPHER_get_id(cipher: *const SSL_CIPHER) -> u32 {
        let cipher = try_ref_from_ptr!(cipher);
        cipher.openssl_id()
    }
}

entry! {
    pub fn _SSL_CIPHER_get_protocol_id(cipher: *const SSL_CIPHER) -> u16 {
        let cipher = try_ref_from_ptr!(cipher);
        cipher.protocol_id()
    }
}

entry! {
    pub fn _SSL_CIPHER_description(
        cipher: *const SSL_CIPHER,
        mut buf: *mut c_char,
        mut size: c_int,
    ) -> *mut c_char {
        let cipher = try_ref_from_ptr!(cipher);
        let required_len = cipher.description.to_bytes_with_nul().len();

        if buf.is_null() {
            // safety: `required_len` is a compile-time constant, and is
            // a reasonable quantity to ask `OPENSSL_malloc` for.
            // In C cast rules, any `*mut c_void` can be viewed as a
            // `*mut c_char`.
            let allocd = unsafe { OPENSSL_malloc(required_len) as *mut c_char };
            if allocd.is_null() {
                return allocd;
            }
            buf = allocd;
            size = required_len as i32;
        } else if size < (required_len as i32) {
            return ptr::null_mut();
        }

        unsafe {
            ptr::copy_nonoverlapping(cipher.description.as_ptr(), buf, required_len as usize);
        };
        buf
    }
}

impl Castable for SSL_CIPHER {
    type Ownership = OwnershipRef;
    type RustType = SSL_CIPHER;
}

/// Normal OpenSSL return value convention success indicator.
///
/// Compare [`crate::ffi::MysteriouslyOppositeReturnValue`].
const C_INT_SUCCESS: c_int = 1;

/// Define an enum that can round trip through a c_int, with no
/// UB for unknown values.
macro_rules! num_enum {
    ($enum_vis:vis enum $enum_name:ident
    { $( $enum_var:ident = $enum_val:expr ),* $(,)? }
    ) => {
        #[derive(Debug, PartialEq, Clone, Copy)]
        $enum_vis enum $enum_name {
            $( $enum_var),*
        }

        impl From<$enum_name> for c_int {
            fn from(item: $enum_name) -> Self {
                match item {
                    $( $enum_name::$enum_var => $enum_val),*
                }
            }
        }

        impl TryFrom<c_int> for $enum_name {
            type Error = ();
            fn try_from(i: c_int) -> Result<Self, ()> {
                match i {
                    $( $enum_val => Ok(Self::$enum_var), )*
                    _ => Err(()),
                }
            }
        }
    }
}

// See `ssl.h` for macros starting `SSL_CTRL_`, eg. `SSL_CTRL_SET_TLSEXT_HOSTNAME`
num_enum! {
    enum SslCtrl {
        Mode = 33,
        SetMsgCallbackArg = 16,
        SetTlsExtHostname = 55,
        SetMaxProtoVersion = 124,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn test_SSL_CTX_new_null() {
        assert!(_SSL_CTX_new(ptr::null()).is_null());
    }

    #[test]
    fn test_SSL_new_null() {
        assert!(_SSL_new(ptr::null_mut()).is_null());
    }

    #[test]
    fn test_SSL_up_ref_null() {
        assert_eq!(_SSL_up_ref(ptr::null_mut()), 0);
    }

    #[test]
    fn test_SSL_free() {
        let ctx = _SSL_CTX_new(_TLS_method());
        assert!(!ctx.is_null());
        let ssl = _SSL_new(ctx);
        assert!(!ssl.is_null());
        _SSL_free(ssl);
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_free_after_up_ref() {
        let ctx = _SSL_CTX_new(_TLS_method());
        assert!(!ctx.is_null());
        let ssl = _SSL_new(ctx);
        assert!(!ssl.is_null());
        assert_eq!(_SSL_up_ref(ssl), 1);
        _SSL_free(ssl); // ref 2
        _SSL_free(ssl); // ref 1
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_CTX_set_alpn_protos_works() {
        let ctx = _SSL_CTX_new(_TLS_method());
        assert_eq!(
            _SSL_CTX_set_alpn_protos(ctx, b"\x05hello" as *const u8, 6) as i32,
            0i32
        );
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_CTX_set_alpn_protos_null_ctx() {
        assert_eq!(
            _SSL_CTX_set_alpn_protos(ptr::null_mut(), b"\x05hello" as *const u8, 6) as i32,
            1i32
        );
    }

    #[test]
    fn test_SSL_CTX_set_alpn_protos_null_proto() {
        let ctx = _SSL_CTX_new(_TLS_method());
        assert_eq!(_SSL_CTX_set_alpn_protos(ctx, ptr::null(), 6) as i32, 1i32);
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_CTX_set_alpn_protos_invalid_proto() {
        let ctx = _SSL_CTX_new(_TLS_method());
        assert_eq!(
            _SSL_CTX_set_alpn_protos(ctx, b"\x05hell" as *const u8, 5) as i32,
            1i32
        );
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_set_alpn_protos_works() {
        let ctx = _SSL_CTX_new(_TLS_method());
        let ssl = _SSL_new(ctx);
        assert_eq!(
            _SSL_set_alpn_protos(ssl, b"\x05hello" as *const u8, 6) as i32,
            0i32
        );
        _SSL_free(ssl);
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_set_alpn_protos_null_ssl() {
        assert_eq!(
            _SSL_set_alpn_protos(ptr::null_mut(), b"\x05hello" as *const u8, 6) as i32,
            1i32
        );
    }

    #[test]
    fn test_SSL_set_alpn_protos_null_proto() {
        let ctx = _SSL_CTX_new(_TLS_method());
        let ssl = _SSL_new(ctx);
        assert_eq!(_SSL_set_alpn_protos(ssl, ptr::null(), 6) as i32, 1i32);
        _SSL_free(ssl);
        _SSL_CTX_free(ctx);
    }

    #[test]
    fn test_SSL_set_alpn_protos_invalid_proto() {
        let ctx = _SSL_CTX_new(_TLS_method());
        let ssl = _SSL_new(ctx);
        assert_eq!(
            _SSL_set_alpn_protos(ssl, b"\x05hell" as *const u8, 5) as i32,
            1i32
        );
        _SSL_free(ssl);
        _SSL_CTX_free(ctx);
    }
}
