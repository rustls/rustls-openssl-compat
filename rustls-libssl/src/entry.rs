//! This file contains all the libssl entrypoints that we implement.
//!
//! It should mainly be concerned with mapping these calls up to
//! the safe APIs implemented elsewhere.

use core::{mem, ptr};
use std::io::{self, Read};
use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use std::sync::Mutex;
use std::{fs, path::PathBuf};

use openssl_sys::{
    stack_st_X509, OPENSSL_malloc, EVP_PKEY, X509, X509_STORE, X509_STORE_CTX,
    X509_V_ERR_UNSPECIFIED,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::bio::{Bio, BIO, BIO_METHOD};
use crate::error::{ffi_panic_boundary, Error, MysteriouslyOppositeReturnValue};
use crate::evp_pkey::EvpPkey;
use crate::ffi::{
    free_arc, str_from_cstring, to_arc_mut_ptr, try_clone_arc, try_from, try_mut_slice_int,
    try_ref_from_ptr, try_slice, try_slice_int, try_str, Castable, OwnershipArc, OwnershipRef,
};
use crate::x509::{load_certs, OwnedX509};
use crate::ShutdownResult;

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

entry! {
    pub fn _BIO_f_ssl() -> *const BIO_METHOD {
        &crate::bio::SSL_BIO_METHOD
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
    let certs = match load_certs(file_names) {
        Err(e) => return e.into(),
        Ok(certs) => certs,
    };

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
    pub fn _SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int {
        let ctx = try_clone_arc!(ctx);
        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ctx| ctx.set_default_verify_paths())
        {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_set_default_verify_dir(ctx: *mut SSL_CTX) -> c_int {
        let ctx = try_clone_arc!(ctx);
        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ctx| ctx.set_default_verify_dir())
        {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_set_default_verify_file(ctx: *mut SSL_CTX) -> c_int {
        let ctx = try_clone_arc!(ctx);
        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ctx| ctx.set_default_verify_file())
        {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
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

entry! {
    pub fn _SSL_CTX_use_certificate_chain_file(
        ctx: *mut SSL_CTX,
        file_name: *const c_char,
    ) -> c_int {
        let ctx = try_clone_arc!(ctx);
        let file_name = try_str!(file_name);

        let mut file_reader = match fs::File::open(file_name) {
            Ok(content) => io::BufReader::new(content),
            Err(err) => return Error::from_io(err).raise().into(),
        };

        let mut chain = Vec::new();

        for cert in rustls_pemfile::certs(&mut file_reader) {
            let cert = match cert {
                Ok(cert) => cert,
                Err(err) => {
                    log::trace!("Failed to parse {file_name:?}: {err:?}");
                    return Error::from_io(err).raise().into();
                }
            };

            match OwnedX509::parse_der(cert.as_ref()) {
                Some(_) => chain.push(cert),
                None => {
                    log::trace!("Failed to parse DER certificate");
                    return Error::bad_data("certificate").raise().into();
                }
            }
        }

        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ctx| ctx.stage_certificate_chain(chain))
        {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> c_int {
        let ctx = try_clone_arc!(ctx);

        if x.is_null() {
            return Error::null_pointer().raise().into();
        }

        let x509 = OwnedX509::new_incref(x);
        let ee = CertificateDer::from(x509.der_bytes());

        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ctx| ctx.stage_certificate_end_entity(ee))
        {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_use_PrivateKey_file(
        ctx: *mut SSL_CTX,
        file_name: *const c_char,
        file_type: c_int,
    ) -> c_int {
        let ctx = try_clone_arc!(ctx);
        let file_name = try_str!(file_name);

        let der_data = match file_type {
            FILETYPE_PEM => {
                let mut file_reader = match fs::File::open(file_name) {
                    Ok(content) => io::BufReader::new(content),
                    Err(err) => return Error::from_io(err).raise().into(),
                };

                match rustls_pemfile::private_key(&mut file_reader) {
                    Ok(Some(key)) => key,
                    Ok(None) => {
                        log::trace!("No keys found in {file_name:?}");
                        return Error::bad_data("pem file").raise().into();
                    }
                    Err(err) => {
                        log::trace!("Failed to read {file_name:?}: {err:?}");
                        return Error::from_io(err).raise().into();
                    }
                }
            }
            FILETYPE_DER => {
                let mut data = vec![];
                match fs::File::open(file_name).and_then(|mut f| f.read_to_end(&mut data)) {
                    Ok(_) => PrivatePkcs8KeyDer::from(data).into(),
                    Err(err) => {
                        log::trace!("Failed to read {file_name:?}: {err:?}");
                        return Error::from_io(err).raise().into();
                    }
                }
            }
            _ => {
                return Error::not_supported("file_type not in (PEM, DER)")
                    .raise()
                    .into();
            }
        };

        let key = match EvpPkey::new_from_der_bytes(der_data) {
            None => return Error::not_supported("invalid key format").raise().into(),
            Some(key) => key,
        };

        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .and_then(|mut ctx| ctx.commit_private_key(key))
        {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, pkey: *mut EVP_PKEY) -> c_int {
        let ctx = try_clone_arc!(ctx);

        if pkey.is_null() {
            return Error::null_pointer().raise().into();
        }

        let pkey = EvpPkey::new_incref(pkey);

        match ctx
            .lock()
            .map_err(|_| Error::cannot_lock())
            .and_then(|mut ctx| ctx.commit_private_key(pkey))
        {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_get0_certificate(ctx: *const SSL_CTX) -> *mut X509 {
        let ctx = try_clone_arc!(ctx);
        ctx.lock()
            .ok()
            .map(|ctx| ctx.get_certificate())
            .unwrap_or(ptr::null_mut())
    }
}

entry! {
    pub fn _SSL_CTX_get0_privatekey(ctx: *const SSL_CTX) -> *mut EVP_PKEY {
        let ctx = try_clone_arc!(ctx);
        ctx.lock()
            .ok()
            .map(|ctx| ctx.get_privatekey())
            .unwrap_or(ptr::null_mut())
    }
}

entry! {
    pub fn _SSL_CTX_check_private_key(_ctx: *const SSL_CTX) -> c_int {
        log::trace!("not implemented: _SSL_CTX_check_private_key, returning success");
        C_INT_SUCCESS
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

        let ssl_ctx = match ctx.lock().ok() {
            Some(ssl_ctx) => ssl_ctx,
            None => return ptr::null_mut(),
        };

        let ssl = match crate::Ssl::new(ctx.clone(), &ssl_ctx).ok() {
            Some(ssl) => ssl,
            None => return ptr::null_mut(),
        };

        to_arc_mut_ptr(Mutex::new(ssl))
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

entry! {
    pub fn _SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int {
        const ERROR: c_int = -1;
        let ssl = try_clone_arc!(ssl, ERROR);
        let slice = try_slice_int!(buf as *const u8, num, ERROR);

        if slice.is_empty() {
            return ERROR;
        }

        match ssl
            .lock()
            .map_err(|_| Error::cannot_lock())
            .and_then(|mut ssl| ssl.write(slice))
            .map_err(|err| err.raise())
        {
            Err(_e) => ERROR,
            Ok(written) => written as c_int,
        }
    }
}

entry! {
    pub fn _SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int {
        const ERROR: c_int = -1;
        let ssl = try_clone_arc!(ssl, ERROR);
        let slice = try_mut_slice_int!(buf as *mut u8, num, ERROR);

        match ssl
            .lock()
            .map_err(|_| Error::cannot_lock())
            .and_then(|mut ssl| ssl.read(slice))
            .map_err(|err| err.raise())
        {
            Err(_e) => ERROR,
            Ok(read) => read as c_int,
        }
    }
}

entry! {
    pub fn _SSL_want(ssl: *const SSL) -> c_int {
        let ssl = try_clone_arc!(ssl);
        let want = ssl.lock().ok().map(|ssl| ssl.want()).unwrap_or_default();

        if want.read {
            SSL_READING
        } else if want.write {
            SSL_WRITING
        } else {
            SSL_NOTHING
        }
    }
}

pub const SSL_NOTHING: i32 = 1;
pub const SSL_WRITING: i32 = 2;
pub const SSL_READING: i32 = 3;

entry! {
    pub fn _SSL_shutdown(ssl: *mut SSL) -> c_int {
        const ERROR: c_int = -1;
        let ssl = try_clone_arc!(ssl, ERROR);

        match ssl
            .lock()
            .map_err(|_| Error::cannot_lock())
            .and_then(|mut ssl| ssl.try_shutdown())
            .map_err(|err| err.raise())
        {
            Err(_e) => ERROR,
            Ok(result) => match result {
                ShutdownResult::Sent => 0 as c_int,
                ShutdownResult::Received => 1 as c_int,
            },
        }
    }
}

entry! {
    pub fn _SSL_get_shutdown(ssl: *const SSL) -> c_int {
        let ssl = try_clone_arc!(ssl);

        ssl.lock().map(|ssl| ssl.get_shutdown()).unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_set_shutdown(ssl: *mut SSL, flags: c_int) {
        let ssl = try_clone_arc!(ssl);

        ssl.lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ssl| ssl.set_shutdown(flags))
            .map_err(|err| err.raise())
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_pending(ssl: *const SSL) -> c_int {
        let ssl = try_clone_arc!(ssl);

        ssl.lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ssl| ssl.get_pending_plaintext() as c_int)
            .map_err(|err| err.raise())
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_has_pending(ssl: *const SSL) -> c_int {
        (_SSL_pending(ssl) > 0) as c_int
    }
}

entry! {
    pub fn _SSL_get_error(ssl: *const SSL, _ret_code: c_int) -> c_int {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .map_err(|_| Error::cannot_lock())
            .map(|mut ssl| ssl.get_error() as c_int)
            .map_err(|err| err.raise())
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_get0_alpn_selected(ssl: *const SSL, data: *mut *const c_uchar, len: *mut c_uint) {
        if data.is_null() || len.is_null() {
            return;
        }

        let ssl = try_clone_arc!(ssl);

        match ssl.lock().ok().and_then(|mut ssl| {
            ssl.get_agreed_alpn().map(|proto| {
                unsafe {
                    // nb. alpn protocols are limited to 255 octets
                    ptr::write(len, proto.len() as u32);
                    ptr::write(data, proto.as_ptr());
                };
            })
        }) {
            Some(()) => {}
            None => unsafe {
                ptr::write(len, 0);
                ptr::write(data, ptr::null());
            },
        }
    }
}

entry! {
    pub fn _SSL_get_peer_cert_chain(ssl: *const SSL) -> *mut stack_st_X509 {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .and_then(|mut ssl| ssl.get_peer_cert_chain().map(|x509| x509.pointer()))
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_get0_verified_chain(ssl: *const SSL) -> *mut stack_st_X509 {
        _SSL_get_peer_cert_chain(ssl)
    }
}

entry! {
    pub fn _SSL_get0_peer_certificate(ssl: *const SSL) -> *mut X509 {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .and_then(|mut ssl| ssl.get_peer_cert().map(|x509| x509.borrow_ref()))
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_get1_peer_certificate(ssl: *const SSL) -> *mut X509 {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .and_then(|mut ssl| ssl.get_peer_cert().map(|x509| x509.up_ref()))
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .and_then(|ssl| ssl.get_negotiated_cipher_suite_id())
            .and_then(crate::SslCipher::find_by_id)
            .map(|cipher| cipher as *const SSL_CIPHER)
            .unwrap_or_else(ptr::null)
    }
}

entry! {
    pub fn _SSL_get_version(ssl: *const SSL) -> *const c_char {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .and_then(|ssl| ssl.get_negotiated_cipher_suite_id())
            .and_then(crate::SslCipher::find_by_id)
            .map(|cipher| cipher.version.as_ptr())
            .unwrap_or_else(ptr::null)
    }
}

entry! {
    pub fn _SSL_get_verify_result(ssl: *const SSL) -> c_long {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|ssl| ssl.get_last_verification_result())
            .unwrap_or(X509_V_ERR_UNSPECIFIED as i64)
    }
}

entry! {
    pub fn _SSL_get_certificate(ssl: *const SSL) -> *mut X509 {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|ssl| ssl.get_certificate())
            .unwrap_or(ptr::null_mut())
    }
}

entry! {
    pub fn _SSL_get_privatekey(ssl: *const SSL) -> *mut EVP_PKEY {
        let ssl = try_clone_arc!(ssl);
        ssl.lock()
            .ok()
            .map(|ssl| ssl.get_privatekey())
            .unwrap_or(ptr::null_mut())
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

const FILETYPE_PEM: c_int = 1;
const FILETYPE_DER: c_int = 2;

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

// --- unimplemented stubs below here ---

macro_rules! entry_stub {
    (pub fn $name:ident($($args:tt)*);) => {
        #[no_mangle]
        pub extern "C" fn $name($($args)*) {
            ffi_panic_boundary! {
                Error::not_supported(stringify!($name)).raise().into()
            }
        }
    };
    (pub fn $name:ident($($args:tt)*) -> $ret:ty;) => {
        #[no_mangle]
        pub extern "C" fn $name($($args)*) -> $ret {
            ffi_panic_boundary! {
                Error::not_supported(stringify!($name)).raise().into()
            }
        }
    };
}

// things we support and should be able to implement to
// some extent:

entry_stub! {
    pub fn _SSL_CTX_set_ex_data(_ssl: *mut SSL_CTX, _idx: c_int, _data: *mut c_void) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_get_ex_data(_ssl: *const SSL_CTX, _idx: c_int) -> *mut c_void;
}

entry_stub! {
    pub fn _SSL_set_ex_data(_ssl: *mut SSL, _idx: c_int, _data: *mut c_void) -> c_int;
}

entry_stub! {
    pub fn _SSL_get_ex_data(_ssl: *const SSL, _idx: c_int) -> *mut c_void;
}

entry_stub! {
    pub fn _SSL_set_session(_ssl: *mut SSL, _session: *mut SSL_SESSION) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_set_keylog_callback(_ctx: *mut SSL_CTX, _cb: SSL_CTX_keylog_cb_func);
}

pub type SSL_CTX_keylog_cb_func =
    Option<unsafe extern "C" fn(ssl: *const SSL, line: *const c_char)>;

entry_stub! {
    pub fn _SSL_CTX_add_client_CA(_ctx: *mut SSL_CTX, _x: *mut X509) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_sess_set_new_cb(_ctx: *mut SSL_CTX, _new_session_cb: SSL_CTX_new_session_cb);
}

pub type SSL_CTX_new_session_cb =
    Option<unsafe extern "C" fn(_ssl: *mut SSL, _sess: *mut SSL_SESSION) -> c_int>;

entry_stub! {
    pub fn _SSL_CTX_set_cipher_list(_ctx: *mut SSL_CTX, _s: *const c_char) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_set_ciphersuites(_ctx: *mut SSL_CTX, _s: *const c_char) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_use_certificate_file(
        _ctx: *mut SSL_CTX,
        _file: *const c_char,
        _type_: c_int,
    ) -> c_int;
}

// The SSL_CTX X509_STORE isn't being meaningfully used yet.
entry_stub! {
    pub fn _SSL_CTX_set_default_verify_store(_ctx: *mut SSL_CTX) -> c_int;
}

pub struct SSL_SESSION;

entry_stub! {
    pub fn _SSL_SESSION_free(_sess: *mut SSL_SESSION);
}

// no individual message logging

entry_stub! {
    pub fn _SSL_CTX_set_msg_callback(_ctx: *mut SSL_CTX, _cb: SSL_CTX_msg_cb_func);
}

pub type SSL_CTX_msg_cb_func = Option<
    unsafe extern "C" fn(
        write_p: c_int,
        version: c_int,
        content_type: c_int,
        buf: *const c_void,
        len: usize,
        ssl: *mut SSL,
        arg: *mut c_void,
    ),
>;

// no NPN (obsolete precursor to ALPN)

entry_stub! {
    pub fn _SSL_CTX_set_next_proto_select_cb(
        _ctx: *mut SSL_CTX,
        _cb: SSL_CTX_npn_select_cb_func,
        _arg: *mut c_void,
    );
}

pub type SSL_CTX_npn_select_cb_func = Option<
    unsafe extern "C" fn(
        s: *mut SSL,
        out: *mut *mut c_uchar,
        outlen: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_uint,
        arg: *mut c_void,
    ) -> c_int,
>;

// no password-protected key loading

entry_stub! {
    pub fn _SSL_CTX_set_default_passwd_cb(_ctx: *mut SSL_CTX, _cb: pem_password_cb);
}

pub type pem_password_cb = Option<
    unsafe extern "C" fn(
        buf: *mut c_char,
        size: c_int,
        rwflag: c_int,
        userdata: *mut c_void,
    ) -> c_int,
>;

entry_stub! {
    pub fn _SSL_CTX_set_default_passwd_cb_userdata(_ctx: *mut SSL_CTX, _u: *mut c_void);
}

// no SRP

entry_stub! {
    pub fn _SSL_CTX_set_srp_password(_ctx: *mut SSL_CTX, _password: *mut c_char) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_set_srp_username(_ctx: *mut SSL_CTX, _name: *mut c_char) -> c_int;
}

// no post-handshake auth

entry_stub! {
    pub fn _SSL_CTX_set_post_handshake_auth(_ctx: *mut SSL_CTX, _val: c_int);
}

entry_stub! {
    pub fn _SSL_set_post_handshake_auth(_s: *mut SSL, _val: c_int);
}

// ---------------------

#[cfg(test)]
mod tests {
    use super::*;

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
