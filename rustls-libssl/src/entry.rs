//! This file contains all the libssl entrypoints that we implement.
//!
//! It should mainly be concerned with mapping these calls up to
//! the safe APIs implemented elsewhere.

use core::{mem, ptr};
use std::io::{self, Read};
use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use std::sync::Arc;
use std::{fs, path::PathBuf};

use openssl_sys::{
    stack_st_X509, stack_st_X509_NAME, OPENSSL_malloc, TLSEXT_NAMETYPE_host_name, EVP_PKEY,
    OPENSSL_NPN_NEGOTIATED, OPENSSL_NPN_NO_OVERLAP, X509, X509_STORE, X509_STORE_CTX,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::bio::{Bio, BIO, BIO_METHOD};
use crate::callbacks::SslCallbackContext;
use crate::constants::sig_scheme_to_nid;
use crate::error::{ffi_panic_boundary, Error, MysteriouslyOppositeReturnValue};
use crate::evp_pkey::EvpPkey;
use crate::ex_data::ExData;
use crate::ffi::{
    clone_arc, free_arc, free_arc_into_inner, free_box, str_from_cstring, string_from_cstring,
    to_arc_mut_ptr, to_boxed_mut_ptr, try_clone_arc, try_from, try_mut_slice_int, try_ref_from_ptr,
    try_slice, try_slice_int, try_str, Castable, OwnershipArc, OwnershipBox, OwnershipRef,
};
use crate::not_thread_safe::NotThreadSafe;
use crate::x509::{load_certs, OwnedX509, OwnedX509Stack};
use crate::{conf, HandshakeState, ShutdownResult};

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

pub type SSL_CTX = crate::SslContext;

entry! {
    pub fn _SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX {
        let method = try_ref_from_ptr!(meth);
        let out: *mut SSL_CTX = to_arc_mut_ptr(NotThreadSafe::new(crate::SslContext::new(method)));
        // safety: we just made this object, the pointer must be valid
        match clone_arc(out).unwrap().get_mut().complete_construction(out) {
            Err(err) => {
                _SSL_CTX_free(out);
                err.raise().into()
            }
            Ok(()) => out,
        }
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
        if let Some(inner) = free_arc_into_inner(ctx) {
            inner.get_mut().flush_all_sessions();
        }
    }
}

entry! {
    pub fn _SSL_CTX_set_ex_data(ctx: *mut SSL_CTX, idx: c_int, data: *mut c_void) -> c_int {
        match try_clone_arc!(ctx).get_mut().set_ex_data(idx, data) {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_get_ex_data(ctx: *const SSL_CTX, idx: c_int) -> *mut c_void {
        try_clone_arc!(ctx).get().get_ex_data(idx)
    }
}

entry! {
    pub fn _SSL_CTX_get_options(ctx: *const SSL_CTX) -> u64 {
        try_clone_arc!(ctx).get().get_options()
    }
}

entry! {
    pub fn _SSL_CTX_clear_options(ctx: *mut SSL_CTX, op: u64) -> u64 {
        try_clone_arc!(ctx).get_mut().clear_options(op)
    }
}

entry! {
    pub fn _SSL_CTX_set_options(ctx: *mut SSL_CTX, op: u64) -> u64 {
        try_clone_arc!(ctx).get_mut().set_options(op)
    }
}

entry! {
    pub fn _SSL_CTX_set_num_tickets(ctx: *mut SSL_CTX, num_tickets: usize) -> c_int {
        try_clone_arc!(ctx).get_mut().set_num_tickets(num_tickets);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_get_num_tickets(ctx: *const SSL_CTX) -> usize {
        try_clone_arc!(ctx).get().get_num_tickets()
    }
}

entry! {
    pub fn _SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
        let ctx = try_clone_arc!(ctx);

        match SslCtrl::try_from(cmd) {
            Ok(SslCtrl::Mode) => {
                log::warn!("unimplemented SSL_CTX_set_mode()");
                0
            }
            Ok(SslCtrl::SetMsgCallbackArg) => {
                log::warn!("unimplemented SSL_CTX_set_msg_callback_arg()");
                0
            }
            Ok(SslCtrl::SetMinProtoVersion) => {
                if larg < 0 || larg > u16::MAX.into() {
                    return 0;
                }
                ctx.get_mut().set_min_protocol_version(larg as u16);
                C_INT_SUCCESS as c_long
            }
            Ok(SslCtrl::GetMinProtoVersion) => ctx.get().get_min_protocol_version().into(),
            Ok(SslCtrl::SetMaxProtoVersion) => {
                if larg < 0 || larg > u16::MAX.into() {
                    return 0;
                }
                ctx.get_mut().set_max_protocol_version(larg as u16);
                C_INT_SUCCESS as c_long
            }
            Ok(SslCtrl::GetMaxProtoVersion) => ctx.get().get_max_protocol_version().into(),
            Ok(SslCtrl::SetTlsExtHostname) | Ok(SslCtrl::SetTlsExtServerNameCallback) => {
                // not a defined operation in the OpenSSL API
                0
            }
            Ok(SslCtrl::SetChain) => {
                let chain = if parg.is_null() {
                    // this is `SSL_CTX_clear_chain_certs`
                    vec![]
                } else {
                    match larg {
                        // this is `SSL_CTX_set1_chain` (incs ref)
                        1 => OwnedX509Stack::new_copy(parg as *mut stack_st_X509).to_rustls(),
                        // this is `SSL_CTX_set0_chain` (retain ref)
                        _ => OwnedX509Stack::new(parg as *mut stack_st_X509).to_rustls(),
                    }
                };

                ctx.get_mut().stage_certificate_chain(chain);
                C_INT_SUCCESS as i64
            }
            Ok(SslCtrl::SetTlsExtServerNameArg) => {
                ctx.get_mut().set_servername_callback_context(parg);
                C_INT_SUCCESS as c_long
            }
            Ok(SslCtrl::SetSessCacheSize) => {
                if larg < 0 {
                    return 0;
                }
                ctx.get_mut().set_session_cache_size(larg as usize) as c_long
            }
            Ok(SslCtrl::GetSessCacheSize) => ctx.get().get_session_cache_size() as c_long,
            Ok(SslCtrl::SetSessCacheMode) => {
                if larg < 0 {
                    return 0;
                }
                ctx.get_mut().set_session_cache_mode(larg as u32) as c_long
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
        if callback.is_some() {
            // supporting verify callbacks would mean we need to fully use
            // the openssl certificate verifier, because X509_STORE and
            // X509_STORE_CTX are both in libcrypto.
            return Error::not_supported("verify callback").raise().into();
        }

        try_clone_arc!(ctx)
            .get_mut()
            .set_verify(crate::VerifyMode::from(mode));
    }
}

entry! {
    pub fn _SSL_CTX_get_verify_callback(ctx: *const SSL_CTX) -> SSL_verify_cb {
        try_clone_arc!(ctx).get().get_verify_callback()
    }
}

entry! {
    pub fn _SSL_CTX_get_verify_mode(ctx: *const SSL_CTX) -> c_int {
        try_clone_arc!(ctx).get().get_verify_mode().into()
    }
}

entry! {
    pub fn _SSL_CTX_set_verify_depth(ctx: *mut SSL_CTX, depth: c_int) {
        try_clone_arc!(ctx).get_mut().set_verify_depth(depth)
    }
}

entry! {
    pub fn _SSL_CTX_get_verify_depth(ctx: *mut SSL_CTX) -> c_int {
        try_clone_arc!(ctx).get().get_verify_depth()
    }
}

pub type SSL_verify_cb =
    Option<unsafe extern "C" fn(preverify_ok: c_int, x509_ctx: *mut X509_STORE_CTX) -> c_int>;

entry! {
    pub fn _SSL_CTX_get_cert_store(ctx: *const SSL_CTX) -> *mut X509_STORE {
        try_clone_arc!(ctx).get().get_x509_store()
    }
}

entry! {
    pub fn _SSL_CTX_set_cert_store(ctx: *mut SSL_CTX, store: *mut X509_STORE) {
        try_clone_arc!(ctx).get_mut().set_x509_store(store);
    }
}

fn load_verify_files(
    ctx: &NotThreadSafe<SSL_CTX>,
    file_names: impl Iterator<Item = PathBuf>,
) -> c_int {
    let certs = match load_certs(file_names) {
        Err(e) => return e.into(),
        Ok(certs) => certs,
    };

    match ctx.get_mut().add_trusted_certs(certs) {
        Err(e) => e.raise().into(),
        Ok(()) => C_INT_SUCCESS,
    }
}

entry! {
    pub fn _SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int {
        try_clone_arc!(ctx).get_mut().set_default_verify_paths();
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_default_verify_dir(ctx: *mut SSL_CTX) -> c_int {
        try_clone_arc!(ctx).get_mut().set_default_verify_dir();
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_default_verify_file(ctx: *mut SSL_CTX) -> c_int {
        try_clone_arc!(ctx).get_mut().set_default_verify_file();
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_load_verify_file(ctx: *mut SSL_CTX, ca_file: *const c_char) -> c_int {
        let ctx = try_clone_arc!(ctx);
        let ca_file = try_str!(ca_file);
        let path_buf = PathBuf::from(ca_file);
        load_verify_files(&ctx, [path_buf].into_iter())
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
    pub fn _SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX,
        ca_file: *const c_char,
        ca_path: *const c_char,
    ) -> c_int {
        if ca_path.is_null() && ca_path.is_null() {
            return 0;
        }

        if !ca_file.is_null() && _SSL_CTX_load_verify_file(ctx, ca_file) == 0 {
            return 0;
        }

        if !ca_path.is_null() && _SSL_CTX_load_verify_dir(ctx, ca_path) == 0 {
            return 0;
        }

        C_INT_SUCCESS
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

        ctx.get_mut().set_alpn_offer(alpn);
        MysteriouslyOppositeReturnValue::Success
    }
}

entry! {
    pub fn _SSL_CTX_use_certificate_chain_file(
        ctx: *mut SSL_CTX,
        file_name: *const c_char,
    ) -> c_int {
        let ctx = try_clone_arc!(ctx);
        let chain = match use_cert_chain_file(try_str!(file_name)) {
            Ok(chain) => chain,
            Err(err) => return err.raise().into(),
        };

        ctx.get_mut().stage_certificate_chain(chain);
        C_INT_SUCCESS
    }
}

pub(crate) fn use_cert_chain_file(file_name: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut file_reader = match fs::File::open(file_name) {
        Ok(content) => io::BufReader::new(content),
        Err(err) => return Err(Error::from_io(err)),
    };

    let mut chain = Vec::new();
    for cert in rustls_pemfile::certs(&mut file_reader) {
        let cert = match cert {
            Ok(cert) => cert,
            Err(err) => {
                log::trace!("Failed to parse {file_name:?}: {err:?}");
                return Err(Error::from_io(err));
            }
        };

        match OwnedX509::parse_der(cert.as_ref()) {
            Some(_) => chain.push(cert),
            None => {
                log::trace!("Failed to parse DER certificate");
                return Err(Error::bad_data("certificate"));
            }
        }
    }

    Ok(chain)
}

entry! {
    pub fn _SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> c_int {
        let ctx = try_clone_arc!(ctx);

        if x.is_null() {
            return Error::null_pointer().raise().into();
        }

        let x509 = OwnedX509::new_incref(x);
        let ee = CertificateDer::from(x509.der_bytes());

        ctx.get_mut().stage_certificate_end_entity(ee);
        C_INT_SUCCESS
    }
}

pub(crate) fn use_private_key_file(file_name: &str, file_type: c_int) -> Result<EvpPkey, Error> {
    let der_data = match file_type {
        FILETYPE_PEM => {
            let mut file_reader = match fs::File::open(file_name) {
                Ok(content) => io::BufReader::new(content),
                Err(err) => return Err(Error::from_io(err)),
            };

            match rustls_pemfile::private_key(&mut file_reader) {
                Ok(Some(key)) => key,
                Ok(None) => {
                    log::trace!("No keys found in {file_name:?}");
                    return Err(Error::bad_data("pem file"));
                }
                Err(err) => {
                    log::trace!("Failed to read {file_name:?}: {err:?}");
                    return Err(Error::from_io(err));
                }
            }
        }
        FILETYPE_DER => {
            let mut data = vec![];
            match fs::File::open(file_name).and_then(|mut f| f.read_to_end(&mut data)) {
                Ok(_) => PrivatePkcs8KeyDer::from(data).into(),
                Err(err) => {
                    log::trace!("Failed to read {file_name:?}: {err:?}");
                    return Err(Error::from_io(err));
                }
            }
        }
        _ => {
            return Err(Error::not_supported("file_type not in (PEM, DER)"));
        }
    };

    match EvpPkey::new_from_der_bytes(der_data) {
        None => Err(Error::not_supported("invalid key format")),
        Some(key) => Ok(key),
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

        let key = match use_private_key_file(file_name, file_type) {
            Ok(key) => key,
            Err(err) => {
                return err.raise().into();
            }
        };

        match ctx.get_mut().commit_private_key(key) {
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

        match ctx.get_mut().commit_private_key(pkey) {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_CTX_get0_certificate(ctx: *const SSL_CTX) -> *mut X509 {
        try_clone_arc!(ctx).get().get_certificate()
    }
}

entry! {
    pub fn _SSL_CTX_get0_privatekey(ctx: *const SSL_CTX) -> *mut EVP_PKEY {
        try_clone_arc!(ctx).get().get_privatekey()
    }
}

entry! {
    pub fn _SSL_CTX_check_private_key(_ctx: *const SSL_CTX) -> c_int {
        log::trace!("not implemented: _SSL_CTX_check_private_key, returning success");
        C_INT_SUCCESS
    }
}

pub type SSL_CTX_alpn_select_cb_func = Option<
    unsafe extern "C" fn(
        ssl: *mut SSL,
        out: *mut *const c_uchar,
        outlen: *mut c_uchar,
        in_: *const c_uchar,
        inlen: c_uint,
        arg: *mut c_void,
    ) -> c_int,
>;

entry! {
    pub fn _SSL_CTX_set_alpn_select_cb(
        ctx: *mut SSL_CTX,
        cb: SSL_CTX_alpn_select_cb_func,
        arg: *mut c_void,
    ) {
        let ctx = try_clone_arc!(ctx);
        ctx.get_mut().set_alpn_select_cb(cb, arg);
    }
}

pub type SSL_CTX_cert_cb_func =
    Option<unsafe extern "C" fn(ssl: *mut SSL, arg: *mut c_void) -> c_int>;

entry! {
    pub fn _SSL_CTX_set_cert_cb(ctx: *mut SSL_CTX, cb: SSL_CTX_cert_cb_func, arg: *mut c_void) {
        let ctx = try_clone_arc!(ctx);
        ctx.get_mut().set_cert_cb(cb, arg);
    }
}

// nb. calls into SSL_CTX_callback_ctrl cast away the real function pointer type,
// and then cast back to the real type based on `cmd`.
pub type SSL_CTX_any_func = Option<unsafe extern "C" fn()>;

pub type SSL_CTX_servername_callback_func =
    Option<unsafe extern "C" fn(ssl: *mut SSL, ad: *mut c_int, arg: *mut c_void) -> c_int>;

entry! {
    pub fn _SSL_CTX_callback_ctrl(ctx: *mut SSL_CTX, cmd: c_int, fp: SSL_CTX_any_func) -> c_long {
        let ctx = try_clone_arc!(ctx);

        match SslCtrl::try_from(cmd) {
            Ok(SslCtrl::SetTlsExtServerNameCallback) => {
                // safety: same layout
                let fp = unsafe {
                    mem::transmute::<SSL_CTX_any_func, SSL_CTX_servername_callback_func>(fp)
                };
                ctx.get_mut().set_servername_callback(fp);
                C_INT_SUCCESS as c_long
            }
            _ => 0,
        }
    }
}

entry! {
    pub fn _SSL_CTX_get_max_early_data(ctx: *const SSL_CTX) -> u32 {
        try_clone_arc!(ctx).get().get_max_early_data()
    }
}

entry! {
    pub fn _SSL_CTX_set_max_early_data(ctx: *mut SSL_CTX, max_early_data: u32) -> c_int {
        try_clone_arc!(ctx)
            .get_mut()
            .set_max_early_data(max_early_data);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_set_cipher_list(_ctx: *mut SSL_CTX, s: *const c_char) -> c_int {
        match try_str!(s) {
            "HIGH:!aNULL:!MD5" => C_INT_SUCCESS,
            _ => Error::not_supported("SSL_CTX_set_cipher_list")
                .raise()
                .into(),
        }
    }
}

entry! {
    pub fn _SSL_CTX_set_session_id_context(
        ctx: *mut SSL_CTX,
        sid_ctx: *const c_uchar,
        sid_ctx_len: c_uint,
    ) -> c_int {
        let sid_ctx = try_slice!(sid_ctx, sid_ctx_len);
        if sid_ctx.len() > SSL_MAX_SID_CTX_LENGTH {
            return Error::not_supported("excess sid_ctx_len").raise().into();
        }
        try_clone_arc!(ctx)
            .get_mut()
            .set_session_id_context(sid_ctx);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CTX_sess_set_new_cb(ctx: *mut SSL_CTX, new_session_cb: SSL_CTX_new_session_cb) {
        try_clone_arc!(ctx)
            .get_mut()
            .set_session_new_cb(new_session_cb)
    }
}

pub type SSL_CTX_new_session_cb =
    Option<unsafe extern "C" fn(_ssl: *mut SSL, _sess: *mut SSL_SESSION) -> c_int>;

entry! {
    pub fn _SSL_CTX_sess_set_get_cb(ctx: *mut SSL_CTX, get_session_cb: SSL_CTX_sess_get_cb) {
        try_clone_arc!(ctx)
            .get_mut()
            .set_session_get_cb(get_session_cb)
    }
}

pub type SSL_CTX_sess_get_cb = Option<
    unsafe extern "C" fn(
        ssl: *mut SSL,
        data: *const c_uchar,
        len: c_int,
        copy: *mut c_int,
    ) -> *mut SSL_SESSION,
>;

entry! {
    pub fn _SSL_CTX_sess_set_remove_cb(
        ctx: *mut SSL_CTX,
        remove_session_cb: SSL_CTX_sess_remove_cb,
    ) {
        try_clone_arc!(ctx)
            .get_mut()
            .set_session_remove_cb(remove_session_cb)
    }
}

pub type SSL_CTX_sess_remove_cb =
    Option<unsafe extern "C" fn(ctx: *mut SSL_CTX, sess: *mut SSL_SESSION)>;

entry! {
    pub fn _SSL_CTX_get_timeout(ctx: *const SSL_CTX) -> c_long {
        try_clone_arc!(ctx).get().get_session_timeout() as c_long
    }
}

entry! {
    pub fn _SSL_CTX_set_timeout(ctx: *mut SSL_CTX, t: c_long) -> c_long {
        let t = if t < 0 { 0 } else { t as u64 };
        try_clone_arc!(ctx).get_mut().set_session_timeout(t) as c_long
    }
}

impl Castable for SSL_CTX {
    type Ownership = OwnershipArc;
    type RustType = NotThreadSafe<SSL_CTX>;
}

pub type SSL = crate::Ssl;

entry! {
    pub fn _SSL_new(ctx: *mut SSL_CTX) -> *mut SSL {
        let ctx = try_clone_arc!(ctx);

        let ssl = match crate::Ssl::new(ctx.clone(), ctx.get()).ok() {
            Some(ssl) => ssl,
            None => return ptr::null_mut(),
        };

        let out = to_arc_mut_ptr(NotThreadSafe::new(ssl));
        let ex_data = match ExData::new_ssl(out) {
            None => {
                _SSL_free(out);
                return ptr::null_mut();
            }
            Some(ex_data) => ex_data,
        };

        // safety: we just made this object, the pointer must be valid.
        clone_arc(out).unwrap().get_mut().install_ex_data(ex_data);
        out
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
    pub fn _SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX {
        Arc::as_ptr(&try_clone_arc!(ssl).get().ctx) as *mut SSL_CTX
    }
}

entry! {
    pub fn _SSL_set_ex_data(ssl: *mut SSL, idx: c_int, data: *mut c_void) -> c_int {
        match try_clone_arc!(ssl).get_mut().set_ex_data(idx, data) {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_get_ex_data(ssl: *const SSL, idx: c_int) -> *mut c_void {
        try_clone_arc!(ssl).get().get_ex_data(idx)
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
            Ok(SslCtrl::SetMinProtoVersion) => {
                if larg < 0 || larg > u16::MAX.into() {
                    return 0;
                }
                ssl.get_mut().set_min_protocol_version(larg as u16);
                C_INT_SUCCESS as c_long
            }
            Ok(SslCtrl::GetMinProtoVersion) => ssl.get().get_min_protocol_version().into(),
            Ok(SslCtrl::SetMaxProtoVersion) => {
                if larg < 0 || larg > u16::MAX.into() {
                    return 0;
                }
                ssl.get_mut().set_max_protocol_version(larg as u16);
                C_INT_SUCCESS as c_long
            }
            Ok(SslCtrl::GetMaxProtoVersion) => ssl.get().get_max_protocol_version().into(),
            Ok(SslCtrl::SetTlsExtHostname) => {
                let hostname = try_str!(parg as *const c_char);
                ssl.get_mut().set_sni_hostname(hostname) as c_long
            }
            Ok(SslCtrl::SetChain) => {
                let chain = if parg.is_null() {
                    // this is `SSL_clear_chain_certs`
                    vec![]
                } else {
                    match larg {
                        // this is `SSL_set1_chain` (incs ref)
                        1 => OwnedX509Stack::new_copy(parg as *mut stack_st_X509).to_rustls(),
                        // this is `SSL_set0_chain` (retain ref)
                        _ => OwnedX509Stack::new(parg as *mut stack_st_X509).to_rustls(),
                    }
                };

                ssl.get_mut().stage_certificate_chain(chain);
                C_INT_SUCCESS as i64
            }
            // not a defined operation in the OpenSSL API
            Ok(SslCtrl::SetTlsExtServerNameCallback)
            | Ok(SslCtrl::SetTlsExtServerNameArg)
            | Ok(SslCtrl::SetSessCacheSize)
            | Ok(SslCtrl::GetSessCacheSize)
            | Ok(SslCtrl::SetSessCacheMode) => 0,
            Err(()) => {
                log::warn!("unimplemented _SSL_ctrl(..., {cmd}, {larg}, ...)");
                0
            }
        }
    }
}

entry! {
    pub fn _SSL_get_options(ssl: *const SSL) -> u64 {
        try_clone_arc!(ssl).get().get_options()
    }
}

entry! {
    pub fn _SSL_clear_options(ssl: *mut SSL, op: u64) -> u64 {
        try_clone_arc!(ssl).get_mut().clear_options(op)
    }
}

entry! {
    pub fn _SSL_set_options(ssl: *mut SSL, op: u64) -> u64 {
        try_clone_arc!(ssl).get_mut().set_options(op)
    }
}

entry! {
    pub fn _SSL_set_num_tickets(ssl: *mut SSL, num_tickets: usize) -> c_int {
        try_clone_arc!(ssl).get_mut().set_num_tickets(num_tickets);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_get_num_tickets(ssl: *const SSL) -> usize {
        try_clone_arc!(ssl).get().get_num_tickets()
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

        ssl.get_mut().set_alpn_offer(alpn);
        MysteriouslyOppositeReturnValue::Success
    }
}

entry! {
    pub fn _SSL_set_connect_state(ssl: *mut SSL) {
        try_clone_arc!(ssl).get_mut().set_client_mode()
    }
}

entry! {
    pub fn _SSL_set_accept_state(ssl: *mut SSL) {
        try_clone_arc!(ssl).get_mut().set_server_mode()
    }
}

entry! {
    pub fn _SSL_is_server(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl).get().is_server() as c_int
    }
}

entry! {
    pub fn _SSL_set1_host(ssl: *mut SSL, hostname: *const c_char) -> c_int {
        let maybe_hostname = str_from_cstring(hostname);
        try_clone_arc!(ssl)
            .get_mut()
            .set_verify_hostname(maybe_hostname) as c_int
    }
}

entry! {
    pub fn _SSL_set_fd(ssl: *mut SSL, fd: c_int) -> c_int {
        let bio = Bio::new_fd_no_close(fd);
        try_clone_arc!(ssl).get_mut().set_bio(bio);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO) {
        try_clone_arc!(ssl)
            .get_mut()
            .set_bio_pair(Some(rbio), Some(wbio));
    }
}

entry! {
    pub fn _SSL_set0_rbio(ssl: *mut SSL, rbio: *mut BIO) {
        let ssl = try_clone_arc!(ssl);
        if rbio.is_null() {
            return;
        }
        ssl.get_mut().set_bio_pair(Some(rbio), None);
    }
}

entry! {
    pub fn _SSL_set0_wbio(ssl: *mut SSL, wbio: *mut BIO) {
        let ssl = try_clone_arc!(ssl);
        if wbio.is_null() {
            return;
        }
        ssl.get_mut().set_bio_pair(None, Some(wbio));
    }
}

entry! {
    pub fn _SSL_get_rbio(ssl: *const SSL) -> *mut BIO {
        try_clone_arc!(ssl).get().get_rbio()
    }
}

entry! {
    pub fn _SSL_get_wbio(ssl: *const SSL) -> *mut BIO {
        try_clone_arc!(ssl).get().get_wbio()
    }
}

entry! {
    pub fn _SSL_connect(ssl: *mut SSL) -> c_int {
        match try_clone_arc!(ssl).get_mut().connect() {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_accept(ssl: *mut SSL) -> c_int {
        let _callbacks = SslCallbackContext::new(ssl);
        match try_clone_arc!(ssl).get_mut().accept() {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_do_handshake(ssl: *mut SSL) -> c_int {
        let _callbacks = SslCallbackContext::new(ssl);
        let ssl = try_clone_arc!(ssl);

        match ssl.get_mut().handshake() {
            Err(e) => e.raise().into(),
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

        match ssl.get_mut().write(slice) {
            Err(e) => {
                e.raise();
                ERROR
            }
            Ok(written) => written as c_int,
        }
    }
}

entry! {
    pub fn _SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int {
        const ERROR: c_int = 0;
        let ssl = try_clone_arc!(ssl, ERROR);
        let slice = try_mut_slice_int!(buf as *mut u8, num, ERROR);

        match ssl.get_mut().read(slice) {
            Err(e) => {
                e.raise();
                ERROR
            }
            Ok(read) => read as c_int,
        }
    }
}

entry! {
    pub fn _SSL_want(ssl: *const SSL) -> c_int {
        let want = try_clone_arc!(ssl).get().want();

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
        match try_clone_arc!(ssl, ERROR).get_mut().try_shutdown() {
            Err(e) => {
                e.raise();
                ERROR
            }
            Ok(result) => match result {
                ShutdownResult::Sent => 0 as c_int,
                ShutdownResult::Received => 1 as c_int,
            },
        }
    }
}

entry! {
    pub fn _SSL_get_shutdown(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl).get().get_shutdown()
    }
}

entry! {
    pub fn _SSL_set_shutdown(ssl: *mut SSL, flags: c_int) {
        try_clone_arc!(ssl).get_mut().set_shutdown(flags)
    }
}

entry! {
    pub fn _SSL_set_quiet_shutdown(ssl: *mut SSL, mode: c_int) {
        try_clone_arc!(ssl).get_mut().set_quiet_shutdown(mode != 0)
    }
}

entry! {
    pub fn _SSL_pending(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl).get_mut().get_pending_plaintext() as c_int
    }
}

entry! {
    pub fn _SSL_has_pending(ssl: *const SSL) -> c_int {
        (_SSL_pending(ssl) > 0) as c_int
    }
}

entry! {
    pub fn _SSL_get_error(ssl: *const SSL, _ret_code: c_int) -> c_int {
        try_clone_arc!(ssl).get_mut().get_error() as c_int
    }
}

entry! {
    pub fn _SSL_get0_alpn_selected(ssl: *const SSL, data: *mut *const c_uchar, len: *mut c_uint) {
        if data.is_null() || len.is_null() {
            return;
        }

        match try_clone_arc!(ssl).get().get_agreed_alpn() {
            Some(slice) => unsafe {
                // nb. alpn protocols are limited to 255 octets
                ptr::write(len, slice.len() as u32);
                ptr::write(data, slice.as_ptr());
            },
            None => unsafe {
                ptr::write(len, 0);
                ptr::write(data, ptr::null());
            },
        }
    }
}

entry! {
    pub fn _SSL_get_peer_cert_chain(ssl: *const SSL) -> *mut stack_st_X509 {
        try_clone_arc!(ssl)
            .get_mut()
            .get_peer_cert_chain()
            .map(|x509| x509.pointer())
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_get_peer_signature_type_nid(ssl: *const SSL, psigtype_nid: *mut c_int) -> c_int {
        if psigtype_nid.is_null() {
            return 0;
        }

        let sigalg_nid = try_clone_arc!(ssl)
            .get()
            .get_last_verification_sig_scheme()
            .and_then(sig_scheme_to_nid);

        match sigalg_nid {
            Some(nid) => {
                unsafe { ptr::write(psigtype_nid, nid) };
                C_INT_SUCCESS
            }
            None => 0,
        }
    }
}

entry! {
    pub fn _SSL_get0_verified_chain(ssl: *const SSL) -> *mut stack_st_X509 {
        _SSL_get_peer_cert_chain(ssl)
    }
}

entry! {
    pub fn _SSL_get0_peer_certificate(ssl: *const SSL) -> *mut X509 {
        try_clone_arc!(ssl)
            .get_mut()
            .get_peer_cert()
            .map(|x509| x509.borrow_ref())
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_get1_peer_certificate(ssl: *const SSL) -> *mut X509 {
        try_clone_arc!(ssl)
            .get_mut()
            .get_peer_cert()
            .map(|x509| x509.up_ref())
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER {
        try_clone_arc!(ssl)
            .get()
            .get_negotiated_cipher_suite_id()
            .and_then(crate::SslCipher::find_by_id)
            .map(|cipher| cipher as *const SSL_CIPHER)
            .unwrap_or_else(ptr::null)
    }
}

entry! {
    pub fn _SSL_get_version(ssl: *const SSL) -> *const c_char {
        try_clone_arc!(ssl)
            .get()
            .get_negotiated_cipher_suite_id()
            .and_then(crate::SslCipher::find_by_id)
            .map(|cipher| cipher.version.as_ptr())
            .unwrap_or_else(ptr::null)
    }
}

entry! {
    pub fn _SSL_version(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl)
            .get()
            .conn()
            .and_then(|conn| {
                conn.protocol_version()
                    .map(|proto| u16::from(proto) as c_int)
            })
            .unwrap_or_default()
    }
}

entry! {
    pub fn _SSL_get_verify_result(ssl: *const SSL) -> c_long {
        try_clone_arc!(ssl).get().get_last_verification_result()
    }
}

entry! {
    pub fn _SSL_get_certificate(ssl: *const SSL) -> *mut X509 {
        try_clone_arc!(ssl).get().get_certificate()
    }
}

entry! {
    pub fn _SSL_get_privatekey(ssl: *const SSL) -> *mut EVP_PKEY {
        try_clone_arc!(ssl).get().get_privatekey()
    }
}

entry! {
    // nb. 0 is a reasonable OSSL_HANDSHAKE_STATE, it is OSSL_HANDSHAKE_STATE_TLS_ST_BEFORE
    pub fn _SSL_get_state(ssl: *const SSL) -> c_uint {
        try_clone_arc!(ssl).get_mut().handshake_state().into()
    }
}

entry! {
    pub fn _SSL_in_init(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl).get_mut().handshake_state().in_init() as c_int
    }
}

entry! {
    pub fn _SSL_in_before(ssl: *const SSL) -> c_int {
        (try_clone_arc!(ssl).get_mut().handshake_state() == HandshakeState::Before) as c_int
    }
}

entry! {
    pub fn _SSL_is_init_finished(ssl: *const SSL) -> c_int {
        (try_clone_arc!(ssl).get_mut().handshake_state() == HandshakeState::Finished) as c_int
    }
}

entry! {
    pub fn _SSL_set_SSL_CTX(ssl: *mut SSL, ctx_ptr: *mut SSL_CTX) -> *mut SSL_CTX {
        let ctx = try_clone_arc!(ctx_ptr);
        try_clone_arc!(ssl).get_mut().set_ctx(ctx);
        ctx_ptr
    }
}

entry! {
    pub fn _SSL_use_certificate(ssl: *mut SSL, x: *mut X509) -> c_int {
        let ssl = try_clone_arc!(ssl);

        if x.is_null() {
            return Error::null_pointer().raise().into();
        }

        let x509 = OwnedX509::new_incref(x);
        let ee = CertificateDer::from(x509.der_bytes());

        ssl.get_mut().stage_certificate_end_entity(ee);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_use_PrivateKey(ssl: *mut SSL, pkey: *mut EVP_PKEY) -> c_int {
        let ssl = try_clone_arc!(ssl);

        if pkey.is_null() {
            return Error::null_pointer().raise().into();
        }

        let pkey = EvpPkey::new_incref(pkey);

        match ssl.get_mut().commit_private_key(pkey) {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_use_PrivateKey_file(
        ssl: *mut SSL,
        file_name: *const c_char,
        file_type: c_int,
    ) -> c_int {
        let ssl = try_clone_arc!(ssl);
        let file_name = try_str!(file_name);

        let key = match use_private_key_file(file_name, file_type) {
            Ok(key) => key,
            Err(err) => {
                return err.raise().into();
            }
        };

        match ssl.get_mut().commit_private_key(key) {
            Err(e) => e.raise().into(),
            Ok(()) => C_INT_SUCCESS,
        }
    }
}

entry! {
    pub fn _SSL_check_private_key(_ssl: *const SSL) -> c_int {
        log::trace!("not implemented: _SSL_check_private_key, returning success");
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_get_servername(ssl: *const SSL, ty: c_int) -> *const c_char {
        if ty != TLSEXT_NAMETYPE_host_name {
            return ptr::null();
        }

        try_clone_arc!(ssl).get_mut().server_name_pointer()
    }
}

entry! {
    pub fn _SSL_get_servername_type(ssl: *const SSL) -> c_int {
        if _SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name).is_null() {
            -1
        } else {
            TLSEXT_NAMETYPE_host_name
        }
    }
}

entry! {
    pub fn _SSL_set_verify(ssl: *mut SSL, mode: c_int, callback: SSL_verify_cb) {
        let ssl = try_clone_arc!(ssl);

        if callback.is_some() {
            // supporting verify callbacks would mean we need to fully use
            // the openssl certificate verifier, because X509_STORE and
            // X509_STORE_CTX are both in libcrypto.
            return Error::not_supported("verify callback").raise().into();
        }

        ssl.get_mut().set_verify(crate::VerifyMode::from(mode));
    }
}

entry! {
    pub fn _SSL_get_verify_mode(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl).get().get_verify_mode().into()
    }
}

entry! {
    pub fn _SSL_set_verify_depth(ssl: *mut SSL, depth: c_int) {
        try_clone_arc!(ssl).get_mut().set_verify_depth(depth)
    }
}

entry! {
    pub fn _SSL_get_verify_depth(ssl: *mut SSL) -> c_int {
        try_clone_arc!(ssl).get().get_verify_depth()
    }
}

entry! {
    pub fn _SSL_get_current_compression(_ssl: *const SSL) -> *const c_void {
        ptr::null()
    }
}

entry! {
    pub fn _SSL_session_reused(ssl: *const SSL) -> c_int {
        try_clone_arc!(ssl).get().was_session_reused() as c_int
    }
}

entry! {
    pub fn _SSL_get1_session(ssl: *mut SSL) -> *mut SSL_SESSION {
        try_clone_arc!(ssl)
            .get()
            .get_current_session()
            .map(|sess| Arc::into_raw(sess) as *mut SSL_SESSION)
            .unwrap_or_else(ptr::null_mut)
    }
}

entry! {
    pub fn _SSL_get_session(ssl: *const SSL) -> *mut SSL_SESSION {
        try_clone_arc!(ssl).get().borrow_current_session()
    }
}

impl Castable for SSL {
    type Ownership = OwnershipArc;
    type RustType = NotThreadSafe<SSL>;
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
        let bits = try_ref_from_ptr!(cipher).bits as c_int;
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
        try_ref_from_ptr!(cipher).openssl_id()
    }
}

entry! {
    pub fn _SSL_CIPHER_get_protocol_id(cipher: *const SSL_CIPHER) -> u16 {
        try_ref_from_ptr!(cipher).protocol_id()
    }
}

entry! {
    pub fn _SSL_CIPHER_description(
        cipher: *const SSL_CIPHER,
        mut buf: *mut c_char,
        mut size: c_int,
    ) -> *mut c_char {
        let description = try_ref_from_ptr!(cipher).description;
        let required_len = description.to_bytes_with_nul().len();

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
            ptr::copy_nonoverlapping(description.as_ptr(), buf, required_len as usize);
        };
        buf
    }
}

impl Castable for SSL_CIPHER {
    type Ownership = OwnershipRef;
    type RustType = SSL_CIPHER;
}

entry! {
    pub fn _SSL_select_next_proto(
        out: *mut *mut c_uchar,
        out_len: *mut c_uchar,
        server: *const c_uchar,
        server_len: c_uint,
        client: *const c_uchar,
        client_len: c_uint,
    ) -> c_int {
        let server = try_slice!(server, server_len);
        let client = try_slice!(client, client_len);

        if out.is_null() || out_len.is_null() {
            return 0;
        }

        // ensure `out` and `out_len` are written even on error.
        unsafe {
            ptr::write(out, ptr::null_mut());
            ptr::write(out_len, 0);
        }

        // ensure `client` is fully validated irrespective of `server` value
        for offer in crate::iter_alpn(client) {
            if offer.is_none() {
                return OPENSSL_NPN_NO_OVERLAP;
            }
        }

        for supported in crate::iter_alpn(server) {
            match supported {
                None => {
                    return OPENSSL_NPN_NO_OVERLAP;
                }

                Some(supported)
                    if crate::iter_alpn(client).any(|offer| offer == Some(supported)) =>
                {
                    unsafe {
                        // safety:
                        // 1) the openssl API is const-incorrect, we must slice the const from `supported`
                        // 2) supported.len() must fit inside c_uchar; it was decoded from that
                        ptr::write(out, supported.as_ptr() as *mut c_uchar);
                        ptr::write(out_len, supported.len() as c_uchar);
                        return OPENSSL_NPN_NEGOTIATED;
                    }
                }

                Some(_) => {
                    continue;
                }
            }
        }

        // fallback: "If no match is found, the first item in client, client_len is returned"
        if let Some(Some(fallback)) = crate::iter_alpn(client).next() {
            unsafe {
                ptr::write(out, fallback.as_ptr() as *mut c_uchar);
                ptr::write(out_len, fallback.len() as c_uchar);
            }
        }
        OPENSSL_NPN_NO_OVERLAP
    }
}

pub type SSL_SESSION = crate::SslSession;

entry! {
    pub fn _SSL_SESSION_get_id(sess: *const SSL_SESSION, len: *mut c_uint) -> *const c_uchar {
        if len.is_null() {
            return ptr::null();
        }

        let sess = try_clone_arc!(sess);
        let id = sess.get().get_id();
        unsafe { *len = id.len() as c_uint };
        id.as_ptr()
    }
}

entry! {
    pub fn _SSL_SESSION_up_ref(sess: *mut SSL_SESSION) -> c_int {
        let sess = try_clone_arc!(sess);
        mem::forget(sess.clone());
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_SESSION_set_time(sess: *mut SSL_SESSION, time: c_long) -> c_long {
        if time < 0 {
            return 0;
        }
        try_clone_arc!(sess)
            .get_mut()
            .set_creation_time(time as u64);
        C_INT_SUCCESS as c_long
    }
}

entry! {
    pub fn _SSL_SESSION_get_time(sess: *const SSL_SESSION) -> c_long {
        try_clone_arc!(sess).get().get_creation_time() as c_long
    }
}

entry! {
    pub fn _SSL_SESSION_set_timeout(sess: *mut SSL_SESSION, time_out: c_long) -> c_long {
        if time_out < 0 {
            return 0;
        }
        try_clone_arc!(sess).get_mut().set_time_out(time_out as u64);
        C_INT_SUCCESS as c_long
    }
}

entry! {
    pub fn _SSL_SESSION_get_timeout(sess: *const SSL_SESSION) -> c_long {
        try_clone_arc!(sess).get().get_time_out() as c_long
    }
}

entry! {
    pub fn _SSL_SESSION_set1_id_context(
        sess: *mut SSL_SESSION,
        sid_ctx: *const c_uchar,
        sid_ctx_len: c_uint,
    ) -> c_int {
        let slice = try_slice!(sid_ctx, sid_ctx_len);
        if slice.len() > SSL_MAX_SID_CTX_LENGTH {
            return Error::not_supported("excess sid_ctx_len").raise().into();
        }
        try_clone_arc!(sess).get_mut().set_context(slice);
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _d2i_SSL_SESSION(
        a: *mut *mut SSL_SESSION,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut SSL_SESSION {
        if !a.is_null() {
            return Error::not_supported("d2i_SSL_SESSION with a != NULL")
                .raise()
                .into();
        }

        if pp.is_null() {
            return Error::bad_data("d2i_SSL_SESSION with pp == NULL")
                .raise()
                .into();
        }

        let ptr = unsafe { ptr::read(pp) };
        let slice = try_slice!(ptr, length);

        let (sess, rest) = match SSL_SESSION::decode(slice) {
            Some(r) => r,
            None => {
                return Error::bad_data("cannot decode SSL_SESSION").raise().into();
            }
        };
        let consumed_bytes = slice.len() - rest.len();

        // move along *pp
        unsafe { ptr::write(pp, ptr.add(consumed_bytes)) };
        to_arc_mut_ptr(NotThreadSafe::new(sess))
    }
}

entry! {
    pub fn _i2d_SSL_SESSION(sess: *const SSL_SESSION, pp: *mut *mut c_uchar) -> c_int {
        let sess = try_clone_arc!(sess);
        let encoded = sess.get().encode();

        if !pp.is_null() {
            let ptr = unsafe { ptr::read(pp) };
            unsafe {
                ptr::copy_nonoverlapping(encoded.as_ptr(), ptr, encoded.len());
                ptr::write(pp, ptr.add(encoded.len()));
            }
        }
        encoded.len() as c_int
    }
}

entry! {
    pub fn _SSL_SESSION_free(sess: *mut SSL_SESSION) {
        free_arc(sess);
    }
}

impl Castable for SSL_SESSION {
    type Ownership = OwnershipArc;
    type RustType = NotThreadSafe<SSL_SESSION>;
}

entry! {
    pub fn _SSL_CONF_CTX_new() -> *mut SSL_CONF_CTX {
        to_boxed_mut_ptr(NotThreadSafe::new(conf::SslConfigCtx::new()))
    }
}

entry! {
    pub fn _SSL_CONF_CTX_free(cctx: *mut SSL_CONF_CTX) {
        free_box(cctx);
    }
}

entry! {
    pub fn _SSL_CONF_CTX_finish(cctx: *mut SSL_CONF_CTX) -> c_int {
        match try_ref_from_ptr!(cctx).get_mut().finish() {
            true => C_INT_SUCCESS,
            false => 0,
        }
    }
}

entry! {
    pub fn _SSL_CONF_CTX_set_flags(cctx: *mut SSL_CONF_CTX, flags: c_uint) -> c_uint {
        try_ref_from_ptr!(cctx).get_mut().set_flags(flags).into()
    }
}

entry! {
    pub fn _SSL_CONF_CTX_clear_flags(cctx: *mut SSL_CONF_CTX, flags: c_uint) -> c_uint {
        try_ref_from_ptr!(cctx).get_mut().clear_flags(flags).into()
    }
}

entry! {
    pub fn _SSL_CONF_CTX_set1_prefix(cctx: *mut SSL_CONF_CTX, prefix: *mut c_char) -> c_int {
        try_ref_from_ptr!(cctx)
            .get_mut()
            .set_prefix(try_str!(prefix));
        C_INT_SUCCESS
    }
}

entry! {
    pub fn _SSL_CONF_cmd(cctx: *mut SSL_CONF_CTX, cmd: *mut c_char, value: *mut c_char) -> c_int {
        // Note: we use string_from_cstring here instead of try_str! because some commands
        //       may allow NULL as a value.
        let value = string_from_cstring(value);
        try_ref_from_ptr!(cctx)
            .get_mut()
            .cmd(try_str!(cmd), value.as_deref())
    }
}

entry! {
    pub fn _SSL_CONF_cmd_value_type(cctx: *mut SSL_CONF_CTX, cmd: *mut c_char) -> c_int {
        try_ref_from_ptr!(cctx)
            .get()
            .cmd_value_type(try_str!(cmd))
            .into()
    }
}

entry! {
    pub fn _SSL_CONF_CTX_set_ssl(cctx: *mut SSL_CONF_CTX, ssl: *mut SSL) {
        let cctx = try_ref_from_ptr!(cctx).get_mut();
        match ssl.is_null() {
            true => cctx.validation_only(),
            false => cctx.apply_to_ssl(try_clone_arc!(ssl)),
        }
    }
}

entry! {
    pub fn _SSL_CONF_CTX_set_ssl_ctx(cctx: *mut SSL_CONF_CTX, ctx: *mut SSL_CTX) {
        let cctx = try_ref_from_ptr!(cctx).get_mut();
        match ctx.is_null() {
            true => cctx.validation_only(),
            false => cctx.apply_to_ctx(try_clone_arc!(ctx)),
        }
    }
}

pub type SSL_CONF_CTX = conf::SslConfigCtx;

impl Castable for SSL_CONF_CTX {
    type Ownership = OwnershipBox; // SSL_CONF_CTX does not do reference counting.
    type RustType = NotThreadSafe<conf::SslConfigCtx>;
}

/// Normal OpenSSL return value convention success indicator.
///
/// Compare [`crate::ffi::MysteriouslyOppositeReturnValue`].
const C_INT_SUCCESS: c_int = 1;

pub(crate) const FILETYPE_PEM: c_int = 1;
const FILETYPE_DER: c_int = 2;

const SSL_MAX_SID_CTX_LENGTH: usize = 32;

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
        SetSessCacheSize = 42,
        GetSessCacheSize = 43,
        SetSessCacheMode = 44,
        SetTlsExtServerNameCallback = 53,
        SetTlsExtServerNameArg = 54,
        SetTlsExtHostname = 55,
        SetChain = 88,
        SetMinProtoVersion = 123,
        SetMaxProtoVersion = 124,
        GetMinProtoVersion = 130,
        GetMaxProtoVersion = 131,
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
    pub fn _SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
}

entry_stub! {
    pub fn _SSL_set_session(_ssl: *mut SSL, _session: *mut SSL_SESSION) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_remove_session(_ssl: *const SSL, _session: *mut SSL_SESSION) -> c_int;
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

entry_stub! {
    pub fn _SSL_write_early_data(
        _ssl: *mut SSL,
        _buf: *const c_void,
        _num: usize,
        _written: *mut usize,
    ) -> c_int;
}

entry_stub! {
    pub fn _SSL_read_early_data(
        _ssl: *mut SSL,
        _buf: *mut c_void,
        _num: usize,
        _readbytes: *mut usize,
    ) -> c_int;
}

entry_stub! {
    pub fn _SSL_CTX_get_client_CA_list(_ctx: *const SSL_CTX) -> *mut stack_st_X509_NAME;
}

entry_stub! {
    pub fn _SSL_CTX_set_client_CA_list(_ctx: *mut SSL_CTX, _name_list: *mut stack_st_X509_NAME);
}

entry_stub! {
    pub fn _SSL_load_client_CA_file(_file: *const c_char) -> *mut stack_st_X509_NAME;
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

// no state machine observation

entry_stub! {
    pub fn _SSL_CTX_set_info_callback(
        _ctx: *mut SSL_CTX,
        _cb: Option<unsafe extern "C" fn(ssl: *const SSL, type_: c_int, val: c_int)>,
    );
}

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

entry_stub! {
    pub fn _SSL_get0_next_proto_negotiated(
        _ssl: *const SSL,
        _data: *mut *const c_uchar,
        _len: *mut c_uint,
    );
}

entry_stub! {
    pub fn _SSL_CTX_set_next_protos_advertised_cb(
        _ctx: *mut SSL_CTX,
        _cb: SSL_CTX_npn_advertised_cb_func,
        _arg: *mut c_void,
    );
}

pub type SSL_CTX_npn_advertised_cb_func = Option<
    unsafe extern "C" fn(
        ssl: *mut SSL,
        out: *mut *const c_uchar,
        outlen: *mut c_uint,
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

// No kTLS/sendfile support

entry_stub! {
    pub fn _SSL_sendfile(
        _ssl: *mut SSL,
        _fd: c_int,
        _offset: c_long,
        _size: usize,
        _flags: c_int,
    ) -> c_long;
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

    #[test]
    fn test_SSL_select_next_proto_match() {
        let mut output = ptr::null_mut();
        let mut output_len = 0u8;
        let client = b"\x05hello\x05world";
        let server = b"\x05uhoh!\x05world";
        assert_eq!(
            _SSL_select_next_proto(
                &mut output as *mut *mut u8,
                &mut output_len as *mut u8,
                server.as_ptr(),
                server.len() as c_uint,
                client.as_ptr(),
                client.len() as c_uint
            ),
            1i32
        );
        assert_eq!(b"world", &server[7..]);
        assert_eq!(output as *const u8, server[7..].as_ptr());
        assert_eq!(output_len, 5);
    }

    #[test]
    fn test_SSL_select_next_proto_no_overlap() {
        let mut output = ptr::null_mut();
        let mut output_len = 0u8;
        let client = b"\x05hello\x05world";
        let server = b"\x05uhoh!\x05what!";
        assert_eq!(
            _SSL_select_next_proto(
                &mut output as *mut *mut u8,
                &mut output_len as *mut u8,
                server.as_ptr(),
                server.len() as c_uint,
                client.as_ptr(),
                client.len() as c_uint
            ),
            2i32
        );
        assert_eq!(b"hello", &client[1..6]);
        assert_eq!(output as *const u8, client[1..].as_ptr());
        assert_eq!(output_len, 5);
    }

    #[test]
    fn test_SSL_select_next_proto_illegal_client() {
        let mut output = ptr::null_mut();
        let mut output_len = 0u8;
        let client = b"\x09hello";
        let server = b"\x05uhoh!\x05world";
        assert_eq!(
            _SSL_select_next_proto(
                &mut output as *mut *mut u8,
                &mut output_len as *mut u8,
                server.as_ptr(),
                server.len() as c_uint,
                client.as_ptr(),
                client.len() as c_uint
            ),
            2i32
        );
        assert_eq!(output as *const u8, ptr::null_mut());
    }

    #[test]
    fn test_SSL_select_next_proto_null() {
        let mut output = ptr::null_mut();
        let mut output_len = 0u8;
        let client = b"\x05hello\x05world";
        let server = b"\x05uhoh!\x05world";

        assert_eq!(
            _SSL_select_next_proto(
                ptr::null_mut(),
                &mut output_len as *mut u8,
                server.as_ptr(),
                server.len() as c_uint,
                client.as_ptr(),
                client.len() as c_uint
            ),
            0
        );

        assert_eq!(
            _SSL_select_next_proto(
                &mut output as *mut *mut u8,
                ptr::null_mut(),
                server.as_ptr(),
                server.len() as c_uint,
                client.as_ptr(),
                client.len() as c_uint
            ),
            0
        );

        assert_eq!(
            _SSL_select_next_proto(
                &mut output as *mut *mut u8,
                &mut output_len as *mut u8,
                ptr::null(),
                server.len() as c_uint,
                client.as_ptr(),
                client.len() as c_uint
            ),
            0
        );

        assert_eq!(
            _SSL_select_next_proto(
                &mut output as *mut *mut u8,
                &mut output_len as *mut u8,
                server.as_ptr(),
                server.len() as c_uint,
                ptr::null(),
                client.len() as c_uint
            ),
            0
        );
    }

    #[test]
    fn test_SSL_SESSION_roundtrip() {
        let sess = crate::SslSession::new(
            vec![1; 32],
            vec![2; 32],
            vec![3; 128],
            crate::cache::TimeBase(123),
            300,
        );
        let sess_ptr = to_arc_mut_ptr(NotThreadSafe::new(sess));

        let mut buffer = [0u8; 1024];
        let mut ptr = buffer.as_mut_ptr();
        let len = _i2d_SSL_SESSION(sess_ptr, &mut ptr);

        println!("encoding: {:?}", &buffer[..len as usize]);

        let mut ptr = buffer.as_ptr();
        let new_sess = _d2i_SSL_SESSION(ptr::null_mut(), &mut ptr, buffer.len() as c_long);
        assert!(!new_sess.is_null());
        assert_eq!(len as usize, (ptr as usize) - (buffer.as_ptr() as usize));

        _SSL_SESSION_free(new_sess);
        _SSL_SESSION_free(sess_ptr);
    }
}
