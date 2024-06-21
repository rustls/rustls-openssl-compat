use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::{borrow, cmp, fmt, mem, ptr};
use std::ffi::CString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use openssl_probe::ProbeResult;
use openssl_sys::{
    EVP_PKEY, SSL_ERROR_NONE, SSL_ERROR_SSL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, X509,
    X509_STORE, X509_V_ERR_UNSPECIFIED,
};
use rustls::client::Resumption;
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{Accepted, Acceptor};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, Connection, HandshakeKind, ProtocolVersion,
    RootCertStore, ServerConfig, SignatureScheme, SupportedProtocolVersion,
};

use not_thread_safe::NotThreadSafe;
use x509::OwnedX509Store;

mod bio;
mod cache;
mod callbacks;
#[macro_use]
mod constants;
#[allow(
    // relax naming convention lints for openssl API
    non_camel_case_types,
    non_snake_case,
    clippy::upper_case_acronyms,
    // false positives on extern entrypoints
    dead_code,
)]
mod entry;
mod error;
mod evp_pkey;
mod ex_data;
#[macro_use]
#[allow(unused_macros, dead_code, unused_imports)]
mod ffi;
mod conf;
#[cfg(miri)]
#[allow(non_camel_case_types, dead_code)]
mod miri;
mod not_thread_safe;
mod sign;
mod verifier;
mod x509;

/// `SSL_METHOD` underlying type.
///
/// # Lifetime
/// Functions that return SSL_METHOD, like `TLS_method()`, give static-lifetime pointers.
pub struct SslMethod {
    client_versions: &'static [&'static SupportedProtocolVersion],
    server_versions: &'static [&'static SupportedProtocolVersion],
}

impl SslMethod {
    fn mode(&self) -> ConnMode {
        match (
            self.client_versions.is_empty(),
            self.server_versions.is_empty(),
        ) {
            (true, false) => ConnMode::Server,
            (false, true) => ConnMode::Client,
            (_, _) => ConnMode::Unknown,
        }
    }
}

static TLS_CLIENT_METHOD: SslMethod = SslMethod {
    client_versions: rustls::ALL_VERSIONS,
    server_versions: &[],
};
static TLS_SERVER_METHOD: SslMethod = SslMethod {
    client_versions: &[],
    server_versions: rustls::ALL_VERSIONS,
};
static TLS_METHOD: SslMethod = SslMethod {
    client_versions: rustls::ALL_VERSIONS,
    server_versions: rustls::ALL_VERSIONS,
};

/// `SSL_CIPHER` underlying type.
///
/// # Lifetime
/// Functions that return `SSL_CIPHER` give static-lifetime pointers.
pub struct SslCipher {
    pub bits: usize,
    pub openssl_name: &'static CStr,
    pub standard_name: &'static CStr,
    pub version: &'static CStr,
    pub description: &'static CStr,
    rustls: &'static rustls::SupportedCipherSuite,
}

impl SslCipher {
    pub fn find_by_id(id: CipherSuite) -> Option<&'static SslCipher> {
        match id {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                Some(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                Some(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                Some(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                Some(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                Some(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                Some(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
            }
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Some(&TLS13_AES_128_GCM_SHA256),
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Some(&TLS13_AES_256_GCM_SHA384),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Some(&TLS13_CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    pub fn protocol_id(&self) -> u16 {
        u16::from(self.rustls.suite())
    }

    pub fn openssl_id(&self) -> u32 {
        0x03000000u32 | (self.protocol_id() as u32)
    }
}

static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    bits: 128,
    openssl_name: c"ECDHE-ECDSA-AES128-GCM-SHA256",
    standard_name: c"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    version: c"TLSv1.2",
    description: c"ECDHE-ECDSA-AES128-GCM-SHA256  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128)            Mac=AEAD\n",
};

static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    bits: 256,
    openssl_name: c"ECDHE-ECDSA-AES256-GCM-SHA384",
    standard_name: c"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    version: c"TLSv1.2",
    description: c"ECDHE-ECDSA-AES256-GCM-SHA384  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256)            Mac=AEAD\n",
};

static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    bits: 256,
    openssl_name: c"ECDHE-ECDSA-CHACHA20-POLY1305",
    standard_name: c"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    version: c"TLSv1.2",
    description: c"ECDHE-ECDSA-CHACHA20-POLY1305  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=CHACHA20/POLY1305(256) Mac=AEAD\n",
};

static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    bits: 128,
    openssl_name: c"ECDHE-RSA-AES128-GCM-SHA256",
    standard_name: c"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    version: c"TLSv1.2",
    description: c"ECDHE-RSA-AES128-GCM-SHA256    TLSv1.2 Kx=ECDH     Au=RSA   Enc=AESGCM(128)            Mac=AEAD\n",
};

static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    bits: 256,
    openssl_name: c"ECDHE-RSA-AES256-GCM-SHA384",
    standard_name: c"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    version: c"TLSv1.2",
    description: c"ECDHE-RSA-AES256-GCM-SHA384    TLSv1.2 Kx=ECDH     Au=RSA   Enc=AESGCM(256)            Mac=AEAD\n",
};

static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    bits: 256,
    openssl_name: c"ECDHE-RSA-CHACHA20-POLY1305",
    standard_name: c"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    version: c"TLSv1.2",
    description: c"ECDHE-RSA-CHACHA20-POLY1305    TLSv1.2 Kx=ECDH     Au=RSA   Enc=CHACHA20/POLY1305(256) Mac=AEAD\n",
};

static TLS13_AES_128_GCM_SHA256: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
    bits: 128,
    openssl_name: c"TLS_AES_128_GCM_SHA256",
    standard_name: c"TLS_AES_128_GCM_SHA256",
    version: c"TLSv1.3",
    description: c"TLS_AES_128_GCM_SHA256         TLSv1.3 Kx=any      Au=any   Enc=AESGCM(128)            Mac=AEAD\n",
};

static TLS13_AES_256_GCM_SHA384: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
    bits: 256,
    openssl_name: c"TLS_AES_256_GCM_SHA384",
    standard_name: c"TLS_AES_256_GCM_SHA384",
    version: c"TLSv1.3",
    description: c"TLS_AES_256_GCM_SHA384         TLSv1.3 Kx=any      Au=any   Enc=AESGCM(256)            Mac=AEAD\n",
};

static TLS13_CHACHA20_POLY1305_SHA256: SslCipher = SslCipher {
    rustls: &provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    bits: 256,
    openssl_name: c"TLS_CHACHA20_POLY1305_SHA256",
    standard_name: c"TLS_CHACHA20_POLY1305_SHA256",
    version: c"TLSv1.3",
    description: c"TLS_CHACHA20_POLY1305_SHA256   TLSv1.3 Kx=any      Au=any   Enc=CHACHA20/POLY1305(256) Mac=AEAD\n",
};

/// Backs a server-side SSL_SESSION object
///
/// Note that this has equality and ordering entirely based on the `id` field.
pub struct SslSession {
    id: SslSessionLookup,
    value: Vec<u8>,
    context: Vec<u8>,
    creation_time: cache::TimeBase,
    time_out: u64,
}

impl SslSession {
    /// A magic number for the start of SslSession encodings.
    ///
    /// Aims to avoid confusion with other SSL_SESSION encodings (eg, from openssl).
    /// We are not compatible with these.
    const MAGIC: &'static [u8] = b"rustlsv1";

    pub fn new(
        id: Vec<u8>,
        value: Vec<u8>,
        context: Vec<u8>,
        creation_time: cache::TimeBase,
        time_out: u64,
    ) -> Self {
        Self {
            id: SslSessionLookup(id),
            value,
            context,
            creation_time,
            time_out,
        }
    }

    /// Encode this session to an opaque binary format.
    ///
    /// This could be DER (OpenSSL does) but currently is ad-hoc.
    pub fn encode(&self) -> Vec<u8> {
        let id_len = self.id.0.len().to_le_bytes();
        let value_len = self.value.len().to_le_bytes();
        let context_len = self.context.len().to_le_bytes();
        let creation_time = self.creation_time.0.to_le_bytes();
        let time_out = self.time_out.to_le_bytes();

        let mut ret = Vec::with_capacity(
            SslSession::MAGIC.len()
                + id_len.len()
                + self.id.0.len()
                + value_len.len()
                + self.value.len()
                + context_len.len()
                + self.context.len()
                + creation_time.len()
                + time_out.len(),
        );
        ret.extend_from_slice(SslSession::MAGIC);
        ret.extend_from_slice(&id_len);
        ret.extend_from_slice(&self.id.0);
        ret.extend_from_slice(&value_len);
        ret.extend_from_slice(&self.value);
        ret.extend_from_slice(&context_len);
        ret.extend_from_slice(&self.context);
        ret.extend_from_slice(&creation_time);
        ret.extend_from_slice(&time_out);
        ret
    }

    /// Decodes from the front of `slice`.  Returns the remainder.
    pub fn decode(slice: &[u8]) -> Option<(Self, &[u8])> {
        fn split_at(slice: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
            if mid <= slice.len() {
                Some(slice.split_at(mid))
            } else {
                None
            }
        }

        fn slice_to_usize(slice: &[u8]) -> usize {
            // unwrap: `slice` must be `usize_len` in length
            usize::from_le_bytes(slice.try_into().unwrap())
        }

        fn slice_to_u64(slice: &[u8]) -> u64 {
            // unwrap: `slice` must be `u64_len` in length
            u64::from_le_bytes(slice.try_into().unwrap())
        }

        let usize_len = mem::size_of::<usize>();
        let u64_len = mem::size_of::<u64>();

        let (magic, slice) = split_at(slice, SslSession::MAGIC.len())?;
        if magic != SslSession::MAGIC {
            return None;
        }
        let (id_len, slice) = split_at(slice, usize_len)?;
        let (id, slice) = split_at(slice, slice_to_usize(id_len))?;
        let (value_len, slice) = split_at(slice, usize_len)?;
        let (value, slice) = split_at(slice, slice_to_usize(value_len))?;
        let (context_len, slice) = split_at(slice, usize_len)?;
        let (context, slice) = split_at(slice, slice_to_usize(context_len))?;
        let (creation_time, slice) = split_at(slice, u64_len)?;
        let (time_out, slice) = split_at(slice, u64_len)?;
        Some((
            Self {
                id: SslSessionLookup(id.to_vec()),
                value: value.to_vec(),
                context: context.to_vec(),
                creation_time: cache::TimeBase(slice_to_u64(creation_time)),
                time_out: slice_to_u64(time_out),
            },
            slice,
        ))
    }

    pub fn get_id(&self) -> &[u8] {
        &self.id.0
    }

    pub fn get_creation_time(&self) -> u64 {
        self.creation_time.0
    }

    pub fn set_creation_time(&mut self, new_time: u64) {
        self.creation_time = cache::TimeBase(new_time);
    }

    pub fn get_time_out(&self) -> u64 {
        self.time_out
    }

    pub fn set_time_out(&mut self, time_out_secs: u64) {
        self.time_out = time_out_secs;
    }

    pub fn set_context(&mut self, new_context: &[u8]) {
        self.context = new_context.to_vec();
    }

    pub fn expired(&self, at_time: cache::TimeBase) -> bool {
        cache::ExpiryTime::calculate(self.creation_time, self.time_out).in_past(at_time)
    }
}

impl PartialOrd<SslSession> for SslSession {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.id.cmp(&other.id))
    }
}

impl Ord for SslSession {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialEq<SslSession> for SslSession {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SslSession {}

impl borrow::Borrow<SslSessionLookup> for Arc<NotThreadSafe<SslSession>> {
    fn borrow(&self) -> &SslSessionLookup {
        &self.get().id
    }
}

impl fmt::Debug for SslSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("SslSession")
            .field("id", &self.id)
            .field("creation_time", &self.creation_time)
            .field("time_out", &self.time_out)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialOrd, Ord, Eq, PartialEq)]
pub struct SslSessionLookup(Vec<u8>);

impl SslSessionLookup {
    pub fn for_id(id: &[u8]) -> Self {
        Self(id.to_vec())
    }
}

pub struct SslContext {
    method: &'static SslMethod,
    ex_data: ex_data::ExData,
    versions: EnabledVersions,
    caches: cache::SessionCaches,
    raw_options: u64,
    verify_mode: VerifyMode,
    verify_depth: c_int,
    verify_roots: RootCertStore,
    verify_x509_store: x509::OwnedX509Store,
    alpn: Vec<Vec<u8>>,
    default_cert_file: Option<PathBuf>,
    default_cert_dir: Option<PathBuf>,
    alpn_callback: callbacks::AlpnCallbackConfig,
    cert_callback: callbacks::CertCallbackConfig,
    servername_callback: callbacks::ServerNameCallbackConfig,
    auth_keys: sign::CertifiedKeySet,
    max_early_data: u32,
}

impl SslContext {
    fn new(method: &'static SslMethod) -> Self {
        Self {
            method,
            ex_data: ex_data::ExData::default(),
            versions: EnabledVersions::default(),
            caches: cache::SessionCaches::default(),
            raw_options: 0,
            verify_mode: VerifyMode::default(),
            verify_depth: -1,
            verify_roots: RootCertStore::empty(),
            verify_x509_store: OwnedX509Store::default(),
            alpn: vec![],
            default_cert_file: None,
            default_cert_dir: None,
            alpn_callback: callbacks::AlpnCallbackConfig::default(),
            cert_callback: callbacks::CertCallbackConfig::default(),
            servername_callback: callbacks::ServerNameCallbackConfig::default(),
            auth_keys: sign::CertifiedKeySet::default(),
            max_early_data: 0,
        }
    }

    fn complete_construction(
        &mut self,
        pointer_to_self: *mut entry::SSL_CTX,
    ) -> Result<(), error::Error> {
        self.caches.set_pointer_to_owning_ssl_ctx(pointer_to_self);

        self.ex_data = ex_data::ExData::new_ssl_ctx(pointer_to_self)
            .ok_or_else(|| error::Error::bad_data("ex_data construction failed"))?;

        Ok(())
    }

    fn set_ex_data(&mut self, idx: c_int, data: *mut c_void) -> Result<(), error::Error> {
        self.ex_data.set(idx, data)
    }

    fn get_ex_data(&self, idx: c_int) -> *mut c_void {
        self.ex_data.get(idx)
    }

    fn get_options(&self) -> u64 {
        self.raw_options
    }

    fn set_options(&mut self, set: u64) -> u64 {
        self.raw_options |= set;
        self.raw_options
    }

    fn clear_options(&mut self, clear: u64) -> u64 {
        self.raw_options &= !clear;
        self.raw_options
    }

    fn set_min_protocol_version(&mut self, ver: u16) {
        self.versions.min = match ver {
            0 => None,
            _ => Some(ProtocolVersion::from(ver)),
        };
    }

    fn get_min_protocol_version(&self) -> u16 {
        self.versions
            .min
            .as_ref()
            .map(|v| u16::from(*v))
            .unwrap_or_default()
    }

    fn set_max_protocol_version(&mut self, ver: u16) {
        self.versions.max = match ver {
            0 => None,
            _ => Some(ProtocolVersion::from(ver)),
        };
    }

    fn get_max_protocol_version(&self) -> u16 {
        self.versions
            .max
            .as_ref()
            .map(|v| u16::from(*v))
            .unwrap_or_default()
    }

    fn get_session_cache_size(&self) -> usize {
        self.caches.size()
    }

    fn set_session_cache_size(&mut self, size: usize) -> usize {
        self.caches.set_size(size)
    }

    fn set_session_cache_mode(&mut self, mode: u32) -> u32 {
        self.caches.set_mode(mode)
    }

    fn set_session_id_context(&mut self, context: &[u8]) {
        self.caches.set_context(context);
    }

    fn set_session_new_cb(&mut self, callback: entry::SSL_CTX_new_session_cb) {
        self.caches.set_new_callback(callback);
    }

    fn set_session_get_cb(&mut self, callback: entry::SSL_CTX_sess_get_cb) {
        self.caches.set_get_callback(callback);
    }

    fn set_session_remove_cb(&mut self, callback: entry::SSL_CTX_sess_remove_cb) {
        self.caches.set_remove_callback(callback);
    }

    fn get_session_timeout(&self) -> u64 {
        self.caches.get_timeout()
    }

    fn set_session_timeout(&mut self, timeout: u64) -> u64 {
        self.caches.set_timeout(timeout)
    }

    fn flush_all_sessions(&mut self) {
        self.caches.flush_all();
    }

    fn set_max_early_data(&mut self, max: u32) {
        self.max_early_data = max;
    }

    fn get_max_early_data(&self) -> u32 {
        self.max_early_data
    }

    fn set_verify(&mut self, mode: VerifyMode) {
        self.verify_mode = mode;
    }

    fn set_default_verify_paths(&mut self) {
        let ProbeResult {
            cert_file,
            cert_dir,
        } = openssl_probe::probe();
        self.default_cert_file = cert_file;
        self.default_cert_dir = cert_dir;
    }

    fn set_default_verify_dir(&mut self) {
        let ProbeResult { cert_dir, .. } = openssl_probe::probe();
        self.default_cert_dir = cert_dir;
    }

    fn set_default_verify_file(&mut self) {
        let ProbeResult { cert_file, .. } = openssl_probe::probe();
        self.default_cert_file = cert_file;
    }

    fn get_verify_mode(&self) -> VerifyMode {
        self.verify_mode
    }

    fn get_verify_callback(&self) -> entry::SSL_verify_cb {
        // TODO: `SSL_CTX_set_verify` currently rejects non-NULL callback
        None
    }

    fn set_verify_depth(&mut self, depth: c_int) {
        self.verify_depth = depth;
    }

    fn get_verify_depth(&self) -> c_int {
        self.verify_depth
    }

    fn add_trusted_certs(
        &mut self,
        certs: Vec<CertificateDer<'static>>,
    ) -> Result<(), error::Error> {
        for c in certs {
            self.verify_roots
                .add(c)
                .map_err(error::Error::from_rustls)?;
        }
        Ok(())
    }

    fn get_x509_store(&self) -> *mut X509_STORE {
        self.verify_x509_store.pointer()
    }

    fn set_x509_store(&mut self, store: *mut X509_STORE) {
        self.verify_x509_store = match store.is_null() {
            true => OwnedX509Store::default(),
            false => OwnedX509Store::new(store),
        };
    }

    fn set_alpn_offer(&mut self, alpn: Vec<Vec<u8>>) {
        self.alpn = alpn;
    }

    fn set_alpn_select_cb(&mut self, cb: entry::SSL_CTX_alpn_select_cb_func, context: *mut c_void) {
        self.alpn_callback = callbacks::AlpnCallbackConfig { cb, context };
    }

    fn set_cert_cb(&mut self, cb: entry::SSL_CTX_cert_cb_func, context: *mut c_void) {
        self.cert_callback = callbacks::CertCallbackConfig { cb, context };
    }

    fn stage_certificate_end_entity(&mut self, end: CertificateDer<'static>) {
        self.auth_keys.stage_certificate_end_entity(end)
    }

    fn stage_certificate_chain(&mut self, chain: Vec<CertificateDer<'static>>) {
        self.auth_keys.stage_certificate_chain(chain)
    }

    fn commit_private_key(&mut self, key: evp_pkey::EvpPkey) -> Result<(), error::Error> {
        self.auth_keys.commit_private_key(key)
    }

    fn get_certificate(&self) -> *mut X509 {
        self.auth_keys.borrow_current_cert()
    }

    fn get_privatekey(&self) -> *mut EVP_PKEY {
        self.auth_keys.borrow_current_key()
    }

    fn set_servername_callback(&mut self, cb: entry::SSL_CTX_servername_callback_func) {
        self.servername_callback.cb = cb;
    }

    fn set_servername_callback_context(&mut self, context: *mut c_void) {
        self.servername_callback.context = context;
    }
}

/// Parse the ALPN wire format (which is used in the openssl API)
/// to rustls's internal representation.
///
/// For an empty `slice`, returns `Some(vec![])`.
/// For a slice with invalid contents, returns `None`.
pub fn parse_alpn(slice: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = vec![];

    for item in iter_alpn(slice) {
        out.push(item?.to_vec());
    }

    Some(out)
}

pub fn iter_alpn(mut slice: &[u8]) -> impl Iterator<Item = Option<&[u8]>> {
    std::iter::from_fn(move || {
        // None => end iteration
        // Some(None) => error
        // Some(_) => an item

        let len = match slice.first() {
            None => {
                return None;
            }
            Some(len) => *len as usize,
        };

        if len == 0 {
            return Some(None);
        }

        match slice.get(1..1 + len) {
            None => Some(None),
            Some(body) => {
                slice = &slice[1 + len..];
                Some(Some(body))
            }
        }
    })
}

struct Ssl {
    ctx: Arc<NotThreadSafe<SslContext>>,
    ex_data: ex_data::ExData,
    versions: EnabledVersions,
    raw_options: u64,
    mode: ConnMode,
    verify_mode: VerifyMode,
    verify_depth: c_int,
    verify_roots: RootCertStore,
    verify_server_name: Option<ServerName<'static>>,
    alpn: Vec<Vec<u8>>,
    alpn_callback: callbacks::AlpnCallbackConfig,
    cert_callback: callbacks::CertCallbackConfig,
    servername_callback: callbacks::ServerNameCallbackConfig,
    sni_server_name: Option<ServerName<'static>>,
    server_name: Option<CString>,
    bio: Option<bio::Bio>,
    conn: ConnState,
    peer_cert: Option<x509::OwnedX509>,
    peer_cert_chain: Option<x509::OwnedX509Stack>,
    shutdown_flags: ShutdownFlags,
    auth_keys: sign::CertifiedKeySet,
    max_early_data: u32,
}

#[allow(clippy::large_enum_variant)]
enum ConnState {
    Nothing,
    Client(Connection, Arc<verifier::ServerVerifier>),
    Accepting(Acceptor),
    Accepted(Accepted),
    Server(
        Connection,
        Arc<verifier::ClientVerifier>,
        Arc<cache::SingleServerCache>,
    ),
}

impl Ssl {
    fn new(ctx: Arc<NotThreadSafe<SslContext>>, inner: &SslContext) -> Result<Self, error::Error> {
        Ok(Self {
            ctx,
            ex_data: ex_data::ExData::default(),
            versions: inner.versions.clone(),
            raw_options: inner.raw_options,
            mode: inner.method.mode(),
            verify_mode: inner.verify_mode,
            verify_depth: inner.verify_depth,
            verify_roots: Self::load_verify_certs(inner)?,
            verify_server_name: None,
            alpn: inner.alpn.clone(),
            alpn_callback: inner.alpn_callback.clone(),
            cert_callback: inner.cert_callback.clone(),
            servername_callback: inner.servername_callback.clone(),
            sni_server_name: None,
            server_name: None,
            bio: None,
            conn: ConnState::Nothing,
            peer_cert: None,
            peer_cert_chain: None,
            shutdown_flags: ShutdownFlags::default(),
            auth_keys: inner.auth_keys.clone(),
            max_early_data: inner.max_early_data,
        })
    }

    fn install_ex_data(&mut self, ex_data: ex_data::ExData) {
        self.ex_data = ex_data;
    }

    fn set_ex_data(&mut self, idx: c_int, data: *mut c_void) -> Result<(), error::Error> {
        self.ex_data.set(idx, data)
    }

    fn get_ex_data(&self, idx: c_int) -> *mut c_void {
        self.ex_data.get(idx)
    }

    fn set_ctx(&mut self, ctx: Arc<NotThreadSafe<SslContext>>) {
        // there are no docs for `SSL_set_SSL_CTX`.  it seems the only
        // meaningful reason to use this is key/certificate switching
        // (eg, based on SNI).  So only bother updating `auth_keys`
        self.ctx = ctx.clone();
        self.auth_keys = ctx.get().auth_keys.clone();
    }

    fn get_options(&self) -> u64 {
        self.raw_options
    }

    fn set_options(&mut self, set: u64) -> u64 {
        self.raw_options |= set;
        self.raw_options
    }

    fn clear_options(&mut self, clear: u64) -> u64 {
        self.raw_options &= !clear;
        self.raw_options
    }

    fn set_min_protocol_version(&mut self, ver: u16) {
        self.versions.min = match ver {
            0 => None,
            _ => Some(ProtocolVersion::from(ver)),
        };
    }

    fn get_min_protocol_version(&self) -> u16 {
        self.versions
            .min
            .as_ref()
            .map(|v| u16::from(*v))
            .unwrap_or_default()
    }

    fn set_max_protocol_version(&mut self, ver: u16) {
        self.versions.max = match ver {
            0 => None,
            _ => Some(ProtocolVersion::from(ver)),
        };
    }

    fn get_max_protocol_version(&self) -> u16 {
        self.versions
            .max
            .as_ref()
            .map(|v| u16::from(*v))
            .unwrap_or_default()
    }

    fn set_alpn_offer(&mut self, alpn: Vec<Vec<u8>>) {
        self.alpn = alpn;
    }

    fn set_client_mode(&mut self) {
        // nb. don't fill in `conn` until the last minute.
        // SSL_set_connect_state() .. SSL_set1_host() .. SSL_connect() is a valid
        // sequence of calls.
        self.mode = ConnMode::Client;
    }

    fn set_server_mode(&mut self) {
        self.mode = ConnMode::Server;
    }

    fn is_server(&self) -> bool {
        self.mode == ConnMode::Server
    }

    fn stage_certificate_end_entity(&mut self, end: CertificateDer<'static>) {
        self.auth_keys.stage_certificate_end_entity(end)
    }

    fn stage_certificate_chain(&mut self, chain: Vec<CertificateDer<'static>>) {
        self.auth_keys.stage_certificate_chain(chain)
    }

    fn commit_private_key(&mut self, key: evp_pkey::EvpPkey) -> Result<(), error::Error> {
        self.auth_keys.commit_private_key(key)
    }

    fn set_verify_hostname(&mut self, hostname: Option<&str>) -> bool {
        match hostname {
            // If name is NULL or the empty string, the list of hostnames is
            // cleared and name checks are not performed on the peer certificate.
            None | Some("") => {
                self.verify_server_name = None;
                true
            }
            Some(hostname) => match ServerName::try_from(hostname).ok() {
                Some(server_name) => {
                    self.verify_server_name = Some(server_name.to_owned());
                    true
                }
                None => false,
            },
        }
    }

    fn set_verify(&mut self, mode: VerifyMode) {
        self.verify_mode = mode;
    }

    fn set_verify_depth(&mut self, depth: c_int) {
        self.verify_depth = depth;
    }

    fn get_verify_depth(&self) -> c_int {
        self.verify_depth
    }

    fn set_sni_hostname(&mut self, hostname: &str) -> bool {
        match ServerName::try_from(hostname).ok() {
            Some(server_name) => {
                self.sni_server_name = Some(server_name.to_owned());
                true
            }
            None => false,
        }
    }

    fn server_name_pointer(&mut self) -> *const c_char {
        // This does double duty (see `SSL_get_servername`):
        //
        // for clients, it is just `sni_server_name`
        //   (filled in here, lazily)
        //
        // for servers, it is the client's offered SNI name
        //   (filled in below in `invoke_accepted_callbacks`)
        //
        // the remaining annoyance is that the returned pointer has to NUL-terminated.

        match self.mode {
            ConnMode::Server => self.server_name.as_ref().map(|cstr| cstr.as_ptr()),
            ConnMode::Client | ConnMode::Unknown => match &self.server_name {
                Some(existing) => Some(existing.as_ptr()),
                None => {
                    self.server_name = self
                        .sni_server_name
                        .as_ref()
                        .and_then(|name| CString::new(name.to_str().as_bytes()).ok());
                    self.server_name.as_ref().map(|cstr| cstr.as_ptr())
                }
            },
        }
        .unwrap_or_else(ptr::null)
    }

    fn set_bio(&mut self, bio: bio::Bio) {
        self.bio = Some(bio);
    }

    fn set_bio_pair(&mut self, rbio: Option<*mut bio::BIO>, wbio: Option<*mut bio::BIO>) {
        if let Some(bio) = &mut self.bio {
            bio.update(rbio, wbio);
        } else {
            self.bio = Some(bio::Bio::new_pair(rbio, wbio));
        }
    }

    fn get_rbio(&self) -> *mut bio::BIO {
        self.bio
            .as_ref()
            .map(|b| b.borrow_read())
            .unwrap_or_else(ptr::null_mut)
    }

    fn get_wbio(&self) -> *mut bio::BIO {
        self.bio
            .as_ref()
            .map(|b| b.borrow_write())
            .unwrap_or_else(ptr::null_mut)
    }

    fn handshake(&mut self) -> Result<(), error::Error> {
        match self.mode {
            ConnMode::Client => self.connect(),
            ConnMode::Server => self.accept(),
            ConnMode::Unknown => Err(error::Error::bad_data("connection mode required")),
        }
    }

    fn connect(&mut self) -> Result<(), error::Error> {
        if let ConnMode::Unknown = self.mode {
            self.set_client_mode();
        }

        if matches!(self.conn, ConnState::Nothing) {
            self.init_client_conn()?;
        }

        self.try_io()
    }

    fn init_client_conn(&mut self) -> Result<(), error::Error> {
        // if absent, use a dummy IP address which disables SNI.
        let sni_server_name = match &self.sni_server_name {
            Some(sni_name) => sni_name.clone(),
            None => ServerName::try_from("0.0.0.0").unwrap(),
        };

        let provider = Arc::new(provider::default_provider());
        let verifier = Arc::new(verifier::ServerVerifier::new(
            self.verify_roots.clone().into(),
            provider.clone(),
            self.verify_mode,
            &self.verify_server_name,
        ));

        let versions = self
            .versions
            .reduce_versions(self.ctx.get().method.client_versions)?;

        let wants_resolver = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(error::Error::from_rustls)?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone());

        let mut config = if let Some(resolver) = self.auth_keys.client_resolver() {
            wants_resolver.with_client_cert_resolver(resolver)
        } else {
            wants_resolver.with_no_client_auth()
        };

        config.alpn_protocols.clone_from(&self.alpn);
        config.resumption = Resumption::store(self.ctx.get_mut().caches.get_client());

        let client_conn = ClientConnection::new(Arc::new(config), sni_server_name.clone())
            .map_err(error::Error::from_rustls)?;

        self.conn = ConnState::Client(client_conn.into(), verifier);
        Ok(())
    }

    fn accept(&mut self) -> Result<(), error::Error> {
        if let ConnMode::Unknown = self.mode {
            self.set_server_mode();
        }

        if matches!(self.conn, ConnState::Nothing) {
            self.conn = ConnState::Accepting(Acceptor::default());
        }

        self.try_io()
    }

    fn invoke_accepted_callbacks(&mut self) -> Result<(), error::Error> {
        // called on transition from `Accepting` -> `Accepted`
        let accepted = match &self.conn {
            ConnState::Accepted(accepted) => accepted,
            _ => unreachable!(),
        };

        self.server_name = accepted
            .client_hello()
            .server_name()
            .and_then(|sni| CString::new(sni.as_bytes()).ok());

        self.servername_callback.invoke()?;

        if let Some(alpn_iter) = accepted.client_hello().alpn() {
            let offer = encode_alpn(alpn_iter);

            let choice = self.alpn_callback.invoke(&offer)?;

            if let Some(choice) = choice {
                self.alpn = vec![choice];
            }
        }

        self.cert_callback.invoke()?;

        self.complete_accept()
    }

    fn complete_accept(&mut self) -> Result<(), error::Error> {
        if let ConnState::Accepted(_) = self.conn {
            self.init_server_conn()?;
        }

        self.try_io()
    }

    fn init_server_conn(&mut self) -> Result<(), error::Error> {
        let provider = Arc::new(provider::default_provider());
        let verifier = Arc::new(
            verifier::ClientVerifier::new(
                self.verify_roots.clone().into(),
                provider.clone(),
                self.verify_mode,
            )
            .map_err(error::Error::from_rustls)?,
        );

        let resolver = self
            .auth_keys
            .server_resolver()
            .ok_or_else(|| error::Error::bad_data("missing server keys"))?;

        let versions = self
            .versions
            .reduce_versions(self.ctx.get().method.server_versions)?;

        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(error::Error::from_rustls)?
            .with_client_cert_verifier(verifier.clone())
            .with_cert_resolver(resolver);

        config.alpn_protocols = mem::take(&mut self.alpn);
        config.max_early_data_size = self.max_early_data;
        config.send_tls13_tickets = 2; // match OpenSSL default: see `man SSL_CTX_set_num_tickets`
        let cache = self.ctx.get_mut().caches.get_server();
        config.session_storage = cache.clone();

        let accepted = match mem::replace(&mut self.conn, ConnState::Nothing) {
            ConnState::Accepted(accepted) => accepted,
            _ => unreachable!(),
        };

        // TODO: send alert
        let server_conn = accepted
            .into_connection(Arc::new(config))
            .map_err(|(err, _alert)| error::Error::from_rustls(err))?;

        self.conn = ConnState::Server(server_conn.into(), verifier, cache);
        Ok(())
    }

    fn conn(&self) -> Option<&Connection> {
        match &self.conn {
            ConnState::Client(conn, _) | ConnState::Server(conn, _, _) => Some(conn),
            _ => None,
        }
    }

    fn conn_mut(&mut self) -> Option<&mut Connection> {
        match &mut self.conn {
            ConnState::Client(conn, _) | ConnState::Server(conn, _, _) => Some(conn),
            _ => None,
        }
    }

    fn want(&self) -> Want {
        match &self.conn {
            ConnState::Client(conn, _) | ConnState::Server(conn, _, _) => Want {
                read: conn.wants_read(),
                write: conn.wants_write(),
            },
            ConnState::Accepting(_) => Want {
                read: true,
                write: false,
            },
            _ => Want::default(),
        }
    }

    fn write(&mut self, slice: &[u8]) -> Result<usize, error::Error> {
        let written = match self.conn_mut() {
            Some(conn) => conn.writer().write(slice).map_err(error::Error::from_io)?,
            None => 0,
        };
        self.try_io()?;
        Ok(written)
    }

    fn read(&mut self, slice: &mut [u8]) -> Result<usize, error::Error> {
        let (late_err, read_count) = loop {
            let late_err = self.try_io();

            match self.conn_mut() {
                Some(conn) => match conn.reader().read(slice) {
                    Ok(read) => break (late_err, read),
                    Err(err) if err.kind() == ErrorKind::WouldBlock && late_err.is_ok() => {
                        // no data available, go around again.
                        continue;
                    }
                    Err(err) if late_err.is_ok() => {
                        return Err(error::Error::from_io(err));
                    }
                    Err(_) => break (late_err, 0),
                },
                None => break (late_err, 0),
            };
        };

        if read_count > 0 {
            Ok(read_count)
        } else {
            // Only raise IO errors after all data has been read.
            late_err?;
            Ok(0)
        }
    }

    fn try_io(&mut self) -> Result<(), error::Error> {
        let bio = match self.bio.as_mut() {
            Some(bio) => bio,
            None => return Ok(()), // investigate OpenSSL behaviour without a BIO
        };

        match &mut self.conn {
            ConnState::Client(conn, _) | ConnState::Server(conn, _, _) => {
                match conn.complete_io(bio) {
                    Ok(_) => {}
                    Err(e) => {
                        // obtain underlying TLS protocol error (if any), and let it stamp
                        // out the one wrapped in io::Error.
                        if let Some(tls_err) = conn.process_new_packets().err() {
                            return Err(error::Error::from_rustls(tls_err));
                        }
                        return Err(error::Error::from_io(e));
                    }
                };
                let io_state = conn
                    .process_new_packets()
                    .map_err(error::Error::from_rustls)?;
                if io_state.peer_has_closed() {
                    self.shutdown_flags.set_received();
                }
                Ok(())
            }
            ConnState::Accepting(acceptor) => {
                if let Err(e) = acceptor.read_tls(bio) {
                    return Err(error::Error::from_io(e));
                };

                match acceptor.accept() {
                    Ok(None) => Ok(()),
                    Ok(Some(accepted)) => {
                        self.conn = ConnState::Accepted(accepted);
                        self.invoke_accepted_callbacks()
                    }
                    Err((error, mut alert)) => {
                        alert.write_all(bio).map_err(error::Error::from_io)?;
                        Err(error::Error::from_rustls(error))
                    }
                }
            }
            _ => Ok(()),
        }
    }

    fn try_shutdown(&mut self) -> Result<ShutdownResult, error::Error> {
        if self.shutdown_flags.quiet() {
            self.shutdown_flags.set_sent();
            self.shutdown_flags.set_received();
            return Ok(ShutdownResult::Received);
        }

        if !self.shutdown_flags.is_sent() {
            if let Some(conn) = self.conn_mut() {
                conn.send_close_notify();
            };

            self.shutdown_flags.set_sent();
        }

        self.try_io()?;
        Ok(if self.shutdown_flags.is_received() {
            ShutdownResult::Received
        } else {
            ShutdownResult::Sent
        })
    }

    fn get_shutdown(&self) -> i32 {
        self.shutdown_flags.get()
    }

    fn set_shutdown(&mut self, flags: i32) {
        self.shutdown_flags.set(flags);
    }

    fn set_quiet_shutdown(&mut self, enabled: bool) {
        self.shutdown_flags.set_quiet(enabled);
    }

    fn get_pending_plaintext(&mut self) -> usize {
        self.conn_mut()
            .as_mut()
            .and_then(|conn| {
                let io_state = conn.process_new_packets().ok()?;
                Some(io_state.plaintext_bytes_to_read())
            })
            .unwrap_or_default()
    }

    fn get_agreed_alpn(&self) -> Option<&[u8]> {
        self.conn().and_then(|conn| conn.alpn_protocol())
    }

    fn init_peer_cert(&mut self) {
        let conn = match self.conn() {
            Some(conn) => conn,
            None => return,
        };

        let certs = match conn.peer_certificates() {
            Some(certs) => certs,
            None => return,
        };

        let mut stack = x509::OwnedX509Stack::empty();
        let mut peer_cert = None;

        for (i, cert) in certs.iter().enumerate() {
            let converted = match x509::OwnedX509::parse_der(cert.as_ref()) {
                Some(converted) => converted,
                None => return,
            };

            if i == 0 {
                if !self.is_server() {
                    // See docs for `SSL_get_peer_cert_chain`:
                    // "If called on the client side, the stack also contains
                    // the peer's certificate; if called on the server side, the peer's
                    // certificate must be obtained separately"
                    stack.push(&converted);
                }
                peer_cert = Some(converted);
            } else {
                stack.push(&converted);
            }
        }

        self.peer_cert = peer_cert;
        self.peer_cert_chain = Some(stack);
    }

    fn get_peer_cert(&mut self) -> Option<&x509::OwnedX509> {
        if self.peer_cert.is_none() {
            self.init_peer_cert();
        }
        self.peer_cert.as_ref()
    }

    fn get_peer_cert_chain(&mut self) -> Option<&x509::OwnedX509Stack> {
        if self.peer_cert_chain.is_none() {
            self.init_peer_cert();
        }
        self.peer_cert_chain.as_ref()
    }

    fn get_negotiated_cipher_suite_id(&self) -> Option<CipherSuite> {
        self.conn()
            .and_then(|conn| conn.negotiated_cipher_suite())
            .map(|suite| suite.suite())
    }

    fn get_last_verification_result(&self) -> i64 {
        match &self.conn {
            ConnState::Client(_, verifier) => verifier.last_result(),
            ConnState::Server(_, verifier, _) => verifier.last_result(),
            _ => X509_V_ERR_UNSPECIFIED as i64,
        }
    }

    fn get_last_verification_sig_scheme(&self) -> Option<SignatureScheme> {
        match &self.conn {
            ConnState::Client(_, verifier) => verifier.last_sig_scheme(),
            ConnState::Server(_, verifier, _) => verifier.last_sig_scheme(),
            _ => None,
        }
    }

    fn get_error(&mut self) -> c_int {
        match self.conn_mut() {
            Some(conn) => {
                if let Err(e) = conn.process_new_packets() {
                    error::Error::from_rustls(e).raise();
                    return SSL_ERROR_SSL;
                }

                let want = self.want();

                if let Some(bio) = self.bio.as_ref() {
                    if want.write && bio.write_would_block() {
                        return SSL_ERROR_WANT_WRITE;
                    } else if want.read && bio.read_would_block() {
                        return SSL_ERROR_WANT_READ;
                    }
                }

                SSL_ERROR_NONE
            }
            None => SSL_ERROR_SSL,
        }
    }

    fn load_verify_certs(ctx: &SslContext) -> Result<RootCertStore, error::Error> {
        let mut verify_roots = ctx.verify_roots.clone();

        // If verify_roots isn't empty then it was configured with `SSL_CTX_load_verify_file`
        // or `SSL_CTX_load_verify_dir` and we should use it as-is.
        if !ctx.verify_roots.is_empty() {
            return Ok(verify_roots);
        }

        // Otherwise, try to load the default cert file or cert dir.
        if let Some(default_cert_file) = &ctx.default_cert_file {
            verify_roots.add_parsable_certificates(x509::load_certs(
                vec![default_cert_file.to_path_buf()].into_iter(),
            )?);
        } else if let Some(default_cert_dir) = &ctx.default_cert_dir {
            let entries = match fs::read_dir(default_cert_dir) {
                Ok(iter) => iter,
                Err(err) => return Err(error::Error::from_io(err).raise()),
            }
            .filter_map(|entry| entry.ok())
            .map(|dir_entry| dir_entry.path());

            verify_roots.add_parsable_certificates(x509::load_certs(entries)?);
        }

        Ok(verify_roots)
    }

    fn get_certificate(&self) -> *mut X509 {
        self.auth_keys.borrow_current_cert()
    }

    fn get_privatekey(&self) -> *mut EVP_PKEY {
        self.auth_keys.borrow_current_key()
    }

    fn handshake_state(&mut self) -> HandshakeState {
        let mode = self.mode;
        match self.conn_mut() {
            Some(conn) => {
                if conn.process_new_packets().is_err() {
                    return HandshakeState::Error;
                }

                match (mode, conn.is_handshaking()) {
                    (ConnMode::Server, true) => HandshakeState::ServerAwaitingClientHello,
                    (ConnMode::Client, true) => HandshakeState::ClientAwaitingServerHello,
                    (ConnMode::Unknown, true) => HandshakeState::Before,
                    (_, false) => HandshakeState::Finished,
                }
            }
            None => HandshakeState::Before,
        }
    }

    fn was_session_reused(&self) -> bool {
        match self.conn() {
            Some(conn) => conn.handshake_kind() == Some(HandshakeKind::Resumed),
            None => false,
        }
    }

    fn get_current_session(&self) -> Option<Arc<NotThreadSafe<SslSession>>> {
        match &self.conn {
            ConnState::Server(_, _, cache) => cache.get_most_recent_session(),
            // divergence: `SSL_get1_session` etc only work for server SSLs
            _ => None,
        }
    }

    fn borrow_current_session(&self) -> *mut entry::SSL_SESSION {
        match &self.conn {
            ConnState::Server(_, _, cache) => cache.borrow_most_recent_session(),
            // divergence: `SSL_get_session` etc only work for server SSLs
            _ => ptr::null_mut(),
        }
    }
}

/// Encode rustls's internal representation in the wire format.
fn encode_alpn<'a>(iter: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = vec![];

    for item in iter {
        out.push(item.len() as u8);
        out.extend_from_slice(item);
    }

    out
}

/// This is a reduced-fidelity version of `OSSL_HANDSHAKE_STATE`.
///
/// We don't track all the individual message states (rustls doesn't expose that detail).
#[derive(Debug, PartialEq)]
enum HandshakeState {
    Before,
    Finished,
    Error,
    ClientAwaitingServerHello,
    ServerAwaitingClientHello,
}

impl HandshakeState {
    fn in_init(&self) -> bool {
        match self {
            // nb.
            // 1. openssl 3 behaviour for SSL_in_before or SSL_in_init does not match docs
            // 2. SSL_in_init becomes 1 on sending a fatal alert
            HandshakeState::Before
            | HandshakeState::Error
            | HandshakeState::ClientAwaitingServerHello
            | HandshakeState::ServerAwaitingClientHello => true,
            _ => false,
        }
    }
}

impl From<HandshakeState> for c_uint {
    fn from(hs: HandshakeState) -> c_uint {
        match hs {
            HandshakeState::Before => 0,
            HandshakeState::Finished => 1,
            // error resets openssl state machine to the start
            HandshakeState::Error => 1,
            // aka OSSL_HANDSHAKE_STATE_TLS_ST_CR_SRVR_HELLO
            HandshakeState::ClientAwaitingServerHello => 3,
            // aka OSSL_HANDSHAKE_STATE_TLS_ST_SR_CLNT_HELLO
            HandshakeState::ServerAwaitingClientHello => 22,
        }
    }
}

#[derive(Default)]
struct Want {
    read: bool,
    write: bool,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum ConnMode {
    Unknown,
    Client,
    Server,
}

#[repr(i32)]
enum ShutdownResult {
    Sent = 0,
    Received = 1,
}

#[derive(Default)]
struct ShutdownFlags(i32);

impl ShutdownFlags {
    const SENT: i32 = 1;
    const RECEIVED: i32 = 2;
    const PUBLIC: i32 = Self::SENT | Self::RECEIVED;

    const PRIV_QUIET: i32 = 4;

    fn is_sent(&self) -> bool {
        self.0 & ShutdownFlags::SENT == ShutdownFlags::SENT
    }

    fn is_received(&self) -> bool {
        self.0 & ShutdownFlags::RECEIVED == ShutdownFlags::RECEIVED
    }

    fn set_sent(&mut self) {
        self.0 |= ShutdownFlags::SENT;
    }

    fn set_received(&mut self) {
        self.0 |= ShutdownFlags::RECEIVED;
    }

    fn set(&mut self, flags: i32) {
        self.0 |= flags & ShutdownFlags::PUBLIC;
    }

    fn get(&self) -> i32 {
        self.0 & ShutdownFlags::PUBLIC
    }

    fn set_quiet(&mut self, enabled: bool) {
        if enabled {
            self.0 |= ShutdownFlags::PRIV_QUIET;
        } else {
            self.0 &= !ShutdownFlags::PRIV_QUIET;
        }
    }

    fn quiet(&self) -> bool {
        self.0 & ShutdownFlags::PRIV_QUIET == ShutdownFlags::PRIV_QUIET
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct VerifyMode(i32);

impl VerifyMode {
    const _NONE: i32 = 0x0;
    const PEER: i32 = 0x1;
    const FAIL_IF_NO_PEER_CERT: i32 = 0x2;
    // other flags not mentioned here are not implemented.

    pub fn client_must_verify_server(&self) -> bool {
        self.0 & VerifyMode::PEER == VerifyMode::PEER
    }

    pub fn server_must_attempt_client_auth(&self) -> bool {
        self.0 & VerifyMode::PEER == VerifyMode::PEER
    }

    pub fn server_must_verify_client(&self) -> bool {
        let bitmap = VerifyMode::PEER | VerifyMode::FAIL_IF_NO_PEER_CERT;
        self.0 & bitmap == bitmap
    }

    pub fn server_should_verify_client_but_allow_anon(&self) -> bool {
        self.0 & (VerifyMode::PEER | VerifyMode::FAIL_IF_NO_PEER_CERT) == VerifyMode::PEER
    }
}

impl From<i32> for VerifyMode {
    fn from(i: i32) -> Self {
        Self(i)
    }
}

impl From<VerifyMode> for i32 {
    fn from(v: VerifyMode) -> Self {
        v.0
    }
}

#[derive(Debug, Default, Clone)]
struct EnabledVersions {
    min: Option<ProtocolVersion>,
    max: Option<ProtocolVersion>,
}

impl EnabledVersions {
    fn reduce_versions(
        &self,
        method_versions: &'static [&'static SupportedProtocolVersion],
    ) -> Result<Vec<&'static SupportedProtocolVersion>, error::Error> {
        let acceptable: Vec<&'static SupportedProtocolVersion> = method_versions
            .iter()
            .cloned()
            .filter(|v| self.satisfies(v.version))
            .collect();

        if acceptable.is_empty() {
            Err(error::Error::bad_data(&format!(
                "no versions usable: method enabled {method_versions:?}, filter {self:?}"
            )))
        } else {
            Ok(acceptable)
        }
    }

    fn satisfies(&self, v: ProtocolVersion) -> bool {
        let min = self.min.map(u16::from).unwrap_or(0);
        let max = self.max.map(u16::from).unwrap_or(0xffff);
        let v = u16::from(v);
        min <= v && v <= max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_alpn() {
        assert_eq!(Some(vec![]), parse_alpn(&[]));
        assert_eq!(Some(vec![b"hi".to_vec()]), parse_alpn(&b"\x02hi"[..]));
        assert_eq!(
            Some(vec![b"hi".to_vec(), b"world".to_vec()]),
            parse_alpn(&b"\x02hi\x05world"[..])
        );

        assert_eq!(None, parse_alpn(&[0]));
        assert_eq!(None, parse_alpn(&[1]));
        assert_eq!(None, parse_alpn(&[1, 1, 1]));
        assert_eq!(None, parse_alpn(&[255]));
    }
}
