use core::ffi::CStr;
use std::sync::{Arc, Mutex};

use openssl_sys::X509_STORE;
use rustls::crypto::ring as provider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{CipherSuite, ClientConfig, ClientConnection, Connection, RootCertStore};

mod bio;
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
#[macro_use]
#[allow(unused_macros, dead_code, unused_imports)]
mod ffi;
#[cfg(miri)]
#[allow(non_camel_case_types, dead_code)]
mod miri;
mod verifier;
mod x509;

/// `SSL_METHOD` underlying type.
///
/// # Lifetime
/// Functions that return SSL_METHOD, like `TLS_method()`, give static-lifetime pointers.
pub struct SslMethod {
    client_versions: &'static [&'static rustls::SupportedProtocolVersion],
    server_versions: &'static [&'static rustls::SupportedProtocolVersion],
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
        self.rustls.suite().get_u16()
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

pub struct SslContext {
    method: &'static SslMethod,
    raw_options: u64,
    verify_mode: VerifyMode,
    verify_roots: RootCertStore,
    verify_x509_store: x509::OwnedX509Store,
    alpn: Vec<Vec<u8>>,
}

impl SslContext {
    fn new(method: &'static SslMethod) -> Self {
        Self {
            method,
            raw_options: 0,
            verify_mode: VerifyMode::default(),
            verify_roots: RootCertStore::empty(),
            verify_x509_store: x509::OwnedX509Store::new(),
            alpn: vec![],
        }
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

    fn set_verify(&mut self, mode: VerifyMode) {
        self.verify_mode = mode;
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

    fn set_alpn_offer(&mut self, alpn: Vec<Vec<u8>>) {
        self.alpn = alpn;
    }
}

/// Parse the ALPN wire format (which is used in the openssl API)
/// to rustls's internal representation.
///
/// For an empty `slice`, returns `Some(vec![])`.
/// For a slice with invalid contents, returns `None`.
pub fn parse_alpn(mut slice: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = vec![];

    while !slice.is_empty() {
        let len = *slice.first()? as usize;
        if len == 0 {
            return None;
        }
        let body = slice.get(1..1 + len)?;
        out.push(body.to_vec());
        slice = &slice[1 + len..];
    }

    Some(out)
}

struct Ssl {
    ctx: Arc<Mutex<SslContext>>,
    raw_options: u64,
    mode: ConnMode,
    verify_mode: VerifyMode,
    verify_roots: RootCertStore,
    verify_server_name: Option<ServerName<'static>>,
    alpn: Vec<Vec<u8>>,
    sni_server_name: Option<ServerName<'static>>,
    bio: Option<bio::Bio>,
    conn: Option<Connection>,
    verifier: Option<Arc<verifier::ServerVerifier>>,
}

impl Ssl {
    fn new(ctx: Arc<Mutex<SslContext>>, inner: &SslContext) -> Self {
        Self {
            ctx,
            raw_options: inner.raw_options,
            mode: inner.method.mode(),
            verify_mode: inner.verify_mode,
            verify_roots: inner.verify_roots.clone(),
            verify_server_name: None,
            alpn: inner.alpn.clone(),
            sni_server_name: None,
            bio: None,
            conn: None,
            verifier: None,
        }
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

    fn set_sni_hostname(&mut self, hostname: &str) -> bool {
        match ServerName::try_from(hostname).ok() {
            Some(server_name) => {
                self.sni_server_name = Some(server_name.to_owned());
                true
            }
            None => false,
        }
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

    fn connect(&mut self) -> Result<(), error::Error> {
        self.set_client_mode();
        if self.conn.is_none() {
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

        let method = self
            .ctx
            .lock()
            .map(|ctx| ctx.method)
            .map_err(|_| error::Error::cannot_lock())?;

        let provider = Arc::new(provider::default_provider());
        let verifier = Arc::new(verifier::ServerVerifier::new(
            self.verify_roots.clone().into(),
            provider.clone(),
            self.verify_mode,
            &self.verify_server_name,
        ));
        self.verifier = Some(verifier.clone());

        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(method.client_versions)
            .map_err(error::Error::from_rustls)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        config.alpn_protocols.clone_from(&self.alpn);

        let client_conn = ClientConnection::new(Arc::new(config), sni_server_name.clone())
            .map_err(error::Error::from_rustls)?;

        self.conn = Some(client_conn.into());
        Ok(())
    }

    fn try_io(&mut self) -> Result<(), error::Error> {
        let bio = match self.bio.as_mut() {
            Some(bio) => bio,
            None => return Ok(()), // investigate OpenSSL behaviour without a BIO
        };

        match &mut self.conn {
            Some(ref mut conn) => {
                match conn.complete_io(bio) {
                    Ok(_) => {}
                    Err(e) => {
                        return Err(error::Error::from_io(e));
                    }
                };
                conn.process_new_packets()
                    .map_err(error::Error::from_rustls)
                    .map(|_| ())
            }
            None => Ok(()),
        }
    }
}

#[derive(PartialEq)]
enum ConnMode {
    Unknown,
    Client,
    Server,
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
