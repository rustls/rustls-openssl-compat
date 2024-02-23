use core::ffi::CStr;
use std::sync::{Arc, Mutex};

use rustls::crypto::ring as provider;
use rustls::CipherSuite;

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

/// `SSL_METHOD` underlying type.
///
/// # Lifetime
/// Functions that return SSL_METHOD, like `TLS_method()`, give static-lifetime pointers.
pub struct SslMethod {
    client_versions: &'static [&'static rustls::SupportedProtocolVersion],
    server_versions: &'static [&'static rustls::SupportedProtocolVersion],
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
    alpn: Vec<Vec<u8>>,
}

impl SslContext {
    fn new(method: &'static SslMethod) -> Self {
        Self {
            method,
            alpn: vec![],
        }
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
    alpn: Vec<Vec<u8>>,
}

impl Ssl {
    fn new(ctx: Arc<Mutex<SslContext>>, inner: &SslContext) -> Self {
        Self {
            ctx,
            alpn: inner.alpn.clone(),
        }
    }

    fn set_alpn_offer(&mut self, alpn: Vec<Vec<u8>>) {
        self.alpn = alpn;
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
