use core::ffi::{c_char, c_int, c_long, CStr};
use core::{fmt, ptr};
use std::slice;

use openssl_sys::{
    d2i_AutoPrivateKey, i2d_PUBKEY, EVP_DigestSign, EVP_DigestSignInit, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_saltlen,
    EVP_PKEY_CTX_set_signature_md, EVP_PKEY_free, EVP_PKEY_up_ref, EVP_sha256, EVP_sha384,
    EVP_sha512, OPENSSL_free, EVP_MD, EVP_MD_CTX, EVP_PKEY, EVP_PKEY_CTX, RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING,
};
use rustls::pki_types::PrivateKeyDer;

/// Safe, owning wrapper around an OpenSSL EVP_PKEY.
#[derive(Debug)]
pub struct EvpPkey {
    pkey: *const EVP_PKEY,
}

impl EvpPkey {
    /// Use a pre-existing private key, incrementing ownership.
    ///
    /// `pkey` continues to belong to the caller.
    pub fn new_incref(pkey: *mut EVP_PKEY) -> Self {
        debug_assert!(!pkey.is_null());
        unsafe { EVP_PKEY_up_ref(pkey) };
        Self { pkey }
    }

    /// Parse a key from DER bytes.
    pub fn new_from_der_bytes(data: PrivateKeyDer<'static>) -> Option<Self> {
        let mut old_ptr = ptr::null_mut();
        let mut data_ptr = data.secret_der().as_ptr();
        let data_len = data.secret_der().len();
        let pkey = unsafe { d2i_AutoPrivateKey(&mut old_ptr, &mut data_ptr, data_len as c_long) };

        if pkey.is_null() {
            None
        } else {
            Some(Self { pkey })
        }
    }

    /// Sign a message, returning the signature.
    pub fn sign(&self, scheme: &dyn EvpScheme, message: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ctx = SignCtx::new(scheme.digest(), self.pkey as *mut EVP_PKEY).ok_or(())?;
        scheme.configure_ctx(&mut ctx).ok_or(())?;
        ctx.sign(message)
    }

    pub fn algorithm(&self) -> rustls::SignatureAlgorithm {
        if self.is_rsa_type() {
            rustls::SignatureAlgorithm::RSA
        } else if self.is_ecdsa_type() {
            rustls::SignatureAlgorithm::ECDSA
        } else if self.is_ed25519_type() {
            rustls::SignatureAlgorithm::ED25519
        } else if self.is_ed448_type() {
            rustls::SignatureAlgorithm::ED448
        } else {
            rustls::SignatureAlgorithm::Unknown(0)
        }
    }

    /// Return the Subject Public Key Info bytes for this key.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        let (ptr, len) = unsafe {
            let mut ptr = ptr::null_mut();
            let len = i2d_PUBKEY(self.pkey, &mut ptr);
            (ptr, len)
        };

        if len <= 0 {
            return vec![];
        }
        let len = len as usize;

        let mut v = Vec::with_capacity(len);
        v.extend_from_slice(unsafe { slice::from_raw_parts(ptr, len) });

        unsafe { OPENSSL_free(ptr as *mut _) };
        v
    }

    /// Caller borrows our reference.
    pub fn borrow_ref(&self) -> *mut EVP_PKEY {
        self.pkey as *mut EVP_PKEY
    }

    fn is_rsa_type(&self) -> bool {
        self.is_a(c"RSA") || self.is_a(c"RSA-PSS")
    }

    fn is_ecdsa_type(&self) -> bool {
        self.is_a(c"EC")
    }

    fn is_ed25519_type(&self) -> bool {
        self.is_a(c"ED25519")
    }

    fn is_ed448_type(&self) -> bool {
        self.is_a(c"ED448")
    }

    fn is_a(&self, which: &CStr) -> bool {
        unsafe { EVP_PKEY_is_a(self.pkey, which.as_ptr()) == 1 }
    }
}

impl Clone for EvpPkey {
    fn clone(&self) -> Self {
        unsafe { EVP_PKEY_up_ref(self.pkey as *mut EVP_PKEY) };
        Self { pkey: self.pkey }
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        // safety: cast to *mut is safe, because refcounting is assumed atomic
        unsafe { EVP_PKEY_free(self.pkey as *mut EVP_PKEY) };
    }
}

// We assume read-only (const *EVP_PKEY) functions on EVP_PKEYs are thread safe,
// and refcounting is atomic. The actual facts are not documented.
unsafe impl Sync for EvpPkey {}
unsafe impl Send for EvpPkey {}

pub trait EvpScheme: fmt::Debug {
    fn digest(&self) -> *mut EVP_MD;
    fn configure_ctx(&self, ctx: &mut SignCtx) -> Option<()>;
}

pub fn rsa_pkcs1_sha256() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPkcs1(unsafe { EVP_sha256() }))
}

pub fn rsa_pkcs1_sha384() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPkcs1(unsafe { EVP_sha384() }))
}

pub fn rsa_pkcs1_sha512() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPkcs1(unsafe { EVP_sha512() }))
}

#[derive(Debug)]
struct RsaPkcs1(*const EVP_MD);

impl EvpScheme for RsaPkcs1 {
    fn digest(&self) -> *mut EVP_MD {
        self.0 as *mut EVP_MD
    }

    fn configure_ctx(&self, ctx: &mut SignCtx) -> Option<()> {
        ctx.set_signature_md(self.0)
            .and_then(|_| ctx.set_rsa_padding(RSA_PKCS1_PADDING))
    }
}

unsafe impl Sync for RsaPkcs1 {}
unsafe impl Send for RsaPkcs1 {}

pub fn rsa_pss_sha256() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPss(unsafe { EVP_sha256() }))
}

pub fn rsa_pss_sha384() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPss(unsafe { EVP_sha384() }))
}

pub fn rsa_pss_sha512() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPss(unsafe { EVP_sha512() }))
}

#[derive(Debug)]
struct RsaPss(*const EVP_MD);

impl EvpScheme for RsaPss {
    fn digest(&self) -> *mut EVP_MD {
        self.0 as *mut EVP_MD
    }

    fn configure_ctx(&self, ctx: &mut SignCtx) -> Option<()> {
        const RSA_PSS_SALTLEN_DIGEST: c_int = -1;
        ctx.set_signature_md(self.0)
            .and_then(|_| ctx.set_rsa_padding(RSA_PKCS1_PSS_PADDING))
            .and_then(|_| ctx.set_pss_saltlen(RSA_PSS_SALTLEN_DIGEST))
    }
}

unsafe impl Sync for RsaPss {}
unsafe impl Send for RsaPss {}

pub fn ed25519() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ed25519)
}

#[derive(Debug)]
struct Ed25519;

impl EvpScheme for Ed25519 {
    fn digest(&self) -> *mut EVP_MD {
        // "When calling EVP_DigestSignInit() or EVP_DigestVerifyInit(), the
        // digest type parameter MUST be set to NULL."
        // <https://www.openssl.org/docs/man3.0/man7/EVP_SIGNATURE-ED25519.html>
        ptr::null_mut()
    }

    fn configure_ctx(&self, _: &mut SignCtx) -> Option<()> {
        // "No additional parameters can be set during one-shot signing or verification."
        Some(())
    }
}

pub fn ecdsa_sha256() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ecdsa(unsafe { EVP_sha256() }))
}

pub fn ecdsa_sha384() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ecdsa(unsafe { EVP_sha384() }))
}

pub fn ecdsa_sha512() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ecdsa(unsafe { EVP_sha512() }))
}

#[derive(Debug)]
struct Ecdsa(*const EVP_MD);

impl EvpScheme for Ecdsa {
    fn digest(&self) -> *mut EVP_MD {
        self.0 as *mut EVP_MD
    }

    fn configure_ctx(&self, _: &mut SignCtx) -> Option<()> {
        Some(())
    }
}

unsafe impl Sync for Ecdsa {}
unsafe impl Send for Ecdsa {}

/// Owning wrapper for a signing `EVP_MD_CTX`
pub(crate) struct SignCtx {
    md_ctx: *mut EVP_MD_CTX,
    // owned by `md_ctx`
    pkey_ctx: *mut EVP_PKEY_CTX,
}

impl SignCtx {
    fn new(md: *mut EVP_MD, pkey: *mut EVP_PKEY) -> Option<Self> {
        let md_ctx = unsafe { EVP_MD_CTX_new() };
        let mut pkey_ctx = ptr::null_mut();

        match unsafe { EVP_DigestSignInit(md_ctx, &mut pkey_ctx, md, ptr::null_mut(), pkey) } {
            1 => {}
            _ => {
                unsafe { EVP_MD_CTX_free(md_ctx) };
                return None;
            }
        };

        Some(SignCtx { md_ctx, pkey_ctx })
    }

    fn set_signature_md(&mut self, md: *const EVP_MD) -> Option<()> {
        unsafe { EVP_PKEY_CTX_set_signature_md(self.pkey_ctx, md) == 1 }.then_some(())
    }

    fn set_rsa_padding(&mut self, pad: c_int) -> Option<()> {
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.pkey_ctx, pad) == 1 }.then_some(())
    }

    fn set_pss_saltlen(&mut self, saltlen: c_int) -> Option<()> {
        unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(self.pkey_ctx, saltlen) == 1 }.then_some(())
    }

    fn sign(self, data: &[u8]) -> Result<Vec<u8>, ()> {
        // determine length
        let mut max_len = 0;
        match unsafe {
            EVP_DigestSign(
                self.md_ctx,
                ptr::null_mut(),
                &mut max_len,
                data.as_ptr(),
                data.len(),
            )
        } {
            1 => {}
            _ => return Err(()),
        };

        // do the signature
        let mut out = vec![0u8; max_len];
        let mut actual_len = max_len;

        match unsafe {
            EVP_DigestSign(
                self.md_ctx,
                out.as_mut_ptr(),
                &mut actual_len,
                data.as_ptr(),
                data.len(),
            )
        } {
            1 => {}
            _ => return Err(()),
        }

        out.truncate(actual_len);
        Ok(out)
    }
}

impl Drop for SignCtx {
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.md_ctx) };
    }
}

extern "C" {
    pub fn EVP_PKEY_is_a(pkey: *const EVP_PKEY, name: *const c_char) -> c_int;
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn supports_rsaencryption_keys() {
        let der =
            rustls_pemfile::private_key(&mut &include_bytes!("../test-ca/rsa/server.key")[..])
                .unwrap()
                .unwrap();
        let key = EvpPkey::new_from_der_bytes(der).unwrap();
        println!("{key:?}");
        assert_eq!(key.algorithm(), rustls::SignatureAlgorithm::RSA);
        assert_eq!(
            key.sign(rsa_pkcs1_sha256().as_ref(), b"hello")
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pkcs1_sha384().as_ref(), b"hello")
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pkcs1_sha512().as_ref(), b"hello")
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pss_sha256().as_ref(), b"hello").unwrap().len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pss_sha384().as_ref(), b"hello").unwrap().len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pss_sha512().as_ref(), b"hello").unwrap().len(),
            256
        );
    }

    #[test]
    fn pkey_spki() {
        for (key_path, cert_path) in &[
            ("test-ca/rsa/server.key", "test-ca/rsa/server.cert"),
            (
                "test-ca/ecdsa-p256/server.key",
                "test-ca/ecdsa-p256/server.cert",
            ),
            (
                "test-ca/ecdsa-p384/server.key",
                "test-ca/ecdsa-p384/server.cert",
            ),
            (
                "test-ca/ecdsa-p521/server.key",
                "test-ca/ecdsa-p521/server.cert",
            ),
            ("test-ca/ed25519/server.key", "test-ca/ed25519/server.cert"),
        ] {
            let key_der = std::fs::read(key_path).unwrap();
            let cert_der = std::fs::read(cert_path).unwrap();

            let key_der = rustls_pemfile::private_key(&mut Cursor::new(key_der))
                .unwrap()
                .unwrap();
            let key = EvpPkey::new_from_der_bytes(key_der).unwrap();

            let cert_der = rustls_pemfile::certs(&mut Cursor::new(cert_der))
                .next()
                .unwrap()
                .unwrap();
            let parsed_cert = rustls::server::ParsedCertificate::try_from(&cert_der).unwrap();

            let cert_spki = parsed_cert.subject_public_key_info();
            let key_spki = key.subject_public_key_info();
            assert_eq!(&key_spki, cert_spki.as_ref());
        }
    }
}
