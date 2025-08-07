use std::ptr;
use std::sync::Arc;

use openssl_sys::{EVP_PKEY, X509};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign;
use rustls::{SignatureAlgorithm, SignatureScheme};

use crate::error;
use crate::evp_pkey::{
    ecdsa_sha256, ecdsa_sha384, ecdsa_sha512, ed25519, rsa_pkcs1_sha256, rsa_pkcs1_sha384,
    rsa_pkcs1_sha512, rsa_pss_sha256, rsa_pss_sha384, rsa_pss_sha512, EvpPkey, EvpScheme,
};
use crate::x509::OwnedX509Stack;

/// This matches up to the implied state machine in `SSL_CTX_use_certificate_chain_file`
/// and `SSL_CTX_use_PrivateKey_file`, and matching man pages.
#[derive(Clone, Default, Debug)]
pub struct CertifiedKeySet {
    item: KeySetItem,
}

impl CertifiedKeySet {
    /// Set the entirety of the current certificate chain to `chain`.
    ///
    /// `chain[0]` is the end-entity cert.
    pub fn stage_certificate_full_chain(
        &mut self,
        mut chain: Vec<CertificateDer<'static>>,
    ) -> Result<(), error::Error> {
        match chain.is_empty() {
            false => {
                self.stage_certificate_end_entity(chain.remove(0))?;
                self.stage_certificate_chain_tail(chain)
            }
            true => Err(error::Error::bad_data("empty certificate full chain")),
        }
    }

    /// Set the "bottom part" of the current certificate chain to `chain`.
    ///
    /// This does not contain the end-entity certificate.  That must be provided separately
    /// with `stage_certificate_end_entity()`.
    pub fn stage_certificate_chain_tail(
        &mut self,
        chain: Vec<CertificateDer<'static>>,
    ) -> Result<(), error::Error> {
        self.item.adopt_chain_tail(Some(chain));
        Ok(())
    }

    pub fn stage_certificate_end_entity(
        &mut self,
        end: CertificateDer<'static>,
    ) -> Result<(), error::Error> {
        self.item.cert_end_entity = Some(end);
        self.item.promote()
    }

    pub fn commit_private_key(&mut self, key: EvpPkey) -> Result<(), error::Error> {
        self.item.key = Some(key);
        self.item.promote()
    }

    pub fn client_resolver(&self) -> Option<Arc<dyn ResolvesClientCert>> {
        self.item
            .constructed
            .as_ref()
            .map(|ck| ck.client_resolver())
    }

    pub fn server_resolver(&self) -> Option<Arc<dyn ResolvesServerCert>> {
        self.item
            .constructed
            .as_ref()
            .map(|ck| ck.server_resolver())
    }

    /// For `SSL_get_certificate`
    pub fn borrow_current_cert(&self) -> *mut X509 {
        self.item
            .constructed
            .as_ref()
            .map(|ck| ck.borrow_cert())
            .unwrap_or(ptr::null_mut())
    }

    /// For `SSL_get_privatekey`
    pub fn borrow_current_key(&self) -> *mut EVP_PKEY {
        self.item
            .constructed
            .as_ref()
            .map(|ck| ck.borrow_key())
            .unwrap_or(ptr::null_mut())
    }
}

#[derive(Clone, Debug, Default)]
pub struct KeySetItem {
    /// Most recent certificate chain tail.
    cert_chain_tail: Option<Vec<CertificateDer<'static>>>,

    /// Most recent end-entity certificate.
    cert_end_entity: Option<CertificateDer<'static>>,

    /// Most recent value from `SSL_CTX_use_PrivateKey_file`
    key: Option<EvpPkey>,

    /// The key and certificate we're currently using.
    ///
    /// This is constructed eagerly to validate the cert/key are consistent.
    constructed: Option<OpenSslCertifiedKey>,
}

impl KeySetItem {
    fn adopt_chain_tail(&mut self, cert_chain_tail: Option<Vec<CertificateDer<'static>>>) {
        if let Some(tail) = cert_chain_tail {
            self.cert_chain_tail = Some(tail);
        }
    }

    /// If `self` has enough parts (a key and at least an end-entity cert) then fill in
    /// `constructed`.
    fn promote(&mut self) -> Result<(), error::Error> {
        let Some(key) = &self.key else {
            return Ok(());
        };

        // Reconstitute full chain from parts.
        let chain = match (&self.cert_end_entity, &self.cert_chain_tail) {
            (Some(end_entity), Some(tail)) => {
                let mut chain = tail.clone();
                chain.insert(0, end_entity.clone());
                chain
            }
            (Some(end_entity), None) => vec![end_entity.clone()],
            _ => return Ok(()),
        };

        self.constructed = Some(OpenSslCertifiedKey::new(chain, key.clone())?);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct OpenSslCertifiedKey {
    key: EvpPkey,
    openssl_chain: OwnedX509Stack,
    rustls_chain: Vec<CertificateDer<'static>>,
}

impl OpenSslCertifiedKey {
    pub(super) fn new(
        chain: Vec<CertificateDer<'static>>,
        key: EvpPkey,
    ) -> Result<Self, error::Error> {
        Ok(Self {
            key,
            openssl_chain: OwnedX509Stack::from_rustls(&chain)?,
            rustls_chain: chain,
        })
    }

    pub(super) fn keys_match(&self) -> bool {
        match sign::CertifiedKey::new(
            self.rustls_chain.clone(),
            Arc::new(OpenSslKey(self.key.clone())),
        )
        .keys_match()
        {
            // Note: we allow "Unknown" to be treated as success here. This is returned
            //   when it wasn't possible to get the SPKI for the private key, and so we
            //   aren't certain if it matches or not.
            Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
                true
            }
            _ => false,
        }
    }

    fn borrow_cert(&self) -> *mut X509 {
        self.openssl_chain.borrow_top_ref()
    }

    fn borrow_key(&self) -> *mut EVP_PKEY {
        self.key.borrow_ref()
    }

    fn client_resolver(&self) -> Arc<dyn ResolvesClientCert> {
        Arc::new(AlwaysResolvesClientCert(Arc::new(sign::CertifiedKey::new(
            self.rustls_chain.clone(),
            Arc::new(OpenSslKey(self.key.clone())),
        ))))
    }

    fn server_resolver(&self) -> Arc<dyn ResolvesServerCert> {
        Arc::new(AlwaysResolvesServerCert(Arc::new(sign::CertifiedKey::new(
            self.rustls_chain.clone(),
            Arc::new(OpenSslKey(self.key.clone())),
        ))))
    }
}

#[derive(Debug)]
struct AlwaysResolvesClientCert(Arc<sign::CertifiedKey>);

impl ResolvesClientCert for AlwaysResolvesClientCert {
    fn has_certs(&self) -> bool {
        true
    }

    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _schemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[derive(Debug)]
struct AlwaysResolvesServerCert(Arc<sign::CertifiedKey>);

impl ResolvesServerCert for AlwaysResolvesServerCert {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[derive(Debug)]
struct OpenSslKey(EvpPkey);

impl sign::SigningKey for OpenSslKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn sign::Signer>> {
        match self.0.algorithm() {
            SignatureAlgorithm::RSA => {
                if offered.contains(&SignatureScheme::RSA_PSS_SHA512) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: rsa_pss_sha512(),
                        scheme: SignatureScheme::RSA_PSS_SHA512,
                    }));
                }
                if offered.contains(&SignatureScheme::RSA_PSS_SHA384) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: rsa_pss_sha384(),
                        scheme: SignatureScheme::RSA_PSS_SHA384,
                    }));
                }
                if offered.contains(&SignatureScheme::RSA_PSS_SHA256) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: rsa_pss_sha256(),
                        scheme: SignatureScheme::RSA_PSS_SHA256,
                    }));
                }

                if offered.contains(&SignatureScheme::RSA_PKCS1_SHA512) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: rsa_pkcs1_sha512(),
                        scheme: SignatureScheme::RSA_PKCS1_SHA512,
                    }));
                }
                if offered.contains(&SignatureScheme::RSA_PKCS1_SHA384) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: rsa_pkcs1_sha384(),
                        scheme: SignatureScheme::RSA_PKCS1_SHA384,
                    }));
                }
                if offered.contains(&SignatureScheme::RSA_PKCS1_SHA256) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: rsa_pkcs1_sha256(),
                        scheme: SignatureScheme::RSA_PKCS1_SHA256,
                    }));
                }

                None
            }
            SignatureAlgorithm::ED25519 => {
                if offered.contains(&SignatureScheme::ED25519) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: ed25519(),
                        scheme: SignatureScheme::ED25519,
                    }));
                }

                None
            }
            SignatureAlgorithm::ECDSA => {
                if offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: ecdsa_sha256(),
                        scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                    }));
                }
                if offered.contains(&SignatureScheme::ECDSA_NISTP384_SHA384) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: ecdsa_sha384(),
                        scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
                    }));
                }
                if offered.contains(&SignatureScheme::ECDSA_NISTP521_SHA512) {
                    return Some(Box::new(OpenSslSigner {
                        pkey: self.0.clone(),
                        pscheme: ecdsa_sha512(),
                        scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
                    }));
                }

                None
            }
            _ => None,
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            self.0.subject_public_key_info(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct OpenSslSigner {
    pkey: EvpPkey,
    pscheme: Box<dyn EvpScheme + Send + Sync>,
    scheme: SignatureScheme,
}

impl sign::Signer for OpenSslSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.pkey
            .sign(self.pscheme.as_ref(), message)
            .map_err(|_| rustls::Error::General("signing failed".to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
