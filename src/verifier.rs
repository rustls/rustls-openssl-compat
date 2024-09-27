use core::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};

use openssl_sys::{
    X509_V_ERR_CERT_HAS_EXPIRED, X509_V_ERR_CERT_NOT_YET_VALID, X509_V_ERR_CERT_REVOKED,
    X509_V_ERR_HOSTNAME_MISMATCH, X509_V_ERR_INVALID_PURPOSE,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, X509_V_ERR_UNSPECIFIED, X509_V_OK,
};

use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor, verify_server_name,
    },
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    server::{ParsedCertificate, WebPkiClientVerifier},
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore,
    SignatureScheme,
};

use crate::VerifyMode;

/// This is a verifier that implements the selection of bad ideas from OpenSSL:
///
/// - that the SNI name and verified certificate server name are unrelated
/// - that the server name can be empty, and that implicitly disables hostname verification
/// - that the behaviour defaults to verifying nothing
#[derive(Debug)]
pub struct ServerVerifier {
    root_store: Arc<RootCertStore>,

    provider: Arc<CryptoProvider>,

    /// Expected server name.
    ///
    /// `None` means server name verification is disabled.
    verify_hostname: Option<ServerName<'static>>,

    mode: VerifyMode,

    last_result: AtomicI64,

    last_sig_scheme: RwLock<Option<SignatureScheme>>,
}

impl ServerVerifier {
    pub fn new(
        root_store: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
        mode: VerifyMode,
        hostname: &Option<ServerName<'static>>,
    ) -> Self {
        Self {
            root_store,
            provider,
            verify_hostname: hostname.clone(),
            mode,
            last_result: AtomicI64::new(X509_V_ERR_UNSPECIFIED as i64),
            last_sig_scheme: RwLock::new(None),
        }
    }

    pub fn last_result(&self) -> i64 {
        self.last_result.load(Ordering::Acquire)
    }

    pub fn update_last_result(&self, v: i64) {
        self.last_result.store(v, Ordering::Relaxed);
    }

    pub fn last_sig_scheme(&self) -> Option<SignatureScheme> {
        self.last_sig_scheme.read().ok().map(|scheme| *scheme)?
    }

    fn verify_server_cert_inner(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), Error> {
        let end_entity = ParsedCertificate::try_from(end_entity)?;

        verify_server_cert_signed_by_trust_anchor(
            &end_entity,
            &self.root_store,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;

        if let Some(server_name) = &self.verify_hostname {
            verify_server_name(&end_entity, server_name)?;
        }

        Ok(())
    }

    fn update_sig_scheme(&self, scheme: SignatureScheme) {
        if let Ok(mut last_scheme) = self.last_sig_scheme.write() {
            *last_scheme = Some(scheme);
        }
    }
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _ignored_server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let result = self.verify_server_cert_inner(end_entity, intermediates, now);

        let openssl_rv = translate_verify_result(&result);
        self.last_result.store(openssl_rv as i64, Ordering::Release);

        // Call it success if it succeeded, or the `mode` says not to care.
        if openssl_rv == X509_V_OK || !self.mode.client_must_verify_server() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(result.unwrap_err())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.update_sig_scheme(dss.scheme);
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.update_sig_scheme(dss.scheme);
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct ClientVerifier {
    parent: Arc<dyn ClientCertVerifier>,
    mode: VerifyMode,
    last_result: AtomicI64,
    last_sig_scheme: RwLock<Option<SignatureScheme>>,
}

impl ClientVerifier {
    pub fn new(
        root_store: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
        mode: VerifyMode,
    ) -> Result<Self, Error> {
        let (parent, initial_result) = if !mode.server_must_attempt_client_auth() {
            (Ok(WebPkiClientVerifier::no_client_auth()), X509_V_OK)
        } else {
            let builder = WebPkiClientVerifier::builder_with_provider(root_store, provider);

            if mode.server_must_verify_client() {
                (builder.build(), X509_V_ERR_UNSPECIFIED)
            } else {
                (
                    builder.allow_unauthenticated().build(),
                    X509_V_ERR_UNSPECIFIED,
                )
            }
        };

        let parent = parent.map_err(|err| Error::General(err.to_string()))?;

        Ok(Self {
            parent,
            mode,
            last_result: AtomicI64::new(initial_result as i64),
            last_sig_scheme: RwLock::new(None),
        })
    }

    pub fn last_result(&self) -> i64 {
        self.last_result.load(Ordering::Acquire)
    }

    pub fn update_last_result(&self, v: i64) {
        self.last_result.store(v, Ordering::Relaxed);
    }

    pub fn last_sig_scheme(&self) -> Option<SignatureScheme> {
        self.last_sig_scheme.read().ok().map(|scheme| *scheme)?
    }

    fn update_sig_scheme(&self, scheme: SignatureScheme) {
        if let Ok(mut last_scheme) = self.last_sig_scheme.write() {
            *last_scheme = Some(scheme);
        }
    }
}

impl ClientCertVerifier for ClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.mode.server_must_attempt_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mode.server_must_verify_client()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let result = self
            .parent
            .verify_client_cert(end_entity, intermediates, now)
            .map(|_| ());

        let openssl_rv = translate_verify_result(&result);
        self.last_result.store(openssl_rv as i64, Ordering::Release);

        // Call it success if it succeeded, or the `mode` says not to care.
        if openssl_rv == X509_V_OK || !self.mode.server_must_verify_client() {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(result.unwrap_err())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.update_sig_scheme(dss.scheme);
        self.parent.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.update_sig_scheme(dss.scheme);
        self.parent.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.parent.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.parent.root_hint_subjects()
    }
}

fn translate_verify_result(result: &Result<(), Error>) -> i32 {
    match result {
        Ok(()) => X509_V_OK,
        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer)) => {
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        }
        Err(Error::InvalidCertificate(CertificateError::NotValidYet)) => {
            X509_V_ERR_CERT_NOT_YET_VALID
        }
        Err(Error::InvalidCertificate(CertificateError::Expired)) => X509_V_ERR_CERT_HAS_EXPIRED,
        Err(Error::InvalidCertificate(CertificateError::Revoked)) => X509_V_ERR_CERT_REVOKED,
        Err(Error::InvalidCertificate(CertificateError::InvalidPurpose)) => {
            X509_V_ERR_INVALID_PURPOSE
        }
        Err(Error::InvalidCertificate(CertificateError::NotValidForName)) => {
            X509_V_ERR_HOSTNAME_MISMATCH
        }
        // TODO: more mappings can go here
        Err(_) => X509_V_ERR_UNSPECIFIED,
    }
}
