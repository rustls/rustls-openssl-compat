use core::ffi::{c_int, CStr};
use openssl_sys::{
    NID_X9_62_prime256v1, NID_rsaEncryption, NID_rsassaPss, NID_secp384r1, NID_secp521r1,
    NID_ED25519, NID_ED448,
};

use rustls::{AlertDescription, SignatureScheme};

pub fn alert_desc_to_long_string(value: c_int) -> &'static CStr {
    match AlertDescription::from(value as u8) {
        AlertDescription::CloseNotify => c"close notify",
        AlertDescription::UnexpectedMessage => c"unexpected_message",
        AlertDescription::BadRecordMac => c"bad record mac",
        AlertDescription::DecryptionFailed => c"decryption failed",
        AlertDescription::RecordOverflow => c"record overflow",
        AlertDescription::DecompressionFailure => c"decompression failure",
        AlertDescription::HandshakeFailure => c"handshake failure",
        AlertDescription::NoCertificate => c"no certificate",
        AlertDescription::BadCertificate => c"bad certificate",
        AlertDescription::UnsupportedCertificate => c"unsupported certificate",
        AlertDescription::CertificateRevoked => c"certificate revoked",
        AlertDescription::CertificateExpired => c"certificate expired",
        AlertDescription::CertificateUnknown => c"certificate unknown",
        AlertDescription::IllegalParameter => c"illegal parameter",
        AlertDescription::UnknownCA => c"unknown CA",
        AlertDescription::AccessDenied => c"access denied",
        AlertDescription::DecodeError => c"decode error",
        AlertDescription::DecryptError => c"decrypt error",
        AlertDescription::ExportRestriction => c"export restriction",
        AlertDescription::ProtocolVersion => c"protocol version",
        AlertDescription::InsufficientSecurity => c"insufficient security",
        AlertDescription::InternalError => c"internal error",
        AlertDescription::UserCanceled => c"user canceled",
        AlertDescription::NoRenegotiation => c"no renegotiation",
        AlertDescription::UnsupportedExtension => c"unsupported extension",
        AlertDescription::CertificateUnobtainable => c"certificate unobtainable",
        AlertDescription::UnrecognisedName => c"unrecognized name",
        AlertDescription::BadCertificateStatusResponse => c"bad certificate status response",
        AlertDescription::BadCertificateHashValue => c"bad certificate hash value",
        AlertDescription::UnknownPSKIdentity => c"unknown PSK identity",
        AlertDescription::NoApplicationProtocol => c"no application protocol",
        // these are not supported by openssl:
        // AlertDescription::InappropriateFallback => c"inappropriate fallback",
        // AlertDescription::MissingExtension => c"missing extension",
        // AlertDescription::CertificateRequired => c"certificate required",
        _ => c"unknown",
    }
}

pub fn alert_desc_to_short_string(value: c_int) -> &'static CStr {
    match AlertDescription::from(value as u8) {
        AlertDescription::CloseNotify => c"CN",
        AlertDescription::UnexpectedMessage => c"UM",
        AlertDescription::BadRecordMac => c"BM",
        AlertDescription::DecryptionFailed => c"DC",
        AlertDescription::RecordOverflow => c"RO",
        AlertDescription::DecompressionFailure => c"DF",
        AlertDescription::HandshakeFailure => c"HF",
        AlertDescription::NoCertificate => c"NC",
        AlertDescription::BadCertificate => c"BC",
        AlertDescription::UnsupportedCertificate => c"UC",
        AlertDescription::CertificateRevoked => c"CR",
        AlertDescription::CertificateExpired => c"CE",
        AlertDescription::CertificateUnknown => c"CU",
        AlertDescription::IllegalParameter => c"IP",
        AlertDescription::UnknownCA => c"CA",
        AlertDescription::AccessDenied => c"AD",
        AlertDescription::DecodeError => c"DE",
        AlertDescription::DecryptError => c"CY",
        AlertDescription::ExportRestriction => c"ER",
        AlertDescription::ProtocolVersion => c"PV",
        AlertDescription::InsufficientSecurity => c"IS",
        AlertDescription::InternalError => c"IE",
        AlertDescription::UserCanceled => c"US",
        AlertDescription::NoRenegotiation => c"NR",
        AlertDescription::UnsupportedExtension => c"UE",
        AlertDescription::CertificateUnobtainable => c"CO",
        AlertDescription::UnrecognisedName => c"UN",
        AlertDescription::BadCertificateStatusResponse => c"BR",
        AlertDescription::BadCertificateHashValue => c"BH",
        AlertDescription::UnknownPSKIdentity => c"UP",
        // these are not supported by openssl:
        // AlertDescription::NoApplicationProtocol => c"no application protocol",
        // AlertDescription::InappropriateFallback => c"inappropriate fallback",
        // AlertDescription::MissingExtension => c"missing extension",
        // AlertDescription::CertificateRequired => c"certificate required",
        _ => c"UK",
    }
}

pub fn sig_scheme_to_nid(scheme: SignatureScheme) -> Option<c_int> {
    use SignatureScheme::*;
    match scheme {
        RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PKCS1_SHA512 => Some(NID_rsaEncryption),
        RSA_PSS_SHA256 | RSA_PSS_SHA384 | RSA_PSS_SHA512 => Some(NID_rsassaPss),
        ECDSA_NISTP256_SHA256 => Some(NID_X9_62_prime256v1),
        ECDSA_NISTP384_SHA384 => Some(NID_secp384r1),
        ECDSA_NISTP521_SHA512 => Some(NID_secp521r1),
        ED25519 => Some(NID_ED25519),
        ED448 => Some(NID_ED448),
        // Omitted: SHA1 legacy schemes.
        _ => None,
    }
}
