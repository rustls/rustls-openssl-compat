use std::sync::{Arc, Mutex};

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

pub struct SslContext {
    method: &'static SslMethod,
}

impl SslContext {
    fn new(method: &'static SslMethod) -> Self {
        Self { method }
    }
}

struct Ssl {
    ctx: Arc<Mutex<SslContext>>,
}

impl Ssl {
    fn new(ctx: Arc<Mutex<SslContext>>) -> Self {
        Self { ctx }
    }
}
