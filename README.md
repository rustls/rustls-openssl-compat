# rustls-openssl-compat

This is the planned home of several rustls ↔️ OpenSSL compatibility layers.
Currently here:

- **rustls-libssl**: an implementation of the OpenSSL libssl ABI in terms of rustls.

Not yet here:

- **rustls-libcrypto**: an implementation of rustls `CryptoProvider` in terms of OpenSSL's libcrypto.
