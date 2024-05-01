# rustls-openssl-compat

This is the planned home of several rustls to OpenSSL compatibility layers.
Currently here:

- **[rustls-libssl](rustls-libssl/)**: an implementation of the OpenSSL libssl ABI in terms of rustls.

Not yet here:

- **rustls-libcrypto**: an implementation of rustls `CryptoProvider` in terms of OpenSSL's libcrypto.
