# Rustls OpenSSL Compatibility Layer

OpenSSL consists of several libraries. We offer a safer version of OpenSSL's `libssl` (TLS support), and we intend to eventually offer a safer version of OpenSSL's `libcrypto` (cryptography support).

## rustls-libssl

This is ready for use with Nginx on Ubuntu 22.04 and later. Using it is as simple as:

```
$ wget https://github.com/rustls/rustls-openssl-compat/releases/latest/download/rustls-libssl_amd64.deb
$ sudo dpkg -i rustls-libssl_amd64.deb
$ sudo rustls-libssl-nginx enable
$ sudo systemctl daemon-reload
$ sudo service nginx restart
```

Get more information about our implementation of libssl's ABI from the [rustls-libssl README](rustls-libssl/).

## rustls-libcrypto

This will be implemented using rustls `CryptoProvider`.

# Change Log

We offer a [detailed list of changes](https://github.com/rustls/rustls-openssl-compat/releases) in each release.
