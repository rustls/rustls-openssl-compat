# Rustls OpenSSL Compatibility Layer

This is an implementation of the OpenSSL libssl ABI which uses [Rustls](https://github.com/rustls/rustls/) for TLS.

## Use With Nginx on Ubuntu

Initially we targeted support for use with Nginx on Ubuntu 22.04 or higher. It's very simple to replace Nginx usage of OpenSSL with Rustls on Ubuntu:

```
$ wget https://github.com/rustls/rustls-openssl-compat/releases/latest/download/rustls-libssl_amd64.deb
$ sudo dpkg -i rustls-libssl_amd64.deb
$ sudo rustls-libssl-nginx enable
$ sudo systemctl daemon-reload
$ sudo service nginx restart
```

## Future

* Simple Fedora-based packaging and instructions.
* Additional libssl ABI surface implementation.
* Provide an implementation of OpenSSL's libcrypto ABI which uses rustls `cryptoprovider`.
