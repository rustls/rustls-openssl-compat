<p align="center">
  <img width="460" height="300" src="https://raw.githubusercontent.com/rustls/rustls/main/admin/rustls-logo-web.png">
</p>

rustls-libssl is a partial reimplementation of the OpenSSL 3 libssl ABI.
It is written in rust and uses rustls.  It does not replace libcrypto:
this is still required.

[![rustls-libssl](https://github.com/rustls/rustls-openssl-compat/actions/workflows/libssl.yaml/badge.svg)](https://github.com/rustls/rustls-openssl-compat/actions/workflows/libssl.yaml)

# Status

This project is experimental.  We have aimed for the subset of libssl
used by:

- curl on Ubuntu 22.04 LTS
- nginx on Ubuntu 22.04 LTS and 24.04 LTS
- nginx on Fedora 40

We have a [compatibility matrix](MATRIX.md) and
[known issues](https://github.com/rustls/rustls-openssl-compat/issues).

# Usage

## Installation
Ubuntu/Debian users:

```shell
$ wget https://github.com/rustls/rustls-openssl-compat/releases/latest/download/rustls-libssl_amd64.deb
$ sudo dpkg -i rustls-libssl_amd64.deb
```

or Fedora/Redhat users:

```shell
$ wget https://github.com/rustls/rustls-openssl-compat/releases/latest/download/rustls-libssl.x86_64.rpm
$ sudo yum localinstall -y rustls-libssl.x86_64.rpm
```

Using curl:

```shell
$ with-rustls-libssl curl https://google.com/
```

`with-rustls-libssl` just sets `LD_LIBRARY_PATH` and executes the given process.

Using nginx:

```shell
$ sudo rustls-libssl-nginx enable
$ sudo systemctl daemon-reload
$ sudo service nginx restart
```

`rustls-libssl-nginx enable` installs a systemd drop-in in `/etc/systemd/system/nginx.service.d/`.
`rustls-libssl-nginx disable` undoes that.

# Changelog
The detailed list of changes in each release can be found at
https://github.com/rustls/rustls-openssl-compat/releases.

# License
rustls-libssl is distributed under the Apache-2.0 license. See [LICENSE](LICENSE).
