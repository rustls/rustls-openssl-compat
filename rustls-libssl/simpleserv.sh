#!/usr/bin/env bash
openssl s_server \
  -cert test-ca/rsa/end.cert \
  -cert_chain test-ca/rsa/inter.cert \
  -key test-ca/rsa/end.key \
  -alpn "hello,world" \
  -accept localhost:4443 \
  -rev
