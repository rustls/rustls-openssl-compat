#ifndef TESTS_COMMON_H
#define TESTS_COMMON_H

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int trace(int rc, const char *str) {
  printf("%s: %d\n", str, rc);
  return rc;
}

#define TRACE(fn) trace((fn), #fn)

static int require(int expect_rc, int got_rc, const char *str) {
  if (expect_rc != got_rc) {
    printf("REQUIRED(%s) failed: wanted=%d, got=%d\n", str, expect_rc, got_rc);
    abort();
  }
  return got_rc;
}

#define REQUIRE(expect, fn) require((expect), (fn), #fn)

static void hexdump(const char *label, const void *buf, int n) {
  const uint8_t *ubuf = (const uint8_t *)buf;
  printf("%s (%d bytes): ", label, n);
  for (int i = 0; i < n; i++) {
    printf("%02x", ubuf[i]);
  }
  printf("\n");
}

static void dump_openssl_error_stack(void) {
  if (ERR_peek_error() != 0) {
    printf("openssl error: %08lx\n", ERR_peek_error());
    ERR_print_errors_fp(stderr);
  }
}

static void state(const SSL *s) {
  OSSL_HANDSHAKE_STATE st = SSL_get_state(s);
  printf("state: %d (before:%d, init:%d, fin:%d)\n", st, SSL_in_before(s),
         SSL_in_init(s), SSL_is_init_finished(s));
}

static void show_peer_certificate(const char *peer_name, const SSL *ssl) {
  // check the peer certificate and chain
  X509 *cert = SSL_get1_peer_certificate(ssl);
  if (cert) {
    char *name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    printf("%s subject: %s\n", peer_name, name);
    free(name);
  } else {
    printf("%s cert absent\n", peer_name);
  }
  X509_free(cert);

  STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
  if (chain) {
    printf("%d certs in %s chain\n", sk_X509_num(chain), peer_name);
    for (int i = 0; i < sk_X509_num(chain); i++) {
      X509 *cert = sk_X509_value(chain, i);
      char *name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
      printf("  %d: %s\n", i, name);
      free(name);
    }
  } else {
    printf("%s cert chain absent\n", peer_name);
  }
}

#endif // TESTS_COMMON_H
