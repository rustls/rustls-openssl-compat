/**
 * Simple client test program.
 *
 * Expects to connect to an `openssl s_server -rev` server.
 */

#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int trace(int rc, const char *str) {
  printf("%s: %d\n", str, rc);
  return rc;
}

#define TRACE(fn) trace((fn), #fn)

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
    printf("openssl error: ");
    ERR_print_errors_fp(stdout);
  }
}

int main(int argc, char **argv) {
  if (argc != 4) {
    printf("%s <host> <port> <ca-cert>\n\n", argv[0]);
    return 1;
  }

  const char *host = argv[1], *port = argv[2], *cacert = argv[3];

  struct addrinfo *result = NULL;
  TRACE(getaddrinfo(host, port, NULL, &result));

  int sock = TRACE(
      socket(result->ai_family, result->ai_socktype, result->ai_protocol));
  TRACE(connect(sock, result->ai_addr, result->ai_addrlen));
  freeaddrinfo(result);

  TRACE(OPENSSL_init_ssl(0, NULL));
  dump_openssl_error_stack();
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  dump_openssl_error_stack();
  if (strcmp(cacert, "insecure") != 0) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    dump_openssl_error_stack();
    TRACE(SSL_CTX_load_verify_file(ctx, cacert));
    dump_openssl_error_stack();
  } else {
    printf("certificate verification disabled\n");
  }
  TRACE(SSL_CTX_set_alpn_protos(ctx, (const uint8_t *)"\x02hi\x05world", 9));
  dump_openssl_error_stack();
  SSL *ssl = SSL_new(ctx);
  dump_openssl_error_stack();
  TRACE(SSL_set1_host(ssl, host));
  dump_openssl_error_stack();
  TRACE(SSL_set_fd(ssl, sock));
  dump_openssl_error_stack();
  TRACE(SSL_connect(ssl));
  dump_openssl_error_stack();

  // check the alpn (also sees that SSL_connect completed handshake)
  const uint8_t *alpn_ptr = NULL;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(ssl, &alpn_ptr, &alpn_len);
  hexdump("alpn", alpn_ptr, alpn_len);

  printf("version: %s\n", SSL_get_version(ssl));
  printf("verify-result: %ld\n", SSL_get_verify_result(ssl));
  printf("cipher: %s\n", SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl)));

  // check the peer certificate and chain
  X509 *cert = SSL_get1_peer_certificate(ssl);
  if (cert) {
    char *name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    printf("server subject: %s\n", name);
    free(name);
  } else {
    printf("server cert absent\n");
  }
  X509_free(cert);

  STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
  if (chain) {
    printf("%d certs in server chain\n", sk_X509_num(chain));
    for (int i = 0; i < sk_X509_num(chain); i++) {
      X509 *cert = sk_X509_value(chain, i);
      char *name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
      printf("  %d: %s\n", i, name);
      free(name);
    }
  } else {
    printf("server cert chain absent\n");
  }

  // write some data and close
  int wr = TRACE(SSL_write(ssl, "hello", 5));
  dump_openssl_error_stack();
  assert(wr == 5);
  TRACE(SSL_shutdown(ssl));
  dump_openssl_error_stack();

  // read back data, using SSL_pending on the way
  char buf[10] = {0};
  int rd = TRACE(SSL_read(ssl, buf, 1));
  dump_openssl_error_stack();
  TRACE(SSL_pending(ssl));
  dump_openssl_error_stack();
  TRACE(SSL_has_pending(ssl));
  dump_openssl_error_stack();
  int rd2 = TRACE(SSL_read(ssl, buf + 1, sizeof(buf) - 1));
  hexdump("result", buf, rd + rd2);
  assert(memcmp(buf, "olleh\n", 6) == 0);

  close(sock);
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  printf("PASS\n\n");
  return 0;
}