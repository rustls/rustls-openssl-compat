/**
 * Simple server test program.
 *
 * Listens on the given port, and accepts one connection on it.
 *
 */

#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "helpers.h"

static int ssl_ctx_ex_data_idx_message;
static int ssl_ex_data_idx_message;

static int alpn_cookie = 12345;

static int alpn_callback(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                         const uint8_t *in, unsigned int inlen, void *arg) {
  printf("in alpn_callback:\n");
  assert(ssl != NULL);
  assert(arg == &alpn_cookie);
  printf("  ssl_ex_data_idx_message: %s\n",
         (const char *)SSL_get_ex_data(ssl, ssl_ex_data_idx_message));
  hexdump("  in", in, (int)inlen);
  if (SSL_select_next_proto((uint8_t **)out, outlen,
                            (const uint8_t *)"\x08http/1.1", 9, in,
                            inlen) == OPENSSL_NPN_NEGOTIATED) {
    hexdump("  select", *out, (int)*outlen);
    return SSL_TLSEXT_ERR_OK;
  } else {
    printf("  alpn failed\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
}

static int cert_cookie = 12345;

static int cert_callback(SSL *ssl, void *arg) {
  printf("in cert_callback\n");
  assert(ssl != NULL);
  assert(arg == &cert_cookie);
  printf("  ssl_ex_data_idx_message: %s\n",
         (const char *)SSL_get_ex_data(ssl, ssl_ex_data_idx_message));
  return 1;
}

static int sni_cookie = 12345;

static int sni_callback(SSL *ssl, int *al, void *arg) {
  printf("in sni_callback\n");
  assert(ssl != NULL);
  assert(arg == &sni_cookie);
  assert(*al == SSL_AD_UNRECOGNIZED_NAME);
  printf("  SSL_get_servername: %s (%d)\n",
         SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name),
         SSL_get_servername_type(ssl));
  printf("  ssl_ex_data_idx_message: %s\n",
         (const char *)SSL_get_ex_data(ssl, ssl_ex_data_idx_message));
  return SSL_TLSEXT_ERR_OK;
}

static int sess_new_callback(SSL *ssl, SSL_SESSION *sess) {
  printf("in sess_new_callback\n");
  assert(ssl != NULL);
  assert(sess != NULL);
  unsigned id_len = 0;
  SSL_SESSION_get_id(sess, &id_len);
  printf("  SSL_SESSION_get_id len=%u\n", id_len);
  TRACE(SSL_SESSION_set_timeout(sess, SSL_SESSION_get_timeout(sess)));
  TRACE(SSL_SESSION_set1_id_context(sess, (uint8_t *)"hello", 5));
  return 0;
}

static SSL_SESSION *sess_get_callback(SSL *ssl, const uint8_t *id, int id_len,
                                      int *copy) {
  (void)id;
  printf("in sess_get_callback\n");
  assert(ssl != NULL);
  printf("  id_len=%d\n", id_len);
  *copy = 0;
  return NULL;
}

static void sess_remove_callback(SSL_CTX *ctx, SSL_SESSION *sess) {
  printf("in sess_remove_callback\n");
  assert(ctx != NULL);
  assert(sess != NULL);
}

int main(int argc, char **argv) {
  if (argc != 6) {
    printf("%s <port> <key-file> <cert-chain-file> <cacert>|unauth "
           "none|internal|external|internal+external|ticket\n\n",
           argv[0]);
    return 1;
  }

  const char *port = argv[1], *keyfile = argv[2], *certfile = argv[3],
             *cacert = argv[4], *cache = argv[5];

  int listener = TRACE(socket(AF_INET, SOCK_STREAM, 0));
  struct sockaddr_in us, them;
  memset(&us, 0, sizeof(us));
  us.sin_family = AF_INET;
  us.sin_addr.s_addr = htonl(INADDR_ANY);
  us.sin_port = htons(atoi(port));
  REQUIRE(0, bind(listener, (struct sockaddr *)&us, sizeof(us)));
  REQUIRE(0, listen(listener, 5));
  printf("listening\n");
  fflush(stdout);
  socklen_t them_len = sizeof(them);
  int sock = TRACE(accept(listener, (struct sockaddr *)&them, &them_len));

  TRACE(OPENSSL_init_ssl(0, NULL));
  dump_openssl_error_stack();
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  dump_openssl_error_stack();
  if (strcmp(cacert, "unauth") != 0) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    dump_openssl_error_stack();
    TRACE(SSL_CTX_load_verify_file(ctx, cacert));
    dump_openssl_error_stack();
  } else {
    printf("client auth disabled\n");
  }

  ssl_ctx_ex_data_idx_message =
      SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  TRACE(SSL_CTX_set_ex_data(ctx, ssl_ctx_ex_data_idx_message,
                            "hello from SSL_CTX!"));
  printf("ssl_ctx_ex_data_idx_message: %s\n",
         (const char *)SSL_CTX_get_ex_data(ctx, ssl_ctx_ex_data_idx_message));

  SSL_CTX_set_alpn_select_cb(ctx, alpn_callback, &alpn_cookie);
  dump_openssl_error_stack();

  SSL_CTX_set_cert_cb(ctx, cert_callback, &cert_cookie);
  dump_openssl_error_stack();

  SSL_CTX_set_tlsext_servername_callback(ctx, sni_callback);
  dump_openssl_error_stack();
  SSL_CTX_set_tlsext_servername_arg(ctx, &sni_cookie);
  dump_openssl_error_stack();

  // Default to no tickets.
  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
  TRACE(SSL_CTX_set_num_tickets(ctx, 0));

  if (strstr(cache, "external")) {
    SSL_CTX_sess_set_new_cb(ctx, sess_new_callback);
    SSL_CTX_sess_set_get_cb(ctx, sess_get_callback);
    SSL_CTX_sess_set_remove_cb(ctx, sess_remove_callback);
  }

  if (strstr(cache, "internal")) {
    TRACE(SSL_CTX_sess_set_cache_size(ctx, 10));
    TRACE(SSL_CTX_sess_get_cache_size(ctx));
    TRACE(SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER));
  }

  if (strcmp(cache, "none") == 0) {
    TRACE(SSL_CTX_set_session_cache_mode(ctx, 0));
  }

  if (strcmp(cache, "ticket") == 0) {
    SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);
    TRACE(SSL_CTX_set_num_tickets(ctx, 3));
  }
  TRACE(SSL_CTX_get_num_tickets(ctx));

  X509 *server_cert = NULL;
  EVP_PKEY *server_key = NULL;
  TRACE(SSL_CTX_use_certificate_chain_file(ctx, certfile));
  TRACE(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM));
  server_key = SSL_CTX_get0_privatekey(ctx);
  server_cert = SSL_CTX_get0_certificate(ctx);

  printf("SSL_CTX_get_max_early_data default %lu\n",
         (unsigned long)SSL_CTX_get_max_early_data(ctx));

  SSL *ssl = SSL_new(ctx);
  dump_openssl_error_stack();
  printf("SSL_new: SSL_get_privatekey %s SSL_CTX_get0_privatekey\n",
         SSL_get_privatekey(ssl) == server_key ? "same as" : "differs to");
  printf("SSL_new: SSL_get_certificate %s SSL_CTX_get0_certificate\n",
         SSL_get_certificate(ssl) == server_cert ? "same as" : "differs to");
  TRACE(SSL_get_num_tickets(ssl));

  ssl_ex_data_idx_message = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  TRACE(SSL_set_ex_data(ssl, ssl_ex_data_idx_message, "hello from SSL!"));
  printf("ssl_ex_data_idx_message: %s\n",
         (const char *)SSL_get_ex_data(ssl, ssl_ex_data_idx_message));

  state(ssl);
  TRACE(SSL_set_fd(ssl, sock));
  dump_openssl_error_stack();
  state(ssl);
  TRACE(SSL_accept(ssl));
  dump_openssl_error_stack();
  state(ssl);
  printf("SSL_accept: SSL_get_privatekey %s SSL_CTX_get0_privatekey\n",
         SSL_get_privatekey(ssl) == server_key ? "same as" : "differs to");
  printf("SSL_accept: SSL_get_certificate %s SSL_CTX_get0_certificate\n",
         SSL_get_certificate(ssl) == server_cert ? "same as" : "differs to");

  // check the alpn (also sees that SSL_accept completed handshake)
  const uint8_t *alpn_ptr = NULL;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(ssl, &alpn_ptr, &alpn_len);
  hexdump("alpn", alpn_ptr, alpn_len);

  printf("version: %s\n", SSL_get_version(ssl));
  printf("numeric version: %d\n", SSL_version(ssl));
  printf("verify-result: %ld\n", SSL_get_verify_result(ssl));
  printf("cipher: %s\n", SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl)));
  int cipher_nid = 0;
  TRACE(SSL_get_peer_signature_type_nid(ssl, &cipher_nid));
  dump_openssl_error_stack();
  printf("cipher NID: %d\n", cipher_nid);

  printf("SSL_get_servername: %s (%d)\n",
         SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name),
         SSL_get_servername_type(ssl));

  show_peer_certificate("client", ssl);

  // read "request"
  while (1) {
    char buf[128] = {0};
    int rd = TRACE(SSL_read(ssl, buf, sizeof(buf)));
    dump_openssl_error_stack();
    TRACE(SSL_pending(ssl));
    dump_openssl_error_stack();
    TRACE(SSL_has_pending(ssl));
    dump_openssl_error_stack();
    if (rd == 0) {
      printf("nothing read\n");
      break;
    } else {
      hexdump("result", buf, rd);
    }
    state(ssl);

    if (!TRACE(SSL_has_pending(ssl))) {
      break;
    }
  }

  // write some data and close
  const char response[] = "HTTP/1.0 200 OK\r\n\r\nhello\r\n";
  int wr = TRACE(SSL_write(ssl, response, sizeof(response) - 1));
  dump_openssl_error_stack();
  assert(wr == sizeof(response) - 1);
  TRACE(SSL_shutdown(ssl));
  dump_openssl_error_stack();

  printf("ssl_ex_data_idx_message: %s\n",
         (const char *)SSL_get_ex_data(ssl, ssl_ex_data_idx_message));
  printf("ssl_ctx_ex_data_idx_message: %s\n",
         (const char *)SSL_CTX_get_ex_data(ctx, ssl_ctx_ex_data_idx_message));
  close(sock);
  close(listener);
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  printf("PASS\n\n");
  return 0;
}
