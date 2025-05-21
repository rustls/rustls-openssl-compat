/**
 * Exercises SSL_CIPHER functions like `SSL_CIPHER_get_protocol_id`
 */

#include <stdio.h>

#include <openssl/ssl.h>

static void print_cipher(const SSL_CIPHER *cipher) {
  if (cipher) {
    printf("openssl_id=0x%08x protocol_id=0x%08x auth=%d ",
           SSL_CIPHER_get_id(cipher), SSL_CIPHER_get_protocol_id(cipher),
           SSL_CIPHER_get_auth_nid(cipher));
  } else {
    // SSL_CIPHER_get_id(NULL), SSL_CIPHER_get_protocol_id(NULL),
    // SSL_CIPHER_get_auth_nid(NULL) all segfault
    printf("openssl_id=undef protocol_id=undef auth=undef ");
  }
  int alg_bits = -1;
  printf("bits=%d ", SSL_CIPHER_get_bits(cipher, &alg_bits));
  printf("alg_bits=%d\n", alg_bits);

  printf("name='%s' standard_name='%s' version='%s'\n",
         SSL_CIPHER_get_name(cipher), SSL_CIPHER_standard_name(cipher),
         SSL_CIPHER_get_version(cipher));
  if (cipher) {
    char *desc = SSL_CIPHER_description(cipher, NULL, 0);
    printf("desc='%s'\n", desc);
    OPENSSL_free(desc);
  } else {
    // SSL_CIPHER_description(NULL) documented as working, it actually segfaults
    printf("desc=undef\n");
  }
}

static void cipher(SSL *ssl, uint16_t protocol_id) {
  const uint8_t id_bytes[2] = {
      (protocol_id & 0xff00) >> 8,
      protocol_id & 0xff,
  };
  const SSL_CIPHER *const cipher = SSL_CIPHER_find(ssl, id_bytes);
  if (!cipher) {
    printf("Nothing found for 0x%04x\n", protocol_id);
    return;
  }
  printf("Found for 0x%04x\n", protocol_id);
  print_cipher(cipher);
}

int main(void) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  SSL *ssl = SSL_new(ctx);
  // We only care about SSL_CIPHERs representing suites implemented
  // by rustls: this is not exhaustive.
  cipher(ssl, 0xc02b); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  cipher(ssl, 0xc02c); // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  cipher(ssl, 0xcca9); // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  cipher(ssl, 0xc02f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  cipher(ssl, 0xc030); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  cipher(ssl, 0xcca8); // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  cipher(ssl, 0x1301); // TLS13_AES_128_GCM_SHA256
  cipher(ssl, 0x1302); // TLS13_AES_256_GCM_SHA384
  cipher(ssl, 0x1303); // TLS13_CHACHA20_POLY1305_SHA256
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  print_cipher(NULL);
  return 0;
}
