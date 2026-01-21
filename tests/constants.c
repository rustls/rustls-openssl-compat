/**
 * Exercises openssl functions like `SSL_alert_desc_string_long`
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/obj_mac.h>
#include <openssl/ssl.h>

void print_group_to_name() {
  // secp{256, 384}r1, x25519
  int supported_nids[] = {NID_X9_62_prime256v1, NID_secp384r1, NID_X25519};
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  if (!ctx) {
    printf("Failed allocating SSL context\n");
    return;
  }
  SSL *ssl_inst = SSL_new(ctx);
  if (!ssl_inst) {
    SSL_CTX_free(ctx);
    printf("Failed allocating SSL struct\n");
    return;
  }

  for (size_t i = 0; i < sizeof(supported_nids) / sizeof(int); i += 1) {
    const char *group_name = SSL_group_to_name(ssl_inst, supported_nids[i]);
    if (group_name)
      printf("%d: '%s'\n", supported_nids[i], group_name);
    else
      printf("Unknown: %d\n", supported_nids[i]);
  }

  SSL_free(ssl_inst);
  SSL_CTX_free(ctx);
}

void print_alert_desc_string() {
  for (int i = -1; i < 260; i++) {
    printf("%d: '%s' '%s'\n", i, SSL_alert_desc_string(i),
           SSL_alert_desc_string_long(i));
  }
}

int main(void) {
  print_alert_desc_string();
  print_group_to_name();
  return 0;
}
