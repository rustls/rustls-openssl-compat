/**
 * Exercises openssl functions like `SSL_alert_desc_string_long`
 */

#include <stdio.h>

#include <openssl/ssl.h>

int main(void) {
  for (int i = -1; i < 260; i++) {
    printf("%d: '%s' '%s'\n", i, SSL_alert_desc_string(i),
           SSL_alert_desc_string_long(i));
  }
  return 0;
}
