/**
 * Exercises openssl functions like `SSL_CONF_cmd_value_type`
 */

#include <assert.h>
#include <stdio.h>

#include <openssl/ssl.h>

#define CUSTOM_PREFIX "Rustls-"

static const int conf_flags[] = {SSL_CONF_FLAG_SERVER, SSL_CONF_FLAG_CLIENT,
                                 SSL_CONF_FLAG_CERTIFICATE};

#define NUM_FLAGS (sizeof(conf_flags) / sizeof(conf_flags[0]))

static const char *supported_cmds[] = {
    "-min_protocol",
    CUSTOM_PREFIX "min_protocol",
    "MinProtocol",
    CUSTOM_PREFIX "MinProtocol",

    "-max_protocol",
    CUSTOM_PREFIX "max_protocol",
    "MaxProtocol",
    CUSTOM_PREFIX "MaxProtocol",

    "VerifyMode",
    CUSTOM_PREFIX "VerifyMode",

    "-cert",
    CUSTOM_PREFIX "cert",
    "Certificate",
    CUSTOM_PREFIX "Certificate",

    "-key",
    CUSTOM_PREFIX "key",
    "PrivateKey",
    CUSTOM_PREFIX "PrivateKey"

                  "-verifyCApath",
    CUSTOM_PREFIX "verifyCApath",
    "VerifyCAPath",
    CUSTOM_PREFIX "VerifyCAPath",

    "-verifyCAfile",
    CUSTOM_PREFIX "verifyCAfile",
    "VerifyCAFile",
    CUSTOM_PREFIX "VerifyCAFile"

                  "-no_ticket",
    CUSTOM_PREFIX "no_ticket",

    "Options",
    CUSTOM_PREFIX "Options",
};

#define NUM_SUPPORTED_CMDS (sizeof(supported_cmds) / sizeof(supported_cmds[0]))

void test_supported_cmd_value_types(int base_flags, const char *prefix) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);
  assert(SSL_CONF_CTX_set1_prefix(cctx, prefix));

  int flags = base_flags;
  for (unsigned long i = 0; i <= NUM_FLAGS; i++) {
    unsigned int new_flags = SSL_CONF_CTX_set_flags(cctx, flags);
    printf("cctx flags = %u\n", new_flags);

    for (unsigned long j = 0; j < NUM_SUPPORTED_CMDS; j++) {
      const char *cmd = supported_cmds[j];
      int value = SSL_CONF_cmd_value_type(cctx, cmd);
      printf("\tsupported cmd %s has value type %d\n", cmd, value);
    }

    if (i < NUM_FLAGS) {
      flags |= conf_flags[i];
    }
  }

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
}

static const char *fictional_cmds[] = {"", "does-not-exist", "DoesNotExist"};

#define NUM_FICTIONAL_CMDS (sizeof(fictional_cmds) / sizeof(fictional_cmds[0]))

void test_fictional_cmds(void) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);

  // Set all possible flags.
  int all_flags = 0;
  for (unsigned long i = 0; i < NUM_FLAGS; i++) {
    all_flags |= conf_flags[i];
  }
  unsigned int new_flags = SSL_CONF_CTX_set_flags(cctx, all_flags);
  printf("cctx flags = %u\n", new_flags);

  for (unsigned long j = 0; j < NUM_FICTIONAL_CMDS; j++) {
    const char *cmd = fictional_cmds[j];
    int value = SSL_CONF_cmd_value_type(cctx, cmd);
    printf("\tfictional cmd %s has value type %d\n", cmd, value);

    int res = SSL_CONF_cmd(cctx, cmd, "value");
    printf("\tfictional cmd %s set with \"value\" returns %d\n", cmd, res);
    res = SSL_CONF_cmd(cctx, cmd, NULL);
    printf("\tfictional cmd %s set with NULL returns %d\n", cmd, res);
  }

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
}

void cmd_apply_protocol_versions(SSL_CONF_CTX *cctx, const char *min_version,
                                 const char *max_version) {
  int res = SSL_CONF_cmd(cctx, "MinProtocol", min_version);
  printf("\t\tcmd MinProtocol %s returns %d\n", min_version, res);
  res = SSL_CONF_cmd(cctx, "MaxProtocol", max_version);
  printf("\t\tcmd MaxProtocol %s returns %d\n", max_version, res);
}

#define BAD_MIN_PROTOCOL "SSLv69"
#define BAD_MAX_PROTOCOL "SSLv70"
#define GOOD_MIN_PROTOCOL "TLSv1.3"
#define GOOD_MAX_PROTOCOL "TLSv1.2"

void test_min_max_versions(void) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);

  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);

  printf("Pre-ctx\n");
  printf("\tBad version:\n");
  cmd_apply_protocol_versions(cctx, BAD_MIN_PROTOCOL, BAD_MAX_PROTOCOL);

  printf("\tGood version:\n");
  cmd_apply_protocol_versions(cctx, GOOD_MIN_PROTOCOL, GOOD_MAX_PROTOCOL);

  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  assert(ctx != NULL);
  SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

  printf("Post-ctx:\n");
  printf("\tBad version:\n");
  cmd_apply_protocol_versions(cctx, BAD_MIN_PROTOCOL, BAD_MAX_PROTOCOL);
  printf("\t\tSSL_CTX_get_min_proto_version 0x%lx\n",
         SSL_CTX_get_min_proto_version(ctx));
  printf("\t\tSSL_CTX_get_max_proto_version 0x%lx\n",
         SSL_CTX_get_max_proto_version(ctx));

  printf("\tGood version:\n");
  cmd_apply_protocol_versions(cctx, GOOD_MIN_PROTOCOL, GOOD_MAX_PROTOCOL);
  printf("\t\tSSL_CTX_get_min_proto_version 0x%lx\n",
         SSL_CTX_get_min_proto_version(ctx));
  printf("\t\tSSL_CTX_get_max_proto_version 0x%lx\n",
         SSL_CTX_get_max_proto_version(ctx));

  SSL *ssl = SSL_new(ctx);
  assert(ssl != NULL);
  printf("Post-ssl:\n");
  printf("\tBad version:\n");
  cmd_apply_protocol_versions(cctx, BAD_MIN_PROTOCOL, BAD_MAX_PROTOCOL);
  printf("\t\tSSL_get_min_proto_version 0x%lx\n",
         SSL_get_min_proto_version(ssl));
  printf("\t\tSSL_get_max_proto_version 0x%lx\n",
         SSL_get_max_proto_version(ssl));

  printf("\tGood version:\n");
  cmd_apply_protocol_versions(cctx, GOOD_MIN_PROTOCOL, GOOD_MAX_PROTOCOL);
  printf("\t\tSSL_get_min_proto_version 0x%lx\n",
         SSL_get_min_proto_version(ssl));
  printf("\t\tSSL_get_max_proto_version 0x%lx\n",
         SSL_get_max_proto_version(ssl));

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
  SSL_CTX_free(ctx);
  SSL_free(ssl);
}

static const char *verify_modes[] = {
    NULL,   "",        "Ludicrous", "Ludicrous,Absurd",
    "Peer", "Request", "Require",   "Request,Require",
};

#define NUM_VERIFY_MODES (sizeof(verify_modes) / sizeof(verify_modes[0]))

void set_verify_modes(SSL_CONF_CTX *cctx, SSL_CTX *ctx, SSL *ssl) {
  for (unsigned long i = 0; i < NUM_VERIFY_MODES; i++) {
    const char *mode = verify_modes[i];
    int res = SSL_CONF_cmd(cctx, "VerifyMode", mode);
    printf("\t\tcmd VerifyMode '%s' returns %d\n", mode == NULL ? "NULL" : mode,
           res);
    if (ctx != NULL) {
      printf("\t\tSSL_CTX_get_verify_mode %d\n", SSL_CTX_get_verify_mode(ctx));
    }
    if (ssl != NULL) {
      printf("\t\tSSL_get_verify_mode %d\n", SSL_get_verify_mode(ssl));
    }
  }
}

void test_verify_mode(void) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);

  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
  printf("\tPre-ctx (not client or server):\n");
  set_verify_modes(cctx, NULL, NULL);

  printf("\tPre-ctx (client):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
  set_verify_modes(cctx, NULL, NULL);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CLIENT);

  printf("\tPre-ctx (server):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
  set_verify_modes(cctx, NULL, NULL);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_SERVER);

  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  assert(ctx != NULL);
  SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

  printf("\tWith ctx (not client or server):\n");
  set_verify_modes(cctx, ctx, NULL);

  printf("\tWith ctx (client):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
  set_verify_modes(cctx, ctx, NULL);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CLIENT);

  printf("\tWith ctx (server):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
  set_verify_modes(cctx, ctx, NULL);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_SERVER);

  SSL *ssl = SSL_new(ctx);
  assert(ssl != NULL);
  SSL_CONF_CTX_set_ssl(cctx, ssl);

  printf("\tWith ssl (not client or server):\n");
  set_verify_modes(cctx, NULL, ssl);

  printf("\tWith ssl (client):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
  set_verify_modes(cctx, NULL, ssl);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CLIENT);

  printf("\tWith ssl (server):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
  set_verify_modes(cctx, NULL, ssl);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_SERVER);

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
  SSL_CTX_free(ctx);
  SSL_free(ssl);
}

void set_cert_and_key(SSL_CONF_CTX *cctx) {
  // Note: we don't test invalid values here - our implementation diverges
  //       slightly due to early processing of the cert/key pair.
  printf("\t\tcmd Certificate NULL returns %d\n",
         SSL_CONF_cmd(cctx, "Certificate", NULL));
  printf("\t\tcmd Certificate 'test-ca/rsa/server.cert' returns %d\n",
         SSL_CONF_cmd(cctx, "Certificate", "test-ca/rsa/server.cert"));

  printf("\t\tcmd PrivateKey NULL returns %d\n",
         SSL_CONF_cmd(cctx, "PrivateKey", NULL));
  printf("\t\tcmd PrivateKey 'test-ca/rsa/server.key' returns %d\n",
         SSL_CONF_cmd(cctx, "PrivateKey", "test-ca/rsa/server.key"));
}

void test_certificate_and_private_key(void) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);

  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
  printf("\tPre-ctx (not certificate flag):\n");
  set_cert_and_key(cctx);

  printf("\tPre-ctx (certificate flag):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
  set_cert_and_key(cctx);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);

  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  assert(ctx != NULL);
  SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

  printf("\tWith ctx (not certificate flag):\n");
  set_cert_and_key(cctx);

  printf("\tWith ctx (certificate flag):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
  set_cert_and_key(cctx);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);

  // Note: we do not test with `SSL_CONF_set_ssl()` here - we lack
  //       support for the `Certificate` command updating an `SSL`
  //       struct at this time.

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
  SSL_CTX_free(ctx);
}

void set_verify_ca(SSL_CONF_CTX *cctx) {
  // Note: we don't test invalid values here - our implementation diverges
  //       slightly due to later processing of the cert file/dir.
  printf("\t\tcmd VerifyCAPath NULL returns %d\n",
         SSL_CONF_cmd(cctx, "VerifyCAPath", NULL));
  printf("\t\tcmd VerifyCAPath 'test-ca/rsa' returns %d\n",
         SSL_CONF_cmd(cctx, "VerifyCAPath", "test-ca/rsa"));

  printf("\t\tcmd VerifyCAFile NULL returns %d\n",
         SSL_CONF_cmd(cctx, "VerifyCAFile", NULL));
  printf("\t\tcmd VerifyCAFile 'test-ca/rsa/ca.cert' returns %d\n",
         SSL_CONF_cmd(cctx, "VerifyCAFile", "test-ca/rsa/ca.cert"));
}

void test_verify_ca_path_file(void) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);

  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);

  printf("\tPre-ctx (not certificate flag):\n");
  set_verify_ca(cctx);

  printf("\tPre-ctx (certificate flag):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
  set_verify_ca(cctx);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);

  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  assert(ctx != NULL);
  SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

  printf("\tWith ctx (not certificate flag):\n");
  set_verify_ca(cctx);

  printf("\tWith ctx (certificate flag):\n");
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
  set_verify_ca(cctx);
  SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);

  // Note: we do not test with `SSL_CONF_set_ssl()` here - we lack
  //       support for the `Certificate` command updating an `SSL`
  //       struct at this time.

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
  SSL_CTX_free(ctx);
}

#define NO_TICKET_SET(X) (((X)&SSL_OP_NO_TICKET) == SSL_OP_NO_TICKET)

void test_no_ticket(void) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);

  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CMDLINE);

  printf("\tPre-ctx:\n");
  printf("\t\tcmd -no_ticket NULL returns %d\n",
         SSL_CONF_cmd(cctx, "-no_ticket", NULL));

  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  assert(ctx != NULL);
  SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

  printf("\tWith ctx:\n");
  printf("\t\tSSL_OP_NO_TICKET before: %d\n",
         NO_TICKET_SET(SSL_CTX_get_options(ctx)));
  printf("\t\tcmd -no_ticket NULL returns %d\n",
         SSL_CONF_cmd(cctx, "-no_ticket", NULL));
  printf("\t\tSSL_OP_NO_TICKET after: %d\n",
         NO_TICKET_SET(SSL_CTX_get_options(ctx)));

  SSL_CTX_clear_options(
      ctx, SSL_OP_NO_TICKET); // Reset the ctx opts since ssl will inherit.

  SSL *ssl = SSL_new(ctx);
  assert(ssl != NULL);
  SSL_CONF_CTX_set_ssl(cctx, ssl);

  printf("\tWith ssl:\n");
  printf("\t\tSSL_OP_NO_TICKET before: %d\n",
         NO_TICKET_SET(SSL_get_options(ssl)));
  printf("\t\tcmd -no_ticket NULL returns %d\n",
         SSL_CONF_cmd(cctx, "-no_ticket", NULL));
  printf("\t\tSSL_OP_NO_TICKET after: %d\n",
         NO_TICKET_SET(SSL_get_options(ssl)));

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
  SSL_CTX_free(ctx);
  SSL_free(ssl);
}

int main(void) {
  printf("Supported commands:\n");
  printf("no base flags, default prefix:\n");
  test_supported_cmd_value_types(0, "");
  printf("no base flags, custom prefix:\n");
  test_supported_cmd_value_types(0, CUSTOM_PREFIX);

  printf("CMDLINE base flags, default prefix:\n");
  test_supported_cmd_value_types(SSL_CONF_FLAG_CMDLINE, "");
  printf("CMDLINE base flags,custom prefix:\n");
  test_supported_cmd_value_types(SSL_CONF_FLAG_CMDLINE, CUSTOM_PREFIX);

  printf("FILE base flags, default prefix:\n");
  test_supported_cmd_value_types(SSL_CONF_FLAG_FILE, "");
  printf("FILE base flags, custom prefix:\n");
  test_supported_cmd_value_types(SSL_CONF_FLAG_FILE, CUSTOM_PREFIX);

  printf("Fictional commands:\n");
  test_fictional_cmds();

  printf("Min/Max version:\n");
  test_min_max_versions();

  printf("VerifyMode:\n");
  test_verify_mode();

  printf("Certificate/PrivateKey:\n");
  test_certificate_and_private_key();

  printf("VerifyCAPath/VerifyCAFile:\n");
  test_verify_ca_path_file();

  printf("no_ticket\n");
  test_no_ticket();
}
