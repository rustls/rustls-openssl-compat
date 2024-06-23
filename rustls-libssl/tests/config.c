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
    "-min_protocol", CUSTOM_PREFIX "min_protocol",
    "MinProtocol",   CUSTOM_PREFIX "MinProtocol",

    "-max_protocol", CUSTOM_PREFIX "max_protocol",
    "MaxProtocol",   CUSTOM_PREFIX "MaxProtocol",

    "VerifyMode",    CUSTOM_PREFIX "VerifyMode",
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
}
