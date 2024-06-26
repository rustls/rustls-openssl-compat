| Symbol | curl[^curl] | nginx[^nginx] | implemented? |
|---|---|---|---|
| `BIO_f_ssl`  | :white_check_mark: |  | :white_check_mark: |
| `BIO_new_buffer_ssl_connect`  |  |  |  |
| `BIO_new_ssl`  |  |  |  |
| `BIO_new_ssl_connect`  |  |  |  |
| `BIO_ssl_copy_session_id`  |  |  |  |
| `BIO_ssl_shutdown`  |  |  |  |
| `DTLS_client_method`  |  |  |  |
| `DTLS_get_data_mtu`  |  |  |  |
| `DTLS_method`  |  |  |  |
| `DTLS_server_method`  |  |  |  |
| `DTLS_set_timer_cb`  |  |  |  |
| `DTLSv1_2_client_method` [^deprecatedin_1_1_0] [^dtls1_2_method] |  |  |  |
| `DTLSv1_2_method` [^deprecatedin_1_1_0] [^dtls1_2_method] |  |  |  |
| `DTLSv1_2_server_method` [^deprecatedin_1_1_0] [^dtls1_2_method] |  |  |  |
| `DTLSv1_client_method` [^deprecatedin_1_1_0] [^dtls1_method] |  |  |  |
| `DTLSv1_listen` [^sock] |  |  |  |
| `DTLSv1_method` [^deprecatedin_1_1_0] [^dtls1_method] |  |  |  |
| `DTLSv1_server_method` [^deprecatedin_1_1_0] [^dtls1_method] |  |  |  |
| `ERR_load_SSL_strings` [^deprecatedin_3_0] |  |  |  |
| `OPENSSL_cipher_name`  |  |  |  |
| `OPENSSL_init_ssl`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `OSSL_default_cipher_list`  |  |  |  |
| `OSSL_default_ciphersuites`  |  |  |  |
| `PEM_read_SSL_SESSION` [^stdio] |  |  |  |
| `PEM_read_bio_SSL_SESSION`  |  |  |  |
| `PEM_write_SSL_SESSION` [^stdio] |  |  |  |
| `PEM_write_bio_SSL_SESSION`  |  |  |  |
| `SRP_Calc_A_param` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CIPHER_description`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CIPHER_find`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CIPHER_get_auth_nid`  |  |  |  |
| `SSL_CIPHER_get_bits`  |  |  | :white_check_mark: |
| `SSL_CIPHER_get_cipher_nid`  |  |  |  |
| `SSL_CIPHER_get_digest_nid`  |  |  |  |
| `SSL_CIPHER_get_handshake_digest`  |  |  |  |
| `SSL_CIPHER_get_id`  |  |  | :white_check_mark: |
| `SSL_CIPHER_get_kx_nid`  |  |  |  |
| `SSL_CIPHER_get_name`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CIPHER_get_protocol_id`  |  |  | :white_check_mark: |
| `SSL_CIPHER_get_version`  |  |  | :white_check_mark: |
| `SSL_CIPHER_is_aead`  |  |  |  |
| `SSL_CIPHER_standard_name`  |  |  | :white_check_mark: |
| `SSL_COMP_add_compression_method`  |  |  |  |
| `SSL_COMP_get0_name`  |  |  |  |
| `SSL_COMP_get_compression_methods`  |  |  |  |
| `SSL_COMP_get_id`  |  |  |  |
| `SSL_COMP_get_name`  |  |  |  |
| `SSL_COMP_set0_compression_methods`  |  |  |  |
| `SSL_CONF_CTX_clear_flags`  |  |  | :white_check_mark: |
| `SSL_CONF_CTX_finish`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CONF_CTX_free`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CONF_CTX_new`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CONF_CTX_set1_prefix`  |  |  | :white_check_mark: |
| `SSL_CONF_CTX_set_flags`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CONF_CTX_set_ssl`  |  |  | :white_check_mark: |
| `SSL_CONF_CTX_set_ssl_ctx`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CONF_cmd`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CONF_cmd_argv`  |  |  |  |
| `SSL_CONF_cmd_value_type`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_SRP_CTX_free` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CTX_SRP_CTX_init` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CTX_add1_to_CA_list`  |  |  |  |
| `SSL_CTX_add_client_CA`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_add_client_custom_ext`  |  |  |  |
| `SSL_CTX_add_custom_ext`  |  |  |  |
| `SSL_CTX_add_server_custom_ext`  |  |  |  |
| `SSL_CTX_add_session`  |  |  |  |
| `SSL_CTX_callback_ctrl`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_check_private_key`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_CTX_clear_options`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_config`  |  |  |  |
| `SSL_CTX_ct_is_enabled` [^ct] |  |  |  |
| `SSL_CTX_ctrl`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_dane_clear_flags`  |  |  |  |
| `SSL_CTX_dane_enable`  |  |  |  |
| `SSL_CTX_dane_mtype_set`  |  |  |  |
| `SSL_CTX_dane_set_flags`  |  |  |  |
| `SSL_CTX_enable_ct` [^ct] |  |  |  |
| `SSL_CTX_flush_sessions`  |  |  |  |
| `SSL_CTX_free`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get0_CA_list`  |  |  |  |
| `SSL_CTX_get0_certificate`  |  |  | :white_check_mark: |
| `SSL_CTX_get0_ctlog_store` [^ct] |  |  |  |
| `SSL_CTX_get0_param`  |  |  |  |
| `SSL_CTX_get0_privatekey`  |  |  | :white_check_mark: |
| `SSL_CTX_get0_security_ex_data`  |  |  |  |
| `SSL_CTX_get_cert_store`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get_ciphers`  |  |  |  |
| `SSL_CTX_get_client_CA_list`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_CTX_get_client_cert_cb`  |  |  |  |
| `SSL_CTX_get_default_passwd_cb`  |  |  |  |
| `SSL_CTX_get_default_passwd_cb_userdata`  |  |  |  |
| `SSL_CTX_get_ex_data`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get_info_callback`  |  |  |  |
| `SSL_CTX_get_keylog_callback`  |  |  |  |
| `SSL_CTX_get_max_early_data`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get_num_tickets`  |  |  | :white_check_mark: |
| `SSL_CTX_get_options`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get_quiet_shutdown`  |  |  |  |
| `SSL_CTX_get_record_padding_callback_arg`  |  |  |  |
| `SSL_CTX_get_recv_max_early_data`  |  |  |  |
| `SSL_CTX_get_security_callback`  |  |  |  |
| `SSL_CTX_get_security_level`  |  |  |  |
| `SSL_CTX_get_ssl_method`  |  |  |  |
| `SSL_CTX_get_timeout`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get_verify_callback`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get_verify_depth`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_get_verify_mode`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_has_client_custom_ext`  |  |  |  |
| `SSL_CTX_load_verify_dir`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_CTX_load_verify_file`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_CTX_load_verify_locations`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_load_verify_store`  |  |  |  |
| `SSL_CTX_new`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_new_ex`  |  |  |  |
| `SSL_CTX_remove_session`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_CTX_sess_get_get_cb`  |  |  |  |
| `SSL_CTX_sess_get_new_cb`  |  |  |  |
| `SSL_CTX_sess_get_remove_cb`  |  |  |  |
| `SSL_CTX_sess_set_get_cb`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_sess_set_new_cb`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_sess_set_remove_cb`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_sessions`  |  |  |  |
| `SSL_CTX_set0_CA_list`  |  |  |  |
| `SSL_CTX_set0_ctlog_store` [^ct] |  |  |  |
| `SSL_CTX_set0_security_ex_data`  |  |  |  |
| `SSL_CTX_set0_tmp_dh_pkey`  |  |  |  |
| `SSL_CTX_set1_cert_store`  |  |  |  |
| `SSL_CTX_set1_param`  |  |  |  |
| `SSL_CTX_set_allow_early_data_cb`  |  |  |  |
| `SSL_CTX_set_alpn_protos`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_alpn_select_cb`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_async_callback`  |  |  |  |
| `SSL_CTX_set_async_callback_arg`  |  |  |  |
| `SSL_CTX_set_block_padding`  |  |  |  |
| `SSL_CTX_set_cert_cb`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_cert_store`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_CTX_set_cert_verify_callback`  |  |  |  |
| `SSL_CTX_set_cipher_list`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_ciphersuites`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_client_CA_list`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_CTX_set_client_cert_cb`  |  |  |  |
| `SSL_CTX_set_client_cert_engine` [^engine] |  |  |  |
| `SSL_CTX_set_client_hello_cb`  |  |  |  |
| `SSL_CTX_set_cookie_generate_cb`  |  |  |  |
| `SSL_CTX_set_cookie_verify_cb`  |  |  |  |
| `SSL_CTX_set_ct_validation_callback` [^ct] |  |  |  |
| `SSL_CTX_set_ctlog_list_file` [^ct] |  |  |  |
| `SSL_CTX_set_default_ctlog_list_file` [^ct] |  |  |  |
| `SSL_CTX_set_default_passwd_cb`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_default_passwd_cb_userdata`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_default_read_buffer_len`  |  |  |  |
| `SSL_CTX_set_default_verify_dir`  |  |  | :white_check_mark: |
| `SSL_CTX_set_default_verify_file`  |  |  | :white_check_mark: |
| `SSL_CTX_set_default_verify_paths`  |  |  | :white_check_mark: |
| `SSL_CTX_set_default_verify_store`  |  |  | :exclamation: [^stub] |
| `SSL_CTX_set_ex_data`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_generate_session_id`  |  |  |  |
| `SSL_CTX_set_info_callback`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_CTX_set_keylog_callback`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_max_early_data`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_msg_callback`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_next_proto_select_cb` [^nextprotoneg] | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_next_protos_advertised_cb` [^nextprotoneg] |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_CTX_set_not_resumable_session_callback`  |  |  |  |
| `SSL_CTX_set_num_tickets`  |  |  | :white_check_mark: |
| `SSL_CTX_set_options`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_post_handshake_auth`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_psk_client_callback` [^psk] |  |  |  |
| `SSL_CTX_set_psk_find_session_callback`  |  |  |  |
| `SSL_CTX_set_psk_server_callback` [^psk] |  |  |  |
| `SSL_CTX_set_psk_use_session_callback`  |  |  |  |
| `SSL_CTX_set_purpose`  |  |  |  |
| `SSL_CTX_set_quiet_shutdown`  |  |  |  |
| `SSL_CTX_set_record_padding_callback`  |  |  |  |
| `SSL_CTX_set_record_padding_callback_arg`  |  |  |  |
| `SSL_CTX_set_recv_max_early_data`  |  |  |  |
| `SSL_CTX_set_security_callback`  |  |  |  |
| `SSL_CTX_set_security_level`  |  |  |  |
| `SSL_CTX_set_session_id_context`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_session_ticket_cb`  |  |  |  |
| `SSL_CTX_set_srp_cb_arg` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CTX_set_srp_client_pwd_callback` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CTX_set_srp_password` [^deprecatedin_3_0] [^srp] | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_srp_strength` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CTX_set_srp_username` [^deprecatedin_3_0] [^srp] | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_set_srp_username_callback` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CTX_set_srp_verify_param_callback` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_CTX_set_ssl_version` [^deprecatedin_3_0] |  |  |  |
| `SSL_CTX_set_stateless_cookie_generate_cb`  |  |  |  |
| `SSL_CTX_set_stateless_cookie_verify_cb`  |  |  |  |
| `SSL_CTX_set_timeout`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_tlsext_max_fragment_length`  |  |  |  |
| `SSL_CTX_set_tlsext_ticket_key_evp_cb`  |  |  |  |
| `SSL_CTX_set_tlsext_use_srtp` [^srtp] |  |  |  |
| `SSL_CTX_set_tmp_dh_callback` [^deprecatedin_3_0] [^dh] |  |  |  |
| `SSL_CTX_set_trust`  |  |  |  |
| `SSL_CTX_set_verify`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_set_verify_depth`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_up_ref`  |  |  | :white_check_mark: |
| `SSL_CTX_use_PrivateKey`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_use_PrivateKey_ASN1`  |  |  |  |
| `SSL_CTX_use_PrivateKey_file`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_CTX_use_RSAPrivateKey` [^deprecatedin_3_0] |  |  |  |
| `SSL_CTX_use_RSAPrivateKey_ASN1` [^deprecatedin_3_0] |  |  |  |
| `SSL_CTX_use_RSAPrivateKey_file` [^deprecatedin_3_0] |  |  |  |
| `SSL_CTX_use_cert_and_key`  |  |  |  |
| `SSL_CTX_use_certificate`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_CTX_use_certificate_ASN1`  |  |  |  |
| `SSL_CTX_use_certificate_chain_file`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_CTX_use_certificate_file`  | :white_check_mark: |  | :exclamation: [^stub] |
| `SSL_CTX_use_psk_identity_hint` [^psk] |  |  |  |
| `SSL_CTX_use_serverinfo`  |  |  |  |
| `SSL_CTX_use_serverinfo_ex`  |  |  |  |
| `SSL_CTX_use_serverinfo_file`  |  |  |  |
| `SSL_SESSION_dup`  |  |  |  |
| `SSL_SESSION_free`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_SESSION_get0_alpn_selected`  |  |  |  |
| `SSL_SESSION_get0_cipher`  |  |  |  |
| `SSL_SESSION_get0_hostname`  |  |  |  |
| `SSL_SESSION_get0_id_context`  |  |  |  |
| `SSL_SESSION_get0_peer`  |  |  |  |
| `SSL_SESSION_get0_ticket`  |  |  |  |
| `SSL_SESSION_get0_ticket_appdata`  |  |  |  |
| `SSL_SESSION_get_compress_id`  |  |  |  |
| `SSL_SESSION_get_ex_data`  |  |  |  |
| `SSL_SESSION_get_id`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_SESSION_get_master_key`  |  |  |  |
| `SSL_SESSION_get_max_early_data`  |  |  |  |
| `SSL_SESSION_get_max_fragment_length`  |  |  |  |
| `SSL_SESSION_get_protocol_version`  |  |  |  |
| `SSL_SESSION_get_ticket_lifetime_hint`  |  |  |  |
| `SSL_SESSION_get_time`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_SESSION_get_timeout`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_SESSION_has_ticket`  |  |  |  |
| `SSL_SESSION_is_resumable`  |  |  |  |
| `SSL_SESSION_new`  |  |  |  |
| `SSL_SESSION_print`  |  |  |  |
| `SSL_SESSION_print_fp` [^stdio] |  |  |  |
| `SSL_SESSION_print_keylog`  |  |  |  |
| `SSL_SESSION_set1_alpn_selected`  |  |  |  |
| `SSL_SESSION_set1_hostname`  |  |  |  |
| `SSL_SESSION_set1_id`  |  |  |  |
| `SSL_SESSION_set1_id_context`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_SESSION_set1_master_key`  |  |  |  |
| `SSL_SESSION_set1_ticket_appdata`  |  |  |  |
| `SSL_SESSION_set_cipher`  |  |  |  |
| `SSL_SESSION_set_ex_data`  |  |  |  |
| `SSL_SESSION_set_max_early_data`  |  |  |  |
| `SSL_SESSION_set_protocol_version`  |  |  |  |
| `SSL_SESSION_set_time`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_SESSION_set_timeout`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_SESSION_up_ref`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_SRP_CTX_free` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_SRP_CTX_init` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_accept`  |  |  | :white_check_mark: |
| `SSL_add1_host`  |  |  |  |
| `SSL_add1_to_CA_list`  |  |  |  |
| `SSL_add_client_CA`  |  |  |  |
| `SSL_add_dir_cert_subjects_to_stack`  |  |  |  |
| `SSL_add_file_cert_subjects_to_stack`  |  |  |  |
| `SSL_add_ssl_module`  |  |  |  |
| `SSL_add_store_cert_subjects_to_stack`  |  |  |  |
| `SSL_alert_desc_string`  |  |  | :white_check_mark: |
| `SSL_alert_desc_string_long`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_alert_type_string`  |  |  |  |
| `SSL_alert_type_string_long`  |  |  |  |
| `SSL_alloc_buffers`  |  |  |  |
| `SSL_bytes_to_cipher_list`  |  |  |  |
| `SSL_callback_ctrl`  |  |  |  |
| `SSL_certs_clear`  |  |  |  |
| `SSL_check_chain`  |  |  |  |
| `SSL_check_private_key`  |  |  | :white_check_mark: |
| `SSL_clear`  |  |  |  |
| `SSL_clear_options`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_client_hello_get0_ciphers`  |  |  |  |
| `SSL_client_hello_get0_compression_methods`  |  |  |  |
| `SSL_client_hello_get0_ext`  |  |  |  |
| `SSL_client_hello_get0_legacy_version`  |  |  |  |
| `SSL_client_hello_get0_random`  |  |  |  |
| `SSL_client_hello_get0_session_id`  |  |  |  |
| `SSL_client_hello_get1_extensions_present`  |  |  |  |
| `SSL_client_hello_isv2`  |  |  |  |
| `SSL_client_version`  |  |  |  |
| `SSL_config`  |  |  |  |
| `SSL_connect`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_copy_session_id`  |  |  |  |
| `SSL_ct_is_enabled` [^ct] |  |  |  |
| `SSL_ctrl`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_dane_clear_flags`  |  |  |  |
| `SSL_dane_enable`  |  |  |  |
| `SSL_dane_set_flags`  |  |  |  |
| `SSL_dane_tlsa_add`  |  |  |  |
| `SSL_do_handshake`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_dup`  |  |  |  |
| `SSL_dup_CA_list`  |  |  |  |
| `SSL_enable_ct` [^ct] |  |  |  |
| `SSL_export_keying_material`  |  |  |  |
| `SSL_export_keying_material_early`  |  |  |  |
| `SSL_extension_supported`  |  |  |  |
| `SSL_free`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_free_buffers`  |  |  |  |
| `SSL_get0_CA_list`  |  |  |  |
| `SSL_get0_alpn_selected`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get0_dane`  |  |  |  |
| `SSL_get0_dane_authority`  |  |  |  |
| `SSL_get0_dane_tlsa`  |  |  |  |
| `SSL_get0_next_proto_negotiated` [^nextprotoneg] |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_get0_param`  |  |  |  |
| `SSL_get0_peer_CA_list`  |  |  |  |
| `SSL_get0_peer_certificate`  |  |  | :white_check_mark: |
| `SSL_get0_peer_scts` [^ct] |  |  |  |
| `SSL_get0_peername`  |  |  |  |
| `SSL_get0_security_ex_data`  |  |  |  |
| `SSL_get0_verified_chain`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get1_peer_certificate`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get1_session`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_get1_supported_ciphers`  |  |  |  |
| `SSL_get_SSL_CTX`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_get_all_async_fds`  |  |  |  |
| `SSL_get_async_status`  |  |  |  |
| `SSL_get_certificate`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_changed_async_fds`  |  |  |  |
| `SSL_get_cipher_list`  |  |  |  |
| `SSL_get_ciphers`  |  |  |  |
| `SSL_get_client_CA_list`  |  |  |  |
| `SSL_get_client_ciphers`  |  |  |  |
| `SSL_get_client_random`  |  |  |  |
| `SSL_get_current_cipher`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_current_compression`  |  |  | :white_check_mark: |
| `SSL_get_current_expansion`  |  |  |  |
| `SSL_get_default_passwd_cb`  |  |  |  |
| `SSL_get_default_passwd_cb_userdata`  |  |  |  |
| `SSL_get_default_timeout`  |  |  |  |
| `SSL_get_early_data_status`  |  |  |  |
| `SSL_get_error`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_ex_data`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_ex_data_X509_STORE_CTX_idx`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_get_fd`  |  |  |  |
| `SSL_get_finished`  |  |  |  |
| `SSL_get_info_callback`  |  |  |  |
| `SSL_get_key_update_type`  |  |  |  |
| `SSL_get_max_early_data`  |  |  |  |
| `SSL_get_num_tickets`  |  |  | :white_check_mark: |
| `SSL_get_options`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_get_peer_cert_chain`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_peer_finished`  |  |  |  |
| `SSL_get_peer_signature_type_nid`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_get_pending_cipher`  |  |  |  |
| `SSL_get_privatekey`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_get_psk_identity` [^psk] |  |  |  |
| `SSL_get_psk_identity_hint` [^psk] |  |  |  |
| `SSL_get_quiet_shutdown`  |  |  |  |
| `SSL_get_rbio`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_get_read_ahead`  |  |  |  |
| `SSL_get_record_padding_callback_arg`  |  |  |  |
| `SSL_get_recv_max_early_data`  |  |  |  |
| `SSL_get_rfd`  |  |  |  |
| `SSL_get_security_callback`  |  |  |  |
| `SSL_get_security_level`  |  |  |  |
| `SSL_get_selected_srtp_profile` [^srtp] |  |  |  |
| `SSL_get_server_random`  |  |  |  |
| `SSL_get_servername`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_get_servername_type`  |  |  | :white_check_mark: |
| `SSL_get_session`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_get_shared_ciphers`  |  |  |  |
| `SSL_get_shared_sigalgs`  |  |  |  |
| `SSL_get_shutdown`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_sigalgs`  |  |  |  |
| `SSL_get_signature_type_nid`  |  |  |  |
| `SSL_get_srp_N` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_get_srp_g` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_get_srp_userinfo` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_get_srp_username` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_get_srtp_profiles` [^srtp] |  |  |  |
| `SSL_get_ssl_method`  |  |  |  |
| `SSL_get_state`  |  |  | :white_check_mark: |
| `SSL_get_verify_callback`  |  |  |  |
| `SSL_get_verify_depth`  |  |  | :white_check_mark: |
| `SSL_get_verify_mode`  |  |  | :white_check_mark: |
| `SSL_get_verify_result`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_version`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_get_wbio`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_get_wfd`  |  |  |  |
| `SSL_group_to_name`  |  |  |  |
| `SSL_has_matching_session_id`  |  |  |  |
| `SSL_has_pending`  |  |  | :white_check_mark: |
| `SSL_in_before`  |  |  | :white_check_mark: |
| `SSL_in_init`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_is_dtls`  |  |  |  |
| `SSL_is_init_finished`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_is_server`  |  |  | :white_check_mark: |
| `SSL_key_update`  |  |  |  |
| `SSL_load_client_CA_file`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_load_client_CA_file_ex`  |  |  |  |
| `SSL_new`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_new_session_ticket`  |  |  |  |
| `SSL_peek`  |  |  |  |
| `SSL_peek_ex`  |  |  |  |
| `SSL_pending`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_read`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_read_early_data`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_read_ex`  |  |  |  |
| `SSL_renegotiate`  |  |  |  |
| `SSL_renegotiate_abbreviated`  |  |  |  |
| `SSL_renegotiate_pending`  |  |  |  |
| `SSL_rstate_string`  |  |  |  |
| `SSL_rstate_string_long`  |  |  |  |
| `SSL_select_next_proto`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_sendfile`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_session_reused`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set0_CA_list`  |  |  |  |
| `SSL_set0_rbio`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_set0_security_ex_data`  |  |  |  |
| `SSL_set0_tmp_dh_pkey`  |  |  |  |
| `SSL_set0_wbio`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_set1_host`  |  |  | :white_check_mark: |
| `SSL_set1_param`  |  |  |  |
| `SSL_set_SSL_CTX`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set_accept_state`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set_allow_early_data_cb`  |  |  |  |
| `SSL_set_alpn_protos`  |  |  | :white_check_mark: |
| `SSL_set_async_callback`  |  |  |  |
| `SSL_set_async_callback_arg`  |  |  |  |
| `SSL_set_bio`  | :white_check_mark: |  | :white_check_mark: |
| `SSL_set_block_padding`  |  |  |  |
| `SSL_set_cert_cb`  |  |  |  |
| `SSL_set_cipher_list`  |  |  |  |
| `SSL_set_ciphersuites`  |  |  |  |
| `SSL_set_client_CA_list`  |  |  |  |
| `SSL_set_connect_state`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_set_ct_validation_callback` [^ct] |  |  |  |
| `SSL_set_debug` [^deprecatedin_1_1_0] |  |  |  |
| `SSL_set_default_passwd_cb`  |  |  |  |
| `SSL_set_default_passwd_cb_userdata`  |  |  |  |
| `SSL_set_default_read_buffer_len`  |  |  |  |
| `SSL_set_ex_data`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_set_fd` [^sock] | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_set_generate_session_id`  |  |  |  |
| `SSL_set_hostflags`  |  |  |  |
| `SSL_set_info_callback`  |  |  |  |
| `SSL_set_max_early_data`  |  |  |  |
| `SSL_set_msg_callback`  |  |  |  |
| `SSL_set_not_resumable_session_callback`  |  |  |  |
| `SSL_set_num_tickets`  |  |  | :white_check_mark: |
| `SSL_set_options`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set_post_handshake_auth`  |  |  | :exclamation: [^stub] |
| `SSL_set_psk_client_callback` [^psk] |  |  |  |
| `SSL_set_psk_find_session_callback`  |  |  |  |
| `SSL_set_psk_server_callback` [^psk] |  |  |  |
| `SSL_set_psk_use_session_callback`  |  |  |  |
| `SSL_set_purpose`  |  |  |  |
| `SSL_set_quiet_shutdown`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set_read_ahead`  |  |  |  |
| `SSL_set_record_padding_callback`  |  |  |  |
| `SSL_set_record_padding_callback_arg`  |  |  |  |
| `SSL_set_recv_max_early_data`  |  |  |  |
| `SSL_set_rfd` [^sock] |  |  |  |
| `SSL_set_security_callback`  |  |  |  |
| `SSL_set_security_level`  |  |  |  |
| `SSL_set_session`  | :white_check_mark: | :white_check_mark: | :exclamation: [^stub] |
| `SSL_set_session_id_context`  |  |  |  |
| `SSL_set_session_secret_cb`  |  |  |  |
| `SSL_set_session_ticket_ext`  |  |  |  |
| `SSL_set_session_ticket_ext_cb`  |  |  |  |
| `SSL_set_shutdown`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set_srp_server_param` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_set_srp_server_param_pw` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_set_ssl_method`  |  |  |  |
| `SSL_set_tlsext_max_fragment_length`  |  |  |  |
| `SSL_set_tlsext_use_srtp` [^srtp] |  |  |  |
| `SSL_set_tmp_dh_callback` [^deprecatedin_3_0] [^dh] |  |  |  |
| `SSL_set_trust`  |  |  |  |
| `SSL_set_verify`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set_verify_depth`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_set_verify_result`  |  |  |  |
| `SSL_set_wfd` [^sock] |  |  |  |
| `SSL_shutdown`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_srp_server_param_with_username` [^deprecatedin_3_0] [^srp] |  |  |  |
| `SSL_state_string`  |  |  |  |
| `SSL_state_string_long`  |  |  |  |
| `SSL_stateless`  |  |  |  |
| `SSL_test_functions` [^unit_test] |  |  |  |
| `SSL_trace` [^ssl_trace] |  |  |  |
| `SSL_up_ref`  |  |  | :white_check_mark: |
| `SSL_use_PrivateKey`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_use_PrivateKey_ASN1`  |  |  |  |
| `SSL_use_PrivateKey_file`  |  |  | :white_check_mark: |
| `SSL_use_RSAPrivateKey` [^deprecatedin_3_0] |  |  |  |
| `SSL_use_RSAPrivateKey_ASN1` [^deprecatedin_3_0] |  |  |  |
| `SSL_use_RSAPrivateKey_file` [^deprecatedin_3_0] |  |  |  |
| `SSL_use_cert_and_key`  |  |  |  |
| `SSL_use_certificate`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_use_certificate_ASN1`  |  |  |  |
| `SSL_use_certificate_chain_file`  |  |  |  |
| `SSL_use_certificate_file`  |  |  |  |
| `SSL_use_psk_identity_hint` [^psk] |  |  |  |
| `SSL_verify_client_post_handshake`  |  |  |  |
| `SSL_version`  |  | :white_check_mark: | :white_check_mark: |
| `SSL_waiting_for_async`  |  |  |  |
| `SSL_want`  |  |  | :white_check_mark: |
| `SSL_write`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `SSL_write_early_data`  |  | :white_check_mark: | :exclamation: [^stub] |
| `SSL_write_ex`  |  |  |  |
| `SSLv3_client_method` [^deprecatedin_1_1_0] [^ssl3_method] |  |  |  |
| `SSLv3_method` [^deprecatedin_1_1_0] [^ssl3_method] |  |  |  |
| `SSLv3_server_method` [^deprecatedin_1_1_0] [^ssl3_method] |  |  |  |
| `TLS_client_method`  | :white_check_mark: |  | :white_check_mark: |
| `TLS_method`  |  | :white_check_mark: | :white_check_mark: |
| `TLS_server_method`  |  |  | :white_check_mark: |
| `TLSv1_1_client_method` [^deprecatedin_1_1_0] [^tls1_1_method] |  |  |  |
| `TLSv1_1_method` [^deprecatedin_1_1_0] [^tls1_1_method] |  |  |  |
| `TLSv1_1_server_method` [^deprecatedin_1_1_0] [^tls1_1_method] |  |  |  |
| `TLSv1_2_client_method` [^deprecatedin_1_1_0] [^tls1_2_method] |  |  |  |
| `TLSv1_2_method` [^deprecatedin_1_1_0] [^tls1_2_method] |  |  |  |
| `TLSv1_2_server_method` [^deprecatedin_1_1_0] [^tls1_2_method] |  |  |  |
| `TLSv1_client_method` [^deprecatedin_1_1_0] [^tls1_method] |  |  |  |
| `TLSv1_method` [^deprecatedin_1_1_0] [^tls1_method] |  |  |  |
| `TLSv1_server_method` [^deprecatedin_1_1_0] [^tls1_method] |  |  |  |
| `d2i_SSL_SESSION`  |  | :white_check_mark: | :white_check_mark: |
| `i2d_SSL_SESSION`  |  | :white_check_mark: | :white_check_mark: |

[^stub]: symbol exists, but just returns an error.
[^deprecatedin_1_1_0]: deprecated in openssl 1.1.0
[^deprecatedin_3_0]: deprecated in openssl 3.0
[^stdio]: depends on C stdio `FILE*`
[^ct]: certificate transparency-specific (NYI in rustls)
[^nextprotoneg]: next protocol negotiation (NPN) feature -- non-standard precursor to ALPN
[^srp]: SRP-specific
[^srtp]: SRTP-specific
[^psk]: pre-shared-key-specific
[^sock]: specific to platforms with file descriptors
[^unit_test]: access to openssl internals for unit testing
[^ssl_trace]: protocol tracing API
[^dtls1_2_method]: DTLS 1.2-specific
[^dtls1_method]: DTLS 1.0-specific
[^dh]: Diffie-Hellman-specific
[^ssl3_method]: SSL 3.0-specific
[^tls1_method]: TLS 1.0-specific
[^tls1_1_method]: TLS 1.1-specific
[^tls1_2_method]: TLS 1.2-specific
[^engine]: openssl ENGINE-specific
[^curl]: curl 7.81.0-1ubuntu1.16 (ubuntu 22.04)
[^nginx]: nginx 1.18.0-6ubuntu14.4 (ubuntu 22.04)
