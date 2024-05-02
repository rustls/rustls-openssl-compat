use std::{env, fs, path};

fn main() {
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--soname=libssl.so.3");

        // We require lld, because ld only supports one --version-script
        // and rustc uses it for its own purposes (and provides no API for us).
        println!("cargo:rustc-cdylib-link-arg=-fuse-ld=lld");

        let filename = write_version_file();
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={filename}");

        for symbol in ENTRYPOINTS {
            // Rename underscore-prefixed symbols (produced by rust code) to
            // unprefixed symbols (manipulated by our version file).
            println!(
                "cargo:rustc-cdylib-link-arg=-Wl,--defsym={}=_{}",
                symbol, symbol
            );
        }
    }
}

fn write_version_file() -> String {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = path::Path::new(&out_dir).join("versions.map");

    let mut content = String::new();
    content.push_str("OPENSSL_3.0.0 {\n");
    content.push_str("    global:\n");
    for e in ENTRYPOINTS {
        content.push_str(&format!("        {e};\n"));
    }
    content.push_str("    local:\n");
    content.push_str("        *;\n");
    content.push_str("};\n");

    fs::write(&dest, content).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    dest.to_str().unwrap().to_string()
}

const ENTRYPOINTS: &[&str] = &[
    "BIO_f_ssl",
    "d2i_SSL_SESSION",
    "i2d_SSL_SESSION",
    "OPENSSL_init_ssl",
    "SSL_accept",
    "SSL_alert_desc_string",
    "SSL_alert_desc_string_long",
    "SSL_check_private_key",
    "SSL_CIPHER_description",
    "SSL_CIPHER_find",
    "SSL_CIPHER_get_bits",
    "SSL_CIPHER_get_id",
    "SSL_CIPHER_get_name",
    "SSL_CIPHER_get_protocol_id",
    "SSL_CIPHER_get_version",
    "SSL_CIPHER_standard_name",
    "SSL_clear_options",
    "SSL_connect",
    "SSL_ctrl",
    "SSL_CTX_add_client_CA",
    "SSL_CTX_callback_ctrl",
    "SSL_CTX_check_private_key",
    "SSL_CTX_clear_options",
    "SSL_CTX_ctrl",
    "SSL_CTX_free",
    "SSL_CTX_get0_certificate",
    "SSL_CTX_get0_privatekey",
    "SSL_CTX_get_cert_store",
    "SSL_CTX_get_client_CA_list",
    "SSL_CTX_get_ex_data",
    "SSL_CTX_get_max_early_data",
    "SSL_CTX_get_options",
    "SSL_CTX_get_timeout",
    "SSL_CTX_get_verify_callback",
    "SSL_CTX_get_verify_depth",
    "SSL_CTX_get_verify_mode",
    "SSL_CTX_load_verify_dir",
    "SSL_CTX_load_verify_file",
    "SSL_CTX_load_verify_locations",
    "SSL_CTX_new",
    "SSL_CTX_remove_session",
    "SSL_CTX_sess_set_get_cb",
    "SSL_CTX_sess_set_new_cb",
    "SSL_CTX_sess_set_remove_cb",
    "SSL_CTX_set_alpn_protos",
    "SSL_CTX_set_alpn_select_cb",
    "SSL_CTX_set_cert_cb",
    "SSL_CTX_set_cipher_list",
    "SSL_CTX_set_ciphersuites",
    "SSL_CTX_set_client_CA_list",
    "SSL_CTX_set_default_passwd_cb",
    "SSL_CTX_set_default_passwd_cb_userdata",
    "SSL_CTX_set_default_verify_dir",
    "SSL_CTX_set_default_verify_file",
    "SSL_CTX_set_default_verify_paths",
    "SSL_CTX_set_default_verify_store",
    "SSL_CTX_set_ex_data",
    "SSL_CTX_set_info_callback",
    "SSL_CTX_set_keylog_callback",
    "SSL_CTX_set_max_early_data",
    "SSL_CTX_set_msg_callback",
    "SSL_CTX_set_next_proto_select_cb",
    "SSL_CTX_set_next_protos_advertised_cb",
    "SSL_CTX_set_options",
    "SSL_CTX_set_post_handshake_auth",
    "SSL_CTX_set_session_id_context",
    "SSL_CTX_set_srp_password",
    "SSL_CTX_set_srp_username",
    "SSL_CTX_set_timeout",
    "SSL_CTX_set_verify",
    "SSL_CTX_set_verify_depth",
    "SSL_CTX_up_ref",
    "SSL_CTX_use_certificate",
    "SSL_CTX_use_certificate_chain_file",
    "SSL_CTX_use_certificate_file",
    "SSL_CTX_use_PrivateKey",
    "SSL_CTX_use_PrivateKey_file",
    "SSL_do_handshake",
    "SSL_free",
    "SSL_get0_alpn_selected",
    "SSL_get0_next_proto_negotiated",
    "SSL_get0_peer_certificate",
    "SSL_get0_verified_chain",
    "SSL_get1_peer_certificate",
    "SSL_get1_session",
    "SSL_get_certificate",
    "SSL_get_current_cipher",
    "SSL_get_current_compression",
    "SSL_get_error",
    "SSL_get_ex_data",
    "SSL_get_ex_data_X509_STORE_CTX_idx",
    "SSL_get_options",
    "SSL_get_peer_cert_chain",
    "SSL_get_privatekey",
    "SSL_get_rbio",
    "SSL_get_servername",
    "SSL_get_servername_type",
    "SSL_get_session",
    "SSL_get_shutdown",
    "SSL_get_state",
    "SSL_get_verify_depth",
    "SSL_get_verify_result",
    "SSL_get_version",
    "SSL_get_wbio",
    "SSL_has_pending",
    "SSL_in_before",
    "SSL_in_init",
    "SSL_is_init_finished",
    "SSL_is_server",
    "SSL_load_client_CA_file",
    "SSL_new",
    "SSL_pending",
    "SSL_read",
    "SSL_read_early_data",
    "SSL_select_next_proto",
    "SSL_SESSION_free",
    "SSL_SESSION_get_id",
    "SSL_SESSION_get_time",
    "SSL_SESSION_get_timeout",
    "SSL_session_reused",
    "SSL_SESSION_set1_id_context",
    "SSL_SESSION_set_time",
    "SSL_SESSION_set_timeout",
    "SSL_SESSION_up_ref",
    "SSL_set0_rbio",
    "SSL_set0_wbio",
    "SSL_set1_host",
    "SSL_set_accept_state",
    "SSL_set_alpn_protos",
    "SSL_set_bio",
    "SSL_set_connect_state",
    "SSL_set_ex_data",
    "SSL_set_fd",
    "SSL_set_options",
    "SSL_set_post_handshake_auth",
    "SSL_set_quiet_shutdown",
    "SSL_set_session",
    "SSL_set_shutdown",
    "SSL_set_SSL_CTX",
    "SSL_set_verify",
    "SSL_set_verify_depth",
    "SSL_shutdown",
    "SSL_up_ref",
    "SSL_use_certificate",
    "SSL_use_PrivateKey",
    "SSL_use_PrivateKey_file",
    "SSL_want",
    "SSL_write",
    "SSL_write_early_data",
    "TLS_client_method",
    "TLS_method",
    "TLS_server_method",
];
