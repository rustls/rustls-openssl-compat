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
    "OPENSSL_init_ssl",
    "SSL_alert_desc_string",
    "SSL_alert_desc_string_long",
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
    "SSL_CTX_clear_options",
    "SSL_CTX_ctrl",
    "SSL_CTX_free",
    "SSL_CTX_get_cert_store",
    "SSL_CTX_get_options",
    "SSL_CTX_load_verify_dir",
    "SSL_CTX_load_verify_file",
    "SSL_CTX_new",
    "SSL_CTX_set_alpn_protos",
    "SSL_CTX_set_options",
    "SSL_CTX_set_verify",
    "SSL_CTX_up_ref",
    "SSL_free",
    "SSL_get_options",
    "SSL_get_shutdown",
    "SSL_is_server",
    "SSL_new",
    "SSL_set0_rbio",
    "SSL_set0_wbio",
    "SSL_set1_host",
    "SSL_set_accept_state",
    "SSL_set_alpn_protos",
    "SSL_set_bio",
    "SSL_set_connect_state",
    "SSL_set_fd",
    "SSL_set_options",
    "SSL_set_shutdown",
    "SSL_shutdown",
    "SSL_up_ref",
    "TLS_client_method",
    "TLS_method",
    "TLS_server_method",
];
