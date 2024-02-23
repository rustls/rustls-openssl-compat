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
    "SSL_CTX_free",
    "SSL_CTX_new",
    "SSL_CTX_up_ref",
    "SSL_free",
    "SSL_new",
    "SSL_up_ref",
    "TLS_client_method",
    "TLS_method",
    "TLS_server_method",
];
