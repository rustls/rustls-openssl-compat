use std::process::{Child, Command, Output, Stdio};
use std::{net, thread, time};

/* Note:
 *
 * In the tests below, we are relying on the fact that cargo sets
 * `LD_LIBRARY_PATH` (or equivalent) so that artifacts it built
 * are preferred to others.  This means processes we run from here
 * that depend on OpenSSL will use our libssl.so.
 *
 * We set LD_LIBRARY_PATH="" to disable this where we want
 * to actually use OpenSSL's libssl.
 */

#[test]
#[ignore]
fn client() {
    let _server = KillOnDrop(
        Command::new("openssl")
            .args(&[
                "s_server",
                "-cert",
                "test-ca/rsa/end.cert",
                "-cert_chain",
                "test-ca/rsa/inter.cert",
                "-key",
                "test-ca/rsa/end.key",
                "-alpn",
                "hello,world",
                "-accept",
                "localhost:4443",
                "-rev",
            ])
            .env("LD_LIBRARY_PATH", "")
            .spawn()
            .expect("failed to start openssl s_server"),
    );

    wait_for_port(4443);

    let openssl_insecure_output = Command::new("target/client")
        .env("LD_LIBRARY_PATH", "")
        .args(&["localhost", "4443", "insecure"])
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    let rustls_insecure_output = Command::new("target/client")
        .args(&["localhost", "4443", "insecure"])
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    assert_eq!(openssl_insecure_output, rustls_insecure_output);

    let openssl_secure_output = Command::new("target/client")
        .env("LD_LIBRARY_PATH", "")
        .args(&["localhost", "4443", "test-ca/rsa/ca.cert"])
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    let rustls_secure_output = Command::new("target/client")
        .args(&["localhost", "4443", "test-ca/rsa/ca.cert"])
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    assert_eq!(openssl_secure_output, rustls_secure_output);
}

#[test]
#[ignore]
fn constants() {
    let openssl_output = Command::new("target/constants")
        .env("LD_LIBRARY_PATH", "")
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    let rustls_output = Command::new("target/constants")
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    assert_eq!(openssl_output, rustls_output);
}

#[test]
#[ignore]
fn ciphers() {
    let openssl_output = Command::new("target/ciphers")
        .env("LD_LIBRARY_PATH", "")
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    let rustls_output = Command::new("target/ciphers")
        .stdout(Stdio::piped())
        .output()
        .map(print_output)
        .unwrap();

    assert_eq!(openssl_output, rustls_output);
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.0.kill().expect("failed to kill subprocess");
        self.0.wait().expect("failed to wait for killed subprocess");
    }
}

fn print_output(out: Output) -> Output {
    println!("status: {:?}\n", out.status);
    println!(
        "stdout:\n{}\n",
        String::from_utf8(out.stdout.clone()).unwrap()
    );
    println!(
        "stderr:\n{}\n",
        String::from_utf8(out.stderr.clone()).unwrap()
    );
    out
}

/// Wait until we can connect to localhost:port.
fn wait_for_port(port: u16) -> Option<()> {
    let mut count = 0;
    loop {
        thread::sleep(time::Duration::from_millis(500));
        if net::TcpStream::connect(("localhost", port)).is_ok() {
            return Some(());
        }
        println!("waiting for port {port}");
        count += 1;
        if count == 10 {
            return None;
        }
    }
}
