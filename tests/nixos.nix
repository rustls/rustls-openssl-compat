# SPDX-License-Identifier: MIT

# Derived from:
# https://github.com/NixOS/nixpkgs/blob/4c9ca53890654b5e2fbb22ab8feb1842d81e01c1/nixos/tests/nginx-http3.nix
# Copyright (c) 2003-2024 Eelco Dolstra and the Nixpkgs/NixOS contributors

{ pkgs ? import <nixpkgs> { } }:

let

  caCert = builtins.readFile <nixpkgs/nixos/tests/common/acme/server/ca.cert.pem>;
  certPath = <nixpkgs/nixos/tests/common/acme/server/acme.test.cert.pem>;
  keyPath = <nixpkgs/nixos/tests/common/acme/server/acme.test.key.pem>;

  hosts = ''
    192.168.2.101 acme.test
  '';

in

pkgs.testers.runNixOSTest {
  name = "rustls-libssl";

  nodes = {
    server = { lib, pkgs, ... }: {
      networking = {
        interfaces.eth1 = {
          ipv4.addresses = [
            { address = "192.168.2.101"; prefixLength = 24; }
          ];
        };
        extraHosts = hosts;
        firewall.allowedTCPPorts = [ 443 ];
        firewall.allowedUDPPorts = [ 443 ];
      };

      security.pki.certificates = [ caCert ];

      services.nginx = {
        enable = true;
        package = pkgs.nginxQuic.override {
          modules = [ ];
          openssl = pkgs.callPackage ../dist/package.nix { };
        };

        # Hardcoded sole input accepted by rustls-libssl.
        sslCiphers = "HIGH:!aNULL:!MD5";

        virtualHosts."acme.test" = {
          onlySSL = true;
          sslCertificate = certPath;
          sslCertificateKey = keyPath;
          http2 = true;
          # TODO: Needs SSL_CTX_add_custom_ext
          #http3 = true;
          #http3_hq = false;
          #quic = true;
          reuseport = true;
          root = lib.mkForce (pkgs.runCommandLocal "testdir" {} ''
            mkdir "$out"
            cat > "$out/index.html" <<EOF
            <html><body>Hello World!</body></html>
            EOF
          '');
        };
      };
    };

    client = { pkgs, ... }: {
      environment.systemPackages = [ pkgs.curlHTTP3 ];
      networking = {
        interfaces.eth1 = {
          ipv4.addresses = [
            { address = "192.168.2.201"; prefixLength = 24; }
          ];
        };
        extraHosts = hosts;
      };

      security.pki.certificates = [ caCert ];
    };
  };

  testScript = ''
    start_all()
    server.wait_for_open_port(443)
    client.succeed("curl --verbose --http1.1 https://acme.test | grep 'Hello World!'")
    client.succeed("curl --verbose --http2-prior-knowledge https://acme.test | grep 'Hello World!'")
    #client.succeed("curl --verbose --http3-only https://acme.test | grep 'Hello World!'")
  '';
}
