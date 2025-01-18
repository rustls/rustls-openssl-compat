{ lib, stdenv, llvmPackages, rustPlatform, pkg-config, openssl }:
let
  target = stdenv.hostPlatform.rust.rustcTargetSpec;
  libExt = stdenv.hostPlatform.extensions.sharedLibrary;
in
  rustPlatform.buildRustPackage {
    name = "rustls-libssl";

    src = ../.;
    cargoLock.lockFile = ../Cargo.lock;

    nativeBuildInputs = [
      pkg-config # for openssl-sys
      llvmPackages.lld # see build.rs
    ];
    buildInputs = [
      openssl
    ];

    doCheck = false; # TODO: can't find libcrypto

    outputs = [ "out" "dev" ];
    installPhase = ''
      mkdir -p $out/lib $dev/lib/pkgconfig

      mv target/${target}/release/libssl${libExt} $out/lib/libssl${libExt}.3
      ln -s libssl${libExt}.3 $out/lib/libssl${libExt}

      ln -s ${openssl.out}/lib/libcrypto${libExt}.3 $out/lib/
      ln -s libcrypto${libExt}.3 $out/lib/libcrypto${libExt}

      if [[ -e ${openssl.out}/lib/engines-3 ]]; then
        ln -s ${openssl.out}/lib/engines-3 $out/lib/
      fi
      if [[ -e ${openssl.out}/lib/ossl-modules ]]; then
        ln -s ${openssl.out}/lib/ossl-modules $out/lib/
      fi

      ln -s ${openssl.dev}/include $dev/

      cp ${openssl.dev}/lib/pkgconfig/*.pc $dev/lib/pkgconfig/
      sed -i \
        -e "s|${openssl.out}|$out|g" \
        -e "s|${openssl.dev}|$dev|g" \
        $dev/lib/pkgconfig/*.pc
    '';
  }
