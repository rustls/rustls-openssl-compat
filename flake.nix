{
  outputs = { ... }: {
    overlays.default = final: prev: {
      rustls-libssl = final.callPackage ./dist/package.nix { };
    };
  };
}
