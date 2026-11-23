# The opsmcp package. Built with the Rust toolchain of whichever package set calls it:
#
#   pkgs.callPackage ./nix/package.nix { }              linked against this nixpkgs' glibc
#   pkgs.pkgsStatic.callPackage ./nix/package.nix { }   statically linked (musl), for any
#                                                       distribution: see packaging/static.nix
{
  lib,
  rustPlatform,
}:

let
  manifest = (lib.importTOML ../Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = manifest.name;
  inherit (manifest) version;

  # Only what the build needs, so that editing the README or the tests does not rebuild
  # it and the (large) target/ directory is never copied into the store.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
      ../packaging/config.example.toml
      ../packaging/fleet.example.toml
      ../packaging/hosts.example.toml
      ../packaging/sudoers.example
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;

  # The test suite needs a real system (/proc, sockets, child processes) that the build
  # sandbox does not provide. Run it with `cargo test` in a checkout; the NixOS test in
  # nix/test.nix runs the built package on a real system.
  doCheck = false;

  postInstall = ''
    install -Dm0644 -t $out/share/opsmcp/examples packaging/*.example*
  '';

  meta = {
    inherit (manifest) description homepage;
    license = lib.licenses.cc0;
    mainProgram = "opsmcp";
    platforms = lib.platforms.linux;
  };
}
