# A statically linked opsmcp (musl libc) that runs on any x86_64 Linux, whatever its
# distribution or glibc version:
#
#     nix-build packaging/static.nix        # gives ./result/bin/opsmcp
#
# AIDEV-NOTE: a binary built with plain `cargo build` on NixOS only runs on NixOS: its
# program loader and libraries are paths in /nix/store. This build has no loader and no
# shared libraries at all. One consequence: users and groups are looked up in
# /etc/passwd and /etc/group only (musl has no NSS modules), so accounts that exist
# only in LDAP or sssd are not found. For those hosts build against glibc on the oldest
# distribution release you deploy to instead (see the README).
{ pkgs ? import <nixpkgs> { } }:

let
  manifest = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).package;
in
pkgs.pkgsStatic.rustPlatform.buildRustPackage {
  pname = manifest.name;
  version = manifest.version;

  # Only what the build needs, so that editing docs or tests does not rebuild it and
  # the (large) target/ directory is never copied into the store.
  src = pkgs.lib.fileset.toSource {
    root = ../.;
    fileset = pkgs.lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;

  # The test suite needs a real system (/proc, sockets, child processes) that the build
  # sandbox does not provide. Run it with `cargo test` in a checkout.
  doCheck = false;

  meta.mainProgram = "opsmcp";
}
