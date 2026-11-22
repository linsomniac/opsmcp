# A statically linked opsmcp (musl libc) that runs on any x86_64 Linux, whatever its
# distribution or glibc version:
#
#     nix-build packaging/static.nix        # gives ./result/bin/opsmcp
#
# (With flakes: `nix build .#opsmcp-static`, which is the same build.)
#
# AIDEV-NOTE: a binary built with plain `cargo build` on NixOS only runs on NixOS: its
# program loader and libraries are paths in /nix/store. This build has no loader and no
# shared libraries at all. One consequence: users and groups are looked up in
# /etc/passwd and /etc/group only (musl has no NSS modules), so accounts that exist
# only in LDAP or sssd are not found. For those hosts build against glibc on the oldest
# distribution release you deploy to instead (see the README).
{
  pkgs ? import <nixpkgs> { },
}:

pkgs.pkgsStatic.callPackage ../nix/package.nix { }
