#!/usr/bin/env bash
# Packages a release binary that cargo has already built.
#
#   scripts/package-release.sh tarball TARGET    dist/opsmcp-VERSION-TARGET.tar.gz
#   scripts/package-release.sh deb TARGET        dist/opsmcp_VERSION_SUITE_ARCH.deb
#
# TARGET is the Rust target the binary was built for:
#
#   cargo build --release --locked --target TARGET
#
# A tarball is meant for a statically linked binary (a *-linux-musl target), which runs
# on any distribution. A .deb is for the release of Debian or Ubuntu it is built on:
# SUITE and ARCH are this system's (ubuntu26.04, amd64), and the package's dependencies
# are worked out from the libraries the binary was linked against here.
#
# AIDEV-NOTE: the GitHub workflows and a developer's machine both package with this one
# script, so that what CI checks is what a release ships. Neither kind of package
# switches anything on: no caller, no sudoers rule and no running service. Who may do
# what on a host is the operator's to write (see the README). The .deb does install
# configuration files, in /etc/opsmcp, as dpkg conffiles: files that let nobody in
# (packaging/deb/etc, and the tests that keep them so).
#
# AIDEV-NOTE: no package ever writes to /etc/sudoers.d. That is the project owner's
# rule ("We should never write a config file to sudoers.d"), not a detail of this
# script: the sudo rule ships as an example, in /etc/opsmcp for the .deb, and
# installing it is the operator's own step.
set -euo pipefail

usage() {
    echo "usage: $0 tarball|deb TARGET" >&2
    exit 2
}

[[ $# -eq 2 ]] || usage
kind=$1
target=$2
[[ $kind == tarball || $kind == deb ]] || usage

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
if [[ $target_dir != /* ]]; then
    target_dir="$repo_root/$target_dir"
fi

version=$(awk '
    /^\[package\]$/ { in_package = 1; next }
    /^\[/ && in_package { exit }
    in_package && $1 == "version" {
        gsub(/"/, "", $3)
        print $3
        exit
    }
' "$repo_root/Cargo.toml")
[[ -n $version ]] || {
    echo "could not read the package version from Cargo.toml" >&2
    exit 1
}
if [[ -n ${VERSION:-} && $VERSION != "$version" ]]; then
    echo "VERSION $VERSION does not match Cargo.toml version $version" >&2
    exit 1
fi

binary="$target_dir/$target/release/opsmcp"
[[ -x $binary ]] || {
    echo "release binary not found: $binary" >&2
    echo "build it first: cargo build --release --locked --target $target" >&2
    exit 1
}

dist=${DIST_DIR:-"$repo_root/dist"}
mkdir -p "$dist"
stage=$(mktemp -d "${TMPDIR:-/tmp}/opsmcp-package.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT

homepage=https://github.com/linsomniac/opsmcp
# The full examples of the three configuration files, and the sudo rule.
examples=(config.example.toml fleet.example.toml hosts.example.toml)
sudoers_example=sudoers.example
units=(opsmcp-http.service opsmcp-fleet-http.service)

# The binary as shipped: stripped, since the release profile keeps its symbols.
shipped="$stage/opsmcp"
install -m 0755 "$binary" "$shipped"
if command -v strip >/dev/null 2>&1; then
    strip "$shipped" 2>/dev/null || true
fi

if [[ $kind == tarball ]]; then
    name="opsmcp-${version}-${target}"
    root="$stage/$name"
    mkdir -p "$root/examples" "$root/systemd"
    install -m 0755 "$shipped" "$root/opsmcp"
    install -m 0644 "$repo_root/README.md" "$root/README.md"
    install -m 0644 "$repo_root/LICENSE" "$root/LICENSE"
    for file in "${examples[@]}" "$sudoers_example"; do
        install -m 0644 "$repo_root/packaging/$file" "$root/examples/$file"
    done
    for file in "${units[@]}"; do
        install -m 0644 "$repo_root/packaging/$file" "$root/systemd/$file"
    done

    archive="$dist/$name.tar.gz"
    rm -f -- "$archive"
    tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner -czf "$archive" "$name"
    printf 'created %s\n' "$archive"
    exit 0
fi

# ---- .deb ----

for tool in dpkg dpkg-deb dpkg-shlibdeps; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "$tool is required to build a Debian package (packages dpkg and dpkg-dev)" >&2
        exit 1
    }
done
arch=$(dpkg --print-architecture)
# shellcheck disable=SC1091
suite=$(. /etc/os-release && printf '%s%s' "$ID" "$VERSION_ID")
[[ $suite =~ ^[a-z]+[0-9.]+$ ]] || {
    echo "could not tell which release this is from /etc/os-release (got \"$suite\")" >&2
    exit 1
}
# A pre-release (1.2.0-rc1) has to sort before its release, which "~" does and "-" does
# not. The suite is part of the version so that builds for two releases of Ubuntu are
# two versions, the one for the newer release being the newer.
deb_version="${version//-/\~}-1~${suite}"

root="$stage/deb"
doc="$root/usr/share/doc/opsmcp"
# AIDEV-NOTE: the examples are not under /usr/share/doc, where Debian usually has them:
# minimal Ubuntu images (cloud and container ones) tell dpkg to leave everything there
# out except the copyright file, and an operator needs the examples to write a
# configuration at all.
examples_dir="$root/usr/share/opsmcp/examples"
etc="$root/etc/opsmcp"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/systemd/system" "$doc" \
    "$examples_dir" "$etc/fleet"
install -m 0755 "$shipped" "$root/usr/bin/opsmcp"
install -m 0644 "$repo_root/README.md" "$doc/README.md"
# AIDEV-NOTE: opsmcp is CC0 (LICENSE). Debian's place for a package's licence is its
# copyright file, which is also the one file under /usr/share/doc that minimal images
# keep.
install -m 0644 "$repo_root/LICENSE" "$doc/copyright"
for file in "${examples[@]}"; do
    install -m 0644 "$repo_root/packaging/$file" "$examples_dir/$file"
done
# The configuration files, where opsmcp reads them. As installed they let nobody in
# (see the note at the top), and they are not readable by everyone: who has which role
# and which hosts there are is nobody's business but root's until the operator says so.
# dpkg keeps an operator's changes to a conffile, and its owner and mode, on upgrade.
conffiles=(config.toml fleet.toml fleet/hosts.toml)
for file in "${conffiles[@]}"; do
    install -m 0640 "$repo_root/packaging/deb/etc/opsmcp/$file" "$etc/$file"
done
# The sudo rule sits beside them as an example and nowhere else: /etc/sudoers.d is
# never written to.
install -m 0644 "$repo_root/packaging/$sudoers_example" "$etc/$sudoers_example"
conffiles+=("$sudoers_example")
printf '/etc/opsmcp/%s\n' "${conffiles[@]}" >"$root/DEBIAN/conffiles"
chmod 0644 "$root/DEBIAN/conffiles"
# The units are installed and left alone: each needs a configuration that lets
# someone in before it is of any use, so neither is enabled.
for file in "${units[@]}"; do
    install -m 0644 "$repo_root/packaging/$file" "$root/usr/lib/systemd/system/$file"
done
for script in postinst prerm postrm; do
    install -m 0755 "$repo_root/packaging/deb/$script" "$root/DEBIAN/$script"
done

# What the binary needs from this release's libraries, as dpkg itself works it out.
# dpkg-shlibdeps only runs next to a debian/control, so it is given a minimal one.
mkdir -p "$stage/shlibs/debian"
printf 'Source: opsmcp\n\nPackage: opsmcp\nArchitecture: any\n' >"$stage/shlibs/debian/control"
depends=$(cd "$stage/shlibs" && dpkg-shlibdeps -O "$root/usr/bin/opsmcp" 2>/dev/null |
    sed -n 's/^shlibs:Depends=//p')

installed_size=$(du -sk --exclude=DEBIAN "$root" | awk '{ print $1 }')
{
    echo "Package: opsmcp"
    echo "Version: $deb_version"
    echo "Section: admin"
    echo "Priority: optional"
    echo "Architecture: $arch"
    echo "Maintainer: opsmcp contributors <linsomniac@users.noreply.github.com>"
    echo "Installed-Size: $installed_size"
    # A statically linked binary depends on nothing.
    if [[ -n $depends ]]; then
        echo "Depends: $depends"
    fi
    echo "Recommends: sudo"
    echo "Suggests: openssh-client"
    echo "Homepage: $homepage"
    echo "Description: MCP server for audited, permission-controlled Linux operations"
    echo " opsmcp gives AI agents access to operations tasks on a host (services, logs,"
    echo " processes, packages, firewall and more) through the Model Context Protocol."
    echo " What a caller may do is decided by roles in /etc/opsmcp/config.toml, and every"
    echo " call is written to an audit trail."
    echo " ."
    echo " Installing this package switches nothing on: the configuration it puts in"
    echo " /etc/opsmcp lists no caller, and there is no sudoers rule and no running"
    echo " service until you add them. Examples are in /usr/share/opsmcp/examples."
} >"$root/DEBIAN/control"
chmod 0644 "$root/DEBIAN/control"
# Checksums of everything but the conffiles, which dpkg tracks by itself.
(cd "$root" && find usr -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum) >"$root/DEBIAN/md5sums"
chmod 0644 "$root/DEBIAN/md5sums"

# GitHub rewrites "~" in the name of a release asset, so the file is named without the
# package's own version string.
deb="$dist/opsmcp_${version}_${suite}_${arch}.deb"
rm -f -- "$deb"
dpkg-deb --root-owner-group --build "$root" "$deb" >/dev/null
printf 'created %s (version %s)\n' "$deb" "$deb_version"
