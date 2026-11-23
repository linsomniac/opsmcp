#!/usr/bin/env bash
# Installs a .deb made by package-release.sh on THIS system and checks what it did.
#
#   scripts/test-deb.sh dist/opsmcp_VERSION_SUITE_ARCH.deb
#
# For a throwaway container or CI job only: it runs as root, installs and removes
# packages, and writes a configuration to /etc/opsmcp. For example:
#
#   docker run --rm -v "$PWD":/src:ro ubuntu:26.04 /src/scripts/test-deb.sh /src/dist/opsmcp_...deb
set -euo pipefail

[[ $# -eq 1 && -f $1 ]] || {
    echo "usage: $0 PACKAGE.deb" >&2
    exit 2
}
[[ $(id -u) -eq 0 ]] || {
    echo "$0 installs a package: run it as root, in a container you can throw away" >&2
    exit 1
}
deb=$(realpath "$1")
export DEBIAN_FRONTEND=noninteractive

check() {
    printf 'check: %s\n' "$1"
}
fail() {
    printf 'FAILED: %s\n' "$1" >&2
    exit 1
}

check "the package installs, with its dependencies taken from this release"
apt-get update -qq
apt-get install -y -qq --no-install-recommends "$deb" >/dev/null

check "the binary runs here and says which version it is"
packaged=$(dpkg-deb -f "$deb" Version)
running=$(opsmcp --version)
[[ $running == opsmcp\ * ]] || fail "opsmcp --version printed \"$running\""
[[ ${packaged//\~/-} == "${running#opsmcp }"-1-* ]] ||
    fail "the package is version $packaged but the binary says \"$running\""

# The README is in the package too, but under /usr/share/doc, which minimal Ubuntu
# images leave out when installing (all but the copyright file), so it is not asked for.
check "files are where the documentation says, owned by root"
for file in \
    /usr/bin/opsmcp \
    /usr/lib/systemd/system/opsmcp-http.service \
    /usr/lib/systemd/system/opsmcp-fleet-http.service \
    /usr/share/doc/opsmcp/copyright \
    /usr/share/opsmcp/examples/config.example.toml \
    /usr/share/opsmcp/examples/fleet.example.toml \
    /usr/share/opsmcp/examples/hosts.example.toml \
    /usr/share/opsmcp/examples/sudoers.example; do
    [[ -f $file ]] || fail "$file is missing"
    [[ $(stat -c '%U:%G' "$file") == root:root ]] || fail "$file is not owned by root"
    [[ $(($(stat -c '%#a' "$file") & 0022)) -eq 0 ]] || fail "$file is writable by others"
done
[[ $(stat -c '%a' /usr/bin/opsmcp) == 755 ]] || fail "/usr/bin/opsmcp is not mode 755"
grep -q 'CC0 1.0 Universal' /usr/share/doc/opsmcp/copyright ||
    fail "the copyright file does not carry the licence"
[[ $(dpkg-deb -f "$deb" Homepage) == https://github.com/* ]] ||
    fail "the package does not say where it comes from"
[[ -d /etc/opsmcp ]] || fail "/etc/opsmcp is missing"

check "installing switched nothing on"
[[ -z $(ls -A /etc/opsmcp) ]] || fail "the package put files into /etc/opsmcp"
[[ ! -e /etc/sudoers.d/opsmcp ]] || fail "the package installed a sudoers rule"
if find /etc/systemd/system -name 'opsmcp*' 2>/dev/null | grep -q .; then
    fail "the package enabled a service"
fi

check "the unit files start the binary the package installed"
for unit in opsmcp-http opsmcp-fleet-http; do
    grep -q '^ExecStart=/usr/bin/opsmcp ' "/usr/lib/systemd/system/$unit.service" ||
        fail "$unit.service does not start /usr/bin/opsmcp"
done

check "with a configuration, it answers a call"
cat >/etc/opsmcp/config.toml <<'CONFIG'
[roles.readonly]
allow = ["@read"]
[unix_users.root]
roles = ["readonly"]
[audit]
syslog = false
file = "/var/log/opsmcp-test-audit.jsonl"
CONFIG
chmod 0600 /etc/opsmcp/config.toml
opsmcp check-config >/dev/null || fail "check-config refused a minimal configuration"
request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"system_info","arguments":{}}}'
answer=$(printf '%s\n' "$request" | opsmcp serve)
[[ $answer == *'"isError":false'* && $answer == *Kernel:* ]] ||
    fail "system_info was not answered: $answer"
grep -q '"tool":"system_info"' /var/log/opsmcp-test-audit.jsonl ||
    fail "the call is not in the audit trail"

check "installing it again (an upgrade) and removing it both work"
apt-get install -y -qq --reinstall --no-install-recommends "$deb" >/dev/null
apt-get remove -y -qq opsmcp >/dev/null
[[ ! -e /usr/bin/opsmcp ]] || fail "/usr/bin/opsmcp is still there after removal"
[[ -f /etc/opsmcp/config.toml ]] || fail "removal took the operator's configuration with it"

# shellcheck disable=SC1091
echo "ok: $(basename "$deb") installs, runs and removes cleanly on $(. /etc/os-release && echo "$PRETTY_NAME")"
