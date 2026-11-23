#!/usr/bin/env bash
# Installs a .deb made by package-release.sh on THIS system and checks what it did.
#
#   scripts/test-deb.sh dist/opsmcp_VERSION_SUITE_ARCH.deb
#
# For a throwaway container or CI job only: it runs as root, installs and removes
# packages (opsmcp and sudo), and edits the configuration in /etc/opsmcp. For example:
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
    /etc/opsmcp/config.toml \
    /etc/opsmcp/fleet.toml \
    /etc/opsmcp/fleet/hosts.toml \
    /etc/opsmcp/sudoers.example; do
    [[ -f $file ]] || fail "$file is missing"
    [[ $(stat -c '%U:%G' "$file") == root:root ]] || fail "$file is not owned by root"
    [[ $(($(stat -c '%#a' "$file") & 0022)) -eq 0 ]] || fail "$file is writable by others"
done
[[ $(stat -c '%a' /usr/bin/opsmcp) == 755 ]] || fail "/usr/bin/opsmcp is not mode 755"
grep -q 'CC0 1.0 Universal' /usr/share/doc/opsmcp/copyright ||
    fail "the copyright file does not carry the licence"
[[ $(dpkg-deb -f "$deb" Homepage) == https://github.com/* ]] ||
    fail "the package does not say where it comes from"

check "what is in /etc/opsmcp is configuration to dpkg, and only root reads it"
conffiles=$(dpkg-query -W -f='${Conffiles}\n' opsmcp | awk 'NF { print $1 }' | sort | xargs)
expected="/etc/opsmcp/config.toml /etc/opsmcp/fleet.toml /etc/opsmcp/fleet/hosts.toml"
expected+=" /etc/opsmcp/sudoers.example"
[[ $conffiles == "$expected" ]] || fail "dpkg has these as configuration files: $conffiles"
for file in config.toml fleet.toml fleet/hosts.toml; do
    [[ $(stat -c '%a' "/etc/opsmcp/$file") == 640 ]] || fail "/etc/opsmcp/$file is not mode 640"
done

check "installing switched nothing on: nobody is a caller"
# (Where there is no syslog, as in a container, check-config adds that the host cannot
# run the configuration yet. Either way it has to find the file itself valid.)
summary=$(opsmcp check-config 2>&1) || true
[[ $summary == *"/etc/opsmcp/config.toml is valid"* ]] ||
    fail "the installed configuration is not valid: $summary"
request='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"system_info","arguments":{}}}'
if refusal=$(printf '%s\n' "$request" | opsmcp serve 2>&1); then
    fail "opsmcp served root, who was never given a role: $refusal"
fi
[[ $refusal == *"has no role"* ]] || fail "opsmcp did not start, but not for want of a role: $refusal"

check "installing switched nothing on: a fleet server does not start"
if refusal=$(opsmcp check-config --config /etc/opsmcp/fleet.toml 2>&1); then
    fail "the installed fleet configuration is usable as it is: $refusal"
fi
[[ $refusal == *"there are no [[fleet.access]] rules"* ]] ||
    fail "the fleet configuration was refused, but not for want of a rule: $refusal"

check "installing switched nothing on: no sudo rule, no enabled service"
# sudo is installed here to have a real /etc/sudoers.d to look into, and visudo to read
# the example with.
apt-get install -y -qq --no-install-recommends sudo >/dev/null
if dpkg -L opsmcp | grep -q '^/etc/sudoers'; then
    fail "the package has a file under /etc/sudoers.d"
fi
if grep -rqs opsmcp /etc/sudoers /etc/sudoers.d; then
    fail "something in /etc/sudoers or /etc/sudoers.d names opsmcp"
fi
if find /etc/systemd/system -name 'opsmcp*' 2>/dev/null | grep -q .; then
    fail "the package enabled a service"
fi

check "the sudo rule it ships as an example is one sudo would accept"
visudo -cf /etc/opsmcp/sudoers.example >/dev/null ||
    fail "visudo does not accept /etc/opsmcp/sudoers.example"

check "the unit files start the binary the package installed"
for unit in opsmcp-http opsmcp-fleet-http; do
    grep -q '^ExecStart=/usr/bin/opsmcp ' "/usr/lib/systemd/system/$unit.service" ||
        fail "$unit.service does not start /usr/bin/opsmcp"
done

check "once the operator adds a caller, it answers a call"
# What an operator does: a caller, added to the file as installed. (And the audit trail
# to a file, since this container has no syslog.)
cat >>/etc/opsmcp/config.toml <<'CONFIG'

[unix_users.root]
roles = ["readonly"]
CONFIG
sed -i 's|^syslog = true$|syslog = false\nfile = "/var/log/opsmcp-test-audit.jsonl"|' \
    /etc/opsmcp/config.toml
opsmcp check-config >/dev/null || fail "check-config refused the configuration with a caller added"
answer=$(printf '%s\n' "$request" | opsmcp serve)
[[ $answer == *'"isError":false'* && $answer == *Kernel:* ]] ||
    fail "system_info was not answered: $answer"
grep -q '"tool":"system_info"' /var/log/opsmcp-test-audit.jsonl ||
    fail "the call is not in the audit trail"

check "installing it again (an upgrade) keeps the operator's configuration"
# Things an operator adds beside it, and an owner and mode of their choosing.
install -d -m 0700 /etc/opsmcp/tls
echo "not a real key" >/etc/opsmcp/tls/server.key
chgrp daemon /etc/opsmcp/fleet.toml
apt-get install -y -qq --reinstall --no-install-recommends "$deb" >/dev/null
grep -q '^\[unix_users.root\]$' /etc/opsmcp/config.toml ||
    fail "reinstalling replaced the operator's configuration"
[[ $(stat -c '%G:%a' /etc/opsmcp/fleet.toml) == daemon:640 ]] ||
    fail "reinstalling changed the group or mode the operator gave fleet.toml"

check "removing it leaves the configuration, and purging takes only what the package put there"
apt-get remove -y -qq opsmcp >/dev/null
[[ ! -e /usr/bin/opsmcp ]] || fail "/usr/bin/opsmcp is still there after removal"
grep -q '^\[unix_users.root\]$' /etc/opsmcp/config.toml ||
    fail "removal took the operator's configuration with it"
apt-get purge -y -qq opsmcp >/dev/null 2>&1
for file in config.toml fleet.toml fleet/hosts.toml sudoers.example; do
    [[ ! -e /etc/opsmcp/$file ]] || fail "/etc/opsmcp/$file is still there after a purge"
done
[[ -f /etc/opsmcp/tls/server.key ]] || fail "purging took a file the operator had added"

# shellcheck disable=SC1091
echo "ok: $(basename "$deb") installs, lets nobody in until told to, and removes cleanly on $(. /etc/os-release && echo "$PRETTY_NAME")"
