# opsmcp

An [MCP](https://modelcontextprotocol.io) server that lets AI agents such as Claude Code
do operations work on a Linux host: look at processes, memory, disks, logs, services,
the network, firewall rules, kernel settings, packages, accounts, containers, databases
and a Pacemaker cluster, see what changed and what the machine looked like earlier, run
your NRPE checks, make a controlled set of changes, and run commands you define.

Every call is checked against the caller's roles and written to an audit trail. Nothing
is allowed unless the configuration grants it.

Status: 0.1, a first complete cut. It has an extensive test suite, and every batch of
tools has had independent security and reliability reviews; what they found was fixed,
apart from the few points recorded under [Security model](#security-model) and
[Not included yet](#not-included-yet). The database, HAProxy, history, configuration
editing, firewall-set, tracing and package-cache tools have been run against the real
programs in a test container (Patroni 3.2 and 4.1 on etcd, PostgreSQL 16, MariaDB
10.11, HAProxy 2.8, sysstat, nftables, strace, apt). Much else has only been exercised
against stand-in commands: Icinga, Galera, MySQL, rpm/dnf, LVM, ipset, smartctl, IPMI,
Pacemaker, chrony, perf across a whole host, and the tools that change systemd units,
sessions, accounts, packages and volumes. It has not yet run in production.

One connection can also reach a whole fleet of such hosts: see
[Fleets](#fleets-one-connection-to-many-hosts).

## Contents

- [Quick start](#quick-start)
- [Three ways to connect](#three-ways-to-connect)
- [Fleets: one connection to many hosts](#fleets-one-connection-to-many-hosts)
- [Permissions](#permissions)
- [Tools](#tools)
- [Custom tools](#custom-tools)
- [Security model](#security-model)
- [Audit trail](#audit-trail)
- [Limits](#limits)
- [Not included yet](#not-included-yet)
- [Development](#development)

## Quick start

```sh
cargo build --release
sudo install -o root -g root -m 0755 target/release/opsmcp /usr/bin/opsmcp

sudo install -d -o root -g root -m 0755 /etc/opsmcp
sudo install -o root -g root -m 0600 packaging/config.example.toml /etc/opsmcp/config.toml
sudoedit /etc/opsmcp/config.toml     # roles, callers, what the tools may touch
sudo opsmcp check-config             # validates, and summarises who may do what
```

`opsmcp tools` lists every tool with its permission. `opsmcp whoami` shows how you are
identified and which tools you would be offered.

### Packages

Each release has these, with a `SHA256SUMS` file:

| File | For |
| --- | --- |
| `opsmcp_VERSION_ubuntu26.04_amd64.deb`, `..._arm64.deb` | Ubuntu 26.04 |
| `opsmcp-VERSION-x86_64-unknown-linux-musl.tar.gz`, `...-aarch64-...` | any distribution: a statically linked binary, the examples and the unit files |

```sh
sudo apt install ./opsmcp_0.1.0_ubuntu26.04_amd64.deb
```

The package installs `/usr/bin/opsmcp`, the two unit files, and the examples under
`/usr/share/opsmcp/examples`. It switches nothing on: there is no configuration, no
sudoers rule and no enabled service until you add them, and nobody can use opsmcp until
`/etc/opsmcp/config.toml` gives them a role. Removing the package leaves `/etc/opsmcp`
alone.

The binary in the tarball looks users and groups up in `/etc/passwd` and `/etc/group`
only (see [below](#building-for-other-hosts)); the one in the `.deb` uses the system's
C library, so accounts from LDAP or sssd are found too.

**NixOS.** The flake has the package (`packages.<system>.default`, and `opsmcp-static`
for the statically linked one), an overlay, and a module:

```nix
{
  inputs.opsmcp.url = "github:OWNER/REPO";

  outputs = { nixpkgs, opsmcp, ... }: {
    nixosConfigurations.web1 = nixpkgs.lib.nixosSystem {
      modules = [
        opsmcp.nixosModules.default
        {
          services.opsmcp = {
            enable = true;
            sudoGroups = [ "wheel" ];       # may run `sudo opsmcp serve`
            settings = {                     # becomes /etc/opsmcp/config.toml
              roles.readonly.allow = [ "@read" ];
              unix_groups.wheel.roles = [ "readonly" ];
            };
          };
        }
      ];
    };
  };
}
```

`services.opsmcp.http.enable` runs `opsmcp serve-http` as configured under
`settings.http`, and `services.opsmcp.usrBinLink` links `/usr/bin/opsmcp`, the path a
fleet server runs on its hosts, so that a NixOS host answers like any other.

To make the packages yourself: `scripts/package-release.sh tarball TARGET` or
`scripts/package-release.sh deb TARGET` after `cargo build --release --target TARGET`
(a `.deb` is for the release of Debian or Ubuntu it is built on), and
`scripts/test-deb.sh` installs one in a throwaway container and tries it.

### Building for other hosts

A binary only runs where the C library it was linked against is present, so build for
where it will run, not for where you build.

**From NixOS (or any host with Nix): a static binary.** A plain `cargo build` on NixOS
produces a binary that only runs on NixOS (`cannot execute: required file not found`
anywhere else: its loader is a `/nix/store` path). Build a statically linked one
instead, which runs on any x86_64 Linux whatever its distribution or glibc version:

```sh
nix-build packaging/static.nix          # or, with flakes: nix build .#opsmcp-static
scp result/bin/opsmcp root@host:/usr/bin/opsmcp
```

A static binary looks users and groups up in `/etc/passwd` and `/etc/group` only. That
is all opsmcp needs when the accounts that use it are local ones.

**If accounts come from LDAP or sssd: a glibc binary.** Build inside a container of the
oldest distribution release you deploy to; the result runs on that release and newer
ones:

```sh
mkdir -p dist
docker run --rm -v "$PWD":/src:ro -v "$PWD/dist":/out -e OWNER="$(id -u):$(id -g)" ubuntu:22.04 bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq curl ca-certificates gcc
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  . "$HOME/.cargo/env"
  cd /src && cargo build --release --locked --target-dir /tmp/target
  install -m 0755 /tmp/target/release/opsmcp /out/opsmcp-ubuntu-22.04
  chown "$OWNER" /out/opsmcp-ubuntu-22.04'
```

On the target host itself, `cargo build --release` with a Rust toolchain from
[rustup](https://rustup.rs) (1.88 or newer) works too.

## Three ways to connect

**Locally (stdio).** `opsmcp serve` speaks MCP on stdin and stdout. The caller is the
Unix user who started it.

```sh
claude mcp add ops -- sudo -n /usr/bin/opsmcp serve
```

Without `sudo` it works too, limited to what your own account can see and do. With it,
opsmcp runs as root and applies the roles of the user who invoked sudo. Allow exactly
that command and nothing else; see [packaging/sudoers.example](packaging/sudoers.example).

**Over SSH.** The same thing, started on the remote host:

```sh
claude mcp add ops-web1 -- ssh -T web1.example.com sudo -n /usr/bin/opsmcp serve
```

**Over HTTPS.** `opsmcp serve-http` listens as configured under `[http]`; install
[packaging/opsmcp-http.service](packaging/opsmcp-http.service) to run it. TLS is
mandatory. Callers authenticate with a bearer token, a TLS client certificate, or both
(`http.auth`).

```sh
opsmcp new-token claude        # prints a token once, and the stanza to add to the config
claude mcp add --transport http ops-web1 https://web1.example.com:8443/mcp \
    --header "Authorization: Bearer opsmcp_..."
```

The endpoint is `POST /mcp`; `GET /healthz` answers `ok` without authentication, for
monitoring. The server keeps no session state.

Claude Code trusts a server certificate from a CA of your own, and presents a client
certificate to a server that asks for one (`auth = "mtls"` and the like), when these are
set in the environment it is started in (checked with Claude Code 2.1.330):

```sh
export NODE_EXTRA_CA_CERTS=/etc/opsmcp/tls/ca.crt
export CLAUDE_CODE_CLIENT_CERT=~/.config/opsmcp/me.crt CLAUDE_CODE_CLIENT_KEY=~/.config/opsmcp/me.key
```

## Fleets: one connection to many hosts

Setting up a connection per host does not scale past a handful. A **fleet server** is one
MCP connection in front of any number of hosts: the agent asks it which hosts there are,
and every tool takes a `fleet_host` argument saying which one (or, for tools that only
read, which several) the call is for. The fleet server passes the call to that host's own
opsmcp, over SSH or HTTPS. It runs no tools itself.

The hosts stay exactly as described above: each has opsmcp and its own
`/etc/opsmcp/config.toml`, applies its own roles and keeps its own audit trail. Nothing
listens on a host unless you choose HTTPS.

```
your machine      agent -- stdio --> opsmcp fleet (as you) ------------ ssh / https --> hosts
bastion, by SSH   agent -- ssh bastion opsmcp fleet (one process per caller) ---------> hosts
bastion, HTTPS    agent -- https + token --> opsmcp fleet-http (a service) -----------> hosts
```

### On your own machine

With an inventory ([packaging/hosts.example.toml](packaging/hosts.example.toml)) and a
fleet configuration ([packaging/fleet.example.toml](packaging/fleet.example.toml)):

```toml
# ~/.config/opsmcp/fleet.toml (owned by you, writable by nobody else)
[roles.me]
allow = ["@all"]
[unix_users.sean]
roles = ["me"]

[fleet]
inventory = "/home/sean/.config/opsmcp/hosts.toml"

[[fleet.access]]
roles = ["me"]
hosts = ["*"]
via = "ssh"
identity = "caller"       # ssh as yourself: your keys, agent and ~/.ssh/config
```

```sh
opsmcp check-config --config ~/.config/opsmcp/fleet.toml   # hosts, rules, what is missing
claude mcp add fleet -- opsmcp fleet --config ~/.config/opsmcp/fleet.toml
```

Each host is reached with `ssh HOST sudo -n /usr/bin/opsmcp serve`, the same command as a
single-host connection, so a host that works by itself works in the fleet. The session to
a host is opened the first time it is needed, kept while in use and closed after five idle
minutes. `opsmcp fleet --read-only` offers and passes on only tools that change nothing,
which is a good default for looking around: see [What changes with a
fleet](#what-changes-with-a-fleet).

### The inventory: your own list, or Ansible's

The hosts come from a file or from a command:

```toml
[fleet]
inventory = "/etc/opsmcp/fleet/hosts.toml"            # opsmcp's own form, .toml or .json
# inventory_command = ["/usr/local/bin/list-hosts"]   # or a command that prints it as JSON
```

**An Ansible inventory** is read as what `ansible-inventory --list` prints, either saved to
a file or printed by the command:

```toml
[fleet]
inventory_format = "ansible"
inventory_command = ["/usr/bin/ansible-inventory", "-i", "/srv/ansible/hosts", "--list"]
# or: inventory = "/etc/opsmcp/fleet/hosts.json"      # ansible-inventory --list > hosts.json
```

Because it is Ansible that builds the list, everything Ansible can build one from works:
INI and YAML files, directories, inventory plugins and scripts, `constructed` groups.

- Every Ansible group is a group here and holds the hosts of its child groups too, so
  `group:all` is every host.
- A host is reached at its `ansible_host` (its name, if it has none) and on its
  `ansible_port`. `ansible_user` is not used: who to log in as is the rule's business
  (`ssh_user`), or the caller's own ssh settings. The other variables of a host are skipped
  as they are read; they are not kept, logged or shown.
- A host that cannot be used here is **left out**, and `check-config` and the log say which
  and why: a name that is not a DNS name (one with `_` in it), an `ansible_host` that is
  still a template (`ansible-inventory` does not fill templates in), a port that is not a
  number. The same goes for a group whose name is not letters, digits, `_`, `-` and `.`.
- The command runs with a UTF-8 locale, which Ansible insists on, and with
  `ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED=1`: left to itself, Ansible only warns about an
  inventory source it could not read (a cloud that did not answer) and prints the hosts of
  the others, and that shorter list would take hosts away from the fleet.
- Its environment is otherwise empty and its directory is `/`. An inventory that needs its
  own `ansible.cfg`, a home directory or cloud credentials gets them from a small script,
  named as the command:

```sh
#!/bin/sh
# /usr/local/bin/fleet-hosts: owned by root (or by you), writable by nobody else
export HOME=/var/lib/opsmcp-fleet
cd /srv/ansible && exec ansible-inventory --list
```

The server waits for the command when it starts (up to two minutes), and Ansible takes a
while when its sources ask a cloud or a cluster. `opsmcp fleet` on your own machine starts
with every session, so a saved file suits it better: write it from cron, or by hand when the
hosts change.

**The inventory is read again while the server runs.** A file is read again when it has
changed (it is looked at every 30 seconds); a command is run again every 5 minutes.
`fleet.inventory_refresh_secs` sets the interval, and 0 turns it off. `opsmcp fleet-http`
also reads it again at once on SIGHUP (`systemctl reload opsmcp-fleet-http`).

- A new list is held to what the first one was: a file that only you or root can write, a
  command that is a trusted program, valid content, at least one host. A list that fails any
  of that **never replaces the one in use**: the hosts already known stay reachable, the log
  and the audit trail say why, and `fleet_hosts` says that its list may be out of date. It
  is tried again at every look until it works.
- A change is written to the audit trail before it takes effect (`fleet_inventory`: the
  hosts that moved to another address, were added, joined or left a group, or were
  removed). If it cannot be written, the change does not take effect.
- A host whose address changed is connected to afresh: a session to the old address is
  never used for it again. A call that is running finishes with the hosts it started with.
- The rest of the configuration (rules, roles, credentials) is read once, at start.

**Whoever can write the inventory decides where credentials are presented.** opsmcp checks
the file, or the program it runs, and nothing behind them: not the inventory scripts,
plugins and `ansible.cfg` that Ansible goes on to use, and not the cloud account whose tags
become groups and addresses. A host that appears in a group a rule names is offered that
rule's credential at whatever address the inventory gives for it. What then stands between
a made-up address and a credential is the check of the host itself: its SSH host key, or
its certificate from your CA. So with an inventory that others can add to, leave
`StrictHostKeyChecking` at its default (not `accept-new`), name your own CA under
`[fleet.https]` and not the machine's public bundle, and give `identity = "fleet"` rules
groups that are yours to define, not `*`.

### What the agent sees

| Tool | What it does |
| --- | --- |
| `fleet_hosts` | the hosts this caller can reach, their groups, how each is reached, and which are not answering |
| every built-in tool, once | with `fleet_host` added: a host name, or for tools that only read, names separated by commas, a pattern (`web*`) or `group:NAME` |
| `fleet_tools` | what one host offers, including the custom tools only that host defines |
| `fleet_call` | calls a tool by name: for those custom tools |

A read sent to several hosts comes back as one result: a count, the hosts that gave no
answer (each with the reason, never passed over as "nothing found"), then the answers,
with hosts that said the same thing shown together. A tool that changes something acts on
**one host per call**; a call that names several is refused for a tool that changes things,
and is otherwise sent read-only, which the hosts enforce themselves.

A host is only ever reached by a name from the inventory. What the agent sends picks
inventory entries; it is never used as an address or put on a command line. A host no rule
lets a caller reach looks, to that caller, like a host that does not exist.

### Rules: who reaches which hosts, and as whom

`[[fleet.access]]` rules are read top to bottom. For a caller and a host, the **first** rule
that names one of the caller's roles and covers the host decides two things: which
credential is presented to the host, and which grants apply here, which are those of the
roles that rule names and no others. If the grants refuse the tool, or the host refuses the
credential, the answer is no. A later rule, or another credential, is never tried instead.

| `via` | `identity` | The host sees | Who decides what is allowed | What the fleet server holds |
| --- | --- | --- | --- | --- |
| `ssh` | `caller` | the person's own account | the host | nothing |
| `https` | `caller` | the person's own token, with the fleet server's certificate | the host | its certificate; it and every host the rule covers see the token (see [Passing tokens on](#a-bastion)) |
| `ssh` | `fleet` | the account of `ssh_user`, by `ssh_key` | this file, then the host for that account | a key for every host the rule covers |
| `https` | `fleet` | the token in `token_file`, with the fleet server's certificate | this file, then the host for that token | that token and its certificate |

- **`identity = "caller"`** reuses what the caller came with, so it only fits callers who
  have it: SSH needs the fleet server to be running as the caller (`opsmcp fleet` started by
  them, not through sudo and not `fleet-http`); HTTPS needs the caller to have presented a
  bearer token, which every host must then know too. A rule that does not fit is passed
  over, and that depends only on how the caller connected, never on what a host answered.
- **`identity = "fleet"`** is how someone gets more through the fleet than their own login
  gives them (a developer with no account on the hosts can still read the web tier). The
  fleet server is then what decides, so give those accounts modest roles on the hosts and
  pin their keys there (below).
- **`read_only = true`** on a rule refuses tools that change things here and tells the
  hosts to refuse them too.
- A grant in a fleet configuration **cannot be limited to a resource**
  (`service.control:nginx.service` is an error there): the fleet server sees a tool's name,
  never the unit or path a host resolves it to. Grant the permission here and limit it in
  the hosts' configuration, for the account the fleet reaches them as.

`opsmcp check-config --config fleet.toml` prints the rules as a table, with how many hosts
each covers, and points out hosts a rule names that the inventory does not have.

### A bastion

**By SSH, as yourself.** `claude mcp add fleet -- ssh -A bastion opsmcp fleet` runs the fleet
server on the bastion as you, one process per connection; rules with `identity = "caller"`
then use your forwarded agent. While you are connected, root on the bastion can use that
agent. If that matters, run `opsmcp fleet` on your own machine instead and make the bastion
a jump host (`options = ["ProxyJump=bastion.example.com"]` under `[fleet.ssh]`, or in your
own `~/.ssh/config`): the key then never leaves your machine.

**By SSH, with keys the bastion holds.** `ssh bastion sudo -n /usr/bin/opsmcp fleet` runs it
as root for the user sudo names, so it can read keys that only root can. Under sudo the
process is not the caller, so rules with `identity = "caller"` never apply: only
`identity = "fleet"` rules do.

**By HTTPS.** `opsmcp fleet-http` listens as configured under `[http]`, with tokens and
client certificates exactly as on a host; install
[packaging/opsmcp-fleet-http.service](packaging/opsmcp-fleet-http.service). It does not need
root. Its callers have no SSH identity, so each rule either passes the caller's own token on
(`via = "https"`, `identity = "caller"`) or uses a credential of the fleet's.

**Passing tokens on.** A rule with `via = "https"` sends a bearer token to every host it
covers: the caller's own (`identity = "caller"`) or the one in `token_file`. A bearer token
is good wherever it alone is enough, so a host that receives one (a compromised host, say)
could use it on the other hosts, and a caller's own token on the fleet server itself.
Mutual TLS closes that, in three places:

- **The fleet server has a client certificate** (`client_cert` and `client_key` under
  `[fleet.https]`). This is required: a configuration with a rule over HTTPS and no
  certificate is refused.
- **The hosts ask for it, and for no other**: `auth = "mtls+token"` under their `[http]`,
  with `client_ca` naming the CA that issued the fleet server's certificate, and that
  certificate listed:

  ```toml
  [http]
  auth = "mtls+token"
  client_ca = "/etc/opsmcp/tls/ca.crt"

  [client_certs.bastion]
  cn = "bastion1.example.com"     # or sha256 = "...", for that one certificate
  ```

  A token is then only good through the fleet server, and the fleet server's certificate
  does nothing without a token. The fleet server cannot see whether a host asks, so this
  half is yours to set.

  The listing matters when the CA issues other certificates too, as one CA for
  everything does: with nothing under `[client_certs]`, a host takes a token with **any**
  certificate of that CA, so every machine holding one could present a token it was
  sent. `check-config` on a host says which of the two is in effect. Listing by `cn`
  relies on the CA never giving that name to anything else; `sha256` names one
  certificate, and has to be changed when it is renewed. Without a CA at all, a
  certificate that signs itself can be named as `client_ca` (with OpenSSL 3):

  ```sh
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
      -subj "/CN=bastion1" -addext "basicConstraints=critical,CA:FALSE" \
      -addext "extendedKeyUsage=clientAuth" -keyout client.key -out client.crt
  ```
- **The fleet server asks its own callers for one** when it passes their tokens on:
  `auth = "mtls+token"` under its own `[http]`, so that a host cannot present a token it
  was sent to the fleet server. `check-config` warns when this is missing. If the callers'
  certificates come from a CA that the hosts' certificates come from too, list the
  callers' under `[client_certs]` here, for the same reason as on the hosts.

The hosts' certificates are always verified, for the address in the inventory, before a
token is sent; there is no option to skip that.

**Pinning a key of the fleet's on the hosts.** In the service account's `authorized_keys`:

```
restrict,from="10.0.0.5",command="sudo -n /usr/bin/opsmcp serve" ssh-ed25519 AAAA... fleet-dev
```

The key then only works from the bastion's address, only runs opsmcp, and cannot forward
anything or get a terminal. Give the account the role it needs in the host's configuration
(`[unix_users.opsmcp-dev] roles = ["readonly"]`) and the one sudoers line for
`/usr/bin/opsmcp serve`.

### Operators and developers through one bastion

When several kinds of people call one `fleet-http`, a host has two ways to tell an
operator from a developer. Neither takes the bastion's word for a role: a host gives a
role only to a credential it knows. The configurations below show only what differs from
[packaging/fleet.example.toml](packaging/fleet.example.toml).

| | A credential per level | Each person's own token |
| --- | --- | --- |
| Rules | `identity = "fleet"`, one rule per level | `via = "https"`, `identity = "caller"` |
| The host sees | an account (or token) that stands for a level; the person's name is beside it in the audit trail, as a note | the person |
| People are managed | on the bastion only | on the bastion and on every host |
| On the hosts | nothing listens (over SSH) | `serve-http`, with `auth = "mtls+token"` |
| The bastion holds | a key for each level | its certificate; it sees the token of everyone who calls through it |

**A credential per level.** The bastion picks the account by the caller's role, and each
host gives that account a role of its own:

```toml
# the bastion: /etc/opsmcp/fleet.toml
[roles.ops]
allow = ["@all"]
[roles.dev]
allow = ["@read"]
[tokens.olga]             # opsmcp new-token olga
sha256 = "..."
roles = ["ops"]
[tokens.dana]
sha256 = "..."
roles = ["dev"]

[[fleet.access]]
name = "ops-all"
roles = ["ops"]
hosts = ["*"]
via = "ssh"
identity = "fleet"
ssh_user = "opsmcp-ops"
ssh_key = "/etc/opsmcp/fleet/ops_ed25519"

[[fleet.access]]
name = "dev-web"
roles = ["dev"]
hosts = ["group:web"]
via = "ssh"
identity = "fleet"
ssh_user = "opsmcp-dev"
ssh_key = "/etc/opsmcp/fleet/dev_ed25519"
read_only = true
```

```toml
# every host: /etc/opsmcp/config.toml
[unix_users.opsmcp-ops]
roles = ["admin"]
[unix_users.opsmcp-dev]
roles = ["readonly"]
```

Each key is pinned to its account as above. People with accounts on the bastion can use
the same rules without tokens or TLS: `ssh bastion sudo -n /usr/bin/opsmcp fleet`, with
`[unix_groups.ops] roles = ["ops"]` in place of the `[tokens]`.

**Each person's own token.** The bastion lets a call through and passes the caller's
token on; each host knows the person and decides:

```toml
# the bastion: /etc/opsmcp/fleet.toml
[roles.staff]
allow = ["@all"]          # the hosts decide who may do what
[tokens.olga]
sha256 = "..."
roles = ["staff"]
[tokens.dana]
sha256 = "..."
roles = ["staff"]

[http]                    # callers show a certificate too: see Passing tokens on
auth = "mtls+token"
client_ca = "/etc/opsmcp/tls/ca.crt"

[[fleet.access]]
name = "own-token"
roles = ["staff"]
hosts = ["*"]
via = "https"
identity = "caller"

[fleet.https]
ca = "/etc/opsmcp/tls/ca.crt"
client_cert = "/etc/opsmcp/fleet/client.crt"
client_key = "/etc/opsmcp/fleet/client.key"
```

```toml
# every host: /etc/opsmcp/config.toml
[tokens.olga]
sha256 = "..."            # the same hash as on the bastion
roles = ["admin"]
[tokens.dana]             # left out on hosts she has no business on
sha256 = "..."
roles = ["readonly"]

[http]
auth = "mtls+token"
client_ca = "/etc/opsmcp/tls/ca.crt"

[client_certs.bastion]    # of all that CA issued, only the bastion's certificate
cn = "bastion1.example.com"
```

### What changes with a fleet

- **Injected text reaches further.** Tool output is host data that others can influence.
  With one host, a log line written to look like instructions can at most misdirect the
  agent on that host. With a fleet, text from one host could steer a call to another. That
  is why a change acts on one host per call (each is its own step for you to approve and
  its own audit record), and why read-only sessions exist. It is also why results mark
  what a host said: in a result from several hosts every line a host sent starts with
  `| `, so one host cannot write another's heading, and the same mark is on the reason a
  host gave no answer (which is largely what `ssh`, `sudo` or the host wrote), on what is
  said about a host that is not answering in `fleet_hosts`, and on a host's descriptions of
  its own tools in `fleet_tools`. Lines without the mark are the fleet server's own words.
  Prefer `--read-only` (or a read-only rule) for investigating, and a separate connection
  with write access for when you mean to change things.
- **`identity = "fleet"` makes the fleet server worth attacking.** Whoever controls it can
  use every credential it holds. Keep the accounts behind those credentials modest, pin the
  keys on the hosts, and prefer `identity = "caller"` wherever people have their own access.
- **SSH host keys are always checked.** A host that is not in `known_hosts`, or whose key has
  changed, is refused, not asked about. `StrictHostKeyChecking=accept-new` may be set under
  `[fleet.ssh] options` to trust hosts on first contact; nothing weaker is accepted. A
  session cannot prompt, forward an agent, X11 or ports, or get a terminal, and with a key
  of the fleet's own, ssh is told to use that key and nothing else: no agent, no
  configuration file, no connection another identity opened.
- **The audit trail is in two places.** The fleet server records each decision and result
  per host (`fleet_call`, `fleet_result`); each host records the call as always, with the
  account that was authenticated as `principal` and, beside it under `via`, what the fleet
  server said: its name, who it was acting for, and its call id, which ties the two trails
  together. `via` is recorded as a claim and decides nothing. The fleet server also records
  every change to its inventory (`fleet_inventory`), so the trail shows which address a
  host name stood for at the time of a call.

```json
{"ts":"2026-11-21T19:02:11Z","event":"fleet_call","call":"9f3c2a11-7","principal":"token:dana","roles":["dev"],"transport":"https","peer":"192.0.2.9:51522","tool":"service_status","permission":"service.view","access":"read","host":"web1.example.com","rule":"dev-web","over":"ssh","identity":"fleet","decision":"allow","args":{"fleet_host":"web1.example.com","unit":"nginx.service"}}
{"ts":"2026-11-21T19:02:11Z","event":"tool_call","call":"5db62a66-3","principal":"opsmcp-dev","roles":["readonly"],"transport":"stdio","peer":"10.0.0.5","tool":"service_status","permission":"service.view","access":"read","resource":"nginx.service","decision":"allow","args":{"unit":"nginx.service"},"read_only":true,"via":{"gateway":"bastion1","caller":"token:dana","call":"9f3c2a11-7"}}
```

### When hosts do not answer

Every step has a time limit: connecting (`fleet.connect_timeout_secs`), logging in and
starting opsmcp, and the call itself (`limits.call_timeout_secs`, which should be at least
what the hosts use). A host that could not be reached, or that refused the credential, is
left alone for `fleet.retry_secs` (a minute), so that a call for two hundred hosts is not
held up by ten dead ones and the fleet server does not get itself banned by hammering a
host that keeps saying no. `fleet_hosts` shows which hosts are in that state. A host that
answers but will not take one request (it is larger than the host accepts, say) is not
left alone: that call fails with what the host said, and the next goes through.

At most `fleet.max_connections` SSH sessions are open at once. A call that needs one more
closes a session nobody is using, or waits a few seconds for one to fall out of use,
before it reports that the fleet server is busy; so calls for many hosts take turns.
Keep `limits.max_output_bytes` and `limits.call_timeout_secs` of the fleet server at least
as large as on the hosts, or a host's own answer or time limit is cut short here.

When a connection drops in the middle of a call, a tool that only reads is asked once more
on a new connection. A tool that changes things is never sent twice: the result says the
connection ended and that the tool may have run. When the agent gives up on a call, the
hosts are told to stop working on it.

### Read-only sessions on a single host

The same narrowing is available without a fleet: `opsmcp serve --read-only` (and
`serve-http --read-only`) offers and runs only tools tagged read, whatever the caller's
roles. Asking for less needs no trust, so any caller may also ask per request; that is how
a fleet server passes it on.

## Permissions

Each tool is tagged **read** or **write** and carries one **permission** such as
`service.control`. A **role** is a list of grants; a caller holds one or more roles.

| Grant | Meaning |
| --- | --- |
| `@read` | every tool tagged read |
| `@all` | everything |
| `service.control` | that permission, on anything |
| `service.*` | a glob over permission names |
| `service.control:nginx.service` | that permission, on one thing |
| `fs.read:/etc/haproxy/**` | that permission, on a glob of things |

In the part after the colon, `*` matches within one path segment, `**` across segments,
and `?` one character.

The rules, in full:

1. Nothing is allowed unless an `allow` grant matches.
2. A matching `deny` grant always wins, whichever of the caller's roles it is in.
3. An `allow` limited to a resource does not cover an operation that names no resource.
   `service.view:nginx.service` lets a caller see nginx's status, but not list every
   unit.
4. An operation that names no resource (list every process, query the whole journal)
   covers everything, so any `deny` for its permission refuses it, limited to a
   resource or not. With `deny = ["journal.view:secret.service"]` a caller can query
   other units one at a time, but not the journal as a whole, which would include the
   unit that was denied.
5. Agents are only shown the tools they could use.

```toml
[roles.web-operator]
allow = ["@read", "service.control:nginx.service", "container.control:web-*", "custom.haproxy_set"]
deny = ["fs.read:/etc/ssl/**"]

[unix_groups.ops]
roles = ["web-operator"]
```

Separately from roles, the configuration sets **host-wide limits** that apply to
everyone, administrators included:

| Setting | What it limits | Default |
| --- | --- | --- |
| `fs.read_roots` | directories whose files can be read | none |
| `fs.deny` | paths that can never be listed or read, on top of a built-in list of password files, private keys and credentials | built-in list |
| `kernel.writable_sysctls`, `kernel.writable_sysfs` | sysctls and `/sys` files that can be changed | none |
| `services.protected` | units that cannot be controlled | journald, logind, udevd, dbus, opsmcp |
| `net.probe_targets` | hosts that `net_probe` and `tls_cert_check` may connect to | none |
| `net.capture_interfaces`, `net.capture_payload` | where `packet_capture` may listen, and whether it may show packet contents | none, no |
| `users.min_uid`, `users.protected` | accounts `user_modify` may not touch (uid 0 never) | below 1000, `root` |
| `users.groups` | groups whose membership `user_modify` may change | none |
| `users.manage_ssh_keys` | whether `user_modify` may edit `authorized_keys` | no |
| `fs.write_roots` | directories whose files `config_edit` may replace | none |
| `monitoring.icinga_url` (with user and password file) | whether `monitoring_downtime` works at all; it only ever acts on this host's own entry | not set |
| `monitoring.max_minutes` | the longest downtime `monitoring_downtime` may set | 240 |
| `storage.reclaim` | the `space_reclaim` actions allowed | none |
| `storage.extendable`, `storage.max_extend_gb` | volumes `lvm_extend` may grow, and by how much in one call | none, 50 |
| `firewall.sets` | address sets `firewall_set_member` may change | none |
| `trace.processes`, `trace.system_wide` | processes `process_trace` and `cpu_profile` may attach to, and whether `cpu_profile` may sample the whole host | none, no |
| `db.show_queries` | whether `db_status` shows the text of running queries | no |
| `package.cve_online` | whether `cve_status` may ask the distribution's security service | no |

## Tools

The "resource" column is what a grant's part after the colon is matched against.

| Tool | Access | Permission | Resource |
| --- | --- | --- | --- |
| `system_info`, `memory_info`, `disk_usage`, `disk_io` | read | `system.view` | |
| `process_list` | read | `process.view` | |
| `process_info` | read | `process.view` | `OWNER/NAME`, e.g. `www-data/nginx` |
| `process_signal` | write | `process.signal` | `OWNER/NAME` |
| `service_list` | read | `service.view` | |
| `service_status` | read | `service.view` | unit, e.g. `nginx.service` (its real name, not an alias) |
| `service_control` | write | `service.control` | unit (its real name, not an alias) |
| `service_enable` | write | `service.enable` | unit |
| `log_list` | read | `logs.view` | directory, with a trailing `/` |
| `log_read` | read | `logs.view` | file path |
| `journal_query` | read | `journal.view` | unit, when the query is for one unit |
| `kernel_log` | read | `kernel_log.view` | |
| `fs_list`, `fs_stat` | read | `fs.view` | path (directories with a trailing `/`) |
| `fs_read` | read | `fs.read` | file path |
| `sysctl_get` | read | `sysctl.view` | key, e.g. `vm.swappiness` |
| `sysctl_set` | write | `sysctl.modify` | key |
| `sysfs_set` | write | `sysfs.modify` | path under `/sys` |
| `iptables_list`, `nft_list` | read | `firewall.view` | |
| `iptables_rule` | write | `firewall.modify` | `iptables/TABLE/CHAIN` or `ip6tables/TABLE/CHAIN` |
| `nft_rule` | write | `firewall.modify` | `nft/FAMILY/TABLE/CHAIN` |
| `firewall_reset_counters` | write | `firewall.modify` | as above, with `*` for "every chain" |
| `container_list`, `container_stats` | read | `container.view` | |
| `container_inspect` | read | `container.view` | container name |
| `container_logs` | read | `container.logs` | container name |
| `container_control` | write | `container.control` | container name |
| `cluster_status`, `corosync_status` | read | `cluster.view` | |
| `cluster_resource` | write | `cluster.modify` | `resource/NAME` |
| `cluster_node` | write | `cluster.modify` | `node/NAME` |
| `cluster_maintenance_mode` | write | `cluster.modify` | `property/maintenance-mode` |
| `nrpe_list` | read | `nrpe.view` | |
| `nrpe_check` | read | `nrpe.run` | check name |
| `net_interfaces`, `net_routes`, `net_sockets` | read | `net.view` | |
| `net_probe` | read | `net.probe` | target host (name in lower case, or address) |
| `packet_capture` | write | `net.capture` | interface |
| `tls_cert_check` | read | `tls.view` | file path, or host |
| `package_query`, `package_updates` | read | `package.view` | |
| `package_upgrade` | write | `package.modify` | package name |
| `host_reboot` | write | `host.reboot` | |
| `block_devices`, `disk_health` | read | `storage.view` | |
| `disk_hogs` | read | `fs.view` | directory, with a trailing `/` |
| `resource_top` | read | `process.view` | |
| `crash_events` | read | `crash.view` | |
| `log_summary` | read | `journal.view` | unit, when the summary is for one unit |
| `incident_snapshot` | read | `system.view` | |
| `time_sync_status` | read | `time.view` | |
| `scheduled_jobs` | read | `schedule.view` | |
| `user_list` | read | `user.view` | user, when one is named |
| `user_modify` | write | `user.modify` | user |
| `config_validate` | read | `config.validate` | check name, e.g. `nginx` |
| `change_history`, `perf_history` | read | `history.view` | |
| `wait_for` | read | `wait.use` | `unit/NAME`, `port/N`, `file/PATH` (the real path) or `log/UNIT` |
| `fs_search` | read | `fs.view` | directory, with a trailing `/` |
| `fs_grep` | read | `fs.read` | file path, or directory with a trailing `/` |
| `config_edit` | write | `fs.write` | file path |
| `monitoring_downtime` | write | `monitoring.downtime` | |
| `haproxy_servers` | read | `haproxy.view` | `BACKEND/SERVER`, or `BACKEND/` for a whole backend |
| `haproxy_server_state` | write | `haproxy.server` | `BACKEND/SERVER` |
| `space_reclaim` | write | `storage.reclaim` | action, e.g. `journal` |
| `lvm_extend` | write | `storage.extend` | `VG/LV` |
| `mount_health` | read | `storage.view` | |
| `cgroup_limits`, `service_dependencies` | read | `service.view` | unit |
| `service_limits` | write | `service.limits` | unit |
| `session_terminate` | write | `user.session` | user |
| `process_trace` | write | `process.trace` | `OWNER/NAME` |
| `cpu_profile` | read | `process.profile` | `OWNER/NAME`, when one process is profiled |
| `limits_headroom`, `kernel_status` | read | `system.view` | |
| `security_denials`, `security_posture` | read | `security.view` | |
| `firewall_set_member` | write | `firewall.set` | `nft/FAMILY/TABLE/SET` or `ipset/NAME` |
| `dns_config` | read | `net.view` | |
| `cve_status` | read | `package.view` | |
| `db_status` | read | `db.view` | engine: `mariadb`, `postgres` or `patroni` |
| `hardware_health` | read | `hardware.view` | |
| custom tools | as configured | `custom.NAME` | |

Paths are always judged by where they really are, after links are resolved. A link in
`/var/log` that points at `/etc/shadow` is `/etc/shadow` as far as every check is
concerned. (On NixOS, where much of `/etc` is links into `/nix/store`, add `/nix/store`
to `fs.read_roots` to read those files.) A file whose real location cannot be
established from the host is refused: one that has been deleted but is still open
somewhere, or one inside a container reached through `/proc/PID/root`.

`nrpe_check` is tagged read, so `@read` includes running the checks in `nrpe.cfg` (as
the NRPE user), just as your monitoring system does every few minutes. If some of your
checks have side effects, add `deny = ["nrpe.run"]` to the role, or grant individual
checks with `nrpe.run:check_load`.

Changes to the firewall, sysctls and `/sys` affect the running system only. They are not
saved, and a reboot brings the configured state back.

### Notes on particular tools

**Reaching other hosts.** `net_probe`, and `tls_cert_check` when given a host, make this
host connect somewhere else, so both are limited to `net.probe_targets` for everyone.
A target is a host name or an address, written out in full: forms such as `127.1` or
`2130706433`, which resolvers read as addresses, are refused. Patterns and grants are
matched against its one standard form: a name in lower case, or an address as it is
normally written (`::ffff:10.0.0.5` counts as `10.0.0.5`). A name is matched as a
name, and what it resolves to is not checked again, so a pattern or a grant for a
name covers whatever this host's resolver says that name is. `net_probe` reports
reachability only: a TCP probe connects and hangs up without sending anything.

**Capturing traffic.** `packet_capture` changes nothing, but it is tagged write so that
`@read` never includes reading other people's traffic; grant `net.capture` by name. It
listens only on `net.capture_interfaces`, without promiscuous mode, for at most 30
seconds and 1000 packets. Each packet is one line of time, addresses, ports, protocol
and length, and the contents are not even captured; TCP flags, decoded protocol
detail and contents appear only with `payload`, which needs `net.capture_payload`.
The filter is a tcpdump expression (it can still select on flags, such as resets);
tcpdump options are not accepted.

**Certificates.** `tls_cert_check` describes the certificates in a file, or the ones a
server presents, with a one-line verdict first (expired, expires soon, wrong name, not
trusted by this host's CA bundle; `UNVERIFIED` rather than `OK` when there is no CA
bundle to check against). A file is subject to the same limits as `fs_list`,
so it cannot be pointed at a private key; only certificate details are ever returned.

**Packages.** `package_query` and `package_updates` work on dpkg/apt and rpm/dnf hosts
and never refresh the package lists. `package_upgrade` upgrades packages that are
already installed and may bring in new dependencies (a new kernel, for instance). On
apt hosts it never removes a package, so an update that would need one removed stays
pending, and it keeps locally changed configuration files. On dnf hosts dnf's own
upgrade rules apply: an obsoleted package can be replaced and old kernels removed.
A real run is started as a systemd unit of its
own (`opsmcp-pkg-...`), so it is not cut off half way if it outlasts the call; the
result then names the unit to follow. A grant such as `package.modify:nginx*` limits
it to those packages; upgrading everything, or only refreshing the lists, needs the
permission without a resource.

**Rebooting.** `host_reboot` only reboots (never powers off), one minute ahead by
default so that it can be cancelled, and warns logged-in users. On a Pacemaker node it
refuses unless the node is offline, or in standby with its resources gone; maintenance
mode does not count, because resources keep running there. It also refuses when it
cannot tell (the cluster does not answer, or `crm_mon` fails for any reason other
than no cluster running), and on a cluster node the reboot must be within ten minutes
of that check. `force` overrides all of this.

**Disk space.** `disk_hogs` adds up a directory tree itself: one filesystem, no links
followed, stopping at the time limit with what it has (unfinished directories are
marked `>=`). Everything under the directory counts towards its totals, but only
paths the caller could list with `fs_list` are named. It also lists deleted files
that a process still holds open, which is space `du` cannot see; which process holds
them is shown only to a caller who also has `process.view`.

**One-call triage.** `incident_snapshot` gathers load, memory, full filesystems, top
processes, failed units, recent errors, crashes and interface errors. Each part is
included only if the caller holds the permission of the tool it comes from
(`process.view` for the processes, `journal.view` for the errors, and so on), so it
never shows more than the caller could have asked for piece by piece. The same holds
for the per-unit figures in `resource_top`, which need `service.view`.

**Log summaries.** `log_summary` counts journal entries by source and groups repeated
messages. A source is the systemd unit an entry came from; an entry from no unit is
filed under the name its sender gave itself and marked `(syslog id)`, because any
local user can pick that name.

**Scheduled jobs.** `scheduled_jobs` lists systemd timers with how each unit's last
run ended, and every crontab on the host, including users' own. Scripts and files
that cron would skip (not executable, or a name such as `job.dpkg-old`) are marked.
Cron lines often carry passwords. They are masked on the same best-effort basis as
process command lines, so treat `schedule.view` like `process.view`.

**Accounts.** `user_list` and `user_modify` see the accounts in `/etc/passwd`; accounts
that exist only in LDAP or sssd are not shown and cannot be changed. `user_modify` can
lock and unlock an account, change membership of the groups in `users.groups`, and,
with `users.manage_ssh_keys`, add or remove keys in `authorized_keys`. Locking refuses
password and key logins alike but does not end sessions that are already running.
Unlocking undoes only that: an expiry date someone set on the account is left as it
is. A key to be added must be a complete key of its type, with no options in front.
Password hashes are never shown; only whether a password is set or locked.

**Checking configuration.** `config_validate` runs a service's own check (`nginx -t`,
`haproxy -c`, `sshd -t`, `visudo -c` and others) with fixed arguments. Some checkers
report a mistake only as a warning and still exit cleanly (`postfix check` does); the
verdict then reads "valid, with warnings". Checks for other services can be added as
custom tools.

**What changed, and what happened earlier.** `change_history` puts package installs and
removals, boots, unit starts, stops and failures, files changed under `/etc` and sudo
use on one timeline. Each kind appears only if the caller holds the permission of the
tool that owns it (`package.view`, `service.view`, `fs.view` with `/etc` inside
`fs.list_roots`, `journal.view`); events
that repeat, such as a timer firing or monitoring running sudo, are collapsed into one
line with a count. `perf_history` shows CPU, memory, I/O, load or network for a past
period from the sysstat (`sar`) records, or atop's; it needs one of the two to be
collecting. Times in both are the host's local time.

**Waiting.** `wait_for` waits, for at most ten minutes and never longer than one call
may take, for a unit to become active or inactive, a TCP port to be listening or
closed, a file to appear or go, or a line matching a pattern to be logged by a unit.
At most half of the call slots may be taken by waits at once, so waits cannot crowd
out other calls.
A wait is a way of finding something out, so besides `wait.use` the caller must hold
the permission that the corresponding tool needs on the same thing: `service.view` on
the unit, `net.view`, `fs.view` on the path, `journal.view` on the unit.

**Searching files.** `fs_search` finds files by name, age, size, type or owner under a
directory, with the limits of `fs_list`; `fs_grep` searches the contents of files, with
the limits of `fs_read` (`fs.read_roots`, the never-readable list, the caller's
grants on each file) and the same masking of secrets as elsewhere. Neither follows a
link or leaves the filesystem it started on, and both stop at a time limit and say so.

**Editing configuration.** `config_edit` replaces a file under `fs.write_roots`:
either one exact piece of text that occurs once (`replace`), or the whole content
(`write`). The previous content is first copied to `fs.backup_dir` (the newest twenty
versions of each file are kept, readable by root only) and can be put back with
`restore`. The new file is written beside the old one and renamed over it, so a reader
never sees half a file. It keeps the old file's owner, permissions, ACL, security
label (SELinux or another) and other extended attributes, and does not pick up an ACL
that the directory would give a new file; if one of those cannot be carried over,
nothing is changed. A file it creates gets the mode asked for together with whatever
the directory gives new files (a default ACL, a label), as a file made there by hand
would, and the result says so when that is stricter than the mode asked for. With `validate`, the
service's own check from `config_validate` runs afterwards, and if it fails the old
content is put back at once; the caller needs `config.validate` on that check as
well, since the check's output is shown. Things to know:

- One call carries at most about 3000 bytes, because a change's arguments must fit
  whole in the audit trail. Larger changes are several `replace` calls. It also means
  the audit trail holds every piece of text written this way.
- It never writes the account files, sudoers, PAM configuration, the dynamic linker's
  files, SSH keys or opsmcp's own files, and never through a symbolic link or to a file
  with a second hard link.
- Being able to write a directory that root runs things from (cron, systemd units,
  profile scripts) is being able to become root. List the directories of particular
  services in `fs.write_roots`, and scope the grant: `fs.write:/etc/nginx/**`.
- `replace` has to find text in the file, which is a way of reading it, so it needs
  `fs.read` on the file as well (and the file inside `fs.read_roots`). `write` and
  `restore` do not, and no result ever shows old content.
- Files with a set-user-id, set-group-id or sticky bit, or with file capabilities, are
  refused: those are programs, not configuration. Integrity signatures (IMA, EVM) are
  not carried over, since they are of the old content.
- Edits are made one at a time within one server. Separate sessions over stdio or SSH
  are separate servers; between them an edit is refused if the file changed while it
  was being prepared.
- A file that configuration management (Ansible, Puppet) also manages will be
  overwritten at its next run.

**Monitoring downtime.** `monitoring_downtime` sets, lists and cancels Icinga 2
downtimes for this host and its services, through the Icinga API. The host it acts on
comes from the configuration, never from the caller, and `cancel` removes only
downtimes that opsmcp set. It needs an API user and a password file on the host; give
that user only `actions/schedule-downtime`, `actions/remove-downtime` and
`objects/query/Downtime`, each with a filter on this host, so that a stolen password
cannot silence anything else. The API's certificate is always verified. It refuses to
add a downtime when opsmcp has already set ten on the host.

**HAProxy.** Looking and changing are two tools, so that a read-only role can watch
and only a role that was granted it can act. `haproxy_servers` (read) shows each
server's status and the sessions it has in progress, for one backend or for all of
them; that is how a drain is watched. `haproxy_server_state` (write) puts a server into
`drain` or `maint`, or back to `ready`, through the admin socket, and shows the backend
before and after. It refuses to take the last server that is up out of a backend unless
forced; a server without a health check counts as up. The change is to the running
HAProxy only. Both list only the servers the caller's grant covers.

**Freeing and adding disk space.** `space_reclaim` runs one of a fixed set of actions,
each of which must be listed in `storage.reclaim`: shrink the journal to a size, empty
the package cache, prune unused container images, delete old core dumps, or run the
host's own temporary-file cleanup. Shrinking the journal removes its oldest entries,
and with them any opsmcp audit records that are kept only in the journal: send the
audit trail to a file or another host as well if you grant that action. `lvm_extend`
grows a logical volume listed in
`storage.extendable` and the filesystem on it, by at most `storage.max_extend_gb` a
call. It only ever grows, only plain volumes (not snapshots, thin volumes, mirrors or
RAID), and runs as a systemd unit of its own so that it is not cut off half way.

**Mounts.** `mount_health` asks every network filesystem for its status with a time
limit, so a hung or stale NFS mount shows up as such instead of hanging the caller,
and reports filesystems that have gone read-only and `fstab` entries that are not
mounted. A mount that did not answer is left alone for five minutes before it is
asked again, so repeated calls do not pile up stuck processes.

**Limits on services.** `cgroup_limits` says whether a unit is at its memory limit,
has had processes killed for memory, or is having its CPU throttled.
`service_limits` sets a memory, CPU or task limit on a running service or scope
without restarting it. Slices are not offered: a limit on a slice holds back
everything under it, protected units included. It refuses a memory limit below what
the unit uses now, which would make the kernel kill processes at once, and a CPU
quota under 10%, unless forced. The limit lasts until the next reboot; nothing is
written under `/etc`. `service_dependencies` shows what a unit
needs, what needs it, which requirement or start condition was not met, and the chain
of units that delayed it at boot. Other units are named only if the caller may see
them.

**Ending sessions.** `session_terminate` ends a user's login sessions, all or one,
under the same limits as `user_modify` (never uid 0, never accounts below
`users.min_uid` or in `users.protected`), and never the user opsmcp itself runs as. A
local or SSH caller cannot end all the sessions of the account they are calling from.
Processes the user started outside a login session are counted, not killed.

**Tracing and profiling.** `process_trace` runs `strace` on one process for at most 30
seconds: a per-call summary of counts, time and errors, or the calls themselves. Data
passed to read and write calls is never shown, but file names and network addresses
are, and tracing slows the process down, so the tool is tagged write and granted by
name, like `packet_capture`. `cpu_profile` samples with `perf` and lists where CPU
time went, for one process or, with `trace.system_wide`, the whole host. Both work
only on processes matching `trace.processes`, and you state the name of the process
you mean, as with `process_signal`.

**Headroom.** `limits_headroom` lists the limits a host can run into without the usual
graphs showing it (open files, process ids, inotify watches, connection tracking, TCP
memory, the ARP table, inodes) with how full each is, and the kernel counters that
say a limit has already been hit since boot. The processes nearest their own
open-file limit are listed for a caller with `process.view`; when that check was not
made, or only in part, the first line says so.

**Security checks.** `security_denials` groups recent AppArmor, SELinux and seccomp
denials by program, the usual cause when something fails although its permissions
look right. It reads only what the kernel and the audit system recorded, so a log
line a user wrote to look like a denial is not counted. `security_posture` is a one-screen summary with the same shape on every
host: effective sshd settings, the firewall's default policy, pending security
updates, risky accounts, the access-control mode, kernel hardening settings and
exposed ports. Parts that belong to another permission are shown only to callers who
hold it. `cve_status` says whether the fix for a CVE is in an installed package. On
dpkg hosts it reads the installed packages' changelogs and quotes the lines that name
the CVE: a package that names it normally carries the fix, but read the lines, since
a changelog can also mention a CVE without fixing anything. It cannot tell "not
affected" from "not fixed yet", and a fix that is installed takes effect only once
the programs using it are restarted (a kernel: after a reboot). With `online`, which
needs `package.cve_online`, it also asks `pro` on Ubuntu, or fresh repository data on
rpm hosts; that needs outbound network access and sends the CVE id out. On rpm hosts
it otherwise uses dnf's cached advisory data.

**Firewall sets.** `firewall_set_member` adds an address or network to a named
nftables set or ipset, or removes it, optionally with an expiry, without touching any
rule. Only sets listed in `firewall.sets` can be changed. Networks wider than /8
(IPv4) or /16 (IPv6) are refused, and so, unless forced, is a change that covers the
address of the HTTPS caller making it, since the tool cannot know whether the set
blocks or allows. A network is added to an ipset only if the set holds networks, since
a set of single addresses would take it one address at a time. The change is to the
running firewall only.

**Name resolution.** `dns_config` shows `resolv.conf`, what systemd-resolved uses per
link and its cache statistics, the `hosts:` line of `nsswitch.conf` and the entries
in `/etc/hosts`.

**Databases.** `db_status` runs fixed status queries and nothing the caller supplies.
`mariadb` covers MariaDB, MySQL and Percona, with Galera state when present;
`postgres` covers connections, replication in both directions, replication slots,
long transactions, locks, sizes and transaction-id age; `patroni` shows the cluster as
`patronictl` sees it: leader, members, lag, timelines, maintenance mode, pending
restarts and the last leader changes. The first line is a verdict, with `PROBLEM:`
items when something is wrong. The text of running queries is shown only with
`db.show_queries`, because queries can hold personal data; the same setting decides
whether a replication error is shown with the statement and values it names.
PostgreSQL is reached as the `postgres` user over its local socket on the default
port (a different user needs the `pg_monitor` role, and the report says so when it
sees only part), MariaDB by socket authentication or the client options file named in
`db.mysql_defaults_file` (a `~/.my.cnf` is not read: commands run without a home
directory; when opsmcp runs as root that file must be root's own, like every file it
trusts). No password is ever put on a command line. A part of the report that could
not be read is named as such and never reads as "none". With the cluster store (etcd)
unreachable `patronictl` retries for minutes, so `db_status` gives it fifteen seconds
and then says so.

**Kernel and hardware.** `kernel_status` shows the running kernel, why it is tainted,
out-of-tree modules, live patches and CPU vulnerability mitigations. `hardware_health`
reads temperatures, fans, memory-error counters, power supplies and, where there is a
management controller and `ipmitool`, its failing sensors and event log. On a virtual
machine most of it is empty, and it says so.

## Custom tools

Your own scripts become tools by listing them in the configuration:

```toml
[custom.haproxy_set]
description = "Mark this host up, down or draining in HAProxy. Drain before maintenance."
access = "write"                                   # read: covered by @read
command = ["/usr/local/sbin/haproxystatus", "{state}"]
# optional: timeout_secs, run_as, ok_exit_codes, [custom.haproxy_set.env]

[custom.haproxy_set.params.state]
type = "enum"                                      # string | integer | boolean | enum
description = "State to set"
values = ["up", "down", "drain"]
required = true
```

`command` is an argument list, not a command line. The first element is the program, as
an absolute path. In the others, `{name}` is replaced by a parameter (the element is
dropped if the parameter was not given) and `{name?text}` becomes `text` when a boolean
parameter is true. No shell is involved, and a value always stays inside one argument.

String values must match the parameter's `pattern` in full. Without one, a string may
contain letters, digits and `_ . : @ / = + , -` and may not start with `-`. Integers are
not negative unless you set `min`.

The description is what the agent reads to decide when to use the tool; make it say
what the command does and when it is appropriate. The permission is `custom.NAME`.

## Security model

**Who is trusted.** The operator who writes `/etc/opsmcp/config.toml` (and `nrpe.cfg`) is
trusted. Callers are not: an agent is assumed to be capable of anything its roles allow,
whether by mistake or because something it read told it to.

**Identity.** On stdio, the caller is the Unix user who started opsmcp, or under sudo the
user sudo says invoked it. sudo is the only supported way to give it more privilege; a
setuid opsmcp refuses to run. Over HTTPS, the caller is the bearer token (compared by
hash, in constant time) or the client certificate (by common name or fingerprint, once
TLS has verified it against your CA). A token that is presented must be valid: a bad
token is never ignored in favour of a certificate.

**Running as root.** When opsmcp runs as root it only uses a configuration file, TLS
files, an `nrpe.cfg` and programs that are owned by root and that nobody else can
replace, checking every directory on the way to them. A user allowed to run
`sudo opsmcp serve` therefore cannot point it at a configuration or a program of their
own.

**Running commands.** External programs are started with an argument list and never
through a shell (the one exception is NRPE checks, whose command lines come only from
`nrpe.cfg`, take no caller input, and run as the NRPE user). They get a fixed, clean
environment, no stdin, a time limit that kills the whole process group, and a cap on
output. Caller-supplied values are validated before they get near a command line: unit
names, chain names, container names and so on must match what those things can be
called, and firewall rules are checked so that a rule cannot switch table or chain,
start another command, or make iptables run a program.

**Acting on the right thing.** Where a name can refer to something else by the time it is
used, opsmcp pins the thing first and checks what it pinned: files are opened by handle
and checked by their real path; a process is held by pidfd before its owner and name are
checked, and you must state the name of the process you mean to signal; containers are
resolved to a full id and judged by their real name; systemd aliases are resolved to the
unit's real name.

**Client certificates.** A certificate is accepted while it verifies against
`http.client_ca` and is listed; there is no CRL or OCSP check. To revoke one, remove its
entry (or pin certificates by `sha256` rather than `cn`, so that a reissued certificate
has to be listed anew) and restart. With `auth = "mtls+token"` the token is the caller
and a certificate only lets it in: entries under `[client_certs]` then have no roles, and
once there is one, a token is only taken with a listed certificate. With none, any
certificate of the CA will do, which is only right for a CA that issues nothing else.

**Host settings that matter.** `fs.protected_hardlinks` must be 1 (the default on every
current distribution; opsmcp warns at startup if it is not). With it off, a local user
can hard-link a file they cannot read into a directory opsmcp may read from, and a hard
link is the file itself: no path check can tell.

**What agents see.** Tool output is host data that other parties can influence: a log
line can contain text written to look like instructions. opsmcp cannot make that
trustworthy. It does remove terminal escape sequences and invisible or
direction-changing characters (including the tag characters and variation selectors
that can carry text nobody sees), so that what the agent and a human reviewer see is
what is there; a value in a table cannot break out of its cell to add lines of its
own; and it tells the agent to treat output as data. Secrets in process command lines,
cron lines and container definitions are masked on a best-effort basis: options and
variables whose names say they are secrets, `user:password` forms, secret HTTP
headers, and the password options of the MySQL tools and sshpass. Container
environment values are always hidden and process environments are never shown. Do not
rely on the masking: grant `@read` only to callers you would let read your process
list, crontabs and logs.

**Writing in a user's home directory.** When `user_modify` edits `authorized_keys`
it is root working in a directory the user controls. It never follows a symbolic link
there, never writes to a file that has a second hard link, does every step through
open directory handles rather than by path, and replaces the file with a new one that
keeps the old one's owner and permissions. `config_edit` writes the same way, and
also carries the file's ACL and security label over to the new file.

**Credentials opsmcp holds.** Two tools use a credential that the operator puts on the
host: the Icinga API password for `monitoring_downtime` (a file only root can read)
and, optionally, a MariaDB client options file for `db_status`. Neither is ever shown,
logged or passed on a command line. Give the Icinga user rights over this one host
only.

**What it does not protect against.** A caller with broad write grants is as powerful as
those grants: unscoped `firewall.modify` can cut the host off, `user.modify` with key
management on can let someone log in as another user, `host.reboot` can take the host
down, `fs.write` on a directory root runs things from is root, and a custom tool is
only as safe as the script behind it. Scope write grants to the units, chains,
containers, packages, accounts, files and backends that are meant.

## Audit trail

Every tool call produces a record when it is decided and another when it ends, whether
it was allowed or not. Sessions and failed HTTPS authentications are recorded too.
Records are JSON, one per line, sent to syslog (facility `authpriv`) and optionally to a
file:

```json
{"ts":"2026-11-19T22:11:07Z","event":"tool_call","call":"5db62a66-10","principal":"sean","roles":["readonly"],"transport":"stdio","tool":"fs_read","permission":"fs.read","access":"read","resource":"/etc/shadow","decision":"deny","reason":"/etc/shadow matches the never-readable pattern /etc/shadow*","args":{"path":"/etc/shadow"}}
{"ts":"2026-11-19T22:11:07Z","event":"tool_result","call":"5db62a66-10","principal":"sean","tool":"fs_read","outcome":"denied","duration_ms":0,"output_bytes":69}
```

`principal` is a Unix user name, `token:NAME` or `cert:NAME`. `resource` is the real
thing acted on (the resolved path, the unit's real name). `outcome` is `ok`, `failed`,
`denied`, `invalid`, `timeout`, `busy`, `internal`, or `cancelled` when the caller gave
up, disconnected, or the server was stopped part-way.

A read-only session or request adds `"read_only":true` to its records. A call that a
[fleet server](#fleets-one-connection-to-many-hosts) passed on carries `via`: what that
server said about it (its name, who it was acting for, its call id). `via` is a claim made
by `principal`, kept for the record; no decision is ever based on it.

With `audit.fail_closed` (the default) a tool does not run if its record cannot be
written. The arguments are recorded exactly as sent when they fit in a record (3000
bytes). A call that changes something is refused if they do not, so no change is made
whose arguments the trail does not show in full; a read with larger arguments is
recorded with shortened arguments and their SHA-256 (`args_sha256`).

## Limits

Set under `[limits]`: the largest result returned (64 KiB), the time allowed for one
external command (30 s) and for one whole call (120 s), the number of calls running at
once (8), and the largest request (1 MiB).

When there is more than fits in a result, the tool chooses what to keep and says what
it left out: the newest lines of a log tail, journal query or container log; a whole
number of lines of a file, with the offset to continue from. Log reads examine at most
64 MiB of a file.

Over HTTPS, `http.max_connections` bounds open connections, and one client address may
hold at most half of them. A JSON-RPC batch stops starting new requests once one
call's time limit has passed.

## Not included yet

- A safety net for firewall changes (automatic revert unless confirmed), which is the
  most valuable thing to add before granting `firewall.modify` widely.
- Creating and deleting accounts, and changing passwords.
- Filtering collections item by item. A caller with a `deny` limited to one resource
  cannot use the "list everything" tools for that permission at all (rule 4 above).
- Certificate revocation lists.
- Reloading the configuration without a restart. The HTTPS server keeps no state, so a
  restart is cheap.
- Installing or removing packages (only upgrades of installed ones), and Nix.
- A PostgreSQL port other than the default for `db_status`, and MySQL or MariaDB
  servers reached over the network.
- Monitoring systems other than Icinga 2 for `monitoring_downtime`.
- A limit on how many long calls one caller may run at once (waits are limited as a
  whole).
- For fleets: reading Ansible's inventory files where Ansible itself is not installed
  (what `ansible-inventory --list` printed elsewhere can be copied over); short-lived SSH
  certificates in place of the stored keys of `identity = "fleet"` rules; tokens made for
  one host each in place of passing a caller's own token on; a fleet server that hosts
  trust to say which role a caller has (today a host gives a role only to a credential it
  knows, see [Operators and developers through one
  bastion](#operators-and-developers-through-one-bastion)); a change sent to several hosts
  in one call; grants limited to a resource in the fleet's own configuration; limits per
  caller (one caller with slow calls to many hosts can keep the others waiting).

## Development

```sh
cargo test                     # unit tests and end-to-end tests of the built binary
cargo clippy --all-targets     # unwrap, expect and panic are denied outside tests
cargo fmt
nix flake check                # builds the package and boots a NixOS VM set up by the module
```

CI (`.github/workflows/ci.yml`) runs these and builds every package for each push. A
release is a tag: set `version` in `Cargo.toml`, commit, then `git tag vX.Y.Z` and push
the tag; `release.yml` checks that the two agree, tests the tagged source and publishes
the packages.

No `unsafe` code. The layout:

| Path | What is there |
| --- | --- |
| `src/policy.rs`, `src/glob.rs` | grants and how they are matched |
| `src/config.rs` | the configuration and its validation |
| `src/identity.rs` | who the caller is on stdio |
| `src/mcp.rs` | the MCP protocol and the order of checks for a tool call |
| `src/stdio.rs`, `src/http.rs` | the two transports |
| `src/exec.rs` | the only place external programs are started |
| `src/audit.rs` | the audit trail |
| `src/tools/` | the tools, one file per area; `paths.rs` is the safe way to open a path, and `mod.rs` holds the test stand-ins (`FakeBins`) |
| `src/fleet/` | the fleet server: `inventory.rs` (hosts and how callers name them), `access.rs` (which rule decides), `mod.rs` (the order of checks for a call), `ssh.rs`, `https.rs` and `link.rs` (reaching a host), `pool.rs` (sessions kept open, hosts left alone), `merge.rs` (several hosts' answers as one), `setup.rs` (reading the inventory and credentials, and keeping the inventory current) |
| `tests/cli.rs` | end-to-end tests |
| `scripts/`, `packaging/`, `nix/`, `flake.nix` | packaging: the script that makes the tarballs and the `.deb`, the unit files and examples they carry, and the Nix package, NixOS module and its test |

Comments marked `AIDEV-NOTE:` explain the decisions that the security of the whole
rests on; `grep -rn AIDEV- src/` lists them.
