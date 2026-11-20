# opsmcp

An [MCP](https://modelcontextprotocol.io) server that lets AI agents such as Claude Code
do operations work on a Linux host: look at processes, memory, disks, logs, services,
the network, firewall rules, kernel settings, packages, accounts, containers and a
Pacemaker cluster, run your NRPE checks, make a controlled set of changes, and run
commands you define.

Every call is checked against the caller's roles and written to an audit trail. Nothing
is allowed unless the configuration grants it.

Status: 0.1, a first complete cut. It has an extensive test suite, and both the
original tools and the ones added since (network, packages, storage, triage, accounts)
have each had two independent reviews; what they found was fixed, apart from the few
points recorded under [Security model](#security-model) and
[Not included yet](#not-included-yet). Much of it has only been exercised against
stand-in commands: dpkg/apt, rpm/dnf, smartctl, LVM, Pacemaker, chrony and the tools
that change things have not been run against the real thing. It has not yet run in
production.

## Contents

- [Quick start](#quick-start)
- [Three ways to connect](#three-ways-to-connect)
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

### Building for other hosts

A binary only runs where the C library it was linked against is present, so build for
where it will run, not for where you build.

**From NixOS (or any host with Nix): a static binary.** A plain `cargo build` on NixOS
produces a binary that only runs on NixOS (`cannot execute: required file not found`
anywhere else: its loader is a `/nix/store` path). Build a statically linked one
instead, which runs on any x86_64 Linux whatever its distribution or glibc version:

```sh
nix-build packaging/static.nix
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
`haproxy -c`, `sshd -t`, `visudo -c` and others) with fixed arguments. Checks for
other services can be added as custom tools.

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
has to be listed anew) and restart.

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
keeps the old one's owner and permissions.

**What it does not protect against.** A caller with broad write grants is as powerful as
those grants: unscoped `firewall.modify` can cut the host off, `user.modify` with key
management on can let someone log in as another user, `host.reboot` can take the host
down, and a custom tool is only as safe as the script behind it. Scope write grants to
the units, chains, containers, packages and accounts that are meant.

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

## Development

```sh
cargo test                     # unit tests and end-to-end tests of the built binary
cargo clippy --all-targets     # unwrap, expect and panic are denied outside tests
cargo fmt
```

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
| `src/tools/` | the tools, one file per area; `paths.rs` is the safe way to open a path |
| `tests/cli.rs` | end-to-end tests |

Comments marked `AIDEV-NOTE:` explain the decisions that the security of the whole
rests on; `grep -rn AIDEV- src/` lists them.
