//! Configuration: who may do what, and the limits everything runs under.
//!
//! AIDEV-NOTE: every struct here uses `deny_unknown_fields`. A misspelled key in a security
//! configuration must stop the server, not be silently ignored.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::exec::check_trusted_path;
use crate::policy::{Access, Grant, Principal, Rules};
use crate::template::{self, Piece};
use crate::timefmt::parse_date;
use crate::token::{normalize_sha256, sha256_hex};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/opsmcp/config.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Role name to its grants.
    pub roles: BTreeMap<String, RoleCfg>,
    /// Unix user name to roles (local and SSH use).
    pub unix_users: BTreeMap<String, MemberCfg>,
    /// Unix group name to roles (local and SSH use).
    pub unix_groups: BTreeMap<String, MemberCfg>,
    /// Bearer tokens (HTTPS).
    pub tokens: BTreeMap<String, TokenCfg>,
    /// TLS client certificates (HTTPS).
    pub client_certs: BTreeMap<String, ClientCertCfg>,
    pub http: Option<HttpCfg>,
    pub audit: AuditCfg,
    pub limits: LimitsCfg,
    pub paths: PathsCfg,
    pub tools: ToolsCfg,
    pub logs: LogsCfg,
    pub fs: FsCfg,
    pub kernel: KernelCfg,
    pub services: ServicesCfg,
    pub nrpe: NrpeCfg,
    pub net: NetCfg,
    pub users: UsersCfg,
    pub monitoring: MonitoringCfg,
    pub haproxy: HaproxyCfg,
    pub storage: StorageCfg,
    pub firewall: FirewallCfg,
    pub trace: TraceCfg,
    pub db: DbCfg,
    pub package: PackageCfg,
    /// Operator-defined tools, by tool name.
    pub custom: BTreeMap<String, CustomCfg>,
    /// Present in the configuration of a fleet server (`opsmcp fleet`), and only there.
    pub fleet: Option<FleetCfg>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RoleCfg {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCfg {
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenCfg {
    /// SHA-256 of the token, as printed by `opsmcp new-token`.
    pub sha256: String,
    pub roles: Vec<String>,
    /// Optional last valid day, `YYYY-MM-DD` (UTC).
    pub expires: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertCfg {
    /// Subject common name of a certificate issued by `http.client_ca`.
    pub cn: Option<String>,
    /// SHA-256 fingerprint of one exact certificate.
    pub sha256: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Default)]
pub enum AuthMode {
    /// A bearer token is required.
    #[default]
    #[serde(rename = "token")]
    Token,
    /// A client certificate listed in `client_certs` is required.
    #[serde(rename = "mtls")]
    Mtls,
    /// A client certificate from `client_ca` and a bearer token are both required.
    #[serde(rename = "mtls+token")]
    MtlsAndToken,
    /// Either a listed client certificate or a bearer token.
    #[serde(rename = "mtls-or-token")]
    MtlsOrToken,
}

impl AuthMode {
    /// The mode as written in the configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Token => "token",
            AuthMode::Mtls => "mtls",
            AuthMode::MtlsAndToken => "mtls+token",
            AuthMode::MtlsOrToken => "mtls-or-token",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCfg {
    /// Address and port to listen on, e.g. `0.0.0.0:8443`.
    pub listen: String,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    /// CA that client certificates must chain to. Required for the mtls modes.
    pub client_ca: Option<PathBuf>,
    #[serde(default)]
    pub auth: AuthMode,
    /// Browser origins allowed to call the server. Empty: requests carrying an `Origin`
    /// header are refused (non-browser clients do not send one).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_max_connections() -> usize {
    64
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditCfg {
    /// Send audit records to the local syslog (`/dev/log`, facility authpriv).
    pub syslog: bool,
    /// Also append audit records, one JSON object per line, to this file.
    pub file: Option<PathBuf>,
    /// Refuse to run a tool when its audit record cannot be written.
    pub fail_closed: bool,
}

impl Default for AuditCfg {
    fn default() -> Self {
        AuditCfg {
            syslog: true,
            file: None,
            fail_closed: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsCfg {
    /// Largest tool result returned to the agent.
    pub max_output_bytes: usize,
    /// Time limit for one external command.
    pub command_timeout_secs: u64,
    /// Time limit for one whole tool call.
    pub call_timeout_secs: u64,
    pub max_concurrent_calls: usize,
    /// Largest request accepted, in bytes.
    pub max_request_bytes: usize,
}

impl Default for LimitsCfg {
    fn default() -> Self {
        LimitsCfg {
            max_output_bytes: 64 * 1024,
            command_timeout_secs: 30,
            call_timeout_secs: 120,
            max_concurrent_calls: 8,
            max_request_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PathsCfg {
    /// Directories searched, in order, for the system commands the tools run. The
    /// caller's PATH is never used.
    pub search: Vec<PathBuf>,
    /// Exact locations for individual commands, e.g. `systemctl = "/usr/bin/systemctl"`.
    pub bin: BTreeMap<String, PathBuf>,
}

/// Where system commands are looked for unless `paths.search` says otherwise. The last
/// entry is where NixOS keeps them.
pub const DEFAULT_SEARCH: [&str; 7] = [
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
];

impl Default for PathsCfg {
    fn default() -> Self {
        PathsCfg {
            search: DEFAULT_SEARCH.iter().map(PathBuf::from).collect(),
            bin: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ToolsCfg {
    /// Built-in tools to switch off entirely on this host, by tool name.
    pub disabled: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogsCfg {
    /// Directories whose files the log tools may list and read.
    pub dirs: Vec<PathBuf>,
}

impl Default for LogsCfg {
    fn default() -> Self {
        LogsCfg {
            dirs: vec![PathBuf::from("/var/log")],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FsCfg {
    /// Directories that may be listed and stat'ed.
    pub list_roots: Vec<PathBuf>,
    /// Directories whose file contents may be read. Empty by default.
    pub read_roots: Vec<PathBuf>,
    /// Extra path globs that are never listed or read.
    pub deny: Vec<String>,
    /// Keep the built-in list of never-readable paths (shadow files, private keys...),
    /// and the built-in list of paths config_edit never writes.
    pub default_deny: bool,
    /// Directories whose files config_edit may replace. Empty by default: nothing may be
    /// written.
    pub write_roots: Vec<PathBuf>,
    /// Where config_edit keeps the previous content of every file it changes.
    pub backup_dir: PathBuf,
}

impl Default for FsCfg {
    fn default() -> Self {
        FsCfg {
            list_roots: vec![PathBuf::from("/")],
            read_roots: Vec::new(),
            deny: Vec::new(),
            default_deny: true,
            write_roots: Vec::new(),
            backup_dir: PathBuf::from("/var/backups/opsmcp"),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KernelCfg {
    /// Globs over sysctl names that may be changed, e.g. `vm.swappiness`. Empty by default.
    pub writable_sysctls: Vec<String>,
    /// Globs over `/sys` paths that may be written. Empty by default.
    pub writable_sysfs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServicesCfg {
    /// Globs over unit names that may never be stopped, restarted, enabled or disabled
    /// through opsmcp, whatever a role grants.
    pub protected: Vec<String>,
}

impl Default for ServicesCfg {
    fn default() -> Self {
        let protected = [
            "systemd-journald.service",
            "systemd-logind.service",
            "systemd-udevd.service",
            "dbus.service",
            "dbus-broker.service",
            "opsmcp*",
        ];
        ServicesCfg {
            protected: protected.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NrpeCfg {
    /// Path of nrpe.cfg. Unset: the usual locations are tried.
    pub config: Option<PathBuf>,
}

/// Limits on the tools that send or capture network traffic. Both are off until the
/// operator says where they may be used.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetCfg {
    /// Globs over the hosts that net_probe and tls_cert_check may connect to, matched
    /// against the target in its one standard form: a name in lower case without a
    /// trailing dot, or an address as it is normally written (an IPv4-mapped IPv6
    /// address counts as the IPv4 address). What a name resolves to is not checked.
    /// Empty by default: nothing may be probed.
    pub probe_targets: Vec<String>,
    /// Globs over the interfaces packet_capture may listen on. Empty by default: no
    /// capture.
    pub capture_interfaces: Vec<String>,
    /// Let packet_capture return packet contents as well as headers.
    pub capture_payload: bool,
}

/// Limits on what user_modify may change, whatever a role grants.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UsersCfg {
    /// Accounts with a uid below this cannot be modified (system accounts). Uid 0 can
    /// never be modified.
    pub min_uid: u32,
    /// Globs over account names that can never be modified.
    pub protected: Vec<String>,
    /// The groups whose membership may be changed, by exact name. Empty by default: none.
    pub groups: Vec<String>,
    /// Allow adding and removing keys in users' authorized_keys files.
    pub manage_ssh_keys: bool,
}

impl Default for UsersCfg {
    fn default() -> Self {
        UsersCfg {
            min_uid: 1000,
            protected: vec!["root".to_string()],
            groups: Vec::new(),
            manage_ssh_keys: false,
        }
    }
}

/// Where monitoring_downtime reaches the monitoring system. The tool is off until
/// `icinga_url` is set, and it only ever acts on this one host's own entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MonitoringCfg {
    /// The Icinga 2 API, as `https://HOST[:PORT]` (port 5665 when left out).
    pub icinga_url: Option<String>,
    /// The Icinga ApiUser to log in as.
    pub icinga_user: Option<String>,
    /// A file holding that user's password and nothing else. It must not be readable by
    /// group or others.
    pub icinga_password_file: Option<PathBuf>,
    /// The CA that signed the API's certificate. Unset: this host's CA bundle.
    pub icinga_ca: Option<PathBuf>,
    /// The name of this machine's host object in Icinga. Unset: the kernel's host name.
    pub host: Option<String>,
    /// The longest downtime that can be set, in minutes.
    pub max_minutes: u32,
}

impl Default for MonitoringCfg {
    fn default() -> Self {
        MonitoringCfg {
            icinga_url: None,
            icinga_user: None,
            icinga_password_file: None,
            icinga_ca: None,
            host: None,
            max_minutes: 240,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HaproxyCfg {
    /// HAProxy's admin socket (`stats socket ... level admin`).
    pub socket: PathBuf,
}

impl Default for HaproxyCfg {
    fn default() -> Self {
        HaproxyCfg {
            socket: PathBuf::from("/run/haproxy/admin.sock"),
        }
    }
}

/// The actions space_reclaim knows. `storage.reclaim` lists the ones this host allows.
pub const RECLAIM_ACTIONS: [&str; 5] = [
    "journal",
    "package_cache",
    "container_images",
    "core_dumps",
    "tmpfiles",
];

/// Limits on the tools that free or add disk space, whatever a role grants.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageCfg {
    /// The space_reclaim actions allowed on this host, by name (see RECLAIM_ACTIONS).
    /// Empty by default: none.
    pub reclaim: Vec<String>,
    /// Globs over the logical volumes lvm_extend may grow, as `VG/LV`. Empty by default:
    /// none.
    pub extendable: Vec<String>,
    /// The most one lvm_extend call may add, in GiB.
    pub max_extend_gb: u32,
}

impl Default for StorageCfg {
    fn default() -> Self {
        StorageCfg {
            reclaim: Vec::new(),
            extendable: Vec::new(),
            max_extend_gb: 50,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FirewallCfg {
    /// Globs over the address sets firewall_set_member may change, written as
    /// `nft/FAMILY/TABLE/SET` or `ipset/NAME`. Empty by default: none.
    pub sets: Vec<String>,
}

/// Limits on the tools that attach to running processes (process_trace, cpu_profile).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TraceCfg {
    /// Globs over the processes that may be traced or profiled, as `OWNER/NAME` (the
    /// form process grants use). Empty by default: none.
    pub processes: Vec<String>,
    /// Let cpu_profile sample the whole host rather than one process.
    pub system_wide: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PackageCfg {
    /// Let cve_status, when asked to, consult the distribution's security service
    /// (`pro` on Ubuntu, fresh repository metadata on rpm hosts). That makes this host
    /// contact the vendor and sends the CVE id out. Off by default.
    pub cve_online: bool,
}

/// How db_status reaches the database servers on this host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DbCfg {
    /// A client options file with the credentials for MariaDB or MySQL, passed as
    /// `--defaults-extra-file`. Unset: socket authentication as the server's own user.
    pub mysql_defaults_file: Option<PathBuf>,
    /// The Unix user that psql runs as (peer authentication). Used when opsmcp is root.
    pub postgres_user: String,
    /// The directory of PostgreSQL's Unix socket. Unset: psql's own default.
    pub postgres_socket_dir: Option<PathBuf>,
    /// Patroni's configuration file, for patronictl. Unset: the usual locations.
    pub patroni_config: Option<PathBuf>,
    /// Show the text of running queries. Off by default: queries can hold personal data.
    pub show_queries: bool,
}

impl Default for DbCfg {
    fn default() -> Self {
        DbCfg {
            mysql_defaults_file: None,
            postgres_user: "postgres".to_string(),
            postgres_socket_dir: None,
            patroni_config: None,
            show_queries: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCfg {
    /// Shown to the agent: say what the command does and when to use it.
    pub description: String,
    /// `read` or `write`.
    pub access: Access,
    /// The command as an argument list. The first element is the absolute path of the
    /// program. `{name}` is replaced by a parameter; an element whose parameter was not
    /// given is left out; `{name?text}` becomes `text` when a boolean parameter is true.
    /// No shell is involved.
    pub command: Vec<String>,
    pub timeout_secs: Option<u64>,
    /// Unix user to run as (needs root). Unset: run as the server's own user.
    pub run_as: Option<String>,
    /// Exit codes that count as success.
    #[serde(default = "default_ok_exit_codes")]
    pub ok_exit_codes: Vec<i32>,
    /// Extra environment variables for the command.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub params: BTreeMap<String, CustomParamCfg>,
}

fn default_ok_exit_codes() -> Vec<i32> {
    vec![0]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CustomParamType {
    String,
    Integer,
    Boolean,
    Enum,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomParamCfg {
    #[serde(rename = "type")]
    pub kind: CustomParamType,
    pub description: String,
    #[serde(default)]
    pub required: bool,
    /// Allowed values of an `enum` parameter.
    #[serde(default)]
    pub values: Vec<String>,
    /// Regular expression a `string` value must match in full. Unset: a conservative
    /// default that allows letters, digits and `_ . : @ / = + , -`, not starting with `-`.
    pub pattern: Option<String>,
    pub max_len: Option<usize>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

/// How a fleet server reaches a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    Ssh,
    Https,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Ssh => "ssh",
            Via::Https => "https",
        }
    }
}

/// Whose credential a fleet server presents to a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityMode {
    /// The caller's own: their SSH keys and agent, or the bearer token they presented.
    /// The host sees the person and applies its own roles for them.
    Caller,
    /// One this configuration names: an SSH key or a token file. The host sees a
    /// service identity, and what the caller may do is decided here.
    Fleet,
}

impl IdentityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityMode::Caller => "caller",
            IdentityMode::Fleet => "fleet",
        }
    }
}

/// How a fleet server's inventory is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InventoryFormat {
    /// opsmcp's own: `[hosts.NAME]` and `[groups]`, as TOML or JSON.
    Opsmcp,
    /// What `ansible-inventory --list` prints.
    Ansible,
}

/// One `[[fleet.access]]` rule: for callers holding one of `roles`, how the hosts in
/// `hosts` are reached. The first rule that fits decides.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessCfg {
    /// A name for the audit trail and for messages. Unset: its position in the file.
    pub name: Option<String>,
    pub roles: Vec<String>,
    /// Host names, patterns over them, and `group:NAME`.
    pub hosts: Vec<String>,
    pub via: Via,
    pub identity: IdentityMode,
    /// Only tools that change nothing may be used through this rule.
    #[serde(default)]
    pub read_only: bool,
    /// The account to log in to on the hosts. Needed with `identity = "fleet"`; with
    /// `identity = "caller"` it is whatever the caller's own ssh settings say unless set.
    pub ssh_user: Option<String>,
    /// The private key to log in with (`via = "ssh"`, `identity = "fleet"`).
    pub ssh_key: Option<PathBuf>,
    /// A file holding the bearer token to present (`via = "https"`, `identity = "fleet"`).
    pub token_file: Option<PathBuf>,
}

impl AccessCfg {
    /// The rule's name, or `access[N]` (counting from 1) when it has none.
    pub fn label(&self, index: usize) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("access[{}]", index + 1),
        }
    }
}

/// How the fleet server runs `ssh`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FleetSshCfg {
    /// What is run on a host. Words only: it passes through the host's shell.
    pub remote_command: Vec<String>,
    /// Extra `ssh -o` options, as `Key=Value`.
    pub options: Vec<String>,
    /// The port, for hosts whose inventory entry does not set one. Unset: ssh's own.
    pub port: Option<u16>,
}

impl Default for FleetSshCfg {
    fn default() -> Self {
        FleetSshCfg {
            remote_command: ["sudo", "-n", "/usr/bin/opsmcp", "serve"]
                .map(String::from)
                .to_vec(),
            options: Vec::new(),
            port: None,
        }
    }
}

/// How the fleet server reaches hosts that run `opsmcp serve-http`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FleetHttpsCfg {
    /// The port, for hosts whose inventory entry does not set one.
    pub port: u16,
    /// The CA that the hosts' certificates must chain to. Unset: this machine's bundle.
    pub ca: Option<PathBuf>,
    /// A client certificate to present to the hosts, with its key. With
    /// `auth = "mtls+token"` on the hosts, a token is then only usable through here.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

impl Default for FleetHttpsCfg {
    fn default() -> Self {
        FleetHttpsCfg {
            port: 8443,
            ca: None,
            client_cert: None,
            client_key: None,
        }
    }
}

/// The `[fleet]` section: which hosts there are and how callers reach them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FleetCfg {
    /// What this server calls itself to the hosts (it appears in their audit trails).
    /// Unset: this machine's host name.
    pub name: Option<String>,
    /// The hosts and their groups: a `.toml` or `.json` file.
    pub inventory: Option<PathBuf>,
    /// Or a command that prints them as JSON: an argument list, the program first, as
    /// an absolute path.
    pub inventory_command: Option<Vec<String>>,
    /// How the inventory is written.
    pub inventory_format: InventoryFormat,
    /// How often the inventory is looked at again, in seconds: a file is read again
    /// when it has changed, a command is run again. 0: never. Unset: 30 for a file,
    /// 300 for a command.
    pub inventory_refresh_secs: Option<u64>,
    /// The most hosts one call may name.
    pub max_hosts_per_call: usize,
    /// The most hosts asked at the same time within one call.
    pub max_parallel: usize,
    /// The most SSH sessions to hosts kept open.
    pub max_connections: usize,
    /// How long an SSH session to a host is kept after its last use.
    pub idle_secs: u64,
    /// How long a host gets to accept a connection.
    pub connect_timeout_secs: u64,
    /// How long a host that could not be reached is left alone before it is tried again.
    pub retry_secs: u64,
    pub ssh: FleetSshCfg,
    pub https: FleetHttpsCfg,
    pub access: Vec<AccessCfg>,
}

impl Default for FleetCfg {
    fn default() -> Self {
        FleetCfg {
            name: None,
            inventory: None,
            inventory_command: None,
            inventory_format: InventoryFormat::Opsmcp,
            inventory_refresh_secs: None,
            max_hosts_per_call: 50,
            max_parallel: 16,
            max_connections: 64,
            idle_secs: 300,
            connect_timeout_secs: 10,
            retry_secs: 60,
            ssh: FleetSshCfg::default(),
            https: FleetHttpsCfg::default(),
            access: Vec::new(),
        }
    }
}

/// What `Config::validate_grants` found.
#[derive(Debug, Default)]
pub struct GrantProblems {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl Config {
    /// Parses and validates configuration text. Every problem found is reported.
    pub fn parse(text: &str) -> Result<Config, Vec<String>> {
        let cfg: Config = toml::from_str(text).map_err(|e| vec![e.to_string()])?;
        let errors = cfg.validate();
        if errors.is_empty() {
            Ok(cfg)
        } else {
            Err(errors)
        }
    }

    /// Reads, parses and validates the configuration file.
    pub fn load(path: &Path) -> Result<Config, Vec<String>> {
        let shown = path.display();
        // AIDEV-NOTE: the configuration decides who may do what, so it is only read from a
        // file that the user we run as (or root) controls. Under sudo that means root
        // only, which stops a caller pointing a root opsmcp at a file of their own.
        let euid = rustix::process::geteuid().as_raw();
        let extra_owners = if euid == 0 { vec![] } else { vec![euid] };
        // Check, and from here on read, the file's real location: once that is known to
        // be controlled only by trusted users, nothing can be swapped in underneath.
        let path = &std::fs::canonicalize(path).map_err(|e| vec![format!("{shown}: {e}")])?;
        check_trusted_path(path, &extra_owners)
            .map_err(|e| vec![format!("refusing to use configuration {shown}: {e}")])?;
        let size = std::fs::metadata(path)
            .map_err(|e| vec![format!("{shown}: {e}")])?
            .len();
        if size > MAX_CONFIG_BYTES {
            return Err(vec![format!(
                "{shown}: larger than {MAX_CONFIG_BYTES} bytes"
            )]);
        }
        let text = std::fs::read_to_string(path).map_err(|e| vec![format!("{shown}: {e}")])?;
        Config::parse(&text).map_err(|errors| {
            errors
                .into_iter()
                .map(|e| format!("{shown}: {e}"))
                .collect()
        })
    }

    /// Checks everything that can be checked without knowing the tool list.
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();

        for (name, role) in &self.roles {
            if !is_role_name(name) {
                errs.push(format!(
                    "roles.{name}: a role name may only contain a-z, 0-9, '_' and '-'"
                ));
            }
            for (list, grants) in [("allow", &role.allow), ("deny", &role.deny)] {
                for grant in grants {
                    if let Err(e) = Grant::parse(grant) {
                        errs.push(format!("roles.{name}.{list}: {e}"));
                    }
                }
            }
        }

        for (name, member) in &self.unix_users {
            self.check_roles(&format!("unix_users.{name}"), &member.roles, &mut errs);
        }
        for (name, member) in &self.unix_groups {
            self.check_roles(&format!("unix_groups.{name}"), &member.roles, &mut errs);
        }
        for (name, token) in &self.tokens {
            let at = format!("tokens.{name}");
            self.check_roles(&at, &token.roles, &mut errs);
            if normalize_sha256(&token.sha256).is_none() {
                errs.push(format!(
                    "{at}.sha256: not a SHA-256 (64 hex digits, as printed by `opsmcp new-token`)"
                ));
            }
            if let Some(expires) = &token.expires
                && parse_date(expires).is_none()
            {
                errs.push(format!(
                    "{at}.expires: {expires:?} is not a date (YYYY-MM-DD)"
                ));
            }
        }
        for (name, cert) in &self.client_certs {
            let at = format!("client_certs.{name}");
            self.check_roles(&at, &cert.roles, &mut errs);
            match (&cert.cn, &cert.sha256) {
                (None, None) => errs.push(format!("{at}: needs a cn or a sha256 fingerprint")),
                (cn, sha256) => {
                    if cn.as_deref() == Some("") {
                        errs.push(format!("{at}.cn: is empty"));
                    }
                    if let Some(sha256) = sha256
                        && normalize_sha256(sha256).is_none()
                    {
                        errs.push(format!(
                            "{at}.sha256: not a SHA-256 fingerprint (64 hex digits)"
                        ));
                    }
                }
            }
        }

        // Two entries that match the same certificate would make "who is this?" depend
        // on their order; a certificate must have one answer.
        let mut seen_cns: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen_fingerprints: BTreeMap<String, &str> = BTreeMap::new();
        for (name, cert) in &self.client_certs {
            if let Some(cn) = cert.cn.as_deref().filter(|_| cert.sha256.is_none())
                && let Some(other) = seen_cns.insert(cn, name)
            {
                errs.push(format!(
                    "client_certs.{name}.cn: {cn:?} is also the cn of client_certs.{other}"
                ));
            }
            if let Some(fingerprint) = cert.sha256.as_deref().and_then(normalize_sha256)
                && let Some(other) = seen_fingerprints.insert(fingerprint, name)
            {
                errs.push(format!(
                    "client_certs.{name}.sha256: the same certificate is listed as client_certs.{other}"
                ));
            }
        }

        if let Some(http) = &self.http {
            if http.listen.parse::<std::net::SocketAddr>().is_err() {
                errs.push(format!(
                    "http.listen: {:?} is not an address and port (e.g. 0.0.0.0:8443)",
                    http.listen
                ));
            }
            check_absolute("http.tls_cert", &http.tls_cert, &mut errs);
            check_absolute("http.tls_key", &http.tls_key, &mut errs);
            if let Some(ca) = &http.client_ca {
                check_absolute("http.client_ca", ca, &mut errs);
            }
            if http.auth != AuthMode::Token && http.client_ca.is_none() {
                errs.push(
                    "http.client_ca: required when http.auth uses client certificates".to_string(),
                );
            }
            if http.max_connections == 0 || http.max_connections > 4096 {
                errs.push("http.max_connections: must be between 1 and 4096".to_string());
            }
            if http.allowed_origins.iter().any(String::is_empty) {
                errs.push("http.allowed_origins: contains an empty origin".to_string());
            }
        }

        let limits = &self.limits;
        check_range(
            "limits.max_output_bytes",
            limits.max_output_bytes as u64,
            1024,
            16 << 20,
            &mut errs,
        );
        check_range(
            "limits.command_timeout_secs",
            limits.command_timeout_secs,
            1,
            3600,
            &mut errs,
        );
        check_range(
            "limits.call_timeout_secs",
            limits.call_timeout_secs,
            1,
            3600,
            &mut errs,
        );
        check_range(
            "limits.max_concurrent_calls",
            limits.max_concurrent_calls as u64,
            1,
            256,
            &mut errs,
        );
        check_range(
            "limits.max_request_bytes",
            limits.max_request_bytes as u64,
            1024,
            16 << 20,
            &mut errs,
        );

        if limits.call_timeout_secs < limits.command_timeout_secs {
            errs.push(
                "limits.call_timeout_secs: must be at least limits.command_timeout_secs, \
                 or a call is stopped before its command's own time limit"
                    .to_string(),
            );
        }

        for dir in &self.paths.search {
            check_absolute("paths.search", dir, &mut errs);
        }
        for (name, path) in &self.paths.bin {
            if name.is_empty() || name.contains('/') {
                errs.push(format!(
                    "paths.bin.{name}: the key must be a bare command name"
                ));
            }
            check_absolute(&format!("paths.bin.{name}"), path, &mut errs);
        }
        for dir in &self.logs.dirs {
            check_absolute("logs.dirs", dir, &mut errs);
        }
        for dir in &self.fs.list_roots {
            check_absolute("fs.list_roots", dir, &mut errs);
        }
        for dir in &self.fs.read_roots {
            check_absolute("fs.read_roots", dir, &mut errs);
        }
        if self.fs.deny.iter().any(String::is_empty) {
            errs.push("fs.deny: contains an empty pattern".to_string());
        }
        if let Some(file) = &self.audit.file {
            check_absolute("audit.file", file, &mut errs);
        }
        if let Some(file) = &self.nrpe.config {
            check_absolute("nrpe.config", file, &mut errs);
        }
        if self.kernel.writable_sysctls.iter().any(String::is_empty) {
            errs.push("kernel.writable_sysctls: contains an empty pattern".to_string());
        }
        for pattern in &self.kernel.writable_sysfs {
            if !pattern.starts_with("/sys/") {
                errs.push(format!(
                    "kernel.writable_sysfs: {pattern:?} must start with /sys/"
                ));
            }
        }
        if self.services.protected.iter().any(String::is_empty) {
            errs.push("services.protected: contains an empty pattern".to_string());
        }
        if self.net.probe_targets.iter().any(String::is_empty) {
            errs.push("net.probe_targets: contains an empty pattern".to_string());
        }
        if self.net.capture_interfaces.iter().any(String::is_empty) {
            errs.push("net.capture_interfaces: contains an empty pattern".to_string());
        }
        check_range(
            "users.min_uid",
            u64::from(self.users.min_uid),
            1,
            u64::from(u32::MAX),
            &mut errs,
        );
        if self.users.protected.iter().any(String::is_empty) {
            errs.push("users.protected: contains an empty pattern".to_string());
        }
        for group in &self.users.groups {
            if !is_account_name(group) {
                errs.push(format!(
                    "users.groups: {group:?} is not a group name (these are exact names, not patterns)"
                ));
            }
        }

        for dir in &self.fs.write_roots {
            check_absolute("fs.write_roots", dir, &mut errs);
        }
        check_absolute("fs.backup_dir", &self.fs.backup_dir, &mut errs);

        let monitoring = &self.monitoring;
        if let Some(url) = &monitoring.icinga_url {
            if let Err(problem) = parse_https_origin(url, 5665) {
                errs.push(format!("monitoring.icinga_url: {problem}"));
            }
            if monitoring.icinga_user.is_none() || monitoring.icinga_password_file.is_none() {
                errs.push(
                    "monitoring: icinga_url needs icinga_user and icinga_password_file as well"
                        .to_string(),
                );
            }
        }
        if let Some(user) = &monitoring.icinga_user
            && (user.is_empty()
                || user.len() > 128
                || user.contains(':')
                || user.chars().any(char::is_control))
        {
            errs.push(
                "monitoring.icinga_user: must be 1 to 128 characters, without ':' or control characters"
                    .to_string(),
            );
        }
        if let Some(file) = &monitoring.icinga_password_file {
            check_absolute("monitoring.icinga_password_file", file, &mut errs);
        }
        if let Some(file) = &monitoring.icinga_ca {
            check_absolute("monitoring.icinga_ca", file, &mut errs);
        }
        if let Some(host) = &monitoring.host
            && !is_host_name(host)
        {
            errs.push(format!("monitoring.host: {host:?} is not a host name"));
        }
        check_range(
            "monitoring.max_minutes",
            u64::from(monitoring.max_minutes),
            1,
            10_080,
            &mut errs,
        );
        check_absolute("haproxy.socket", &self.haproxy.socket, &mut errs);
        for action in &self.storage.reclaim {
            if !RECLAIM_ACTIONS.contains(&action.as_str()) {
                errs.push(format!(
                    "storage.reclaim: {action:?} is not an action (the actions are {})",
                    RECLAIM_ACTIONS.join(", ")
                ));
            }
        }
        if self.storage.extendable.iter().any(String::is_empty) {
            errs.push("storage.extendable: contains an empty pattern".to_string());
        }
        check_range(
            "storage.max_extend_gb",
            u64::from(self.storage.max_extend_gb),
            1,
            10_240,
            &mut errs,
        );
        if self.firewall.sets.iter().any(String::is_empty) {
            errs.push("firewall.sets: contains an empty pattern".to_string());
        }
        if self.trace.processes.iter().any(String::is_empty) {
            errs.push("trace.processes: contains an empty pattern".to_string());
        }
        if let Some(file) = &self.db.mysql_defaults_file {
            check_absolute("db.mysql_defaults_file", file, &mut errs);
        }
        if let Some(dir) = &self.db.postgres_socket_dir {
            check_absolute("db.postgres_socket_dir", dir, &mut errs);
        }
        if let Some(file) = &self.db.patroni_config {
            check_absolute("db.patroni_config", file, &mut errs);
        }
        if !is_account_name(&self.db.postgres_user) {
            errs.push(format!(
                "db.postgres_user: {:?} is not a user name",
                self.db.postgres_user
            ));
        }

        for (name, custom) in &self.custom {
            validate_custom(name, custom, limits.call_timeout_secs, &mut errs);
        }
        if let Some(fleet) = &self.fleet {
            self.validate_fleet(fleet, &mut errs);
        }
        errs
    }

    /// Checks the `[fleet]` section.
    fn validate_fleet(&self, fleet: &FleetCfg, errs: &mut Vec<String>) {
        // AIDEV-NOTE: a fleet server sees a tool's name and arguments, never the unit,
        // path or container the host resolves them to. A grant limited to a resource
        // could not be honoured here, and ignoring the limit would grant more than was
        // written, so such a grant is an error: the limit belongs in the host's own
        // configuration, for the identity the fleet server reaches it as.
        for (name, role) in &self.roles {
            for (list, grants) in [("allow", &role.allow), ("deny", &role.deny)] {
                for source in grants {
                    if Grant::parse(source).is_ok_and(|grant| grant.resource().is_some()) {
                        errs.push(format!(
                            "roles.{name}.{list}: grant {source:?} is limited to a resource, \
                             which a fleet server cannot check; grant the permission as a \
                             whole here and limit it in the configuration of the hosts"
                        ));
                    }
                }
            }
        }

        if !self.custom.is_empty() {
            errs.push(
                "custom: a fleet server runs no tools itself; define custom tools in the \
                 configuration of the hosts (they are reached with fleet_call)"
                    .to_string(),
            );
        }
        if let Some(name) = &fleet.name
            && !is_plain_name(name)
        {
            errs.push(
                "fleet.name: may only contain letters, digits, '.', '_' and '-' (at most 64)"
                    .to_string(),
            );
        }
        match (&fleet.inventory, &fleet.inventory_command) {
            (None, None) => errs.push(
                "fleet.inventory: name the file that lists the hosts (or set \
                 fleet.inventory_command)"
                    .to_string(),
            ),
            (Some(_), Some(_)) => {
                errs.push("fleet: set either inventory or inventory_command, not both".to_string())
            }
            (Some(path), None) => {
                check_absolute("fleet.inventory", path, errs);
                let extension = path.extension().and_then(|e| e.to_str());
                let ansible = fleet.inventory_format == InventoryFormat::Ansible;
                if !path.is_absolute() {
                    // said above
                } else if ansible && extension != Some("json") {
                    errs.push(format!(
                        "fleet.inventory: {:?} must end in .json: with inventory_format = \
                         \"ansible\" it holds what `ansible-inventory --list` prints, not \
                         one of Ansible's own inventory files",
                        path.display().to_string()
                    ));
                } else if !matches!(extension, Some("toml" | "json")) {
                    errs.push(format!(
                        "fleet.inventory: {:?} must end in .toml or .json, which says how it \
                         is written",
                        path.display().to_string()
                    ));
                }
            }
            (None, Some(command)) => {
                let program_ok = command.first().is_some_and(|p| Path::new(p).is_absolute());
                let words_ok = command
                    .iter()
                    .all(|word| !word.is_empty() && !word.chars().any(char::is_control));
                if !program_ok || !words_ok {
                    errs.push(
                        "fleet.inventory_command: must be an argument list whose first \
                         element is the absolute path of a program, with no empty elements"
                            .to_string(),
                    );
                }
            }
        }
        for (setting, value, min, max) in [
            (
                "max_hosts_per_call",
                fleet.max_hosts_per_call as u64,
                1,
                1000,
            ),
            ("max_parallel", fleet.max_parallel as u64, 1, 256),
            ("max_connections", fleet.max_connections as u64, 1, 4096),
            ("idle_secs", fleet.idle_secs, 10, 86_400),
            ("connect_timeout_secs", fleet.connect_timeout_secs, 1, 120),
            ("retry_secs", fleet.retry_secs, 0, 3600),
            (
                "inventory_refresh_secs",
                fleet.inventory_refresh_secs.unwrap_or(0),
                0,
                86_400,
            ),
        ] {
            check_range(&format!("fleet.{setting}"), value, min, max, errs);
        }
        // One call may ask `max_parallel` hosts at once, each over a session of its own.
        if fleet.max_connections >= 1 && fleet.max_connections < fleet.max_parallel {
            errs.push(
                "fleet.max_connections: must be at least fleet.max_parallel, the number of \
                 hosts one call asks at the same time"
                    .to_string(),
            );
        }

        // AIDEV-NOTE: ssh joins the remote command's words with spaces and the host's
        // shell reads the result, so each word may only contain characters no shell
        // treats specially. This is configuration, not caller input, but a word with a
        // space or a `;` in it would not mean what its author wrote.
        let command = &fleet.ssh.remote_command;
        let is_word = |word: &String| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_./=:@%+,-".contains(c))
        };
        if command.is_empty()
            || !command.iter().all(is_word)
            || command.first().is_some_and(|first| first.starts_with('-'))
        {
            errs.push(
                "fleet.ssh.remote_command: must be a list of plain words (letters, digits \
                 and _ . / = : @ % + , -), the program first"
                    .to_string(),
            );
        }
        for option in &fleet.ssh.options {
            if let Err(problem) = check_ssh_option(option) {
                errs.push(format!("fleet.ssh.options: {option:?} {problem}"));
            }
        }
        if fleet.ssh.port == Some(0) {
            errs.push("fleet.ssh.port: must be between 1 and 65535".to_string());
        }

        let https = &fleet.https;
        if https.port == 0 {
            errs.push("fleet.https.port: must be between 1 and 65535".to_string());
        }
        if let Some(ca) = &https.ca {
            check_absolute("fleet.https.ca", ca, errs);
        }
        match (&https.client_cert, &https.client_key) {
            (Some(cert), Some(key)) => {
                check_absolute("fleet.https.client_cert", cert, errs);
                check_absolute("fleet.https.client_key", key, errs);
            }
            (Some(_), None) => {
                errs.push("fleet.https.client_key: needed with fleet.https.client_cert".to_string())
            }
            (None, Some(_)) => {
                errs.push("fleet.https.client_cert: needed with fleet.https.client_key".to_string())
            }
            (None, None) => {
                // AIDEV-NOTE: over HTTPS a bearer token (a caller's own, or the
                // fleet's) is sent to every host a rule covers, and a token is good
                // wherever it alone is enough: a host that was sent one could use it
                // on the other hosts. The fleet's certificate is what lets hosts
                // refuse a token that did not come through this server. Whether they
                // ask for it cannot be seen from here; that there is one to show is
                // insisted on, so that the only step left is on the hosts.
                let over_https: Vec<String> = fleet
                    .access
                    .iter()
                    .enumerate()
                    .filter(|(_, rule)| rule.via == Via::Https)
                    .map(|(index, rule)| rule.label(index))
                    .collect();
                if !over_https.is_empty() {
                    errs.push(format!(
                        "fleet.https.client_cert: needed (with client_key) because hosts are \
                         reached over HTTPS (rule {}): a bearer token is sent to every host \
                         such a rule covers, and only a certificate of this server's lets \
                         the hosts refuse a token that came from anywhere else. Require it \
                         on the hosts with `auth = \"mtls+token\"`",
                        over_https.join(", ")
                    ));
                }
            }
        }

        if fleet.access.is_empty() {
            errs.push(
                "fleet.access: there are no [[fleet.access]] rules, so no caller could reach \
                 any host"
                    .to_string(),
            );
        }
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for (index, rule) in fleet.access.iter().enumerate() {
            let at = format!("fleet.access[{}]", index + 1);
            if let Some(name) = &rule.name {
                if !is_plain_name(name) {
                    errs.push(format!(
                        "{at}.name: may only contain letters, digits, '.', '_' and '-' (at \
                         most 64)"
                    ));
                } else if !names.insert(name) {
                    errs.push(format!(
                        "{at}.name: {name:?} is also the name of an earlier rule"
                    ));
                }
            }
            self.check_roles(&at, &rule.roles, errs);
            if let Err(problem) = crate::fleet::inventory::Selector::parse_list(&rule.hosts) {
                errs.push(format!("{at}.hosts: {problem}"));
            }
            if let Some(user) = &rule.ssh_user
                && !is_account_name(user)
            {
                errs.push(format!("{at}.ssh_user: {user:?} is not an account name"));
            }
            if let Some(key) = &rule.ssh_key {
                check_absolute(&format!("{at}.ssh_key"), key, errs);
            }
            if let Some(file) = &rule.token_file {
                check_absolute(&format!("{at}.token_file"), file, errs);
            }
            let has = |what: bool, setting: &str, errs: &mut Vec<String>, why: &str| {
                if what {
                    errs.push(format!("{at}.{setting}: {why}"));
                }
            };
            match (rule.via, rule.identity) {
                (Via::Ssh, IdentityMode::Caller) => {
                    has(
                        rule.ssh_key.is_some(),
                        "ssh_key",
                        errs,
                        "not used with identity = \"caller\", which logs in with the \
                         caller's own keys; for a key of the fleet's own, set identity = \
                         \"fleet\"",
                    );
                }
                (Via::Ssh, IdentityMode::Fleet) => {
                    has(
                        rule.ssh_user.is_none(),
                        "ssh_user",
                        errs,
                        "needed with identity = \"fleet\": the account to log in to",
                    );
                    has(
                        rule.ssh_key.is_none(),
                        "ssh_key",
                        errs,
                        "needed with identity = \"fleet\": the private key to log in with",
                    );
                }
                (Via::Https, IdentityMode::Caller) => {
                    has(
                        rule.token_file.is_some(),
                        "token_file",
                        errs,
                        "not used with identity = \"caller\", which passes on the caller's \
                         own token; for a token of the fleet's own, set identity = \"fleet\"",
                    );
                }
                (Via::Https, IdentityMode::Fleet) => {
                    has(
                        rule.token_file.is_none(),
                        "token_file",
                        errs,
                        "needed with identity = \"fleet\": a file holding the token to present",
                    );
                }
            }
            match rule.via {
                Via::Ssh => has(
                    rule.token_file.is_some(),
                    "token_file",
                    errs,
                    "not used with via = \"ssh\"",
                ),
                Via::Https => {
                    has(
                        rule.ssh_user.is_some(),
                        "ssh_user",
                        errs,
                        "not used with via = \"https\"",
                    );
                    has(
                        rule.ssh_key.is_some(),
                        "ssh_key",
                        errs,
                        "not used with via = \"https\"",
                    );
                }
            }
        }
    }

    fn check_roles(&self, at: &str, roles: &[String], errs: &mut Vec<String>) {
        if roles.is_empty() {
            errs.push(format!("{at}: roles is empty"));
        }
        for role in roles {
            if !self.roles.contains_key(role) {
                errs.push(format!("{at}: unknown role {role:?}"));
            }
        }
    }

    /// The combined rules of a set of roles. Anything unexpected yields rules that allow
    /// nothing: a grant that cannot be read must never be skipped, because skipping a
    /// deny would fail open.
    pub fn rules_for(&self, roles: &BTreeSet<String>) -> Rules {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        for name in roles {
            let Some(role) = self.roles.get(name) else {
                return Rules::default();
            };
            for (list, into) in [(&role.allow, &mut allow), (&role.deny, &mut deny)] {
                for grant in list {
                    match Grant::parse(grant) {
                        Ok(grant) => into.push(grant),
                        Err(_) => return Rules::default(),
                    }
                }
            }
        }
        Rules::new(allow, deny)
    }

    fn principal(&self, name: String, roles: BTreeSet<String>) -> Principal {
        let rules = self.rules_for(&roles);
        Principal {
            name,
            roles: roles.into_iter().collect(),
            rules,
        }
    }

    /// Checks that every grant covers at least one permission that exists. A grant that
    /// matches nothing is almost always a typo.
    ///
    /// AIDEV-NOTE: a mistyped `deny` would silently not apply (fail open), so it is an
    /// error. A mistyped `allow` only fails to grant, so it is a warning; that also lets
    /// one roles file be shared by hosts that define different custom tools.
    pub fn validate_grants(&self, known: &[(String, Access)]) -> GrantProblems {
        let mut problems = GrantProblems::default();
        for (name, role) in &self.roles {
            for (list, grants) in [("allow", &role.allow), ("deny", &role.deny)] {
                for source in grants {
                    // A grant that does not parse is reported by `validate`.
                    let Ok(grant) = Grant::parse(source) else {
                        continue;
                    };
                    // AIDEV-NOTE: a fleet server cannot know which custom tools the
                    // hosts define. An `allow` for one is taken on trust: at worst it
                    // grants a tool that does not exist. A `deny` cannot be taken on
                    // trust in silence, because a misspelled one denies nothing; since
                    // it cannot be checked here either, it is pointed out.
                    if self.fleet.is_some() && grant.is_for_custom_tools() {
                        if list == "deny" {
                            problems.warnings.push(format!(
                                "roles.{name}.deny: grant {source:?} names a tool that only \
                                 hosts define, so it cannot be checked here: make sure it is \
                                 spelled as on the hosts, or it denies nothing"
                            ));
                        }
                        continue;
                    }
                    if !known.iter().any(|(p, a)| grant.covers_permission(p, *a)) {
                        let message = format!(
                            "roles.{name}.{list}: grant {source:?} matches no permission \
                             (`opsmcp tools` lists them)"
                        );
                        if list == "deny" {
                            problems.errors.push(message);
                        } else {
                            problems.warnings.push(message);
                        }
                    }
                }
            }
        }
        problems
    }

    /// The caller for a Unix user and their groups, or `None` if they hold no role.
    pub fn principal_for_unix(&self, user: &str, groups: &[String]) -> Option<Principal> {
        let mut roles = BTreeSet::new();
        if let Some(member) = self.unix_users.get(user) {
            roles.extend(member.roles.iter().cloned());
        }
        for group in groups {
            if let Some(member) = self.unix_groups.get(group) {
                roles.extend(member.roles.iter().cloned());
            }
        }
        if roles.is_empty() {
            return None;
        }
        Some(self.principal(user.to_string(), roles))
    }

    /// The caller for a presented bearer token, or `None` if it is unknown or expired.
    pub fn principal_for_token(&self, presented: &str, now: i64) -> Option<Principal> {
        let presented_hash = sha256_hex(presented.as_bytes());
        // AIDEV-NOTE: compare against every configured token in constant time and without
        // stopping early, so timing says nothing about which token (if any) matched.
        let mut found = None;
        for (name, token) in &self.tokens {
            let Some(stored) = normalize_sha256(&token.sha256) else {
                continue;
            };
            if bool::from(stored.as_bytes().ct_eq(presented_hash.as_bytes())) {
                found = Some((name, token));
            }
        }
        let (name, token) = found?;
        if let Some(expires) = &token.expires {
            // Valid through the end of the expiry day (UTC). An unreadable date fails closed.
            let last_day = parse_date(expires)?;
            if now >= last_day + 86_400 {
                return None;
            }
        }
        let roles = token.roles.iter().cloned().collect();
        Some(self.principal(format!("token:{name}"), roles))
    }

    /// The caller for a verified client certificate, or `None` if it is not listed.
    pub fn principal_for_cert(&self, fingerprint: &str, cn: Option<&str>) -> Option<Principal> {
        let fingerprint = normalize_sha256(fingerprint)?;
        // Every attribute an entry names must match. An entry pinned to a fingerprint is
        // more specific than one that only names a CN, so it is preferred.
        let matches = |cert: &ClientCertCfg| -> bool {
            let fingerprint_ok = match &cert.sha256 {
                Some(want) => normalize_sha256(want).as_deref() == Some(fingerprint.as_str()),
                None => true,
            };
            let cn_ok = match &cert.cn {
                Some(want) => cn == Some(want.as_str()),
                None => true,
            };
            (cert.sha256.is_some() || cert.cn.is_some()) && fingerprint_ok && cn_ok
        };
        let (name, cert) = self
            .client_certs
            .iter()
            .filter(|(_, cert)| matches(cert))
            .max_by_key(|(_, cert)| cert.sha256.is_some())?;
        let roles = cert.roles.iter().cloned().collect();
        Some(self.principal(format!("cert:{name}"), roles))
    }
}

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

fn is_role_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// A lowercase identifier starting with a letter, at most `max` characters.
fn is_identifier(name: &str, max: usize) -> bool {
    let mut chars = name.chars();
    name.len() <= max
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A user or group name as the account tools accept it: letters, digits and `_ . -`
/// (and a final `$`), not starting with `-` or `.`, at most 32 characters.
pub fn is_account_name(name: &str) -> bool {
    let body = name.strip_suffix('$').unwrap_or(name);
    !body.is_empty()
        && name.len() <= 32
        && !body.starts_with(['-', '.'])
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

/// A DNS host name: labels of letters, digits and `-` separated by dots, at most 253
/// characters. No trailing dot, no address literals.
pub fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Splits `https://HOST[:PORT]` into host and port. Nothing else is accepted: no other
/// scheme (credentials are sent to it), no user name, path or query. A trailing `/` is
/// allowed. The host is a DNS name or an IPv4 address.
pub fn parse_https_origin(url: &str, default_port: u16) -> Result<(String, u16), String> {
    let wrong = || format!("{url:?} must have the form https://HOST[:PORT]");
    let rest = url.strip_prefix("https://").ok_or_else(wrong)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| wrong())?;
            if port == 0 {
                return Err(wrong());
            }
            (host, port)
        }
        None => (rest, default_port),
    };
    if !is_host_name(host) {
        return Err(wrong());
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// A name for a fleet server or one of its rules: letters, digits, `.`, `_` and `-`.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// `ssh -o` options that cannot be given in `fleet.ssh.options`: the fleet server sets
/// them itself, or they say who to log in as, which is for the rules to decide.
///
/// AIDEV-NOTE: the first group is what makes a session to a host non-interactive, unable
/// to forward anything, and bound to the one command in `fleet.ssh.remote_command`. The
/// second is the identity: with a key of the fleet's own, "that key and nothing else"
/// would not hold if an option here could add an identity file, an agent or a shared
/// connection. ssh takes the first value it is given and ours come first, but for an
/// option that accumulates (IdentityFile) that is no protection, hence this list.
pub const RESERVED_SSH_OPTIONS: &[&str] = &[
    "batchmode",
    "forwardagent",
    "forwardx11",
    "forwardx11trusted",
    "clearallforwardings",
    "permitlocalcommand",
    "localcommand",
    "remotecommand",
    "requesttty",
    "escapechar",
    "sessiontype",
    "stdinnull",
    "forkafterauthentication",
    "loglevel",
    "connecttimeout",
    "serveraliveinterval",
    "serveralivecountmax",
    "sendenv",
    "setenv",
    // who to log in as, and to what
    "identityfile",
    "identityagent",
    "identitiesonly",
    "certificatefile",
    "preferredauthentications",
    "controlmaster",
    "controlpath",
    "controlpersist",
    "user",
    "port",
    "hostname",
];

/// Checks one `Key=Value` for `fleet.ssh.options`.
fn check_ssh_option(option: &str) -> Result<(), String> {
    let (key, value) = option
        .split_once('=')
        .ok_or_else(|| "must be written Key=Value".to_string())?;
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err("must be written Key=Value, the key being an ssh option name".to_string());
    }
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("needs a value, on one line".to_string());
    }
    let key = key.to_ascii_lowercase();
    if RESERVED_SSH_OPTIONS.contains(&key.as_str()) {
        return Err(
            "cannot be given here: opsmcp sets it itself, from the rule and the inventory"
                .to_string(),
        );
    }
    // Host keys must be checked: a host that is not who it says it is would be handed
    // commands meant for another, and its answers believed.
    if key == "stricthostkeychecking" && !matches!(value, "yes" | "accept-new") {
        return Err("may only be yes (the default) or accept-new".to_string());
    }
    Ok(())
}

fn check_absolute(at: &str, path: &Path, errs: &mut Vec<String>) {
    if !path.is_absolute() {
        errs.push(format!(
            "{at}: {:?} must be an absolute path",
            path.display().to_string()
        ));
    }
}

fn check_range(at: &str, value: u64, min: u64, max: u64, errs: &mut Vec<String>) {
    if value < min || value > max {
        errs.push(format!("{at}: must be between {min} and {max}"));
    }
}

fn validate_custom(name: &str, custom: &CustomCfg, call_timeout_secs: u64, errs: &mut Vec<String>) {
    let at = format!("custom.{name}");
    if !is_identifier(name, 48) {
        errs.push(format!(
            "{at}: a tool name must be a-z, 0-9 and '_', start with a letter, and be at most 48 characters"
        ));
    }
    if custom.description.trim().is_empty() {
        errs.push(format!("{at}.description: is empty"));
    }
    match custom.command.first() {
        None => errs.push(format!("{at}.command: is empty")),
        Some(program) => {
            if !Path::new(program).is_absolute() || program.contains(['{', '}']) {
                errs.push(format!(
                    "{at}.command: the program (first element) must be an absolute path, with no placeholders"
                ));
            }
        }
    }

    let mut used = BTreeSet::new();
    for (index, element) in custom.command.iter().enumerate().skip(1) {
        let at = format!("{at}.command[{index}]");
        let pieces = match template::parse(element) {
            Ok(pieces) => pieces,
            Err(e) => {
                errs.push(format!("{at}: {e}"));
                continue;
            }
        };
        for piece in pieces {
            let (param, needs_boolean) = match piece {
                Piece::Text(_) => continue,
                Piece::Param(param) => (param, false),
                Piece::Flag { param, .. } => (param, true),
            };
            match custom.params.get(&param) {
                None => errs.push(format!("{at}: unknown parameter {param:?}")),
                Some(declared) if needs_boolean && declared.kind != CustomParamType::Boolean => {
                    errs.push(format!("{at}: {{{param}?...}} needs a boolean parameter"));
                }
                Some(_) => {}
            }
            used.insert(param);
        }
    }

    for (param_name, param) in &custom.params {
        let at = format!("{at}.params.{param_name}");
        if !is_identifier(param_name, 32) {
            errs.push(format!(
                "{at}: a parameter name must be a-z, 0-9 and '_', start with a letter, and be at most 32 characters"
            ));
        }
        if !used.contains(param_name) {
            errs.push(format!("{at}: is not used in command"));
        }
        let kind = param.kind;
        if kind == CustomParamType::Enum {
            if param.values.is_empty() {
                errs.push(format!(
                    "{at}.values: an enum parameter needs at least one value"
                ));
            }
            if param
                .values
                .iter()
                .any(|v| v.is_empty() || v.chars().any(char::is_control))
            {
                errs.push(format!(
                    "{at}.values: a value is empty or contains a control character"
                ));
            }
        } else if !param.values.is_empty() {
            errs.push(format!("{at}.values: only applies to enum parameters"));
        }
        if kind == CustomParamType::String {
            if let Some(pattern) = &param.pattern
                && let Err(e) = regex::Regex::new(&anchored(pattern))
            {
                errs.push(format!("{at}.pattern: {e}"));
            }
            if param.max_len.is_some_and(|n| n == 0 || n > 4096) {
                errs.push(format!("{at}.max_len: must be between 1 and 4096"));
            }
        } else if param.pattern.is_some() || param.max_len.is_some() {
            errs.push(format!(
                "{at}: pattern and max_len only apply to string parameters"
            ));
        }
        if kind == CustomParamType::Integer {
            if let (Some(min), Some(max)) = (param.min, param.max)
                && min > max
            {
                errs.push(format!("{at}: min is greater than max"));
            }
        } else if param.min.is_some() || param.max.is_some() {
            errs.push(format!(
                "{at}: min and max only apply to integer parameters"
            ));
        }
    }

    match custom.timeout_secs {
        Some(t) if t == 0 || t > 3600 => {
            errs.push(format!("{at}.timeout_secs: must be between 1 and 3600"));
        }
        Some(t) if t > call_timeout_secs => errs.push(format!(
            "{at}.timeout_secs: {t} is more than limits.call_timeout_secs ({call_timeout_secs}), \
             which would stop the command first; raise limits.call_timeout_secs"
        )),
        _ => {}
    }
    if custom.run_as.as_deref() == Some("") {
        errs.push(format!("{at}.run_as: is empty"));
    }
    if custom.ok_exit_codes.is_empty()
        || custom.ok_exit_codes.iter().any(|c| !(0..=255).contains(c))
    {
        errs.push(format!(
            "{at}.ok_exit_codes: needs at least one code, each between 0 and 255"
        ));
    }
    for (key, value) in &custom.env {
        let key_ok = key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !key_ok || value.contains('\0') {
            errs.push(format!("{at}.env.{key}: not a valid environment variable"));
        }
    }
}

/// A pattern that has to match the whole value.
pub fn anchored(pattern: &str) -> String {
    format!("^(?:{pattern})$")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(text: &str) -> Vec<String> {
        Config::parse(text).err().unwrap_or_default()
    }

    fn assert_one_error_mentions(text: &str, needles: &[&str]) {
        let errs = errors(text);
        assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
        for needle in needles {
            assert!(
                errs[0].contains(needle),
                "{:?} should mention {needle:?}",
                errs[0]
            );
        }
    }

    const ROLES: &str = r#"
[roles.readonly]
allow = ["@read"]
[roles.operator]
allow = ["@read", "service.control:nginx.service"]
deny = ["fs.read:/etc/ssl/private/**"]
[roles.admin]
allow = ["@all"]
"#;

    const FLEET: &str = r#"
[roles.ops]
allow = ["@all"]
[roles.dev]
allow = ["@read", "custom.galera_status"]
[unix_groups.ops]
roles = ["ops"]
[fleet]
inventory = "/etc/opsmcp/fleet/hosts.toml"
"#;

    /// A fleet configuration with one rule, written by the test.
    fn fleet_with(rule: &str) -> String {
        format!("{FLEET}\n[[fleet.access]]\n{rule}\n")
    }

    const OPS_RULE: &str =
        "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"caller\"";

    #[test]
    fn a_fleet_configuration_has_defaults_for_everything_but_the_hosts_and_the_rules() {
        let cfg = Config::parse(&fleet_with(OPS_RULE)).unwrap();
        let fleet = cfg.fleet.as_ref().unwrap();
        assert_eq!(
            fleet.ssh.remote_command,
            ["sudo", "-n", "/usr/bin/opsmcp", "serve"]
        );
        assert_eq!(fleet.https.port, 8443);
        assert_eq!(fleet.max_hosts_per_call, 50);
        let rule = &fleet.access[0];
        assert_eq!((rule.via, rule.identity), (Via::Ssh, IdentityMode::Caller));
        assert!(!rule.read_only);
        assert_eq!(rule.label(0), "access[1]");
        // a configuration without the section is not a fleet configuration
        assert!(Config::parse(ROLES).unwrap().fleet.is_none());
    }

    #[test]
    fn every_kind_of_rule_can_be_written() {
        let text = format!(
            "{FLEET}
[[fleet.access]]
name = \"ops-direct\"
{OPS_RULE}
ssh_user = \"ops\"

[[fleet.access]]
roles = [\"dev\"]
hosts = [\"group:web\", \"db*\"]
via = \"ssh\"
identity = \"fleet\"
ssh_user = \"fleet-dev\"
ssh_key = \"/etc/opsmcp/fleet/dev_ed25519\"
read_only = true

[[fleet.access]]
roles = [\"ops\"]
hosts = [\"*\"]
via = \"https\"
identity = \"caller\"

[[fleet.access]]
roles = [\"dev\"]
hosts = [\"group:staging\"]
via = \"https\"
identity = \"fleet\"
token_file = \"/etc/opsmcp/fleet/dev.token\"

[fleet.ssh]
remote_command = [\"/usr/bin/opsmcp\", \"serve\"]
options = [\"ProxyJump=jump.example.com\", \"StrictHostKeyChecking=accept-new\"]
port = 2222

[fleet.https]
port = 9443
ca = \"/etc/opsmcp/fleet/ca.crt\"
client_cert = \"/etc/opsmcp/fleet/client.crt\"
client_key = \"/etc/opsmcp/fleet/client.key\"
"
        );
        let cfg = Config::parse(&text).unwrap_or_else(|e| panic!("{e:?}"));
        let fleet = cfg.fleet.unwrap();
        assert_eq!(fleet.access.len(), 4);
        assert_eq!(fleet.access[0].label(0), "ops-direct");
    }

    #[test]
    fn a_fleet_needs_an_inventory_and_at_least_one_rule() {
        let no_rules = FLEET;
        assert_one_error_mentions(no_rules, &["fleet.access"]);
        let no_inventory =
            fleet_with(OPS_RULE).replace("inventory = \"/etc/opsmcp/fleet/hosts.toml\"\n", "");
        assert_one_error_mentions(&no_inventory, &["fleet.inventory"]);
        let both = fleet_with(OPS_RULE).replace(
            "[fleet]\n",
            "[fleet]\ninventory_command = [\"/usr/local/bin/hosts\"]\n",
        );
        assert_one_error_mentions(&both, &["inventory", "inventory_command"]);
        let relative =
            fleet_with(OPS_RULE).replace("\"/etc/opsmcp/fleet/hosts.toml\"", "\"hosts.toml\"");
        assert_one_error_mentions(&relative, &["fleet.inventory", "absolute"]);
        let odd = fleet_with(OPS_RULE).replace("hosts.toml", "hosts.ini");
        assert_one_error_mentions(&odd, &["fleet.inventory", ".toml"]);
        for bad in ["[]", "[\"hosts\"]", "[\"/usr/bin/hosts\", \"\"]"] {
            let text = fleet_with(OPS_RULE).replace(
                "inventory = \"/etc/opsmcp/fleet/hosts.toml\"",
                &format!("inventory_command = {bad}"),
            );
            assert_one_error_mentions(&text, &["fleet.inventory_command"]);
        }
    }

    #[test]
    fn an_ansible_inventory_is_named_as_one_and_a_file_of_it_is_json() {
        const OWN: &str = "inventory = \"/etc/opsmcp/fleet/hosts.toml\"";
        // opsmcp's own format unless said otherwise
        let fleet = Config::parse(&fleet_with(OPS_RULE)).unwrap().fleet.unwrap();
        assert_eq!(fleet.inventory_format, InventoryFormat::Opsmcp);

        let saved = fleet_with(OPS_RULE).replace(
            OWN,
            "inventory = \"/etc/opsmcp/fleet/hosts.json\"\ninventory_format = \"ansible\"",
        );
        let fleet = Config::parse(&saved).unwrap().fleet.unwrap();
        assert_eq!(fleet.inventory_format, InventoryFormat::Ansible);

        let live = fleet_with(OPS_RULE).replace(
            OWN,
            "inventory_command = [\"/usr/local/bin/fleet-hosts\"]\ninventory_format = \"ansible\"",
        );
        let fleet = Config::parse(&live).unwrap().fleet.unwrap();
        assert_eq!(fleet.inventory_format, InventoryFormat::Ansible);

        // Ansible's own files (INI, YAML) are not read: what it prints from them is
        let ini = fleet_with(OPS_RULE).replace(
            OWN,
            "inventory = \"/etc/ansible/hosts.toml\"\ninventory_format = \"ansible\"",
        );
        assert_one_error_mentions(
            &ini,
            &["fleet.inventory", ".json", "ansible-inventory --list"],
        );
        let unknown =
            fleet_with(OPS_RULE).replace(OWN, &format!("{OWN}\ninventory_format = \"yaml\""));
        assert!(Config::parse(&unknown).is_err());
    }

    #[test]
    fn how_often_the_inventory_is_looked_at_again_can_be_set() {
        const OWN: &str = "inventory = \"/etc/opsmcp/fleet/hosts.toml\"";
        let fleet = Config::parse(&fleet_with(OPS_RULE)).unwrap().fleet.unwrap();
        assert_eq!(fleet.inventory_refresh_secs, None);
        for (written, read) in [("0", 0), ("1", 1), ("300", 300), ("86400", 86_400)] {
            let text = fleet_with(OPS_RULE)
                .replace(OWN, &format!("{OWN}\ninventory_refresh_secs = {written}"));
            let fleet = Config::parse(&text).unwrap().fleet.unwrap();
            assert_eq!(fleet.inventory_refresh_secs, Some(read));
        }
        let long =
            fleet_with(OPS_RULE).replace(OWN, &format!("{OWN}\ninventory_refresh_secs = 86401"));
        assert_one_error_mentions(&long, &["fleet.inventory_refresh_secs"]);
    }

    #[test]
    fn a_rule_must_be_complete_and_consistent() {
        let cases: &[(&str, &[&str])] = &[
            // roles and hosts
            (
                "roles = []\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"caller\"",
                &["roles is empty"],
            ),
            (
                "roles = [\"nobody\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"caller\"",
                &["unknown role", "nobody"],
            ),
            (
                "roles = [\"ops\"]\nhosts = []\nvia = \"ssh\"\nidentity = \"caller\"",
                &["hosts"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"-oProxyCommand=id\"]\nvia = \"ssh\"\nidentity = \"caller\"",
                &["hosts"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"a,b\"]\nvia = \"ssh\"\nidentity = \"caller\"",
                &["hosts"],
            ),
            // the caller's own identity takes no credential from here
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"caller\"\nssh_key = \"/k\"",
                &["ssh_key", "caller"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"caller\"\ntoken_file = \"/t\"",
                &["token_file", "caller"],
            ),
            // an identity of the fleet's own needs its credential
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"fleet\"\nssh_user = \"u\"",
                &["ssh_key"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"fleet\"\nssh_key = \"/k\"",
                &["ssh_user"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"fleet\"",
                &["token_file"],
            ),
            // settings of the other transport are mistakes
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"fleet\"\ntoken_file = \"/t\"\nssh_user = \"u\"",
                &["ssh_user", "https"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"fleet\"\nssh_user = \"u\"\nssh_key = \"/k\"\ntoken_file = \"/t\"",
                &["token_file", "ssh"],
            ),
            // values
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"caller\"\nssh_user = \"-oProxyCommand=id\"",
                &["ssh_user"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"fleet\"\nssh_user = \"u\"\nssh_key = \"key\"",
                &["ssh_key", "absolute"],
            ),
            (
                "roles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"fleet\"\ntoken_file = \"t\"",
                &["token_file", "absolute"],
            ),
            (
                "name = \"two words\"\nroles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"caller\"",
                &["name"],
            ),
        ];
        for (rule, needles) in cases {
            // with the certificate that rules over HTTPS need, so that it is not what
            // is wrong with any of these
            let text = format!(
                "{}\n[fleet.https]\nclient_cert = \"/c.crt\"\nclient_key = \"/c.key\"\n",
                fleet_with(rule)
            );
            assert_one_error_mentions(&text, needles);
        }
        // unknown words are errors
        assert!(!errors(&fleet_with(&OPS_RULE.replace("\"ssh\"", "\"telnet\""))).is_empty());
        assert!(!errors(&fleet_with(&OPS_RULE.replace("\"caller\"", "\"root\""))).is_empty());
        assert!(!errors(&fleet_with(&format!("{OPS_RULE}\nreadonly = true"))).is_empty());
    }

    #[test]
    fn a_rule_that_reaches_hosts_over_https_needs_the_fleets_certificate() {
        // AIDEV-NOTE: over HTTPS a bearer token (the caller's own, or the fleet's) is
        // sent to every host a rule covers, and a token is good wherever it alone is
        // enough: a host that was sent one could use it on the others. A certificate
        // of the fleet's is what lets the hosts refuse a token that did not come
        // through this server (`auth = "mtls+token"` there). Whether they do cannot be
        // seen from here; that this server has one to show can be insisted on.
        const CERT: &str = "[fleet.https]\nclient_cert = \"/c.crt\"\nclient_key = \"/c.key\"\n";
        for rule in [
            "name = \"own-token\"\nroles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"caller\"",
            "name = \"fleet-token\"\nroles = [\"ops\"]\nhosts = [\"*\"]\nvia = \"https\"\nidentity = \"fleet\"\ntoken_file = \"/t\"",
        ] {
            let name = if rule.contains("own-token") {
                "own-token"
            } else {
                "fleet-token"
            };
            assert_one_error_mentions(
                &fleet_with(rule),
                &["fleet.https.client_cert", name, "mtls+token"],
            );
            let with_certificate = format!("{}\n{CERT}", fleet_with(rule));
            assert_eq!(errors(&with_certificate), Vec::<String>::new());
        }
        // a fleet that only uses SSH needs none
        assert_eq!(errors(&fleet_with(OPS_RULE)), Vec::<String>::new());
    }

    #[test]
    fn two_rules_cannot_have_the_same_name() {
        let text = format!(
            "{FLEET}\n[[fleet.access]]\nname = \"a\"\n{OPS_RULE}\n[[fleet.access]]\nname = \"a\"\n{OPS_RULE}\n"
        );
        assert_one_error_mentions(&text, &["name", "\"a\""]);
    }

    #[test]
    fn the_remote_command_is_plain_words() {
        for bad in [
            "[]",
            "[\"\"]",
            "[\"sudo\", \"opsmcp serve\"]",
            "[\"opsmcp\", \"serve;id\"]",
            "[\"opsmcp\", \"$(id)\"]",
            "[\"opsmcp\", \"serve\", \"|\", \"tee\"]",
            "[\"-n\", \"opsmcp\"]",
            "[\"opsmcp\", \"se`rve\"]",
            "[\"opsmcp\", \"serve\\n\"]",
        ] {
            let text = format!(
                "{}\n[fleet.ssh]\nremote_command = {bad}\n",
                fleet_with(OPS_RULE)
            );
            assert_one_error_mentions(&text, &["fleet.ssh.remote_command"]);
        }
    }

    #[test]
    fn ssh_options_cannot_undo_what_the_fleet_relies_on() {
        for bad in [
            "BatchMode=no",
            "batchmode=no",
            "ForwardAgent=yes",
            "StrictHostKeyChecking=no",
            "StrictHostKeyChecking=off",
            "RemoteCommand=id",
            "RequestTTY=yes",
            "IdentityFile=/root/.ssh/id_ed25519",
            "identityagent=/tmp/agent.sock",
            "ControlPath=/tmp/%r@%h",
            "User=root",
            "ConnectTimeout=1",
            "no-equals-sign",
            "=value",
            "Proxy Jump=x",
            "ProxyJump=",
            "ProxyJump=a\\nb",
        ] {
            let text = format!(
                "{}\n[fleet.ssh]\noptions = [\"{bad}\"]\n",
                fleet_with(OPS_RULE)
            );
            assert_one_error_mentions(&text, &["fleet.ssh.options"]);
        }
        for good in [
            "StrictHostKeyChecking=accept-new",
            "ProxyJump=jump.example.com",
            "UserKnownHostsFile=/etc/opsmcp/fleet/known_hosts",
        ] {
            let text = format!(
                "{}\n[fleet.ssh]\noptions = [\"{good}\"]\n",
                fleet_with(OPS_RULE)
            );
            assert!(errors(&text).is_empty(), "{good}: {:?}", errors(&text));
        }
    }

    #[test]
    fn fleet_numbers_and_paths_are_checked() {
        for (line, needle) in [
            ("max_hosts_per_call = 0", "fleet.max_hosts_per_call"),
            ("max_parallel = 0", "fleet.max_parallel"),
            ("max_connections = 0", "fleet.max_connections"),
            ("idle_secs = 1", "fleet.idle_secs"),
            ("connect_timeout_secs = 0", "fleet.connect_timeout_secs"),
            ("retry_secs = 100000", "fleet.retry_secs"),
            ("name = \"two words\"", "fleet.name"),
        ] {
            let text = fleet_with(OPS_RULE).replace("[fleet]\n", &format!("[fleet]\n{line}\n"));
            assert_one_error_mentions(&text, &[needle]);
        }
        for (section, needle) in [
            ("[fleet.ssh]\nport = 0", "fleet.ssh.port"),
            ("[fleet.https]\nport = 0", "fleet.https.port"),
            ("[fleet.https]\nca = \"ca.crt\"", "fleet.https.ca"),
            ("[fleet.https]\nclient_cert = \"/c.crt\"", "client_key"),
            ("[fleet.https]\nclient_key = \"/c.key\"", "client_cert"),
        ] {
            let text = format!("{}\n{section}\n", fleet_with(OPS_RULE));
            assert_one_error_mentions(&text, &[needle]);
        }
    }

    #[test]
    fn a_fleet_keeps_at_least_as_many_sessions_as_it_asks_hosts_at_once() {
        let text = fleet_with(OPS_RULE).replace(
            "[fleet]\n",
            "[fleet]\nmax_parallel = 32\nmax_connections = 16\n",
        );
        assert_one_error_mentions(&text, &["fleet.max_connections", "max_parallel"]);
    }

    #[test]
    fn a_fleet_cannot_check_a_denial_of_a_hosts_own_tool_and_says_so() {
        let text = fleet_with(OPS_RULE).replace(
            "allow = [\"@read\", \"custom.galera_status\"]",
            "allow = [\"@read\", \"custom.galera_status\"]\ndeny = [\"custom.rebot\"]",
        );
        let cfg = Config::parse(&text).unwrap();
        let problems = cfg.validate_grants(&[("system.view".to_string(), Access::Read)]);
        assert!(problems.errors.is_empty(), "{:?}", problems.errors);
        // Granting a tool that no host has does no harm, and is taken on trust. A denial
        // that names no tool (a misspelling) would silently deny nothing, and a fleet
        // server cannot tell: it says so rather than stay quiet.
        assert_eq!(problems.warnings.len(), 1, "{:?}", problems.warnings);
        assert!(
            problems.warnings[0].contains("custom.rebot") && problems.warnings[0].contains("hosts"),
            "{:?}",
            problems.warnings
        );
    }

    #[test]
    fn a_fleet_role_cannot_limit_a_grant_to_a_resource() {
        // the fleet server never sees the unit, path or container a host resolves the
        // call to, so it could not honour such a limit: refusing beats ignoring it
        let text = fleet_with(OPS_RULE).replace(
            "allow = [\"@all\"]",
            "allow = [\"@read\", \"service.control:nginx.service\"]",
        );
        assert_one_error_mentions(
            &text,
            &["roles.ops.allow", "service.control:nginx.service", "host"],
        );
        let text = fleet_with(OPS_RULE).replace(
            "allow = [\"@all\"]",
            "allow = [\"@all\"]\ndeny = [\"fs.read:/etc/ssl/**\"]",
        );
        assert_one_error_mentions(&text, &["roles.ops.deny", "fs.read:/etc/ssl/**"]);
    }

    #[test]
    fn an_empty_configuration_is_valid_and_grants_nothing() {
        let cfg = Config::parse("").unwrap();
        assert!(
            cfg.principal_for_unix("root", &["root".to_string()])
                .is_none()
        );
        assert!(cfg.principal_for_token("opsmcp_x", 0).is_none());
        assert!(
            cfg.principal_for_cert(&"0".repeat(64), Some("root"))
                .is_none()
        );
    }

    #[test]
    fn unknown_keys_are_errors_not_ignored() {
        assert!(!errors("[rolls.admin]\nallow = [\"@all\"]\n").is_empty());
        assert!(!errors("[roles.admin]\nalow = [\"@all\"]\n").is_empty());
        assert!(!errors("[limits]\nmax_output = 5\n").is_empty());
    }

    #[test]
    fn a_malformed_grant_names_its_role() {
        assert_one_error_mentions("[roles.ops]\nallow = [\"@write\"]\n", &["ops", "@write"]);
        assert_one_error_mentions(
            "[roles.ops]\nallow = [\"@read\"]\ndeny = [\"Bad Grant\"]\n",
            &["ops", "Bad Grant"],
        );
    }

    #[test]
    fn a_member_must_reference_roles_that_exist() {
        let text = format!("{ROLES}\n[unix_users.sean]\nroles = [\"admn\"]\n");
        assert_one_error_mentions(&text, &["sean", "admn"]);
        let text = format!("{ROLES}\n[unix_groups.ops]\nroles = []\n");
        assert_one_error_mentions(&text, &["ops"]);
    }

    #[test]
    fn a_token_needs_a_real_hash_and_a_real_expiry_date() {
        let text = format!("{ROLES}\n[tokens.ci]\nsha256 = \"abc\"\nroles = [\"readonly\"]\n");
        assert_one_error_mentions(&text, &["ci", "sha256"]);
        let hash = "a".repeat(64);
        let text = format!(
            "{ROLES}\n[tokens.ci]\nsha256 = \"{hash}\"\nroles = [\"readonly\"]\nexpires = \"2026-02-30\"\n"
        );
        assert_one_error_mentions(&text, &["ci", "expires"]);
    }

    #[test]
    fn a_client_certificate_needs_a_cn_or_a_fingerprint() {
        let text = format!("{ROLES}\n[client_certs.laptop]\nroles = [\"admin\"]\n");
        assert_one_error_mentions(&text, &["laptop"]);
        let text =
            format!("{ROLES}\n[client_certs.laptop]\nsha256 = \"zz\"\nroles = [\"admin\"]\n");
        assert_one_error_mentions(&text, &["laptop", "sha256"]);
    }

    const HTTP: &str = r#"
[http]
listen = "127.0.0.1:8443"
tls_cert = "/etc/opsmcp/tls/server.crt"
tls_key = "/etc/opsmcp/tls/server.key"
"#;

    #[test]
    fn http_settings_are_checked() {
        assert!(errors(HTTP).is_empty());
        assert_one_error_mentions(&HTTP.replace("127.0.0.1:8443", "localhost"), &["listen"]);
        assert_one_error_mentions(&format!("{HTTP}auth = \"mtls\"\n"), &["client_ca"]);
        assert_one_error_mentions(&format!("{HTTP}auth = \"mtls+token\"\n"), &["client_ca"]);
        assert!(errors(&format!("{HTTP}auth = \"password\"\n")).len() == 1);
        assert_one_error_mentions(
            &HTTP.replace("/etc/opsmcp/tls/server.key", "server.key"),
            &["tls_key"],
        );
    }

    #[test]
    fn two_client_certificate_entries_cannot_claim_the_same_certificate() {
        let fingerprint = "ab".repeat(32);
        let text = format!(
            "{ROLES}\n[client_certs.a]\ncn = \"deploy\"\nroles = [\"readonly\"]\n\
             [client_certs.b]\ncn = \"deploy\"\nroles = [\"admin\"]\n"
        );
        assert_one_error_mentions(&text, &["client_certs", "deploy"]);
        // the same fingerprint written two ways is still the same certificate
        let spaced: Vec<String> = fingerprint
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_uppercase())
            .collect();
        let text = format!(
            "{ROLES}\n[client_certs.a]\nsha256 = \"{fingerprint}\"\nroles = [\"readonly\"]\n\
             [client_certs.b]\nsha256 = \"{}\"\nroles = [\"admin\"]\n",
            spaced.join(":")
        );
        assert_one_error_mentions(&text, &["client_certs", "sha256"]);
    }

    #[test]
    fn time_limits_must_fit_inside_one_another() {
        assert_one_error_mentions(
            "[limits]\ncommand_timeout_secs = 60\ncall_timeout_secs = 30\n",
            &["call_timeout_secs", "command_timeout_secs"],
        );
        let text = "[custom.slow]\ndescription = \"Slow\"\naccess = \"read\"\ncommand = [\"/bin/slow\"]\ntimeout_secs = 600\n";
        assert_one_error_mentions(text, &["slow", "timeout_secs", "call_timeout_secs"]);
        assert!(errors(&format!("{text}[limits]\ncall_timeout_secs = 900\n")).is_empty());
    }

    #[test]
    fn limits_must_be_usable() {
        assert_one_error_mentions(
            "[limits]\nmax_concurrent_calls = 0\n",
            &["max_concurrent_calls"],
        );
        assert_one_error_mentions(
            "[limits]\ncommand_timeout_secs = 0\n",
            &["command_timeout_secs"],
        );
        assert_one_error_mentions("[limits]\nmax_output_bytes = 10\n", &["max_output_bytes"]);
    }

    #[test]
    fn directories_must_be_absolute() {
        assert_one_error_mentions("[logs]\ndirs = [\"var/log\"]\n", &["var/log"]);
        assert_one_error_mentions("[fs]\nread_roots = [\"etc\"]\n", &["etc"]);
        assert_one_error_mentions("[paths]\nsearch = [\"bin\"]\n", &["bin"]);
    }

    #[test]
    fn network_and_account_tools_allow_nothing_until_configured() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.net.probe_targets.is_empty());
        assert!(cfg.net.capture_interfaces.is_empty());
        assert!(!cfg.net.capture_payload);
        assert_eq!(cfg.users.min_uid, 1000);
        assert_eq!(cfg.users.protected, ["root"]);
        assert!(cfg.users.groups.is_empty());
        assert!(!cfg.users.manage_ssh_keys);
    }

    #[test]
    fn network_and_account_settings_are_checked() {
        assert_one_error_mentions("[net]\nprobe_targets = [\"\"]\n", &["net.probe_targets"]);
        assert_one_error_mentions(
            "[net]\ncapture_interfaces = [\"\"]\n",
            &["net.capture_interfaces"],
        );
        assert_one_error_mentions("[users]\nmin_uid = 0\n", &["users.min_uid"]);
        assert_one_error_mentions("[users]\nprotected = [\"\"]\n", &["users.protected"]);
        assert_one_error_mentions(
            "[users]\ngroups = [\"www data\"]\n",
            &["users.groups", "www data"],
        );
        assert_one_error_mentions("[users]\ngroups = [\"-x\"]\n", &["users.groups"]);
        let ok = "[net]\nprobe_targets = [\"10.*\", \"*.example.com\"]\ncapture_interfaces = [\"eth*\"]\n\
                  capture_payload = true\n[users]\nmin_uid = 500\nprotected = [\"root\", \"deploy*\"]\n\
                  groups = [\"www-data\", \"dev.team\"]\nmanage_ssh_keys = true\n";
        assert_eq!(errors(ok), Vec::<String>::new());
    }

    #[test]
    fn the_tools_that_change_or_attach_allow_nothing_until_configured() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.fs.write_roots.is_empty());
        assert_eq!(cfg.fs.backup_dir, PathBuf::from("/var/backups/opsmcp"));
        assert!(cfg.monitoring.icinga_url.is_none());
        assert_eq!(cfg.monitoring.max_minutes, 240);
        assert_eq!(cfg.haproxy.socket, PathBuf::from("/run/haproxy/admin.sock"));
        assert!(cfg.storage.reclaim.is_empty());
        assert!(cfg.storage.extendable.is_empty());
        assert_eq!(cfg.storage.max_extend_gb, 50);
        assert!(cfg.firewall.sets.is_empty());
        assert!(cfg.trace.processes.is_empty());
        assert!(!cfg.trace.system_wide);
        assert_eq!(cfg.db.postgres_user, "postgres");
        assert!(!cfg.db.show_queries);
        assert!(!cfg.package.cve_online);
    }

    #[test]
    fn the_settings_of_the_newer_tools_are_checked() {
        assert_one_error_mentions("[fs]\nwrite_roots = [\"etc/nginx\"]\n", &["fs.write_roots"]);
        assert_one_error_mentions("[fs]\nbackup_dir = \"backups\"\n", &["fs.backup_dir"]);
        assert_one_error_mentions("[haproxy]\nsocket = \"admin.sock\"\n", &["haproxy.socket"]);
        assert_one_error_mentions(
            "[storage]\nreclaim = [\"journal\", \"everything\"]\n",
            &["storage.reclaim", "everything", "package_cache"],
        );
        assert_one_error_mentions("[storage]\nextendable = [\"\"]\n", &["storage.extendable"]);
        assert_one_error_mentions("[storage]\nmax_extend_gb = 0\n", &["storage.max_extend_gb"]);
        assert_one_error_mentions("[firewall]\nsets = [\"\"]\n", &["firewall.sets"]);
        assert_one_error_mentions("[trace]\nprocesses = [\"\"]\n", &["trace.processes"]);
        assert_one_error_mentions("[db]\npostgres_user = \"-x\"\n", &["db.postgres_user"]);
        assert_one_error_mentions(
            "[db]\npatroni_config = \"patroni.yml\"\n",
            &["db.patroni_config"],
        );
        assert_one_error_mentions(
            "[db]\nmysql_defaults_file = \"my.cnf\"\n",
            &["db.mysql_defaults_file"],
        );
        assert_one_error_mentions(
            "[db]\npostgres_socket_dir = \"run\"\n",
            &["db.postgres_socket_dir"],
        );
        let ok = "[fs]\nwrite_roots = [\"/etc/nginx\"]\nbackup_dir = \"/var/backups/x\"\n\
                  [haproxy]\nsocket = \"/run/haproxy/admin.sock\"\n\
                  [storage]\nreclaim = [\"journal\", \"core_dumps\"]\nextendable = [\"vg0/*\"]\nmax_extend_gb = 20\n\
                  [firewall]\nsets = [\"nft/inet/filter/blocklist\", \"ipset/*\"]\n\
                  [trace]\nprocesses = [\"www-data/*\"]\nsystem_wide = true\n\
                  [db]\npostgres_user = \"postgres\"\npatroni_config = \"/etc/patroni/patroni.yml\"\nshow_queries = true\n\
                  [package]\ncve_online = true\n";
        assert_eq!(errors(ok), Vec::<String>::new());
    }

    #[test]
    fn the_monitoring_settings_must_be_complete_and_use_https() {
        let whole = "[monitoring]\nicinga_url = \"https://icinga.example.com:5665\"\n\
                     icinga_user = \"opsmcp\"\nicinga_password_file = \"/etc/opsmcp/icinga.password\"\n\
                     icinga_ca = \"/etc/ssl/ca.pem\"\nhost = \"web1.example.com\"\nmax_minutes = 120\n";
        assert_eq!(errors(whole), Vec::<String>::new());
        // a password is never sent anywhere but over TLS
        assert_one_error_mentions(
            "[monitoring]\nicinga_url = \"http://icinga.example.com:5665\"\n\
             icinga_user = \"opsmcp\"\nicinga_password_file = \"/etc/opsmcp/p\"\n",
            &["monitoring.icinga_url", "https://"],
        );
        assert_one_error_mentions(
            "[monitoring]\nicinga_url = \"https://icinga.example.com\"\n",
            &["icinga_user", "icinga_password_file"],
        );
        assert_one_error_mentions(
            "[monitoring]\nicinga_url = \"https://icinga.example.com\"\n\
             icinga_user = \"a:b\"\nicinga_password_file = \"/etc/opsmcp/p\"\n",
            &["monitoring.icinga_user"],
        );
        assert_one_error_mentions(
            "[monitoring]\nicinga_url = \"https://icinga.example.com\"\n\
             icinga_user = \"opsmcp\"\nicinga_password_file = \"p\"\n",
            &["monitoring.icinga_password_file"],
        );
        assert_one_error_mentions("[monitoring]\nhost = \"web 1\"\n", &["monitoring.host"]);
        assert_one_error_mentions(
            "[monitoring]\nmax_minutes = 0\n",
            &["monitoring.max_minutes"],
        );
    }

    #[test]
    fn an_https_origin_is_a_host_and_a_port_and_nothing_else() {
        let ok = |url: &str| parse_https_origin(url, 5665).unwrap();
        assert_eq!(
            ok("https://icinga.example.com"),
            ("icinga.example.com".to_string(), 5665)
        );
        assert_eq!(
            ok("https://Icinga.Example.com:8443/"),
            ("icinga.example.com".to_string(), 8443)
        );
        assert_eq!(ok("https://10.0.0.5:5665"), ("10.0.0.5".to_string(), 5665));
        for bad in [
            "http://icinga.example.com",
            "icinga.example.com",
            "https://",
            "https://user:pw@icinga.example.com",
            "https://user@icinga.example.com",
            "https://icinga.example.com/v1",
            "https://icinga.example.com:0",
            "https://icinga.example.com:99999",
            "https://icinga.example.com:port",
            "https://icinga example.com",
            "https://-icinga.example.com",
            "https://icinga.example.com?x=1",
            "https://icinga.example.com#x",
        ] {
            assert!(parse_https_origin(bad, 5665).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_host_name_is_dns_labels_only() {
        for good in ["web1", "web1.example.com", "a-b.example.com", "10.0.0.5"] {
            assert!(is_host_name(good), "{good}");
        }
        for bad in [
            "", "web 1", "web1.", ".web1", "-web1", "web1-", "web_1", "a..b", "web1/x", "[::1]",
        ] {
            assert!(!is_host_name(bad), "{bad}");
        }
        assert!(!is_host_name(&"a".repeat(254)));
        assert!(!is_host_name(&format!("{}.com", "a".repeat(64))));
    }

    fn custom(body: &str) -> String {
        format!("[custom.haproxy_set]\ndescription = \"Set state\"\naccess = \"write\"\n{body}")
    }

    #[test]
    fn a_valid_custom_tool_is_accepted() {
        let text = custom(
            "command = [\"/usr/local/sbin/haproxystatus\", \"{state}\", \"{force?--force}\"]\n\
             [custom.haproxy_set.params.state]\ntype = \"enum\"\ndescription = \"State\"\n\
             values = [\"up\", \"down\"]\nrequired = true\n\
             [custom.haproxy_set.params.force]\ntype = \"boolean\"\ndescription = \"Force\"\n",
        );
        assert_eq!(errors(&text), Vec::<String>::new());
    }

    #[test]
    fn custom_tool_mistakes_are_reported() {
        // program must be an absolute path: no PATH lookups for operator commands
        assert_one_error_mentions(
            &custom("command = [\"haproxystatus\"]\n"),
            &["haproxy_set", "absolute"],
        );
        assert_one_error_mentions(&custom("command = []\n"), &["haproxy_set", "command"]);
        // a placeholder must name a declared parameter
        assert_one_error_mentions(
            &custom("command = [\"/bin/x\", \"{state}\"]\n"),
            &["haproxy_set", "state"],
        );
        // the conditional form is only for booleans
        assert_one_error_mentions(
            &custom(
                "command = [\"/bin/x\", \"{state?--up}\"]\n\
                 [custom.haproxy_set.params.state]\ntype = \"string\"\ndescription = \"s\"\n",
            ),
            &["haproxy_set", "state"],
        );
        // an enum needs values
        assert_one_error_mentions(
            &custom(
                "command = [\"/bin/x\", \"{state}\"]\n\
                 [custom.haproxy_set.params.state]\ntype = \"enum\"\ndescription = \"s\"\n",
            ),
            &["haproxy_set", "state", "values"],
        );
        // a pattern must be a valid regular expression
        assert_one_error_mentions(
            &custom(
                "command = [\"/bin/x\", \"{state}\"]\n\
                 [custom.haproxy_set.params.state]\ntype = \"string\"\ndescription = \"s\"\npattern = \"(\"\n",
            ),
            &["haproxy_set", "state", "pattern"],
        );
        // unbalanced braces are a mistake, not a literal
        assert_one_error_mentions(
            &custom("command = [\"/bin/x\", \"{state\"]\n"),
            &["haproxy_set"],
        );
    }

    #[test]
    fn custom_tool_names_must_be_plain_identifiers() {
        let text = "[custom.\"Bad-Name\"]\ndescription = \"x\"\naccess = \"read\"\ncommand = [\"/bin/true\"]\n";
        assert_one_error_mentions(text, &["Bad-Name"]);
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let text = "[roles.a]\nallow = [\"@write\"]\n[unix_users.bob]\nroles = [\"missing\"]\n";
        assert_eq!(errors(text).len(), 2, "{:?}", errors(text));
    }

    #[test]
    fn grants_that_match_no_permission_are_reported() {
        let cfg = Config::parse(
            "[roles.ops]\nallow = [\"@read\", \"servce.control\", \"service.*\"]\ndeny = [\"proces.signal\"]\n",
        )
        .unwrap();
        let known = vec![
            ("service.control".to_string(), Access::Write),
            ("service.view".to_string(), Access::Read),
            ("process.signal".to_string(), Access::Write),
        ];
        let problems = cfg.validate_grants(&known);
        // a deny that matches nothing would fail open: an error
        assert_eq!(problems.errors.len(), 1, "{problems:?}");
        assert!(problems.errors[0].contains("proces.signal"), "{problems:?}");
        // an allow that matches nothing grants nothing: a warning
        assert_eq!(problems.warnings.len(), 1, "{problems:?}");
        assert!(
            problems.warnings[0].contains("servce.control"),
            "{problems:?}"
        );
    }

    fn members() -> Config {
        let token_hash = sha256_hex(b"opsmcp_secret");
        let expired_hash = sha256_hex(b"opsmcp_old");
        let fingerprint = "ab".repeat(32);
        let text = format!(
            "{ROLES}
[unix_users.sean]
roles = [\"admin\"]
[unix_groups.ops]
roles = [\"operator\"]
[unix_groups.wheel]
roles = [\"readonly\", \"operator\"]
[tokens.ci]
sha256 = \"{token_hash}\"
roles = [\"readonly\"]
[tokens.old]
sha256 = \"{expired_hash}\"
roles = [\"admin\"]
expires = \"2026-01-31\"
[client_certs.laptop]
sha256 = \"{fingerprint}\"
roles = [\"admin\"]
[client_certs.deploy]
cn = \"deploy.example.com\"
roles = [\"operator\"]
"
        );
        Config::parse(&text).unwrap()
    }

    fn groups(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_unix_caller_gets_their_own_roles_and_their_groups_roles() {
        let cfg = members();
        let p = cfg
            .principal_for_unix("sean", &groups(&["users", "ops"]))
            .unwrap();
        assert_eq!(p.name, "sean");
        assert_eq!(p.roles, vec!["admin", "operator"]);
        assert!(
            p.rules
                .check("process.signal", Access::Write, Some("root/x"))
        );

        let p = cfg
            .principal_for_unix("alice", &groups(&["ops", "wheel"]))
            .unwrap();
        assert_eq!(p.name, "alice");
        assert_eq!(p.roles, vec!["operator", "readonly"]);
        assert!(
            p.rules
                .check("service.control", Access::Write, Some("nginx.service"))
        );
        assert!(
            !p.rules
                .check("service.control", Access::Write, Some("postgres.service"))
        );
    }

    #[test]
    fn a_unix_caller_with_no_role_is_nobody() {
        let cfg = members();
        assert!(
            cfg.principal_for_unix("mallory", &groups(&["users"]))
                .is_none()
        );
        // a group named like a user does not make the user a member
        assert!(cfg.principal_for_unix("ops", &groups(&["users"])).is_none());
    }

    #[test]
    fn a_deny_in_one_role_applies_to_everything_the_caller_holds() {
        let cfg = members();
        let p = cfg.principal_for_unix("sean", &groups(&["ops"])).unwrap();
        // admin allows everything, but operator's deny still wins
        assert!(
            !p.rules
                .check("fs.read", Access::Read, Some("/etc/ssl/private/k.pem"))
        );
        assert!(p.rules.check("fs.read", Access::Read, Some("/etc/hosts")));
    }

    #[test]
    fn a_token_caller_is_found_by_the_token_not_its_hash() {
        let cfg = members();
        let p = cfg.principal_for_token("opsmcp_secret", 0).unwrap();
        assert_eq!(p.name, "token:ci");
        assert_eq!(p.roles, vec!["readonly"]);
        assert!(cfg.principal_for_token("opsmcp_wrong", 0).is_none());
        // presenting the stored hash itself must not work
        assert!(
            cfg.principal_for_token(&sha256_hex(b"opsmcp_secret"), 0)
                .is_none()
        );
        assert!(cfg.principal_for_token("", 0).is_none());
    }

    #[test]
    fn a_token_is_valid_through_its_expiry_day_and_not_after() {
        let cfg = members();
        // 2026-01-31T23:59:59Z and 2026-02-01T00:00:00Z
        assert!(
            cfg.principal_for_token("opsmcp_old", 1_769_903_999)
                .is_some()
        );
        assert!(
            cfg.principal_for_token("opsmcp_old", 1_769_904_000)
                .is_none()
        );
    }

    #[test]
    fn a_certificate_caller_is_found_by_fingerprint_or_common_name() {
        let cfg = members();
        let p = cfg
            .principal_for_cert(&"ab".repeat(32), Some("whoever"))
            .unwrap();
        assert_eq!(p.name, "cert:laptop");
        let p = cfg
            .principal_for_cert(&"cd".repeat(32), Some("deploy.example.com"))
            .unwrap();
        assert_eq!(p.name, "cert:deploy");
        assert_eq!(p.roles, vec!["operator"]);
        assert!(
            cfg.principal_for_cert(&"cd".repeat(32), Some("other.example.com"))
                .is_none()
        );
        assert!(cfg.principal_for_cert(&"cd".repeat(32), None).is_none());
    }
}
