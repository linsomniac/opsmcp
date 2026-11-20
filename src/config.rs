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
    /// Operator-defined tools, by tool name.
    pub custom: BTreeMap<String, CustomCfg>,
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
    /// Keep the built-in list of never-readable paths (shadow files, private keys...).
    pub default_deny: bool,
}

impl Default for FsCfg {
    fn default() -> Self {
        FsCfg {
            list_roots: vec![PathBuf::from("/")],
            read_roots: Vec::new(),
            deny: Vec::new(),
            default_deny: true,
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

        for (name, custom) in &self.custom {
            validate_custom(name, custom, limits.call_timeout_secs, &mut errs);
        }
        errs
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
            for (list, grants, into) in [
                ("allow", &role.allow, &mut problems.warnings),
                ("deny", &role.deny, &mut problems.errors),
            ] {
                for source in grants {
                    // A grant that does not parse is reported by `validate`.
                    let Ok(grant) = Grant::parse(source) else {
                        continue;
                    };
                    if !known.iter().any(|(p, a)| grant.covers_permission(p, *a)) {
                        into.push(format!(
                            "roles.{name}.{list}: grant {source:?} matches no permission \
                             (`opsmcp tools` lists them)"
                        ));
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
