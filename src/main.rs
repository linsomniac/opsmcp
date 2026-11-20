//! opsmcp: an MCP server that gives AI agents audited, permission-controlled access to
//! Linux operations tasks.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod audit;
mod config;
mod exec;
mod glob;
mod http;
mod identity;
mod logging;
mod mcp;
mod policy;
mod sanitize;
mod stdio;
mod template;
mod timefmt;
mod token;
mod tools;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};

use audit::{Audit, Severity};
use config::{Config, DEFAULT_CONFIG_PATH};
use exec::Bins;
use mcp::{Server, Session};
use policy::{Access, Rules};
use tools::{Host, Registry, format_table};

#[derive(Parser)]
#[command(
    name = "opsmcp",
    version,
    about = "MCP server giving AI agents audited, permission-controlled access to Linux operations tasks"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct ConfigArg {
    /// Configuration file
    #[arg(long, value_name = "FILE", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[derive(Args)]
struct ServeArgs {
    #[command(flatten)]
    config: ConfigArg,
    /// Log more to stderr
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Serve MCP on stdin and stdout: for a local agent, or over SSH
    Serve(ServeArgs),
    /// Serve MCP over HTTPS, as configured under [http]
    ServeHttp(ServeArgs),
    /// Check the configuration and summarise who may do what
    CheckConfig(ConfigArg),
    /// List every tool with its access class and permission
    Tools(ConfigArg),
    /// Show how you are identified and which tools you may use
    Whoami(ConfigArg),
    /// Generate a bearer token for the HTTPS transport
    NewToken {
        /// Name for the token in the configuration and the audit log
        #[arg(default_value = "CHANGE-ME")]
        name: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve(args) => serve_stdio(&args),
        Command::ServeHttp(args) => serve_http(&args),
        Command::CheckConfig(arg) => check_config(&arg.config),
        Command::Tools(arg) => list_tools(&arg.config),
        Command::Whoami(arg) => whoami(&arg.config),
        Command::NewToken { name } => new_token(&name),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("opsmcp: {message}");
            ExitCode::FAILURE
        }
    }
}

/// A configuration that has been read and checked, with the tools it results in.
struct Loaded {
    cfg: Config,
    registry: Registry,
    warnings: Vec<String>,
}

fn load(path: &Path) -> Result<Loaded, String> {
    let problems = |errors: Vec<String>| {
        let list: Vec<String> = errors.iter().map(|e| format!("  - {e}")).collect();
        format!("the configuration is not usable:\n{}", list.join("\n"))
    };
    let cfg = Config::load(path).map_err(problems)?;
    let (registry, warnings) = Registry::build(&cfg)
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|e| format!("{}: {e}", path.display()))
                .collect()
        })
        .map_err(problems)?;
    Ok(Loaded {
        cfg,
        registry,
        warnings,
    })
}

/// Everything the tools share. Fails if auditing cannot be set up as configured.
fn build_host(cfg: Config) -> Result<Arc<Host>, String> {
    let audit = Audit::open(&cfg.audit).map_err(|e| format!("cannot set up the audit log: {e}"))?;
    if audit.describe().is_empty() {
        log::warn!("auditing is switched off: neither audit.syslog nor audit.file is set");
    }
    // AIDEV-NOTE: when running as root, every program opsmcp starts must be root's (see
    // exec::check_trusted_path). Running as an ordinary user, the programs can do no more
    // than that user could anyway.
    // AIDEV-NOTE: with fs.protected_hardlinks off, any local user can hard-link a file
    // they cannot read (/etc/shadow) into a directory opsmcp may read from; such a link
    // IS the file, so no path check can tell. Every current distribution turns the
    // protection on; say so loudly if this host has it off.
    if std::fs::read_to_string("/proc/sys/fs/protected_hardlinks").is_ok_and(|v| v.trim() == "0") {
        log::warn!(
            "fs.protected_hardlinks is 0 on this host: local users can hard-link files into \
             the directories opsmcp reads, defeating its path checks; set it to 1"
        );
    }
    let trust = rustix::process::geteuid().is_root().then(Vec::new);
    let bins = Bins::new(&cfg.paths, trust);
    Ok(Arc::new(Host::new(cfg, bins, audit)))
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start: {e}"))
}

/// Completes when the process is asked to stop (SIGTERM, SIGINT or SIGHUP).
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut terminate), Ok(mut interrupt), Ok(mut hangup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        log::warn!("cannot listen for termination signals");
        return std::future::pending().await;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
        _ = hangup.recv() => {}
    }
}

/// Writes a session record to the audit trail.
fn session_event(host: &Host, session: &Session, event: &str, extra: Value) -> Result<(), String> {
    let mut record = json!({
        "event": event,
        "principal": session.principal.name,
        "roles": session.principal.roles,
        "transport": session.transport,
    });
    if let Some(fields) = record.as_object_mut() {
        if let Some(peer) = &session.peer {
            fields.insert("peer".to_string(), json!(peer));
        }
        if let Value::Object(extra) = extra {
            fields.extend(extra);
        }
    }
    host.audit.record(Severity::Info, record)
}

/// The client address of the SSH connection we were started over, if there is one.
fn ssh_peer() -> Option<String> {
    let connection = std::env::var("SSH_CONNECTION").ok()?;
    let address: std::net::IpAddr = connection.split_whitespace().next()?.parse().ok()?;
    Some(address.to_string())
}

fn serve_stdio(args: &ServeArgs) -> Result<(), String> {
    logging::init(args.verbose);
    let me = identity::current()?;
    let loaded = load(&args.config.config)?;
    for warning in &loaded.warnings {
        log::warn!("{warning}");
    }
    // AIDEV-NOTE: a caller with no role is turned away here, before anything is served.
    let principal = loaded
        .cfg
        .principal_for_unix(&me.user, &me.groups)
        .ok_or_else(|| {
            format!(
                "user {} has no role in {}; nothing to serve",
                me.user,
                args.config.config.display()
            )
        })?;
    let host = build_host(loaded.cfg)?;
    let server = Arc::new(Server::new(host.clone(), loaded.registry));
    let session = Session {
        principal: Arc::new(principal),
        transport: "stdio",
        peer: ssh_peer(),
    };

    let runtime = runtime()?;
    let result = runtime.block_on(async {
        let details = json!({"uid": me.uid, "via_sudo": me.via_sudo});
        session_event(&host, &session, "session_start", details)
            .map_err(|e| format!("cannot write to the audit log, so not serving: {e}"))?;
        log::debug!("serving {} on stdio", session.principal.name);
        let stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let served = stdio::serve(
            server,
            session.clone(),
            stdin,
            tokio::io::stdout(),
            shutdown_signal(),
        )
        .await;
        let _ = session_event(&host, &session, "session_end", json!({}));
        served.map_err(|e| format!("stdio: {e}"))
    });
    // The thread tokio reads stdin on may still be blocked in a read; do not wait for it.
    runtime.shutdown_background();
    result
}

fn serve_http(args: &ServeArgs) -> Result<(), String> {
    logging::init(args.verbose);
    let loaded = load(&args.config.config)?;
    for warning in &loaded.warnings {
        log::warn!("{warning}");
    }
    let host = build_host(loaded.cfg)?;
    let server = Arc::new(Server::new(host, loaded.registry));
    let runtime = runtime()?;
    let result = runtime.block_on(http::serve(server, shutdown_signal()));
    runtime.shutdown_background();
    result
}

/// Prints to stdout. A reader that has gone away (`opsmcp tools | head`) is not an error.
fn emit(text: &str) -> Result<(), String> {
    match std::io::stdout().write_all(text.as_bytes()) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(format!("cannot write: {e}")),
        _ => Ok(()),
    }
}

/// The tools a set of rules can use: how many in all, and how many of them change things.
fn usable(registry: &Registry, rules: &Rules) -> (usize, usize) {
    let usable: Vec<_> = registry
        .tools()
        .filter(|tool| rules.may_use(&tool.permission, tool.access))
        .collect();
    let changing = usable
        .iter()
        .filter(|tool| tool.access == Access::Write)
        .count();
    (usable.len(), changing)
}

fn check_config(path: &Path) -> Result<(), String> {
    let loaded = load(path)?;
    let cfg = &loaded.cfg;

    // The file is sound. Can this host actually run it? (Things that would otherwise
    // only show up when the server is started.)
    let mut unready = Audit::problems(&cfg.audit);
    if let Some(http) = &cfg.http
        && let Err(e) = http::check_tls(http)
    {
        unready.push(format!("http: {e}"));
    }
    if !unready.is_empty() {
        let list: Vec<String> = unready.iter().map(|e| format!("  - {e}")).collect();
        return Err(format!(
            "{} is valid, but this host cannot run it yet:\n{}",
            path.display(),
            list.join("\n")
        ));
    }

    let mut out = String::new();
    let _ = writeln!(out, "{} is valid.\n", path.display());

    let custom = cfg.custom.len();
    let offered = loaded.registry.tools().count();
    let _ = writeln!(
        out,
        "Tools: {offered} offered ({} built in, {custom} custom, {} disabled)",
        offered - custom,
        cfg.tools.disabled.len()
    );
    let mut sinks = Vec::new();
    if cfg.audit.syslog {
        sinks.push("syslog".to_string());
    }
    if let Some(file) = &cfg.audit.file {
        sinks.push(format!("file {}", file.display()));
    }
    if sinks.is_empty() {
        let _ = writeln!(out, "Audit: SWITCHED OFF");
    } else {
        let mode = if cfg.audit.fail_closed {
            "tools do not run if it fails"
        } else {
            "tools run even if it fails"
        };
        let _ = writeln!(out, "Audit: {} ({mode})", sinks.join(", "));
    }
    match &cfg.http {
        Some(http) => {
            let _ = writeln!(
                out,
                "HTTPS: {} (authentication: {})",
                http.listen,
                http.auth.as_str()
            );
        }
        None => {
            let _ = writeln!(out, "HTTPS: not configured");
        }
    }

    let _ = writeln!(out, "\nRoles:");
    for name in cfg.roles.keys() {
        let rules = cfg.rules_for(&BTreeSet::from([name.clone()]));
        let (tools, changing) = usable(&loaded.registry, &rules);
        let _ = writeln!(
            out,
            "  {name:<16} {tools} tools, {changing} that change things"
        );
    }

    let _ = writeln!(out, "\nCallers:");
    let mut rows = Vec::new();
    for (name, member) in &cfg.unix_users {
        rows.push(vec![
            "unix user".to_string(),
            name.clone(),
            member.roles.join(", "),
        ]);
    }
    for (name, member) in &cfg.unix_groups {
        rows.push(vec![
            "unix group".to_string(),
            name.clone(),
            member.roles.join(", "),
        ]);
    }
    for (name, token) in &cfg.tokens {
        let expiry = token
            .expires
            .as_ref()
            .map(|e| format!(" (expires {e})"))
            .unwrap_or_default();
        rows.push(vec![
            "token".to_string(),
            name.clone(),
            format!("{}{expiry}", token.roles.join(", ")),
        ]);
    }
    for (name, cert) in &cfg.client_certs {
        rows.push(vec![
            "client certificate".to_string(),
            name.clone(),
            cert.roles.join(", "),
        ]);
    }
    if rows.is_empty() {
        let _ = writeln!(out, "  (none: nobody can use this server)");
    } else {
        let table = format_table(&["KIND", "NAME", "ROLES"], &rows, &[false, false, false]);
        for line in table.lines() {
            let _ = writeln!(out, "  {line}");
        }
    }

    if !loaded.warnings.is_empty() {
        let _ = writeln!(out, "\nWarnings:");
        for warning in &loaded.warnings {
            let _ = writeln!(out, "  - {warning}");
        }
    }
    emit(&out)
}

fn list_tools(path: &Path) -> Result<(), String> {
    let loaded = load(path)?;
    let rows: Vec<Vec<String>> = loaded
        .registry
        .tools()
        .map(|tool| {
            // the first sentence is enough for a listing
            let summary = tool.description.split(". ").next().unwrap_or_default();
            vec![
                tool.name.clone(),
                tool.access.as_str().to_string(),
                tool.permission.clone(),
                summary.trim_end_matches('.').to_string(),
            ]
        })
        .collect();
    let headers = ["TOOL", "ACCESS", "PERMISSION", "WHAT IT DOES"];
    emit(&format_table(
        &headers,
        &rows,
        &[false, false, false, false],
    ))
}

fn whoami(path: &Path) -> Result<(), String> {
    let me = identity::current()?;
    let loaded = load(path)?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "user:   {} (uid {}){}",
        me.user,
        me.uid,
        if me.via_sudo { ", through sudo" } else { "" }
    );
    let _ = writeln!(out, "groups: {}", me.groups.join(", "));
    match loaded.cfg.principal_for_unix(&me.user, &me.groups) {
        None => {
            let _ = writeln!(out, "roles:  none (opsmcp serve will refuse this user)");
        }
        Some(principal) => {
            let _ = writeln!(out, "roles:  {}", principal.roles.join(", "));
            let names: Vec<&str> = loaded
                .registry
                .tools()
                .filter(|tool| principal.rules.may_use(&tool.permission, tool.access))
                .map(|tool| tool.name.as_str())
                .collect();
            let _ = writeln!(
                out,
                "tools:  {} of {}",
                names.len(),
                loaded.registry.tools().count()
            );
            for name in names {
                let _ = writeln!(out, "  {name}");
            }
        }
    }
    emit(&out)
}

fn new_token(name: &str) -> Result<(), String> {
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !plain {
        return Err("a token name may only contain letters, digits, '_' and '-'".to_string());
    }
    let new = token::generate()?;
    emit(&format!(
        "Token. Give it to the client; it is not stored and cannot be shown again:\n\n  \
         {}\n\n\
         Add this to the configuration, with the roles the client should hold:\n\n  \
         [tokens.{name}]\n  sha256 = \"{}\"\n  roles = [\"CHANGE-ME\"]\n",
        new.token, new.sha256
    ))
}
