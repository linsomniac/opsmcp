//! Putting a fleet server together from its configuration: reading the inventory and
//! the credentials the rules name, and finding `ssh`. Also keeping the inventory current
//! while the server runs (`Refresher`).
//!
//! AIDEV-NOTE: everything read here decides where credentials are sent or is a
//! credential itself, so it is held to the same standard as the configuration: files
//! that only root (or the user the server runs as) controls, and secrets that nobody
//! else can read. A problem stops the server from starting; nothing is skipped. Two
//! things follow from the inventory being read again later, and from Ansible's being
//! written for Ansible: an entry of an Ansible inventory that cannot be used here is
//! left out and pointed out (`Inventory::from_ansible`), and a problem with an inventory
//! read while the server runs leaves the one in use in place (`Refresher`).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{AuthMode, Config, FleetCfg, FleetSshCfg, IdentityMode, InventoryFormat, Via};
use crate::exec::{Bins, Cmd, check_trusted_path};
use crate::fleet::access::{AccessRules, Rule};
use crate::fleet::https::{HttpsClient, read_secret_file, trusted_owners};
use crate::fleet::inventory::{Changes, Format, HostEntry, Inventory};
use crate::fleet::ssh::{HostLink, SshTarget, ssh_args};
use crate::fleet::{DialAs, Dialer, Dialing, Fleet, HOST_ARG, LOGIN_ALLOWANCE, Parts};
use crate::token::Secret;
use crate::tools::tls::CA_BUNDLES;
use crate::tools::{Host, Registry};

/// Largest inventory read in opsmcp's own format, from a file or from a command.
const MAX_INVENTORY_BYTES: usize = 4 << 20;
/// Largest output of `ansible-inventory --list` read. It carries every variable of
/// every host, so it is far larger than the part of it that is kept.
const MAX_ANSIBLE_BYTES: usize = 64 << 20;
/// How long an inventory command may take. `ansible-inventory` with sources that ask a
/// cloud or a cluster for their hosts takes its time.
const INVENTORY_COMMAND_LIMIT: Duration = Duration::from_secs(120);
/// How often a file is looked at for changes, and a command run again, unless
/// `fleet.inventory_refresh_secs` says otherwise. Looking at a file costs one `stat`;
/// running a command costs whatever the command does.
const FILE_LOOKED_AT_EVERY: Duration = Duration::from_secs(30);
const COMMAND_RUN_EVERY: Duration = Duration::from_secs(300);

/// Everything a fleet server needs besides its own configuration and audit trail.
pub struct Prepared {
    pub inventory: Inventory,
    /// Where the inventory came from, for reading it again.
    pub source: Source,
    /// The inventory file as it was just before it was read.
    stamp: Option<Stamp>,
    /// What was pointed out about the inventory (also among `warnings`).
    pointed_out: Vec<String>,
    pub rules: AccessRules,
    pub name: String,
    pub dialer: Arc<dyn Dialer>,
    pub https: Option<HttpsClient>,
    pub tokens: HashMap<usize, Secret>,
    /// Things an operator should know about that do not stop the server.
    pub warnings: Vec<String>,
}

/// Where the inventory comes from, how it is written, and how often it is looked at
/// again.
#[derive(Clone, Debug)]
pub struct Source {
    from: From,
    format: InventoryFormat,
    every: Option<Duration>,
}

#[derive(Clone, Debug)]
enum From {
    File(PathBuf),
    Command(Vec<String>),
}

/// An inventory as read, and what in its source could not be used.
struct Listing {
    inventory: Inventory,
    left_out: Vec<String>,
}

/// What tells an inventory file that has changed from one that has not: which file it
/// is (one renamed into place is another file), its size, and when it was last written
/// and last had its owner or mode changed (a file that was refused for its mode is
/// worth another look once that is put right).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    real: PathBuf,
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Source {
    pub fn of(fleet: &FleetCfg) -> Result<Source, String> {
        let from = match (&fleet.inventory, &fleet.inventory_command) {
            (Some(path), _) => From::File(path.clone()),
            (None, Some(command)) => From::Command(command.clone()),
            (None, None) => return Err("fleet.inventory is not set".to_string()),
        };
        let every = match (fleet.inventory_refresh_secs, &from) {
            (Some(0), _) => None,
            (Some(secs), _) => Some(Duration::from_secs(secs)),
            (None, From::File(_)) => Some(FILE_LOOKED_AT_EVERY),
            (None, From::Command(_)) => Some(COMMAND_RUN_EVERY),
        };
        Ok(Source {
            from,
            format: fleet.inventory_format,
            every,
        })
    }

    /// How often the inventory is looked at again. `None`: only when asked.
    pub fn every(&self) -> Option<Duration> {
        self.every
    }

    /// For `check-config`: where the hosts come from and when they are looked at again.
    pub fn describe(&self) -> String {
        let from = match &self.from {
            From::File(path) => format!("the file {}", path.display()),
            From::Command(command) => format!("the command {}", command.join(" ")),
        };
        let format = match self.format {
            InventoryFormat::Opsmcp => "",
            InventoryFormat::Ansible => ", as `ansible-inventory --list` prints them",
        };
        let again = match (&self.from, self.every) {
            (_, None) => "read again only on SIGHUP (fleet-http)".to_string(),
            (From::File(_), Some(every)) => format!(
                "read again when it changes (looked at every {} s) and on SIGHUP (fleet-http)",
                every.as_secs()
            ),
            (From::Command(_), Some(every)) => format!(
                "run again every {} s and on SIGHUP (fleet-http)",
                every.as_secs()
            ),
        };
        format!("{from}{format}; {again}")
    }

    /// The inventory file as it is now. `None` for a command, and for a file that is
    /// not there.
    fn stamp(&self) -> Option<Stamp> {
        let From::File(path) = &self.from else {
            return None;
        };
        let real = std::fs::canonicalize(path).ok()?;
        let meta = std::fs::metadata(&real).ok()?;
        Some(Stamp {
            real,
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.size(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        })
    }

    fn max_bytes(&self) -> usize {
        match self.format {
            InventoryFormat::Opsmcp => MAX_INVENTORY_BYTES,
            InventoryFormat::Ansible => MAX_ANSIBLE_BYTES,
        }
    }

    /// Reads the inventory: the same checks when the server starts and every time
    /// after.
    ///
    /// Reading a file and making sense of the text are done on a thread for blocking
    /// work: what `ansible-inventory` prints can be tens of megabytes, and the calls in
    /// progress should not wait for it.
    async fn read(&self, bins: &Bins) -> Result<Listing, String> {
        let source = self.clone();
        let work = match &self.from {
            From::File(path) => {
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    let (text, format) = read_inventory_file(&path, source.max_bytes())?;
                    source.parse(&text, &path.display().to_string(), format)
                })
            }
            From::Command(command) => {
                let ansible = self.format == InventoryFormat::Ansible;
                let text = run_inventory_command(command, bins, self.max_bytes(), ansible).await?;
                tokio::task::spawn_blocking(move || {
                    source.parse(&text, "fleet.inventory_command", Format::Json)
                })
            }
        };
        work.await.map_err(|problem| {
            log::error!("reading the inventory: {problem}");
            "reading the inventory failed inside the fleet server (see its log)".to_string()
        })?
    }

    /// Makes an inventory of `text`. `at` says where the text is from, for messages.
    fn parse(&self, text: &str, at: &str, format: Format) -> Result<Listing, String> {
        let parsed = match self.format {
            InventoryFormat::Ansible => Inventory::from_ansible(text),
            InventoryFormat::Opsmcp => Inventory::parse(text, format)
                .map(|inventory| (inventory, Vec::new()))
                .map_err(|mut problems| {
                    // The one mistake that is easy to make and hard to read from the
                    // parser's words.
                    if format == Format::Json && text.contains("\"_meta\"") {
                        problems = vec![
                            "this is not opsmcp's own inventory format; if it is what \
                             `ansible-inventory --list` prints, set fleet.inventory_format = \
                             \"ansible\""
                                .to_string(),
                        ];
                    }
                    problems
                }),
        };
        let (inventory, left_out) = parsed.map_err(|problems| {
            let list: Vec<String> = problems.iter().map(|p| format!("{at}: {p}")).collect();
            list.join("\n  - ")
        })?;
        Ok(Listing {
            inventory,
            left_out,
        })
    }
}

/// Reads the inventory file. How it is written is said by its name: `.toml` or `.json`.
fn read_inventory_file(path: &Path, max_bytes: usize) -> Result<(String, Format), String> {
    let shown = path.display();
    let real = std::fs::canonicalize(path).map_err(|e| format!("fleet.inventory {shown}: {e}"))?;
    // It decides which machines credentials are presented to.
    check_trusted_path(&real, &trusted_owners())
        .map_err(|e| format!("refusing to use fleet.inventory {shown}: {e}"))?;
    let size = std::fs::metadata(&real)
        .map_err(|e| format!("fleet.inventory {shown}: {e}"))?
        .len();
    if size > max_bytes as u64 {
        return Err(format!(
            "fleet.inventory {shown}: larger than {max_bytes} bytes"
        ));
    }
    let text =
        std::fs::read_to_string(&real).map_err(|e| format!("fleet.inventory {shown}: {e}"))?;
    let format = match real.extension().and_then(|e| e.to_str()) {
        Some("json") => Format::Json,
        _ => Format::Toml,
    };
    Ok((text, format))
}

/// Runs the inventory command and returns the JSON it prints. `ansible`: it is expected
/// to be (or to run) `ansible-inventory`.
async fn run_inventory_command(
    command: &[String],
    bins: &Bins,
    max_bytes: usize,
    ansible: bool,
) -> Result<String, String> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| "fleet.inventory_command is empty".to_string())?;
    bins.check_program(Path::new(program))
        .map_err(|e| format!("fleet.inventory_command: {e}"))?;
    let mut cmd = Cmd::new(program)
        .args(arguments.iter().cloned())
        .timeout(INVENTORY_COMMAND_LIMIT);
    cmd.max_output = max_bytes;
    cmd.path_env = bins.path_env();
    // What it prints is JSON, which no locale changes, and `ansible-inventory` refuses
    // to start in the plain "C" locale that commands otherwise get here.
    for name in ["LANG", "LC_ALL"] {
        cmd.env.push((name.to_string(), "C.UTF-8".to_string()));
    }
    // AIDEV-NOTE: left to itself, `ansible-inventory` only warns about an inventory
    // source it could not read (a cloud that did not answer) and prints the hosts of
    // the other sources, with exit status 0. That shorter list would take hosts away
    // from a running fleet. With this set it fails instead, and the list in use stays.
    // A wrapper script that wants the old behaviour can unset it.
    if ansible {
        cmd.env.push((
            "ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED".to_string(),
            "1".to_string(),
        ));
    }
    let out = crate::exec::run(cmd)
        .await
        .map_err(|e| format!("fleet.inventory_command: {e}"))?;
    // AIDEV-NOTE: the last line the command wrote to stderr goes into this server's
    // log and audit trail (never to a caller: `fleet_hosts` only says that reading
    // failed). Without it a failing command cannot be diagnosed. It is the operator's
    // own command talking to the operator, cut to one line of 300 characters.
    let said = || {
        let words = crate::sanitize::clean_text(&out.stderr);
        // The last thing it said, past any blank lines after it.
        let line: String = words
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("")
            .chars()
            .take(300)
            .collect();
        if line.is_empty() {
            String::new()
        } else {
            format!(": {line}")
        }
    };
    if out.timed_out {
        return Err(format!(
            "fleet.inventory_command did not finish within {} s",
            INVENTORY_COMMAND_LIMIT.as_secs()
        ));
    }
    if out.code != Some(0) {
        return Err(format!(
            "fleet.inventory_command failed (exit status {}){}",
            out.code.map_or("none".to_string(), |code| code.to_string()),
            said()
        ));
    }
    if out.truncated {
        return Err(format!(
            "fleet.inventory_command printed more than {max_bytes} bytes"
        ));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| "fleet.inventory_command did not print text".to_string())
}

/// What an operator should know about an inventory as read: what in its source could
/// not be used, and what the rules name that it does not have.
fn pointed_out(rules: &AccessRules, listing: &Listing) -> Vec<String> {
    let mut lines: Vec<String> = listing
        .left_out
        .iter()
        .map(|what| format!("left out of the inventory: {what}"))
        .collect();
    for rule in rules.rules() {
        for term in rule.hosts.unmatched(listing.inventory.hosts()) {
            lines.push(format!(
                "fleet.access[{}] ({}): {term:?} matches no host in the inventory",
                rule.index + 1,
                rule.label
            ));
        }
    }
    lines
}

/// Checks a private key that a rule logs in with: a regular file that belongs to a
/// trusted user and that nobody else can read.
fn check_key(path: &Path, at: &str) -> Result<(), String> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{at}.ssh_key {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{at}.ssh_key {shown}: not a regular file"));
    }
    let owners = trusted_owners();
    if meta.uid() != 0 && !owners.contains(&meta.uid()) {
        return Err(format!(
            "{at}.ssh_key {shown}: must be owned by root or by the user opsmcp runs as"
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{at}.ssh_key {shown}: must not be accessible to group or others (chmod 600)"
        ));
    }
    // ssh reads the key again at every login, so it must stay what was checked here:
    // nobody else may be able to replace it.
    check_trusted_path(path, &owners)
        .map_err(|e| format!("refusing to use {at}.ssh_key {shown}: {e}"))
}

/// This machine's name, for what the fleet server calls itself when none is configured.
fn own_name() -> String {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let name: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(64)
        .collect();
    if name.is_empty() {
        "fleet".to_string()
    } else {
        name
    }
}

/// Starts the system's `ssh` for a rule and a host.
pub struct SshDialer {
    program: PathBuf,
    path_env: String,
    ssh: FleetSshCfg,
    connect_timeout_secs: u64,
    max_line: usize,
}

impl Dialer for SshDialer {
    fn dial(&self, rule: &Rule, host: &HostEntry, identity: &DialAs) -> Dialing {
        // AIDEV-NOTE: the key is given exactly when the rule's identity is the fleet's
        // own, and the caller's agent exactly when it is the caller's. A session never
        // has both, and never an agent that belongs to someone other than its caller.
        let (key, agent) = match identity {
            DialAs::Fleet => match &rule.ssh_key {
                Some(key) => (Some(key.clone()), None),
                None => {
                    let label = rule.label.clone();
                    return Box::pin(async move {
                        Err(format!("the rule {label} names no key to log in with"))
                    });
                }
            },
            DialAs::Caller { agent, .. } => (None, agent.clone()),
        };
        let target = SshTarget {
            address: host.address.clone(),
            port: host.ssh_port,
            user: rule.ssh_user.clone(),
            key,
        };
        let mut cmd =
            Cmd::new(&self.program).args(ssh_args(&self.ssh, self.connect_timeout_secs, &target));
        cmd.path_env = self.path_env.clone();
        if let Some(agent) = agent {
            cmd.env.push((
                "SSH_AUTH_SOCK".to_string(),
                agent.to_string_lossy().into_owned(),
            ));
        }
        let max_line = self.max_line;
        let handshake = Duration::from_secs(self.connect_timeout_secs) + LOGIN_ALLOWANCE;
        Box::pin(async move { HostLink::open(&cmd, max_line, handshake).await })
    }
}

/// For a fleet none of whose rules use SSH.
struct NoSsh;

impl Dialer for NoSsh {
    fn dial(&self, _rule: &Rule, _host: &HostEntry, _identity: &DialAs) -> Dialing {
        Box::pin(async { Err("this fleet server was started without ssh".to_string()) })
    }
}

/// The caller's agent socket from the environment, if it is one: an absolute path.
pub fn agent_socket(value: Option<&str>) -> Option<PathBuf> {
    let value = value?;
    let usable =
        value.starts_with('/') && value.len() <= 4096 && !value.chars().any(char::is_control);
    usable.then(|| PathBuf::from(value))
}

/// The largest message accepted from a host: a result of the largest size the fleet
/// itself returns, with room for how JSON writes it.
fn max_line(cfg: &Config) -> usize {
    cfg.limits
        .max_output_bytes
        .saturating_mul(8)
        .saturating_add(64 * 1024)
        .max(1 << 20)
}

/// Reads the inventory and the credentials, and finds `ssh`.
pub async fn prepare(cfg: &Config, bins: &Bins) -> Result<Prepared, String> {
    let fleet: &FleetCfg = cfg
        .fleet
        .as_ref()
        .ok_or_else(|| "the configuration has no [fleet] section".to_string())?;
    let source = Source::of(fleet)?;
    // Taken before the file is read, so that a change made while it is being read is
    // seen at the next look.
    let stamp = source.stamp();
    let listing = source.read(bins).await?;
    let rules = AccessRules::compile(fleet)?;

    let pointed_out = pointed_out(&rules, &listing);
    let inventory = listing.inventory;
    let mut warnings = pointed_out.clone();
    let mut tokens = HashMap::new();
    for rule in rules.rules() {
        let at = format!("fleet.access[{}]", rule.index + 1);
        if rule.identity != IdentityMode::Fleet {
            continue;
        }
        match rule.via {
            Via::Ssh => {
                if let Some(key) = &rule.ssh_key {
                    check_key(key, &at)?;
                }
            }
            Via::Https => {
                if let Some(file) = &rule.token_file {
                    let what = format!("the token of {at}");
                    tokens.insert(rule.index, read_secret_file(file, &what)?);
                }
            }
        }
    }

    // AIDEV-NOTE: a rule that passes a caller's own token on hands that token to every
    // host it covers, and a bearer token is good wherever it alone is enough. A host
    // that receives one (a compromised host, say) could then use it on the other hosts,
    // and on this server as that caller. Two things close that. The hosts requiring
    // this server's certificate as well (`auth = "mtls+token"` there): the
    // configuration cannot be loaded without that certificate (`validate_fleet`), but
    // whether the hosts ask for it cannot be seen from here. And this server requiring
    // a certificate of its own callers, whose absence is pointed out here.
    let passes_tokens = rules
        .rules()
        .iter()
        .any(|rule| rule.via == Via::Https && rule.identity == IdentityMode::Caller);
    if passes_tokens
        && let Some(http) = &cfg.http
        && !matches!(http.auth, AuthMode::MtlsAndToken | AuthMode::Mtls)
    {
        warnings.push(format!(
            "[http] auth = \"{}\" lets a bearer token alone in, and callers' tokens are \
             passed on to hosts: a host that is sent a token could present it here as that \
             caller. `auth = \"mtls+token\"` here keeps a token from being enough by itself",
            http.auth.as_str()
        ));
    }

    let uses = |via: Via| rules.rules().iter().any(|rule| rule.via == via);
    let dialer: Arc<dyn Dialer> = if uses(Via::Ssh) {
        Arc::new(SshDialer {
            program: bins.find("ssh")?,
            path_env: bins.path_env(),
            ssh: fleet.ssh.clone(),
            connect_timeout_secs: fleet.connect_timeout_secs,
            max_line: max_line(cfg),
        })
    } else {
        Arc::new(NoSsh)
    };
    let https = if uses(Via::Https) {
        let bundles: Vec<PathBuf> = CA_BUNDLES.iter().map(PathBuf::from).collect();
        Some(HttpsClient::new(
            &fleet.https,
            &bundles,
            Duration::from_secs(fleet.connect_timeout_secs),
            max_line(cfg),
        )?)
    } else {
        None
    };

    Ok(Prepared {
        inventory,
        source,
        stamp,
        pointed_out,
        rules,
        name: fleet.name.clone().unwrap_or_else(own_name),
        dialer,
        https,
        tokens,
        warnings,
    })
}

/// Checks that the tools this server passes on leave room for its own argument and its
/// own tools.
pub fn check_registry(registry: &Registry) -> Result<(), String> {
    for tool in registry.tools() {
        if tool.name.starts_with("fleet_") {
            return Err(format!(
                "the tool {} has a name reserved for the fleet server's own tools",
                tool.name
            ));
        }
        if tool.params.iter().any(|param| param.name == HOST_ARG) {
            return Err(format!(
                "the tool {} has an argument called {HOST_ARG}, which the fleet server uses \
                 to name the host",
                tool.name
            ));
        }
    }
    Ok(())
}

/// What a look at where the inventory comes from came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Looked {
    /// The file is as it was when it was last read: it was not read.
    Untouched,
    /// It was read, and lists what is in use.
    Same,
    /// It was read and is in use now.
    Replaced(Changes),
    /// It could not be read, or could not be put in use. What was in use still is.
    Failed(String),
}

/// Keeps the inventory of a running fleet server current: looks at where it comes from
/// every so often and when asked, and puts what it finds in use.
///
/// AIDEV-NOTE: reading again is held to exactly what reading at the start is (the same
/// `Source::read`: a file only root or the server's user controls, a command that is a
/// trusted program), and an inventory that cannot be read, is not valid or lists no
/// host NEVER replaces the one in use. A fleet that loses its hosts because a list
/// could not be fetched for a moment would be worse than one that is a little behind.
pub struct Refresher {
    fleet: Arc<Fleet>,
    source: Source,
    /// The inventory file as it was when it was last read.
    stamp: Option<Stamp>,
    /// Why the last look failed, if it did, so that a failure is reported once and not
    /// at every look.
    failing: Option<String>,
    /// What was last pointed out about the inventory, for the same reason.
    pointed_out: Vec<String>,
}

impl Refresher {
    /// Looks once. `asked`: someone asked for it (SIGHUP), so a file is read even if
    /// it looks untouched.
    pub async fn look(&mut self, asked: bool) -> Looked {
        let stamp = self.source.stamp();
        let is_file = matches!(self.source.from, From::File(_));
        // AIDEV-NOTE: a file is left unread only while it is the file that was last
        // read AND put in use, not written to since. After a failure it is read at
        // every look: what kept a list from coming into use need not be in the file
        // (the audit trail could not be written, a directory above it had the wrong
        // mode), so the file staying as it is says nothing about whether it would
        // work now. A failure is still reported once (`failing`).
        let in_use = self.failing.is_none() && stamp.is_some() && stamp == self.stamp;
        if is_file && !asked && in_use {
            return Looked::Untouched;
        }
        self.stamp = stamp;
        let read = self.source.read(&self.fleet.parts.host.bins).await;
        let outcome = read.and_then(|listing| {
            let pointed_out = pointed_out(&self.fleet.parts.rules, &listing);
            let changes = self.fleet.replace_inventory(listing.inventory)?;
            Ok((changes, pointed_out))
        });
        match outcome {
            Ok((changes, pointed_out)) => {
                if self.failing.take().is_some() {
                    log::info!("the inventory can be read again");
                }
                if !changes.is_empty() {
                    log::info!(
                        "the inventory changed: {} hosts now ({} added, {} removed, {} at \
                         another address, {} in other groups)",
                        self.fleet.inventory().len(),
                        changes.added.len(),
                        changes.removed.len(),
                        changes.moved.len(),
                        changes.regrouped.len()
                    );
                }
                for line in &pointed_out {
                    if !self.pointed_out.contains(line) {
                        log::warn!("{line}");
                    }
                }
                self.pointed_out = pointed_out;
                if changes.is_empty() {
                    Looked::Same
                } else {
                    Looked::Replaced(changes)
                }
            }
            Err(why) => {
                if self.failing.as_deref() != Some(why.as_str()) {
                    log::warn!(
                        "the inventory could not be read again; the hosts known so far stay \
                         in use: {why}"
                    );
                    self.fleet.inventory_not_read(&why);
                    self.failing = Some(why.clone());
                }
                Looked::Failed(why)
            }
        }
    }

    /// Looks every so often, and at once whenever `asked` is notified. Never returns.
    pub async fn run(mut self, asked: Arc<tokio::sync::Notify>) {
        loop {
            let was_asked = match self.source.every() {
                Some(every) => tokio::select! {
                    () = tokio::time::sleep(every) => false,
                    () = asked.notified() => true,
                },
                None => {
                    asked.notified().await;
                    true
                }
            };
            self.look(was_asked).await;
        }
    }
}

/// The fleet server, from what `prepare` read, and what keeps its inventory current.
pub fn assemble(
    host: Arc<Host>,
    registry: Registry,
    prepared: Prepared,
) -> (Arc<Fleet>, Refresher) {
    let source = prepared.source.clone();
    let stamp = prepared.stamp.clone();
    let pointed_out = prepared.pointed_out.clone();
    let fleet = assemble_fleet(host, registry, prepared);
    let refresher = Refresher {
        fleet: fleet.clone(),
        source,
        stamp,
        failing: None,
        pointed_out,
    };
    (fleet, refresher)
}

fn assemble_fleet(host: Arc<Host>, registry: Registry, prepared: Prepared) -> Arc<Fleet> {
    Fleet::assemble(
        Parts {
            host,
            registry,
            rules: prepared.rules,
            name: prepared.name,
            dialer: prepared.dialer,
            https: prepared.https,
            tokens: prepared.tokens,
        },
        prepared.inventory,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::write_executable;
    use std::os::unix::fs::PermissionsExt;

    struct Dir {
        dir: tempfile::TempDir,
    }

    impl Dir {
        fn new() -> Dir {
            Dir {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn path(&self, name: &str) -> String {
            self.dir.path().join(name).display().to_string()
        }

        fn write(&self, name: &str, content: &str, mode: u32) -> String {
            let path = self.dir.path().join(name);
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path.display().to_string()
        }

        /// A configuration with one rule; `fleet` and `rule` are extra lines.
        fn config(&self, fleet: &str, rule: &str) -> Config {
            let text = format!(
                "[roles.ops]\nallow = [\"@all\"]\n[paths.bin]\nssh = \"{}\"\n[fleet]\n{fleet}\n\
                 [[fleet.access]]\nroles = [\"ops\"]\n{rule}\n",
                self.path("ssh")
            );
            Config::parse(&text).unwrap_or_else(|e| panic!("{e:?}\n{text}"))
        }
    }

    const OWN: &str = "hosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"caller\"";
    const HOSTS: &str = "[groups]\nweb = [\"web1\", \"web2\"]\n";

    async fn prepared(cfg: &Config) -> Result<Prepared, String> {
        let bins = Bins::new(&cfg.paths, None);
        prepare(cfg, &bins).await
    }

    fn with_ssh() -> Dir {
        let dir = Dir::new();
        write_executable(&dir.dir.path().join("ssh"), "#!/bin/sh\nexit 255\n");
        dir
    }

    #[tokio::test]
    async fn the_inventory_is_read_from_a_toml_or_a_json_file() {
        let dir = with_ssh();
        let toml = dir.write("hosts.toml", HOSTS, 0o644);
        let cfg = dir.config(&format!("inventory = \"{toml}\"\nname = \"bastion1\""), OWN);
        let ready = prepared(&cfg).await.unwrap();
        assert_eq!(ready.inventory.len(), 2);
        assert_eq!(ready.name, "bastion1");
        assert!(ready.warnings.is_empty(), "{:?}", ready.warnings);
        assert!(ready.https.is_none() && ready.tokens.is_empty());

        let json = dir.write("hosts.json", r#"{"groups": {"db": ["db1"]}}"#, 0o644);
        let cfg = dir.config(&format!("inventory = \"{json}\""), OWN);
        let ready = prepared(&cfg).await.unwrap();
        assert!(ready.inventory.get("db1").is_some());
        // with no name configured, this machine's own
        assert!(!ready.name.is_empty());
    }

    #[tokio::test]
    async fn an_inventory_that_is_missing_wrong_or_writable_by_others_stops_the_server() {
        let dir = with_ssh();
        let cfg = dir.config(&format!("inventory = \"{}\"", dir.path("nope.toml")), OWN);
        assert!(prepared(&cfg).await.err().unwrap().contains("nope.toml"));

        let bad = dir.write("bad.toml", "[hosts.\"web 1\"]\n", 0o644);
        let cfg = dir.config(&format!("inventory = \"{bad}\""), OWN);
        assert!(prepared(&cfg).await.err().unwrap().contains("web 1"));

        let open = dir.write("open.toml", HOSTS, 0o666);
        let cfg = dir.config(&format!("inventory = \"{open}\""), OWN);
        let error = prepared(&cfg).await.err().unwrap();
        assert!(error.contains("writable"), "{error}");
    }

    #[tokio::test]
    async fn the_inventory_can_come_from_a_command() {
        let dir = with_ssh();
        let lister = dir.dir.path().join("list-hosts");
        write_executable(
            &lister,
            "#!/bin/sh\necho '{\"hosts\": {\"web1\": {\"address\": \"10.0.0.5\"}}, \"groups\": {\"web\": [\"web1\", \"'\"$1\"'\"]}}'\n",
        );
        let cfg = dir.config(
            &format!("inventory_command = [\"{}\", \"web2\"]", lister.display()),
            OWN,
        );
        let ready = prepared(&cfg).await.unwrap();
        assert_eq!(ready.inventory.len(), 2);
        assert_eq!(ready.inventory.get("web1").unwrap().address, "10.0.0.5");
        assert!(ready.inventory.get("web2").unwrap().groups.contains("web"));
    }

    #[tokio::test]
    async fn an_inventory_command_that_fails_stops_the_server_and_says_why() {
        let dir = with_ssh();
        let lister = dir.dir.path().join("list-hosts");
        write_executable(
            &lister,
            "#!/bin/sh\necho 'cannot reach the CMDB' >&2\nexit 3\n",
        );
        let cfg = dir.config(
            &format!("inventory_command = [\"{}\"]", lister.display()),
            OWN,
        );
        let error = prepared(&cfg).await.err().unwrap();
        assert!(
            error.contains("status 3") && error.contains("cannot reach the CMDB"),
            "{error}"
        );

        write_executable(&lister, "#!/bin/sh\necho 'not json'\n");
        let error = prepared(&cfg).await.err().unwrap();
        assert!(error.contains("fleet.inventory_command"), "{error}");

        let cfg = dir.config("inventory_command = [\"/nonexistent/list-hosts\"]", OWN);
        assert!(prepared(&cfg).await.is_err());
    }

    // ---- an Ansible inventory ----

    const ANSIBLE: &str = r#"{
        "_meta": {"hostvars": {
            "web1": {"ansible_host": "10.0.0.11", "ansible_port": 2222, "db_password": "hunter2"},
            "web_3": {}
        }},
        "all": {"children": ["ungrouped", "web"]},
        "web": {"hosts": ["web1", "web2", "web_3"]}
    }"#;

    #[tokio::test]
    async fn an_ansible_inventory_is_read_from_a_saved_file() {
        let dir = with_ssh();
        let saved = dir.write("hosts.json", ANSIBLE, 0o644);
        let cfg = dir.config(
            &format!("inventory = \"{saved}\"\ninventory_format = \"ansible\""),
            OWN,
        );
        let ready = prepared(&cfg).await.unwrap();
        assert_eq!(ready.inventory.len(), 2);
        let web1 = ready.inventory.get("web1").unwrap();
        assert_eq!(
            (web1.address.as_str(), web1.ssh_port),
            ("10.0.0.11", Some(2222))
        );
        assert!(ready.inventory.get("web2").unwrap().groups.contains("web"));
        // what could not be used is pointed out, and does not stop the server
        assert_eq!(ready.warnings.len(), 1, "{:?}", ready.warnings);
        assert!(
            ready.warnings[0].contains("web_3") && ready.warnings[0].contains("left out"),
            "{:?}",
            ready.warnings
        );
    }

    #[tokio::test]
    async fn an_ansible_inventory_is_read_from_a_command() {
        let dir = with_ssh();
        let data = dir.write("ansible.json", ANSIBLE, 0o644);
        let lister = dir.dir.path().join("fleet-hosts");
        write_executable(&lister, &format!("#!/bin/sh\nexec cat {data}\n"));
        let cfg = dir.config(
            &format!(
                "inventory_command = [\"{}\"]\ninventory_format = \"ansible\"",
                lister.display()
            ),
            OWN,
        );
        let ready = prepared(&cfg).await.unwrap();
        assert_eq!(ready.inventory.len(), 2);
        assert_eq!(ready.inventory.get("web1").unwrap().address, "10.0.0.11");
    }

    #[tokio::test]
    async fn an_inventory_command_runs_with_a_utf8_locale() {
        // `ansible-inventory` refuses to run in the plain "C" locale that tools get, so
        // it could not be named as the command without a wrapper around it.
        let dir = with_ssh();
        let lister = dir.dir.path().join("list-hosts");
        write_executable(
            &lister,
            "#!/bin/sh\n[ \"$LC_ALL\" = C.UTF-8 ] || { echo \"locale is $LC_ALL\" >&2; exit 9; }\n\
             echo '{\"groups\": {\"web\": [\"web1\"]}}'\n",
        );
        let cfg = dir.config(
            &format!("inventory_command = [\"{}\"]", lister.display()),
            OWN,
        );
        let ready = prepared(&cfg).await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(ready.inventory.len(), 1);
    }

    #[tokio::test]
    async fn ansible_is_told_that_a_source_it_cannot_read_is_a_failure() {
        // AIDEV-NOTE: left to itself, `ansible-inventory` warns about an inventory
        // source it could not read (a cloud that did not answer, say) and prints the
        // hosts of the others, with exit status 0. Read again while the server runs,
        // that shorter list would take hosts away from the fleet. With this variable
        // set it fails instead, and the list in use stays.
        let dir = with_ssh();
        let lister = dir.dir.path().join("fleet-hosts");
        write_executable(
            &lister,
            "#!/bin/sh\necho \"{\\\"all\\\": {\\\"hosts\\\": [\\\"strict${ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED}\\\"]}}\"\n",
        );
        let command = format!("inventory_command = [\"{}\"]", lister.display());
        let cfg = dir.config(&format!("{command}\ninventory_format = \"ansible\""), OWN);
        let ready = prepared(&cfg).await.unwrap_or_else(|e| panic!("{e}"));
        assert!(ready.inventory.get("strict1").is_some());
    }

    #[tokio::test]
    async fn what_a_failed_inventory_command_said_last_is_shown_past_blank_lines() {
        let dir = with_ssh();
        let lister = dir.dir.path().join("list-hosts");
        write_executable(
            &lister,
            "#!/bin/sh\nprintf 'a warning\\nERROR: no such inventory\\n\\n  \\n' >&2\nexit 1\n",
        );
        let cfg = dir.config(
            &format!("inventory_command = [\"{}\"]", lister.display()),
            OWN,
        );
        let error = prepared(&cfg).await.err().unwrap();
        assert!(error.contains("ERROR: no such inventory"), "{error}");
    }

    #[tokio::test]
    async fn an_ansible_inventory_that_is_not_one_stops_the_server() {
        let dir = with_ssh();
        let own = dir.write("hosts.json", r#"{"groups": {"web": ["web1"]}}"#, 0o644);
        let cfg = dir.config(
            &format!("inventory = \"{own}\"\ninventory_format = \"ansible\""),
            OWN,
        );
        let error = prepared(&cfg).await.err().unwrap();
        assert!(
            error.contains("hosts.json") && error.contains("ansible-inventory --list"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn what_ansible_prints_given_as_opsmcps_own_format_gets_a_pointer() {
        let dir = with_ssh();
        let saved = dir.write("hosts.json", ANSIBLE, 0o644);
        let cfg = dir.config(&format!("inventory = \"{saved}\""), OWN);
        let error = prepared(&cfg).await.err().unwrap();
        assert!(error.contains("inventory_format = \"ansible\""), "{error}");
        // and none of what the file holds besides
        assert!(!error.contains("hunter2"), "{error}");
    }

    // ---- reading the inventory again while the server runs ----

    /// A fleet server made the way `main` makes one, with what keeps its inventory
    /// current.
    async fn running(dir: &Dir, fleet: &str, rule: &str) -> (Arc<Fleet>, Refresher, MemorySink) {
        let text = format!(
            "[roles.ops]\nallow = [\"@all\"]\n[paths.bin]\nssh = \"{}\"\n[fleet]\n{fleet}\n\
             [[fleet.access]]\nroles = [\"ops\"]\n{rule}\n",
            dir.path("ssh")
        );
        let (host, audit) = crate::tools::testing::host(&text);
        let ready = prepare(&host.cfg, &host.bins)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let (registry, _) = Registry::build(&host.cfg).unwrap();
        let (fleet, refresher) = assemble(host, registry, ready);
        (fleet, refresher, audit)
    }

    fn names(fleet: &Fleet) -> Vec<String> {
        fleet.inventory().hosts().map(|h| h.name.clone()).collect()
    }

    fn inventory_records(audit: &MemorySink) -> Vec<serde_json::Value> {
        audit
            .records()
            .into_iter()
            .filter(|r| r["event"] == "fleet_inventory")
            .collect()
    }

    const MORE_HOSTS: &str = "[groups]\nweb = [\"web1\", \"web2\", \"web3\"]\n";

    #[tokio::test]
    async fn a_changed_inventory_file_is_read_again_and_an_untouched_one_is_not() {
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let (fleet, mut refresher, audit) =
            running(&dir, &format!("inventory = \"{file}\""), OWN).await;
        assert_eq!(names(&fleet), ["web1", "web2"]);
        assert_eq!(refresher.look(false).await, Looked::Untouched);

        dir.write("hosts.toml", MORE_HOSTS, 0o644);
        let Looked::Replaced(changes) = refresher.look(false).await else {
            panic!("the changed file was not read");
        };
        assert_eq!(changes.added, ["web3"]);
        assert_eq!(names(&fleet), ["web1", "web2", "web3"]);
        assert_eq!(inventory_records(&audit).len(), 1);

        assert_eq!(refresher.look(false).await, Looked::Untouched);
        // asked to (SIGHUP), it is read even though it looks untouched
        assert_eq!(refresher.look(true).await, Looked::Same);
        assert_eq!(inventory_records(&audit).len(), 1);
    }

    #[tokio::test]
    async fn a_file_put_in_place_of_the_inventory_is_noticed() {
        // as a deployment does it: written beside the file, then renamed over it
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let (fleet, mut refresher, _audit) =
            running(&dir, &format!("inventory = \"{file}\""), OWN).await;
        // the same size as before, to the byte
        let swapped = HOSTS.replace("web2", "web9");
        let beside = dir.write("hosts.toml.new", &swapped, 0o644);
        std::fs::rename(beside, &file).unwrap();
        assert!(matches!(refresher.look(false).await, Looked::Replaced(_)));
        assert_eq!(names(&fleet), ["web1", "web9"]);
    }

    #[tokio::test]
    async fn an_inventory_that_cannot_be_read_again_leaves_the_hosts_known_in_use() {
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let (fleet, mut refresher, audit) =
            running(&dir, &format!("inventory = \"{file}\""), OWN).await;

        dir.write("hosts.toml", "[hosts.\"web 1\"]\n", 0o644);
        let Looked::Failed(why) = refresher.look(false).await else {
            panic!("a broken inventory was accepted");
        };
        assert!(why.contains("web 1"), "{why}");
        assert_eq!(names(&fleet), ["web1", "web2"]);
        let failed = |audit: &MemorySink| {
            inventory_records(audit)
                .iter()
                .filter(|r| r["outcome"] == "failed")
                .count()
        };
        assert_eq!(failed(&audit), 1);
        // It is tried again at every look, and said once: not again while it keeps
        // failing the same way, whether the look was asked for or not.
        assert!(matches!(refresher.look(false).await, Looked::Failed(_)));
        assert!(matches!(refresher.look(true).await, Looked::Failed(_)));
        assert_eq!(failed(&audit), 1);

        // one that others could have written is not read either
        dir.write("hosts.toml", MORE_HOSTS, 0o666);
        let Looked::Failed(why) = refresher.look(false).await else {
            panic!("an inventory that anyone can write was accepted");
        };
        assert!(why.contains("writable"), "{why}");
        assert_eq!(names(&fleet), ["web1", "web2"]);
        assert_eq!(failed(&audit), 2);

        // gone altogether
        std::fs::remove_file(&file).unwrap();
        assert!(matches!(refresher.look(false).await, Looked::Failed(_)));
        assert!(matches!(refresher.look(false).await, Looked::Failed(_)));
        assert_eq!(names(&fleet), ["web1", "web2"]);
        assert_eq!(failed(&audit), 3);

        // and back, in order: it is read, and that it can be read again is on record
        dir.write("hosts.toml", MORE_HOSTS, 0o644);
        assert!(matches!(refresher.look(false).await, Looked::Replaced(_)));
        assert_eq!(names(&fleet), ["web1", "web2", "web3"]);
        assert_eq!(
            inventory_records(&audit).pop().unwrap()["outcome"],
            "replaced"
        );
    }

    #[tokio::test]
    async fn a_change_that_could_not_be_put_in_use_is_tried_again_at_the_next_look() {
        // AIDEV-NOTE: what keeps a new list from being used is not always in the file:
        // here the audit trail cannot be written for a moment. The file is not touched
        // again afterwards, and the list must still come into use.
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let (fleet, mut refresher, audit) =
            running(&dir, &format!("inventory = \"{file}\""), OWN).await;
        audit.set_failing(true);
        dir.write("hosts.toml", MORE_HOSTS, 0o644);
        let Looked::Failed(why) = refresher.look(false).await else {
            panic!("a change was put in use without a record of it");
        };
        assert!(why.contains("audit"), "{why}");
        assert_eq!(names(&fleet).len(), 2);

        audit.set_failing(false);
        assert!(matches!(refresher.look(false).await, Looked::Replaced(_)));
        assert_eq!(names(&fleet).len(), 3);
        assert_eq!(refresher.look(false).await, Looked::Untouched);
    }

    #[tokio::test]
    async fn a_file_rewritten_with_its_old_size_and_time_is_still_noticed() {
        // Some tools that copy a file put its old modification time back.
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let written = std::fs::metadata(&file).unwrap().modified().unwrap();
        let (fleet, mut refresher, _audit) =
            running(&dir, &format!("inventory = \"{file}\""), OWN).await;
        // long enough for the file system's clock to have moved on
        std::thread::sleep(Duration::from_millis(30));
        dir.write("hosts.toml", &HOSTS.replace("web2", "web9"), 0o644);
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(written)
            .unwrap();
        let now = std::fs::metadata(&file).unwrap();
        assert_eq!(
            (now.modified().unwrap(), now.len()),
            (written, HOSTS.len() as u64)
        );
        assert!(matches!(refresher.look(false).await, Looked::Replaced(_)));
        assert_eq!(names(&fleet), ["web1", "web9"]);
    }

    #[tokio::test]
    async fn an_inventory_command_is_run_again_at_every_look() {
        let dir = with_ssh();
        let data = dir.write("hosts.json", r#"{"groups": {"web": ["web1"]}}"#, 0o644);
        let lister = dir.dir.path().join("list-hosts");
        write_executable(&lister, &format!("#!/bin/sh\nexec cat {data}\n"));
        let (fleet, mut refresher, _audit) = running(
            &dir,
            &format!("inventory_command = [\"{}\"]", lister.display()),
            OWN,
        )
        .await;
        assert_eq!(names(&fleet), ["web1"]);
        assert_eq!(refresher.look(false).await, Looked::Same);

        dir.write(
            "hosts.json",
            r#"{"groups": {"web": ["web1", "web2"]}}"#,
            0o644,
        );
        assert!(matches!(refresher.look(false).await, Looked::Replaced(_)));
        assert_eq!(names(&fleet), ["web1", "web2"]);

        // the command fails: what it listed before stays
        write_executable(
            &lister,
            "#!/bin/sh\necho 'cannot reach the CMDB' >&2\nexit 3\n",
        );
        let Looked::Failed(why) = refresher.look(false).await else {
            panic!("a failed command was accepted");
        };
        assert!(why.contains("cannot reach the CMDB"), "{why}");
        // a command that suddenly lists nothing is a failure too, not an empty fleet
        write_executable(&lister, "#!/bin/sh\necho '{}'\n");
        assert!(matches!(refresher.look(false).await, Looked::Failed(_)));
        assert_eq!(names(&fleet), ["web1", "web2"]);
    }

    #[tokio::test]
    async fn what_a_rule_names_that_a_new_inventory_lacks_is_pointed_out() {
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let rule = "hosts = [\"group:web\"]\nvia = \"ssh\"\nidentity = \"caller\"";
        let (_fleet, mut refresher, _audit) =
            running(&dir, &format!("inventory = \"{file}\""), rule).await;
        assert_eq!(refresher.pointed_out, Vec::<String>::new());
        dir.write("hosts.toml", "[groups]\ndb = [\"db1\"]\n", 0o644);
        assert!(matches!(refresher.look(false).await, Looked::Replaced(_)));
        assert_eq!(
            refresher.pointed_out.len(),
            1,
            "{:?}",
            refresher.pointed_out
        );
        assert!(refresher.pointed_out[0].contains("group:web"));
    }

    #[tokio::test]
    async fn how_often_the_inventory_is_looked_at_depends_on_where_it_comes_from() {
        let dir = with_ssh();
        let every = |fleet: &str| {
            let cfg = dir.config(fleet, OWN);
            Source::of(cfg.fleet.as_ref().unwrap()).unwrap().every()
        };
        // a file costs a look at its timestamp; a command is run
        assert_eq!(
            every("inventory = \"/etc/hosts.toml\""),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            every("inventory_command = [\"/usr/bin/list\"]"),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            every("inventory = \"/etc/hosts.toml\"\ninventory_refresh_secs = 5"),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            every("inventory_command = [\"/usr/bin/list\"]\ninventory_refresh_secs = 0"),
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_inventory_is_looked_at_again_in_time_and_at_once_when_asked() {
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let (fleet, refresher, _audit) =
            running(&dir, &format!("inventory = \"{file}\""), OWN).await;
        let asked = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(refresher.run(asked.clone()));

        dir.write("hosts.toml", MORE_HOSTS, 0o644);
        tokio::time::sleep(Duration::from_secs(29)).await;
        assert_eq!(names(&fleet).len(), 2);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(names(&fleet).len(), 3);

        // asked (SIGHUP): no waiting for the next look
        dir.write("hosts.toml", HOSTS, 0o644);
        asked.notify_one();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(names(&fleet).len(), 2);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn an_inventory_that_is_never_looked_at_again_is_still_read_when_asked() {
        let dir = with_ssh();
        let file = dir.write("hosts.toml", HOSTS, 0o644);
        let (fleet, refresher, _audit) = running(
            &dir,
            &format!("inventory = \"{file}\"\ninventory_refresh_secs = 0"),
            OWN,
        )
        .await;
        let asked = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(refresher.run(asked.clone()));
        dir.write("hosts.toml", MORE_HOSTS, 0o644);
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(names(&fleet).len(), 2);
        asked.notify_one();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(names(&fleet).len(), 3);
        task.abort();
    }

    #[tokio::test]
    async fn hosts_a_rule_names_that_the_inventory_lacks_are_pointed_out() {
        let dir = with_ssh();
        let toml = dir.write("hosts.toml", HOSTS, 0o644);
        let rule = "hosts = [\"group:web\", \"group:cache\", \"db*\"]\nvia = \"ssh\"\nidentity = \"caller\"";
        let cfg = dir.config(&format!("inventory = \"{toml}\""), rule);
        let ready = prepared(&cfg).await.unwrap();
        assert_eq!(ready.warnings.len(), 2, "{:?}", ready.warnings);
        assert!(
            ready.warnings[0].contains("group:cache")
                && ready.warnings[0].contains("matches no host")
        );
        assert!(ready.warnings[1].contains("db*"));
    }

    #[tokio::test]
    async fn a_key_of_the_fleets_own_must_exist_and_be_closed_to_others() {
        let dir = with_ssh();
        let toml = dir.write("hosts.toml", HOSTS, 0o644);
        let rule = |key: &str| {
            format!(
                "hosts = [\"*\"]\nvia = \"ssh\"\nidentity = \"fleet\"\nssh_user = \"fleet\"\nssh_key = \"{key}\""
            )
        };
        let inventory = format!("inventory = \"{toml}\"");
        let cfg = dir.config(&inventory, &rule(&dir.path("missing_key")));
        assert!(prepared(&cfg).await.err().unwrap().contains("missing_key"));
        for mode in [0o644, 0o640, 0o604] {
            let key = dir.write("key", "k\n", mode);
            let error = prepared(&dir.config(&inventory, &rule(&key)))
                .await
                .err()
                .unwrap();
            assert!(
                error.contains("chmod 600") && error.contains("ssh_key"),
                "{error}"
            );
        }
        let key = dir.write("key", "k\n", 0o600);
        assert!(prepared(&dir.config(&inventory, &rule(&key))).await.is_ok());
        // a directory is not a key
        let error = prepared(&dir.config(&inventory, &rule(&dir.path(""))))
            .await
            .err()
            .unwrap();
        assert!(error.contains("not a regular file"), "{error}");
    }

    #[tokio::test]
    async fn a_token_of_the_fleets_own_is_read_and_never_shown() {
        let dir = Dir::new();
        let toml = dir.write("hosts.toml", HOSTS, 0o644);
        let ca = crate::http::testing::authority("ca");
        let ca_file = dir.write("ca.pem", &ca.cert.pem(), 0o644);
        let inventory = format!("inventory = \"{toml}\"");
        let rule = |token: &str| {
            format!(
                "hosts = [\"*\"]\nvia = \"https\"\nidentity = \"fleet\"\ntoken_file = \"{token}\""
            )
        };
        crate::http::testing::issue(
            dir.dir.path(),
            &ca,
            "fleet",
            &[],
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        );
        let certificate = format!(
            "client_cert = \"{}\"\nclient_key = \"{}\"",
            dir.path("fleet.pem"),
            dir.path("fleet.key")
        );
        let build = |token: &str| {
            let text = format!(
                "[roles.ops]\nallow = [\"@all\"]\n[fleet]\n{inventory}\n[fleet.https]\nca = \"{ca_file}\"\n\
                 {certificate}\n[[fleet.access]]\nroles = [\"ops\"]\n{}\n",
                rule(token)
            );
            Config::parse(&text).unwrap()
        };
        let token = dir.write("token", "opsmcp_the_fleets_token\n", 0o600);
        let ready = prepared(&build(&token)).await.unwrap();
        assert_eq!(
            ready.tokens.get(&0).unwrap().expose(),
            "opsmcp_the_fleets_token"
        );
        assert!(ready.https.is_some());

        let open = dir.write("open-token", "opsmcp_the_fleets_token\n", 0o644);
        let error = prepared(&build(&open)).await.err().unwrap();
        assert!(
            error.contains("chmod 600") && error.contains("fleet.access[1]"),
            "{error}"
        );
        assert!(!error.contains("the_fleets_token"), "{error}");
        assert!(prepared(&build(&dir.path("no-token"))).await.is_err());
    }

    #[tokio::test]
    async fn passing_tokens_on_while_a_token_alone_gets_in_here_is_pointed_out() {
        let dir = Dir::new();
        let toml = dir.write("hosts.toml", HOSTS, 0o644);
        let ca = crate::http::testing::authority("ca");
        dir.write("ca.pem", &ca.cert.pem(), 0o644);
        crate::http::testing::issue(
            dir.dir.path(),
            &ca,
            "fleet",
            &[],
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        );
        // The certificate for the hosts to insist on is there: the configuration is
        // not accepted without it.
        let build = |front: &str| {
            let text = format!(
                "[roles.ops]\nallow = [\"@all\"]\n{front}\n[fleet]\ninventory = \"{toml}\"\n\
                 [fleet.https]\nca = \"{}\"\nclient_cert = \"{}\"\nclient_key = \"{}\"\n\
                 [[fleet.access]]\nname = \"own-token\"\nroles = [\"ops\"]\nhosts = [\"*\"]\n\
                 via = \"https\"\nidentity = \"caller\"\n",
                dir.path("ca.pem"),
                dir.path("fleet.pem"),
                dir.path("fleet.key")
            );
            Config::parse(&text).unwrap_or_else(|e| panic!("{e:?}"))
        };
        let front = |auth: &str| {
            format!(
                "[http]\nlisten = \"127.0.0.1:0\"\ntls_cert = \"/c\"\ntls_key = \"/k\"\n\
                 client_ca = \"/ca\"\nauth = \"{auth}\"\n"
            )
        };
        // a token alone gets in here: a host that is sent one could present it here
        let ready = prepared(&build(&front("token"))).await.unwrap();
        assert_eq!(ready.warnings.len(), 1, "{:?}", ready.warnings);
        assert!(ready.warnings[0].contains("[http]") && ready.warnings[0].contains("mtls+token"));
        // with a certificate insisted on here as well, a token alone is good nowhere
        let ready = prepared(&build(&front("mtls+token"))).await.unwrap();
        assert_eq!(ready.warnings, Vec::<String>::new());
        // a fleet that is not served over HTTPS has no front for a token to be used on
        let ready = prepared(&build("")).await.unwrap();
        assert_eq!(ready.warnings, Vec::<String>::new());
    }

    #[tokio::test]
    async fn ssh_must_be_there_when_a_rule_uses_it() {
        let dir = Dir::new(); // no ssh stand-in written
        let toml = dir.write("hosts.toml", HOSTS, 0o644);
        let cfg = dir.config(&format!("inventory = \"{toml}\""), OWN);
        let error = prepared(&cfg).await.err().unwrap();
        assert!(error.contains("ssh"), "{error}");
    }

    #[test]
    fn an_agent_socket_is_an_absolute_path_or_nothing() {
        assert_eq!(
            agent_socket(Some("/run/user/1000/ssh-agent.sock")),
            Some(PathBuf::from("/run/user/1000/ssh-agent.sock"))
        );
        for bad in [
            None,
            Some(""),
            Some("agent.sock"),
            Some("/tmp/a\nb"),
            Some("-oProxyCommand=id"),
        ] {
            assert_eq!(agent_socket(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_packaged_fleet_examples_are_valid() {
        let example = include_str!("../../packaging/fleet.example.toml");
        let cfg = Config::parse(example).unwrap_or_else(|e| panic!("{e:?}"));
        let (registry, warnings) = Registry::build(&cfg).unwrap();
        assert_eq!(warnings, Vec::<String>::new());
        check_registry(&registry).unwrap();
        let fleet = cfg.fleet.as_ref().unwrap();
        let rules = AccessRules::compile(fleet).unwrap();
        // it shows both kinds of identity
        let identities: Vec<IdentityMode> = rules.rules().iter().map(|r| r.identity).collect();
        assert_eq!(identities, [IdentityMode::Caller, IdentityMode::Fleet]);
        // the example inventory has the groups the example rules name
        let hosts = include_str!("../../packaging/hosts.example.toml");
        let inventory = Inventory::parse(hosts, Format::Toml).unwrap_or_else(|e| panic!("{e:?}"));
        for rule in rules.rules() {
            assert_eq!(
                rule.hosts.unmatched(inventory.hosts()),
                Vec::<String>::new()
            );
        }
        assert_eq!(
            inventory.get("cache1.example.com").unwrap().address,
            "10.0.4.17"
        );
        // a group of the people who use it
        assert!(
            cfg.principal_for_unix("someone", &["ops".to_string()])
                .is_some()
        );
    }

    // AIDEV-NOTE: the .deb installs these two files on every machine the package goes
    // onto, most of which are not fleet servers. As installed they must not be a fleet
    // server that works: no rule, no caller and no host, so that `opsmcp fleet` refuses
    // to start until the operator has written who reaches what. Examples belong in
    // packaging/fleet.example.toml and packaging/hosts.example.toml.
    #[test]
    fn the_fleet_configuration_the_package_installs_does_not_start_as_it_is() {
        let installed = include_str!("../../packaging/deb/etc/opsmcp/fleet.toml");
        let errors = Config::parse(installed).err().unwrap();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("there are no [[fleet.access]] rules"),
            "{errors:?}"
        );
        // Its only fault is the missing rule: with one, it is a fleet server that nobody
        // can call, reading the inventory the package puts beside it.
        let with_a_rule = format!(
            "{installed}\n[[fleet.access]]\nname = \"r\"\nroles = [\"ops\"]\nhosts = [\"*\"]\n\
             via = \"ssh\"\nidentity = \"caller\"\n"
        );
        let cfg = Config::parse(&with_a_rule).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(cfg.unix_users.is_empty());
        assert!(cfg.unix_groups.is_empty());
        assert!(cfg.tokens.is_empty());
        assert!(cfg.client_certs.is_empty());
        assert!(cfg.http.is_none());
        assert_eq!(
            cfg.fleet.as_ref().unwrap().inventory.as_deref(),
            Some(Path::new("/etc/opsmcp/fleet/hosts.toml"))
        );

        // and that inventory names no host, which is an error of its own
        let hosts = include_str!("../../packaging/deb/etc/opsmcp/fleet/hosts.toml");
        assert!(Inventory::parse(hosts, Format::Toml).is_err());
    }

    #[test]
    fn the_built_in_tools_leave_room_for_the_fleets_own_argument_and_tools() {
        let cfg = Config::parse("").unwrap();
        let (registry, _) = Registry::build(&cfg).unwrap();
        check_registry(&registry).unwrap();
    }
}
