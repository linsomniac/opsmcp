//! What a tool is handed when it runs, and the only way it can produce a result.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::Semaphore;

use super::ToolResult;
use crate::audit::{Audit, Severity};
use crate::config::Config;
use crate::exec::{self, Bins, Cmd, CmdOutput};
use crate::policy::{Access, Principal};

/// What a tool returns to the agent.
///
/// AIDEV-NOTE: an `Output` can only be made from an `Authorized`, and an `Authorized` only
/// comes from `Ctx::authorize`. So a tool cannot return a result without having asked the
/// policy (and written the audit record) at least once. The compiler enforces this: the
/// fields of both types are private to this module, and the tools live in sibling
/// modules. Do not add a public constructor for either, and do not move a tool in here.
#[derive(Debug)]
pub struct Output {
    text: String,
    /// The operation ran but did not succeed (for example a command exited non-zero).
    is_error: bool,
}

impl Output {
    /// The text, and whether the operation failed.
    pub fn into_parts(self) -> (String, bool) {
        (self.text, self.is_error)
    }
}

/// Read access for assertions in tests.
#[cfg(test)]
impl Output {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn is_error(&self) -> bool {
        self.is_error
    }
}

/// Why a tool did not produce an `Output`.
#[derive(Debug)]
pub enum ToolError {
    /// The policy said no. The message is shown to the agent.
    Denied(String),
    /// The arguments were unusable. The message is shown to the agent.
    Invalid(String),
    /// The operation could not be carried out. The message is shown to the agent.
    Failed(String),
    /// Something unexpected. The message goes to the server log only.
    Internal(String),
}

/// Proof that the policy allowed an operation and that the decision was audited.
#[derive(Debug)]
pub struct Authorized {
    _private: (),
}

impl Authorized {
    /// A successful result.
    pub fn ok(self, text: impl Into<String>) -> ToolResult {
        Ok(Output {
            text: text.into(),
            is_error: false,
        })
    }

    /// The operation was attempted and did not succeed.
    pub fn failed(self, text: impl Into<String>) -> ToolResult {
        Ok(Output {
            text: text.into(),
            is_error: true,
        })
    }

    /// `ok` or `failed`, by flag.
    pub fn done(self, text: impl Into<String>, success: bool) -> ToolResult {
        if success {
            self.ok(text)
        } else {
            self.failed(text)
        }
    }
}

/// What every call shares: configuration, command lookup and the audit trail.
pub struct Host {
    pub cfg: Config,
    pub bins: Bins,
    pub audit: Audit,
    /// Slots for blocking work (file and /proc reads). See `tools::blocking`.
    pub blocking_slots: Arc<Semaphore>,
}

impl Host {
    pub fn new(cfg: Config, bins: Bins, audit: Audit) -> Host {
        // Normally at most `max_concurrent_calls` blocking jobs run at once. The extra
        // room is for jobs whose call has timed out but which are still stuck in the
        // kernel (a dead NFS server); once those fill the slots, further jobs are
        // refused rather than piling up threads.
        let slots = cfg.limits.max_concurrent_calls.saturating_mul(4).max(8);
        Host {
            cfg,
            bins,
            audit,
            blocking_slots: Arc::new(Semaphore::new(slots)),
        }
    }
}

/// One tool call in progress.
pub struct Call {
    /// Ties together the audit records of one call.
    pub id: String,
    pub transport: &'static str,
    /// The network peer, for HTTPS.
    pub peer: Option<String>,
    pub principal: Arc<Principal>,
    pub tool: String,
    pub permission: String,
    pub access: Access,
    /// The arguments as recorded in the audit trail: complete if they fit in a record.
    pub args: Value,
    /// When `args` had to be shortened: the SHA-256 of the complete arguments.
    pub args_sha256: Option<String>,
    /// The call may only use a tool that changes nothing: the session is read-only, or
    /// the request asked to be held to that.
    pub read_only: bool,
    /// What a fleet server that passed the call on says about it (its own name, who it
    /// is acting for, its call id). Recorded as a claim; it never decides anything.
    pub via: Option<Value>,
}

/// Handed to a tool when it runs.
#[derive(Clone)]
pub struct Ctx {
    host: Arc<Host>,
    call: Arc<Call>,
}

impl Ctx {
    pub fn new(host: Arc<Host>, call: Arc<Call>) -> Ctx {
        Ctx { host, call }
    }

    pub fn cfg(&self) -> &Config {
        &self.host.cfg
    }

    pub fn bins(&self) -> &Bins {
        &self.host.bins
    }

    pub fn principal(&self) -> &Principal {
        &self.call.principal
    }

    /// Whether this call may only use a tool that changes nothing.
    pub fn read_only(&self) -> bool {
        self.call.read_only
    }

    /// Asks the policy whether this call may act on `resource` (`None` when the operation
    /// names no particular thing), and writes the decision to the audit trail.
    ///
    /// Tools must call this BEFORE doing the work, with the canonical name of what they
    /// are about to act on (the resolved path, the unit's real name...).
    pub fn authorize(&self, resource: Option<&str>) -> Result<Authorized, ToolError> {
        self.decide(resource, true)
    }

    /// `authorize`, for a resource whose name the caller did not give and may not be
    /// entitled to learn (a process looked up by pid): a refusal does not name it.
    pub fn authorize_hidden(&self, resource: Option<&str>) -> Result<Authorized, ToolError> {
        self.decide(resource, false)
    }

    /// Whether a deny grant covers `resource`. For leaving denied items out of what a
    /// collection operation returns, after the operation itself has been authorized.
    pub fn is_denied(&self, resource: &str) -> bool {
        let call = &self.call;
        call.principal
            .rules
            .denies(&call.permission, call.access, resource)
    }

    /// Whether the policy would allow this call on `resource`. Nothing is audited.
    ///
    /// AIDEV-NOTE: for filtering only. A tool that walks a tree or lists many things
    /// authorizes (and so audits) the operation itself with `authorize`, then uses this to
    /// leave out the items the caller could not have asked for one at a time. It must
    /// never be used INSTEAD of `authorize`.
    pub fn permits(&self, resource: &str) -> bool {
        let call = &self.call;
        call.principal
            .rules
            .check(&call.permission, call.access, Some(resource))
    }

    /// Whether the caller also holds `permission`, which must be the permission of a READ
    /// tool, for everything it covers (not just for some resources). Nothing is audited.
    ///
    /// AIDEV-NOTE: for tools that assemble several views into one answer
    /// (incident_snapshot). Each part is included only if the caller could have got it
    /// from the tool that owns that permission, so a combined tool can never show what a
    /// deny, or a missing grant, keeps from the caller elsewhere. Only pass the name of a
    /// read permission: the `@read` group is taken to cover whatever is named here.
    pub fn holds_read(&self, permission: &str) -> bool {
        self.call
            .principal
            .rules
            .check(permission, Access::Read, None)
    }

    /// Whether the caller holds `permission`, which must be the permission of a READ
    /// tool, for this one `resource`. Nothing is audited.
    ///
    /// AIDEV-NOTE: for a tool that answers a question another read tool also answers
    /// (wait_for watching a unit, a port, a file or the journal). The tool authorizes the
    /// call under its own permission as always, and uses this to refuse anything the
    /// caller could not have asked the owning tool directly, so it cannot be used to get
    /// around a missing grant or a deny. `resource` must be named exactly as the owning
    /// tool names it. Only pass the name of a read permission (see `holds_read`).
    pub fn holds_read_on(&self, permission: &str, resource: &str) -> bool {
        self.call
            .principal
            .rules
            .check(permission, Access::Read, Some(resource))
    }

    /// The network address the call came from (`ADDRESS:PORT`), for calls over HTTPS.
    /// `None` for local and SSH use.
    pub fn peer(&self) -> Option<&str> {
        self.call.peer.as_deref()
    }

    /// How much text a tool should produce at most, leaving room in the server's output
    /// limit for a header and notes. Tools that would exceed it choose what to keep
    /// (the newest lines of a log, a whole number of characters of a file) rather than
    /// leave it to the final cut, which keeps the start.
    pub fn output_budget(&self) -> usize {
        self.host
            .cfg
            .limits
            .max_output_bytes
            .saturating_sub(512)
            .max(256)
    }

    /// The slots that bound blocking work. See `tools::blocking`.
    pub fn blocking_slots(&self) -> Arc<Semaphore> {
        self.host.blocking_slots.clone()
    }

    fn decide(&self, resource: Option<&str>, name_it: bool) -> Result<Authorized, ToolError> {
        let call = &self.call;
        let allowed = call
            .principal
            .rules
            .check(&call.permission, call.access, resource);
        // The record is written before anything is done. If it cannot be written and the
        // configuration says to fail closed, nothing is done.
        self.audit_decision(resource, allowed, None).map_err(|e| {
            ToolError::Failed(format!(
                "Refusing to run {}: the audit log is unavailable ({e}).",
                call.tool
            ))
        })?;
        if !allowed {
            let on = match resource {
                Some(resource) if name_it => format!(" on {resource:?}"),
                Some(_) => " on that".to_string(),
                None => String::new(),
            };
            return Err(ToolError::Denied(format!(
                "Permission denied: {} is not granted {}{on}.",
                call.principal.name, call.permission
            )));
        }
        Ok(Authorized { _private: () })
    }

    /// Refuses the operation because a host-wide limit in the configuration forbids it,
    /// whatever the caller has been granted (a path outside the readable directories, a
    /// protected unit...). The refusal is audited like any other.
    pub fn deny(&self, resource: Option<&str>, reason: &str) -> ToolError {
        let _ = self.audit_decision(resource, false, Some(reason));
        ToolError::Denied(format!("Refused: {reason}."))
    }

    /// Writes the audit record for a decision about this call.
    pub fn audit_decision(
        &self,
        resource: Option<&str>,
        allowed: bool,
        reason: Option<&str>,
    ) -> Result<(), String> {
        let call = &self.call;
        let mut event = json!({
            "event": "tool_call",
            "call": call.id,
            "principal": call.principal.name,
            "roles": call.principal.roles,
            "transport": call.transport,
        });
        if let Some(fields) = event.as_object_mut() {
            if let Some(peer) = &call.peer {
                fields.insert("peer".to_string(), json!(peer));
            }
            fields.insert("tool".to_string(), json!(call.tool));
            fields.insert("permission".to_string(), json!(call.permission));
            fields.insert("access".to_string(), json!(call.access.as_str()));
            if let Some(resource) = resource {
                fields.insert("resource".to_string(), json!(resource));
            }
            fields.insert(
                "decision".to_string(),
                json!(if allowed { "allow" } else { "deny" }),
            );
            if let Some(reason) = reason {
                fields.insert("reason".to_string(), json!(reason));
            }
            fields.insert("args".to_string(), call.args.clone());
            if let Some(digest) = &call.args_sha256 {
                fields.insert("args_sha256".to_string(), json!(digest));
            }
            if call.read_only {
                fields.insert("read_only".to_string(), json!(true));
            }
            // AIDEV-NOTE: `via` is what the caller SAYS about where the call came from.
            // `principal` above is who was authenticated, and the only thing any decision
            // is based on. Keep the two apart: never copy a claim into `principal`.
            if let Some(via) = &call.via {
                fields.insert("via".to_string(), via.clone());
            }
        }
        let severity = if allowed {
            Severity::Info
        } else {
            Severity::Warning
        };
        self.host.audit.record(severity, event)
    }

    /// A system command by name, with the configured time limit.
    pub fn command(&self, name: &str) -> Result<Cmd, ToolError> {
        let program = self.host.bins.find(name).map_err(ToolError::Failed)?;
        Ok(self.command_at(program))
    }

    /// A system command that may well not be installed: `Ok(None)` when it is not there.
    /// One that is there but may not be run is an error, as with `command`.
    pub fn optional_command(&self, name: &str) -> Result<Option<Cmd>, ToolError> {
        let found = self.host.bins.lookup(name).map_err(ToolError::Failed)?;
        Ok(found.map(|program| self.command_at(program)))
    }

    /// A command at a known path, with the configured time limit.
    pub fn command_at(&self, program: PathBuf) -> Cmd {
        let mut cmd = Cmd::new(program).timeout(Duration::from_secs(
            self.host.cfg.limits.command_timeout_secs,
        ));
        cmd.path_env = self.host.bins.path_env();
        cmd
    }

    pub async fn run(&self, cmd: Cmd) -> Result<CmdOutput, ToolError> {
        exec::run(cmd).await.map_err(ToolError::Failed)
    }
}
