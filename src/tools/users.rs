//! Accounts: who exists and who has logged in; locking, groups and SSH keys.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use super::args::{Args, Param};
use super::paths::open_path;
use super::{
    Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_table, required,
};
use crate::config::is_account_name;
use crate::glob::glob_match;
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_text};
use crate::timefmt::{now_secs, rfc3339_utc};

/// Largest account database file that is read.
const MAX_DB_BYTES: u64 = 4 * 1024 * 1024;
/// Largest authorized_keys file that is read or rewritten.
const MAX_KEYS_FILE_BYTES: u64 = 1024 * 1024;
/// Membership of one of these groups is what the SUDO column of the list reports.
const SUDO_GROUPS: [&str; 3] = ["sudo", "wheel", "admin"];
/// The "nobody" account: above every `min_uid`, but not a person.
const NOBODY_UID: u32 = 65534;
/// The account expiry (in days since 1970) that `lock` sets and `unlock` clears. Any
/// other expiry date is somebody's decision and is never cleared here.
const LOCK_EXPIRY_DAY: i64 = 1;

/// Where the account databases are. A parameter so that the tests can run against a
/// temporary directory; the server always uses `Env::system()`.
#[derive(Clone, Debug)]
pub struct Env {
    pub passwd: PathBuf,
    pub group: PathBuf,
    pub shadow: PathBuf,
    /// Who must own the files in a user's `~/.ssh`. `None`, as it always is in the
    /// server, means the account itself. Tests, which cannot create files owned by
    /// another user, name their own uid and gid here.
    pub file_owner: Option<(u32, u32)>,
}

impl Env {
    pub fn system() -> Env {
        Env {
            passwd: PathBuf::from("/etc/passwd"),
            group: PathBuf::from("/etc/group"),
            shadow: PathBuf::from("/etc/shadow"),
            file_owner: None,
        }
    }
}

pub fn tools() -> Vec<Tool> {
    tools_with(Env::system())
}

/// The tools, working on the account databases named by `env`.
pub fn tools_with(env: Env) -> Vec<Tool> {
    let env = Arc::new(env);
    let list_env = env.clone();
    let modify_env = env;
    vec![
        Tool::new(
            "user_modify",
            "Change a local account: lock it (password and SSH key logins are both refused) \
             or unlock it, add it to or remove it from a group, or add or remove a key in its \
             authorized_keys file. System accounts and the superuser cannot be changed; which \
             groups may be changed, and whether keys may be, is set in this host's \
             configuration. Locking does not end sessions that are already running.",
            Access::Write,
            "user.modify",
            vec![
                Param::str("user", "The account to change")
                    .max_len(32)
                    .required(),
                Param::choice("action", "What to do", &ACTIONS).required(),
                Param::str("group", "The group, for add_group and remove_group").max_len(32),
                Param::str(
                    "key",
                    "For add_key: one public key line, 'TYPE BASE64 [comment]' (the content of \
                     a .pub file). Options such as command= are not accepted",
                )
                .max_len(2500),
                Param::str(
                    "fingerprint",
                    "For remove_key: the key's fingerprint as user_list shows it (SHA256:...)",
                )
                .max_len(64),
            ],
            move |ctx, args| user_modify(modify_env.clone(), ctx, args),
        ),
        user_list_tool(list_env),
    ]
}

fn user_list_tool(list_env: Arc<Env>) -> Tool {
    Tool::new(
        "user_list",
        "List the accounts on this host: user, uid, groups, shell, whether a password is \
         set or locked, and membership of a sudo group; then who is logged in now and the \
         recent and failed logins. Name one user to see that account in detail: password \
         aging and expiry, its sudo rules, the fingerprints of its SSH keys and its recent \
         logins. Only accounts in the local passwd file are shown (not LDAP or sssd).",
        Access::Read,
        "user.view",
        vec![
            Param::str("user", "Show this one account in detail").max_len(32),
            Param::bool(
                "system",
                "Include system accounts (daemons and services) in the list",
            ),
            Param::int(
                "logins",
                "How many recent (and failed) login lines to show (default 10, 0 for none)",
                0,
                50,
            ),
        ],
        move |ctx, args| user_list(list_env.clone(), ctx, args),
    )
}

/// Checks a user or group name given as an argument.
fn checked_name(what: &str, name: &str) -> Result<String, ToolError> {
    if is_account_name(name) {
        Ok(name.to_string())
    } else {
        Err(ToolError::Invalid(format!(
            "{name:?} is not a {what} name (letters, digits and _ . - only, at most 32 characters)"
        )))
    }
}

/// The account databases, as read for one call.
struct Db {
    accounts: Vec<Account>,
    groups: Vec<GroupEntry>,
    /// `None` when the shadow file could not be read (the server is not root).
    shadow: Option<HashMap<String, Shadow>>,
}

fn read_text(path: &Path) -> std::io::Result<String> {
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_DB_BYTES)
        .read_to_end(&mut data)?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

impl Db {
    fn load(env: &Env) -> Result<Db, ToolError> {
        let passwd = read_text(&env.passwd)
            .map_err(|e| ToolError::Failed(format!("cannot read {}: {e}", env.passwd.display())))?;
        let groups = read_text(&env.group).map(|text| parse_group(&text));
        // AIDEV-NOTE: the shadow text lives only inside this expression. Whether it could
        // be read is all that is remembered about a failure: no error text is kept that
        // could ever quote the file.
        let shadow = read_text(&env.shadow).ok().map(|text| parse_shadow(&text));
        Ok(Db {
            accounts: parse_passwd(&passwd),
            groups: groups.unwrap_or_default(),
            shadow,
        })
    }

    fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.iter().find(|account| account.name == name)
    }

    /// The account's primary group (by name, or by number if it has no name) and the
    /// other groups it is a member of.
    fn groups_of(&self, account: &Account) -> (String, Vec<String>) {
        let primary = self
            .groups
            .iter()
            .find(|group| group.gid == account.gid)
            .map(|group| group.name.clone())
            .unwrap_or_else(|| account.gid.to_string());
        let others = self
            .groups
            .iter()
            .filter(|group| group.name != primary && group.members.contains(&account.name))
            .map(|group| group.name.clone())
            .collect();
        (primary, others)
    }

    fn shadow_of(&self, name: &str) -> Option<&Shadow> {
        self.shadow.as_ref()?.get(name)
    }
}

/// `YYYY-MM-DD` for a day counted from 1970-01-01, as the shadow file counts them.
fn day_to_date(day: i64) -> String {
    rfc3339_utc(day.saturating_mul(86_400))
        .chars()
        .take(10)
        .collect()
}

/// The table of accounts.
fn accounts_table(db: &Db, min_uid: u32, system: bool) -> String {
    let mut rows = Vec::new();
    let mut hidden = 0;
    for account in &db.accounts {
        let person = account.uid == 0 || (account.uid >= min_uid && account.uid != NOBODY_UID);
        if !person && !system {
            hidden += 1;
            continue;
        }
        let (primary, others) = db.groups_of(account);
        let sudo = std::iter::once(&primary)
            .chain(&others)
            .any(|group| SUDO_GROUPS.contains(&group.as_str()));
        let mut groups = vec![primary];
        groups.extend(others);
        let password = db
            .shadow_of(&account.name)
            .map_or("?", |shadow| shadow.state.as_str());
        let shell = if account.shell.trim().is_empty() {
            "-"
        } else {
            account.shell.as_str()
        };
        rows.push(vec![
            account.name.clone(),
            account.uid.to_string(),
            groups.join(","),
            shell.to_string(),
            password.to_string(),
            if sudo { "group" } else { "-" }.to_string(),
        ]);
    }
    let headers = ["USER", "UID", "GROUPS", "SHELL", "PASSWORD", "SUDO"];
    let mut text = format_table(&headers, &rows, &[false, true, false, false, false, false]);
    text.push('\n');
    if hidden > 0 {
        text.push_str(&format!(
            "[{hidden} system accounts not shown; pass system to include them]\n"
        ));
    }
    if db.shadow.is_none() {
        text.push_str(
            "[PASSWORD is unknown: the shadow file could not be read (that needs root)]\n",
        );
    }
    text.push_str(
        "[SUDO is 'group' for members of the sudo, wheel or admin group; sudoers rules are not \
         evaluated here. Ask for one user to see that user's sudo rules]\n\
         [only accounts in the local passwd file are listed, not those from LDAP or sssd]\n",
    );
    text
}

/// The password and expiry lines for one account.
fn aging_lines(shadow: Option<&Shadow>, shadow_readable: bool, now: i64) -> String {
    let Some(shadow) = shadow else {
        let why = if shadow_readable {
            "this account has no entry in the shadow file"
        } else {
            "the shadow file could not be read; that needs root"
        };
        return format!("Password:  ? ({why})\n");
    };
    let changed = match shadow.last_change {
        Some(0) => "must be changed at the next login".to_string(),
        Some(day) => format!("last changed {}", day_to_date(day)),
        None => "last change not recorded".to_string(),
    };
    let max_age = match shadow.max_days {
        Some(days) if days > 0 && days < 99_999 => format!("must be changed every {days} days"),
        _ => "no maximum age".to_string(),
    };
    let account = match shadow.expires {
        Some(day) if day.saturating_mul(86_400) <= now => {
            format!("EXPIRED on {} (logins are refused)", day_to_date(day))
        }
        Some(day) => format!("expires {}", day_to_date(day)),
        None => "does not expire".to_string(),
    };
    format!(
        "Password:  {}; {changed}; {max_age}\nAccount:   {account}\n",
        shadow.state.as_str()
    )
}

/// The identity lines for one account.
fn account_lines(db: &Db, account: &Account, now: i64) -> String {
    let (primary, others) = db.groups_of(account);
    let mut text = format!("User:      {} (uid {})\n", account.name, account.uid);
    let full_name = account.gecos.split(',').next().unwrap_or("").trim();
    if !full_name.is_empty() {
        text.push_str(&format!("Full name: {full_name}\n"));
    }
    text.push_str(&format!("Group:     {primary} (gid {})", account.gid));
    if !others.is_empty() {
        text.push_str(&format!("; also in: {}", others.join(", ")));
    }
    text.push_str(&format!(
        "\nHome:      {}\nShell:     {}\n",
        account.home, account.shell
    ));
    text.push_str(&aging_lines(
        db.shadow_of(&account.name),
        db.shadow.is_some(),
        now,
    ));
    text
}

/// The keys in a user's authorized_keys file: type, fingerprint, comment and the names
/// of any options. Never the key data, and never what an option says.
///
/// AIDEV-NOTE: the server is root and this file belongs to the user, who could make it
/// (or `~/.ssh`) a link to any file on the host. It is read only if it is a regular
/// file, with a single name, whose real path is exactly `<real home>/.ssh/authorized_keys`.
fn ssh_keys_section(home: &str) -> String {
    let path = format!("{home}/.ssh/authorized_keys");
    let heading = format!("SSH keys ({path}):\n");
    let not_read = |why: &str| format!("{heading}  not read: {why}\n");
    if matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return format!("{heading}  no authorized_keys file\n");
    }
    let (Ok(real_home), Ok(opened)) = (open_path(home, true), open_path(&path, false)) else {
        return not_read("it could not be opened");
    };
    if opened.meta.file_type().is_symlink() {
        return not_read("it is a symbolic link");
    }
    let expected = format!(
        "{}/.ssh/authorized_keys",
        real_home.real.trim_end_matches('/')
    );
    if opened.real != expected {
        return not_read("~/.ssh leads outside the home directory");
    }
    if !opened.meta.is_file() {
        return not_read("it is not a regular file");
    }
    if opened.meta.nlink() != 1 {
        return not_read("it has more than one hard link");
    }
    if opened.meta.len() > MAX_KEYS_FILE_BYTES {
        return not_read("it is too large");
    }
    let mut data = Vec::new();
    let read = opened
        .reopen_read()
        .and_then(|file| file.take(MAX_KEYS_FILE_BYTES).read_to_end(&mut data));
    if read.is_err() {
        return not_read("it could not be read");
    }
    let mut rows = Vec::new();
    let mut invalid = 0;
    for line in String::from_utf8_lossy(&data).lines() {
        match parse_key_line(line) {
            Line::Blank => {}
            Line::Invalid => invalid += 1,
            Line::Key(key) => {
                let mut row = format!("  {}  {}", key.key_type, fingerprint(&key.blob));
                if !key.comment.is_empty() {
                    let comment: String = key.comment.chars().take(100).collect();
                    row.push_str(&format!("  {comment}"));
                }
                if !key.options.is_empty() {
                    row.push_str(&format!("  [options: {}]", key.options.join(", ")));
                }
                rows.push(row);
            }
        }
    }
    let mut text = heading;
    if rows.is_empty() {
        text.push_str("  no keys\n");
    }
    for row in rows {
        text.push_str(&row);
        text.push('\n');
    }
    match invalid {
        0 => {}
        1 => text.push_str("  [1 line is not a valid key; sshd ignores it]\n"),
        n => text.push_str(&format!(
            "  [{n} lines are not valid keys; sshd ignores them]\n"
        )),
    }
    text
}

/// True for the terminal column of a `last`/`lastb` line: where the login came from.
fn is_terminal_name(token: &str) -> bool {
    let display = token
        .strip_prefix(':')
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
    display
        || token == "console"
        || ["ssh:", "tty", "pts/", "tts/", "hvc"]
            .iter()
            .any(|prefix| token.starts_with(prefix))
}

/// Replaces the user name at the start of each line of `lastb` output with `(unknown)`
/// unless it is the name of an account.
///
/// AIDEV-NOTE: the failed-login log records whatever was typed at the login prompt as
/// the user name, and now and then that is somebody's password. This is a read tool, so
/// only names that are already known (accounts on this host) are passed through.
///   * The name is everything before the terminal column (`ssh:notty`, `tty1`, `pts/3`),
///     not just the first word: a pass phrase has spaces in it.
///   * A line in which no terminal column can be found is not shown at all.
///   * `lastb` cuts names to 8 characters, so an 8-character start of an account name
///     counts as that account.
fn mask_unknown_names(text: &str, known: &[String]) -> String {
    let is_known = |name: &str| {
        known
            .iter()
            .any(|account| account == name || (name.len() >= 8 && account.starts_with(name)))
    };
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if line.trim().is_empty() || line.starts_with("btmp begins") {
            out.push_str(line);
            continue;
        }
        // Where the terminal column starts: the first word that names a terminal.
        let mut offset = 0;
        let mut terminal_at = None;
        // A line that does not start with a blank starts with the name, whatever that
        // name looks like.
        let name_first = !line.starts_with(char::is_whitespace);
        for (index, word) in line.split_inclusive(char::is_whitespace).enumerate() {
            let is_name = index == 0 && name_first;
            if !is_name && is_terminal_name(word.trim_end()) {
                terminal_at = Some(offset);
                break;
            }
            offset += word.len();
        }
        let parts = terminal_at.and_then(|at| Some((line.get(..at)?, line.get(at..)?)));
        match parts {
            Some((name, _)) if name.trim().is_empty() || is_known(name.trim()) => {
                out.push_str(line);
            }
            Some((_, rest)) => {
                out.push_str("(unknown) ");
                out.push_str(rest);
            }
            None => out.push_str("(a line in a format that is not recognised is not shown)\n"),
        }
    }
    out
}

/// One section made from a command's output, or a bracketed note when the command is
/// missing or cannot be run. A command that fails still shows what it said. With
/// `only_names`, user names in the command's output that are not in that list are
/// masked (see `mask_unknown_names`).
async fn command_section(
    ctx: &Ctx,
    title: &str,
    program: &str,
    argv: Vec<String>,
    when_empty: &str,
    only_names: Option<&[String]>,
) -> String {
    let cmd = match ctx.command(program) {
        Ok(cmd) => cmd,
        Err(ToolError::Failed(why)) => {
            return format!("[{program} is not available: {why}]\n");
        }
        Err(_) => return format!("[{program} is not available]\n"),
    };
    match ctx.run(cmd.args(argv)).await {
        Ok(mut out) => {
            if let Some(known) = only_names {
                let masked = mask_unknown_names(&String::from_utf8_lossy(&out.stdout), known);
                out.stdout = masked.into_bytes();
            }
            let body = redact_text(&command_text(&out));
            if body.trim().is_empty() {
                format!("{title}:\n  {when_empty}\n")
            } else {
                format!("{title}:\n{body}")
            }
        }
        Err(ToolError::Failed(why)) => format!("[{title}: {why}]\n"),
        Err(_) => format!("[{title}: could not be run]\n"),
    }
}

/// Cuts `text` to the output budget, saying so if anything was dropped.
fn fit(ctx: &Ctx, text: &str) -> String {
    let (mut kept, dropped) = keep_head(text, ctx.output_budget());
    if dropped > 0 {
        kept.push_str(&format!(
            "[{dropped} more lines left out to fit the output limit]\n"
        ));
    }
    kept
}

async fn user_list(env: Arc<Env>, ctx: Ctx, args: Args) -> ToolResult {
    let logins = args.int("logins").unwrap_or(10);
    let system = args.bool("system") == Some(true);
    let Some(name) = args.str("user") else {
        // Every account: needs a grant that is not limited to particular users.
        let auth = ctx.authorize(None)?;
        let min_uid = ctx.cfg().users.min_uid;
        let load_env = env.clone();
        let (mut text, names) = blocking(ctx.clone(), move || {
            let db = Db::load(&load_env)?;
            let names: Vec<String> = db.accounts.iter().map(|a| a.name.clone()).collect();
            Ok((accounts_table(&db, min_uid, system), names))
        })
        .await?;
        text.push('\n');
        let who = command_section(&ctx, "Logged in now", "who", Vec::new(), "nobody", None);
        text.push_str(&who.await);
        if logins > 0 {
            let count = vec!["-n".to_string(), logins.to_string()];
            let none = "none recorded";
            let recent = command_section(&ctx, "Recent logins", "last", count.clone(), none, None);
            text.push_str(&recent.await);
            let title = "Failed logins (names that are not accounts are shown as (unknown))";
            let failed = command_section(&ctx, title, "lastb", count, none, Some(&names));
            text.push_str(&failed.await);
        }
        return auth.ok(fit(&ctx, &text));
    };

    // AIDEV-NOTE: the name is authorized BEFORE it is looked up, so a caller who may not
    // view an account cannot use this tool to find out whether it exists.
    let name = checked_name("user", name)?;
    let auth = ctx.authorize(Some(&name))?;
    let load_env = env.clone();
    let wanted = name.clone();
    let mut text = blocking(ctx.clone(), move || {
        let db = Db::load(&load_env)?;
        let Some(account) = db.account(&wanted) else {
            return Err(ToolError::Failed(format!(
                "there is no account named {wanted} in {} (accounts from LDAP or sssd are not shown)",
                load_env.passwd.display()
            )));
        };
        let mut text = account_lines(&db, account, now_secs());
        text.push_str(&ssh_keys_section(&account.home));
        Ok(text)
    })
    .await?;
    let sudo_args = ["-n", "-l", "-U", name.as_str()]
        .map(str::to_string)
        .to_vec();
    let title = format!("Sudo rules (sudo -l -U {name})");
    text.push_str(&command_section(&ctx, &title, "sudo", sudo_args, "none", None).await);
    if logins > 0 {
        let argv = vec![
            "-n".to_string(),
            logins.to_string(),
            "--".to_string(),
            name.clone(),
        ];
        let recent = command_section(&ctx, "Recent logins", "last", argv, "none recorded", None);
        text.push_str(&recent.await);
    }
    auth.ok(fit(&ctx, &text))
}

// ---------------------------------------------------------------------------------------
// user_modify
// ---------------------------------------------------------------------------------------

const ACTIONS: [&str; 6] = [
    "lock",
    "unlock",
    "add_group",
    "remove_group",
    "add_key",
    "remove_key",
];

/// What a call to user_modify asks for, with its arguments checked.
enum Request {
    Lock,
    Unlock,
    AddGroup(String),
    RemoveGroup(String),
    AddKey(KeyLine),
    /// The fingerprint of the key to remove.
    RemoveKey(String),
}

impl Request {
    /// Checks that the action has exactly the arguments it takes.
    fn parse(args: &Args) -> Result<Request, ToolError> {
        let action = required(args, "action")?;
        let (takes, what) = match action {
            "add_group" | "remove_group" => ("group", "the group"),
            "add_key" => ("key", "the public key line"),
            "remove_key" => ("fingerprint", "the key's fingerprint"),
            _ => ("", ""),
        };
        for other in ["group", "key", "fingerprint"] {
            if other != takes && args.str(other).is_some() {
                return Err(ToolError::Invalid(format!(
                    "{action} does not take the argument {other:?}"
                )));
            }
        }
        let value = || {
            args.str(takes).ok_or_else(|| {
                ToolError::Invalid(format!("{action} needs the argument {takes:?} ({what})"))
            })
        };
        Ok(match action {
            "lock" => Request::Lock,
            "unlock" => Request::Unlock,
            "add_group" => Request::AddGroup(checked_name("group", value()?)?),
            "remove_group" => Request::RemoveGroup(checked_name("group", value()?)?),
            "add_key" => Request::AddKey(check_new_key(value()?).map_err(ToolError::Invalid)?),
            "remove_key" => {
                let fingerprint = value()?;
                check_fingerprint(fingerprint).map_err(ToolError::Invalid)?;
                Request::RemoveKey(fingerprint.to_string())
            }
            other => {
                return Err(ToolError::Invalid(format!(
                    "{other:?} is not an action of user_modify"
                )));
            }
        })
    }
}

/// AIDEV-NOTE: the order of the checks is deliberate.
///   1. the arguments (nothing is audited for a malformed call);
///   2. the host-wide limits that need no lookup (`users.protected`, `users.groups`,
///      `users.manage_ssh_keys`): refused with `ctx.deny`, whatever the caller is granted;
///   3. the caller's grant for this user (`ctx.authorize`);
///   4. only then is the account looked up, so that someone not allowed to modify a
///      name cannot use this tool to learn whether it exists;
///   5. the limits that depend on the account: uid 0 can NEVER be modified (this is not
///      configurable), nor can the "nobody" account or anything below `users.min_uid`.
async fn user_modify(env: Arc<Env>, ctx: Ctx, args: Args) -> ToolResult {
    let user = checked_name("user", required(&args, "user")?)?;
    let request = Request::parse(&args)?;

    let limits = &ctx.cfg().users;
    if let Some(pattern) = limits.protected.iter().find(|p| glob_match(p, &user)) {
        let reason =
            format!("{user} is a protected account on this host (users.protected: {pattern})");
        return Err(ctx.deny(Some(&user), &reason));
    }
    match &request {
        Request::AddGroup(group) | Request::RemoveGroup(group)
            if !limits.groups.contains(group) =>
        {
            let reason = format!(
                "membership of the group {group} cannot be changed through opsmcp on this host \
                 (it is not listed in users.groups)"
            );
            return Err(ctx.deny(Some(&user), &reason));
        }
        Request::AddKey(_) | Request::RemoveKey(_) if !limits.manage_ssh_keys => {
            let reason = "SSH keys cannot be changed through opsmcp on this host \
                          (users.manage_ssh_keys is off)";
            return Err(ctx.deny(Some(&user), reason));
        }
        _ => {}
    }

    let auth = ctx.authorize(Some(&user))?;

    let load_env = env.clone();
    let wanted = user.clone();
    let (account, bare_lock, old_expiry) = blocking(ctx.clone(), move || {
        let db = Db::load(&load_env)?;
        let Some(account) = db.account(&wanted) else {
            return Err(ToolError::Failed(format!(
                "there is no account named {wanted} in {} (accounts from LDAP or sssd cannot be \
                 changed here)",
                load_env.passwd.display()
            )));
        };
        let shadow = db.shadow_of(&wanted);
        let bare_lock = shadow.is_some_and(|shadow| shadow.bare_lock);
        let old_expiry = shadow.and_then(|shadow| shadow.expires);
        Ok((account.clone(), bare_lock, old_expiry))
    })
    .await?;

    if account.uid == 0 {
        let reason =
            format!("{user} has uid 0: the superuser account is never modified through opsmcp");
        return Err(ctx.deny(Some(&user), &reason));
    }
    if account.uid == NOBODY_UID {
        let reason = format!("{user} is the 'nobody' account, not a person's account");
        return Err(ctx.deny(Some(&user), &reason));
    }
    if account.uid < limits.min_uid {
        let reason = format!(
            "{user} is a system account (uid {} is below users.min_uid = {})",
            account.uid, limits.min_uid
        );
        return Err(ctx.deny(Some(&user), &reason));
    }

    match request {
        Request::Lock => {
            // AIDEV-NOTE: locking the password alone still lets SSH keys in. Expiring the
            // account as well (day 1 = 1970-01-02) makes sshd and PAM refuse every login.
            let argv = ["--lock", "--expiredate", "1", "--", user.as_str()];
            debug_assert_eq!(LOCK_EXPIRY_DAY, 1);
            let mut done = format!(
                "{user} is locked: password and SSH key logins are both refused (the password \
                 is locked and the account is marked as expired).\n\
                 Running sessions and processes of {user} are not ended; process_list and \
                 process_signal can find and stop them.\n"
            );
            // Our own lock mark aside, an expiry date was a real one.
            if let Some(day) = old_expiry.filter(|day| *day != LOCK_EXPIRY_DAY) {
                done.push_str(&format!(
                    "The account had an expiry date of {}, which the lock replaces. Unlocking \
                     clears the expiry; set that date again afterwards (chage -E) if it is \
                     still wanted.\n",
                    day_to_date(day)
                ));
            }
            run_change(&ctx, auth, "usermod", &argv, done).await
        }
        Request::Unlock => {
            // AIDEV-NOTE: two things are undone separately, and only when they are ours.
            //
            // The expiry: `lock` marks the account as expired on day 1. Only that mark
            // is cleared. Any other expiry date was set by someone for a reason (a
            // contractor's last day): clearing it would turn an account that ends into
            // one that never does, so it is left alone and the result says so.
            //
            // The password: an account whose password field is just the lock mark has
            // no password to unlock, and `usermod --unlock` refuses it outright (it
            // would create an account that needs no password). Such an account (the
            // usual kind on a server: key logins only) is unlocked by clearing the
            // expiry mark alone.
            let our_mark = old_expiry == Some(LOCK_EXPIRY_DAY);
            let mut argv: Vec<&str> = Vec::new();
            if !bare_lock {
                argv.push("--unlock");
            }
            if our_mark {
                argv.extend(["--expiredate", ""]);
            }
            if argv.is_empty() {
                return auth.failed(format!(
                    "{user} has no password to unlock and is not marked as expired by a lock: \
                     there is nothing to unlock. user_list with user={user} shows the account.\n"
                ));
            }
            argv.extend(["--", user.as_str()]);
            let mut done = match (bare_lock, our_mark) {
                (true, _) => format!(
                    "{user} is unlocked: the account is no longer marked as expired, so SSH \
                     key logins work again. It has no password, so password login stays \
                     locked.\n"
                ),
                (false, true) => format!(
                    "{user} is unlocked: the password lock is removed and the account is no \
                     longer marked as expired.\n"
                ),
                (false, false) => format!("{user}: the password lock is removed.\n"),
            };
            if let Some(day) = old_expiry.filter(|day| *day != LOCK_EXPIRY_DAY) {
                let past = day.saturating_mul(86_400) <= now_secs();
                done.push_str(&format!(
                    "The account has an expiry date of {} that no lock here set; it was left \
                     as it is{}. `chage -E` changes it.\n",
                    day_to_date(day),
                    if past {
                        ", and since it has passed, logins are still refused"
                    } else {
                        ""
                    }
                ));
            }
            run_change(&ctx, auth, "usermod", &argv, done).await
        }
        Request::AddGroup(group) => {
            let argv = ["-a", user.as_str(), group.as_str()];
            let done = format!(
                "{user} was added to the group {group}. Sessions that are already running \
                 keep their old groups until the next login.\n"
            );
            run_change(&ctx, auth, "gpasswd", &argv, done).await
        }
        Request::RemoveGroup(group) => {
            let argv = ["-d", user.as_str(), group.as_str()];
            let done = format!(
                "{user} was removed from the group {group}. Sessions that are already \
                 running keep the group until they end.\n"
            );
            run_change(&ctx, auth, "gpasswd", &argv, done).await
        }
        Request::AddKey(key) => {
            let change = KeyChange::Add(key);
            change_keys(&env, &ctx, auth, account, change).await
        }
        Request::RemoveKey(fingerprint) => {
            let change = KeyChange::Remove(fingerprint);
            change_keys(&env, &ctx, auth, account, change).await
        }
    }
}

/// Runs an authorized account change and reports how it went.
async fn run_change(
    ctx: &Ctx,
    auth: super::Authorized,
    program: &str,
    argv: &[&str],
    done: String,
) -> ToolResult {
    let out = ctx
        .run(ctx.command(program)?.args(argv.iter().copied()))
        .await?;
    let mut text = command_text(&out);
    if command_ok(&out) {
        text.push_str(&done);
        auth.ok(text)
    } else {
        text.push_str(&format!(
            "FAILED: {program} did not succeed. user_list shows the account as it is now.\n"
        ));
        auth.failed(text)
    }
}

// ---------------------------------------------------------------------------------------
// Changing a user's authorized_keys
// ---------------------------------------------------------------------------------------
//
// AIDEV-NOTE: SECURITY-CRITICAL. The server is root and this code writes inside a
// directory that belongs to the user being modified, who may be hostile and may change
// that directory while we work. The rules, all of which have tests:
//
//   * Nothing is ever opened, created, chowned or renamed by path. The home directory is
//     opened once (not followed if it is a link); everything after that is done relative
//     to an open directory descriptor (`openat`, `mkdirat`, `renameat`, `unlinkat`), and
//     ownership and permissions are set on an open descriptor (`fchown`, `fchmod`). A
//     name being swapped for something else under us can therefore never redirect a
//     write or a chown to another file.
//   * No symbolic link is followed: `.ssh` and `authorized_keys` are opened with
//     O_NOFOLLOW and must be a real directory and a real regular file.
//   * The existing file must have exactly one name (a hard link could be a root-owned
//     file the user wants copied or replaced) and must belong to the user or to root.
//   * The file is never modified in place. The new content goes to a new file made with
//     O_CREAT|O_EXCL in the same directory, which is then renamed over the old one. The
//     new file takes the OWNER AND PERMISSIONS OF THE FILE IT REPLACES: if that was a
//     root-owned file the user cannot read, its content is not handed to the user.
//   * A `.ssh` directory we create is given to the user only after checking, through the
//     descriptor, that what we opened is the empty private directory we just made (see
//     `is_fresh_private_dir`).

/// The uid and gid that a user's files are expected to have.
#[derive(Clone, Copy, Debug)]
struct Owner {
    uid: u32,
    gid: u32,
}

impl Owner {
    /// The user's own files, and files root made for the user, are both acceptable
    /// (sshd's StrictModes takes the same view).
    fn accepts(self, uid: u32) -> bool {
        uid == self.uid || uid == 0
    }
}

enum KeyChange {
    Add(KeyLine),
    /// Remove every line whose key has this fingerprint.
    Remove(String),
}

enum KeyOutcome {
    Added { created_dir: bool },
    AlreadyThere,
    Removed(usize),
    NotThere,
    NoFile,
}

fn os_error(error: Errno) -> std::io::Error {
    std::io::Error::from(error)
}

/// Opens the account's home directory. A home directory that is itself a symbolic link
/// is not followed.
fn open_home(home: &str, owner: Owner) -> Result<File, String> {
    if !home.starts_with('/') {
        return Err(format!(
            "the account's home directory {home:?} is not an absolute path"
        ));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dir = rustix::fs::open(home, flags, Mode::empty())
        .map(File::from)
        .map_err(|e| {
            format!(
                "cannot open the home directory {home} (a home directory that is a symbolic \
                 link is not followed): {}",
                os_error(e)
            )
        })?;
    let meta = dir
        .metadata()
        .map_err(|e| format!("cannot examine the home directory {home}: {e}"))?;
    if !owner.accepts(meta.uid()) {
        return Err(format!(
            "the home directory {home} is not owned by the user or by root"
        ));
    }
    Ok(dir)
}

/// True when `dir` is a directory that `creator` made a moment ago and that nobody else
/// can have touched: owned by `creator`, closed to group and others, and empty.
///
/// AIDEV-NOTE: this is what makes it safe to chown a directory we created by name.
/// Between our `mkdirat` and our `openat` the user can rename our directory away and put
/// another one in its place; without this check we would hand them ownership of
/// whatever they put there (a root-owned directory they could move but not read, say).
/// A directory that passes is either ours or indistinguishable from it: root-owned,
/// private and empty, so there is nothing in it to give away, and nobody but root can
/// add anything before the chown.
fn is_fresh_private_dir(dir: &File, creator: u32) -> bool {
    let Ok(meta) = dir.metadata() else {
        return false;
    };
    if !meta.is_dir() || meta.uid() != creator || meta.mode() & 0o077 != 0 {
        return false;
    }
    let Ok(entries) = rustix::fs::Dir::read_from(dir) else {
        return false;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return false;
        }
    }
    true
}

/// Opens `~/.ssh` relative to the open home directory. With `create`, a missing
/// directory is made (0700, owned by the user); otherwise `Ok(None)` says there is none.
/// The flag in the result says whether it was created.
fn open_ssh_dir(home: &File, owner: Owner, create: bool) -> Result<Option<(File, bool)>, String> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let unusable = |e: Errno| {
        format!(
            "~/.ssh is a symbolic link or is not a directory, and is not followed: {}",
            os_error(e)
        )
    };
    match rustix::fs::openat(home, ".ssh", flags, Mode::empty()) {
        Ok(fd) => {
            let dir = File::from(fd);
            let meta = dir
                .metadata()
                .map_err(|e| format!("cannot examine ~/.ssh: {e}"))?;
            if !owner.accepts(meta.uid()) {
                return Err("~/.ssh is not owned by the user or by root".to_string());
            }
            Ok(Some((dir, false)))
        }
        Err(Errno::NOENT) if !create => Ok(None),
        Err(Errno::NOENT) => {
            rustix::fs::mkdirat(home, ".ssh", Mode::from_raw_mode(0o700))
                .map_err(|e| format!("cannot create ~/.ssh: {}", os_error(e)))?;
            let dir = rustix::fs::openat(home, ".ssh", flags, Mode::empty())
                .map(File::from)
                .map_err(unusable)?;
            if !is_fresh_private_dir(&dir, rustix::process::geteuid().as_raw()) {
                return Err(
                    "~/.ssh was changed by someone else while it was being created; nothing \
                     was written"
                        .to_string(),
                );
            }
            rustix::fs::fchmod(&dir, Mode::from_raw_mode(0o700))
                .map_err(|e| format!("cannot set the permissions of ~/.ssh: {}", os_error(e)))?;
            std::os::unix::fs::fchown(&dir, Some(owner.uid), Some(owner.gid))
                .map_err(|e| format!("cannot give ~/.ssh to the user: {e}"))?;
            Ok(Some((dir, true)))
        }
        Err(e) => Err(unusable(e)),
    }
}

/// An authorized_keys file as it is now.
struct Existing {
    content: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
}

/// Reads `authorized_keys` from the open `~/.ssh`, if there is one.
fn read_existing(ssh_dir: &File, owner: Owner) -> Result<Option<Existing>, String> {
    // NONBLOCK: a FIFO put there on purpose must not hang the server.
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = match rustix::fs::openat(ssh_dir, "authorized_keys", flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => {
            return Err("authorized_keys is a symbolic link; it is not followed".to_string());
        }
        Err(e) => return Err(format!("cannot open authorized_keys: {}", os_error(e))),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot examine authorized_keys: {e}"))?;
    if !meta.is_file() {
        return Err("authorized_keys is not a regular file".to_string());
    }
    if meta.nlink() != 1 {
        return Err(
            "authorized_keys has more than one hard link (it is also another file); it is \
             left alone"
                .to_string(),
        );
    }
    if !owner.accepts(meta.uid()) {
        return Err("authorized_keys is not owned by the user or by root".to_string());
    }
    let too_large = || {
        format!(
            "authorized_keys is too large (more than {} KiB)",
            MAX_KEYS_FILE_BYTES / 1024
        )
    };
    if meta.len() > MAX_KEYS_FILE_BYTES {
        return Err(too_large());
    }
    let mut content = Vec::new();
    file.take(MAX_KEYS_FILE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|e| format!("cannot read authorized_keys: {e}"))?;
    if content.len() as u64 > MAX_KEYS_FILE_BYTES {
        return Err(too_large());
    }
    Ok(Some(Existing {
        content,
        mode: meta.mode() & 0o777,
        uid: meta.uid(),
        gid: meta.gid(),
    }))
}

/// Puts `content` in place as `authorized_keys`: written to a new file in the same
/// directory, which is then renamed over the old one.
fn replace_keys_file(
    ssh_dir: &File,
    content: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|e| format!("cannot get random bytes: {e}"))?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let temp = format!(".authorized_keys.opsmcp-{suffix}");
    // EXCL: the file is new and ours; an existing name (or a link) is never written to.
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = rustix::fs::openat(ssh_dir, temp.as_str(), flags, Mode::from_raw_mode(0o600))
        .map(File::from)
        .map_err(|e| format!("cannot create a file in ~/.ssh: {}", os_error(e)))?;
    let written = (|| -> std::io::Result<()> {
        file.write_all(content)?;
        rustix::fs::fchmod(&file, Mode::from_raw_mode(mode))?;
        std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        file.sync_all()?;
        rustix::fs::renameat(ssh_dir, temp.as_str(), ssh_dir, "authorized_keys")?;
        Ok(())
    })();
    if let Err(e) = written {
        let _ = rustix::fs::unlinkat(ssh_dir, temp.as_str(), AtFlags::empty());
        return Err(format!("cannot write authorized_keys: {e}"));
    }
    // Best effort: make the rename itself durable.
    let _ = ssh_dir.sync_all();
    Ok(())
}

/// The line written for a new key: rebuilt from its checked parts.
fn key_line_text(key: &KeyLine) -> String {
    let mut line = format!("{} {}", key.key_type, b64_encode(&key.blob, true));
    if !key.comment.is_empty() {
        line.push(' ');
        line.push_str(&key.comment);
    }
    line
}

/// Applies one change to the authorized_keys file under `home`.
fn edit_keys(home: &str, owner: Owner, change: &KeyChange) -> Result<KeyOutcome, String> {
    let home_dir = open_home(home, owner)?;
    match change {
        KeyChange::Add(key) => {
            let Some((ssh_dir, created_dir)) = open_ssh_dir(&home_dir, owner, true)? else {
                return Err("~/.ssh could not be created".to_string());
            };
            let existing = read_existing(&ssh_dir, owner)?;
            let wanted = fingerprint(&key.blob);
            let mut content = Vec::new();
            // A new file belongs to the user; a replaced one keeps its owner and mode.
            let (mut mode, mut uid, mut gid) = (0o600, owner.uid, owner.gid);
            if let Some(existing) = existing {
                let present = String::from_utf8_lossy(&existing.content)
                    .lines()
                    .any(|line| matches!(parse_key_line(line), Line::Key(k) if fingerprint(&k.blob) == wanted));
                if present {
                    return Ok(KeyOutcome::AlreadyThere);
                }
                (mode, uid, gid) = (existing.mode, existing.uid, existing.gid);
                content = existing.content;
            }
            if !content.is_empty() && !content.ends_with(b"\n") {
                content.push(b'\n');
            }
            content.extend_from_slice(key_line_text(key).as_bytes());
            content.push(b'\n');
            if content.len() as u64 > MAX_KEYS_FILE_BYTES {
                return Err("authorized_keys would become too large".to_string());
            }
            replace_keys_file(&ssh_dir, &content, mode, uid, gid)?;
            Ok(KeyOutcome::Added { created_dir })
        }
        KeyChange::Remove(wanted) => {
            let Some((ssh_dir, _)) = open_ssh_dir(&home_dir, owner, false)? else {
                return Ok(KeyOutcome::NoFile);
            };
            let Some(existing) = read_existing(&ssh_dir, owner)? else {
                return Ok(KeyOutcome::NoFile);
            };
            // Every other line is kept exactly as it is, byte for byte.
            let mut kept = Vec::with_capacity(existing.content.len());
            let mut removed = 0;
            for raw in existing.content.split_inclusive(|byte| *byte == b'\n') {
                let line = String::from_utf8_lossy(raw);
                if matches!(parse_key_line(&line), Line::Key(k) if fingerprint(&k.blob) == *wanted)
                {
                    removed += 1;
                } else {
                    kept.extend_from_slice(raw);
                }
            }
            if removed == 0 {
                return Ok(KeyOutcome::NotThere);
            }
            replace_keys_file(&ssh_dir, &kept, existing.mode, existing.uid, existing.gid)?;
            Ok(KeyOutcome::Removed(removed))
        }
    }
}

/// Carries out an authorized key change and reports exactly what was done.
async fn change_keys(
    env: &Env,
    ctx: &Ctx,
    auth: super::Authorized,
    account: Account,
    change: KeyChange,
) -> ToolResult {
    let (uid, gid) = env.file_owner.unwrap_or((account.uid, account.gid));
    let owner = Owner { uid, gid };
    let user = account.name.clone();
    let file = format!(
        "{}/.ssh/authorized_keys",
        account.home.trim_end_matches('/')
    );
    let described = match &change {
        KeyChange::Add(key) => {
            let comment = if key.comment.is_empty() {
                String::new()
            } else {
                format!(", {}", key.comment)
            };
            format!("{} ({}{comment})", fingerprint(&key.blob), key.key_type)
        }
        KeyChange::Remove(fingerprint) => fingerprint.clone(),
    };
    let home = account.home;
    let outcome = blocking(ctx.clone(), move || Ok(edit_keys(&home, owner, &change))).await?;
    match outcome {
        Ok(KeyOutcome::Added { created_dir }) => {
            let created = if created_dir {
                " (~/.ssh did not exist and was created; on a host that enforces SELinux, \
                 check its label with restorecon)"
            } else {
                ""
            };
            auth.ok(format!(
                "Added the key {described} to {file}{created}. {user} can now log in with it.\n"
            ))
        }
        Ok(KeyOutcome::AlreadyThere) => auth.failed(format!(
            "The key {described} is already in {file}; nothing was changed.\n"
        )),
        Ok(KeyOutcome::Removed(count)) => {
            let lines = if count == 1 {
                "1 line"
            } else {
                &format!("{count} lines")
            };
            auth.ok(format!(
                "Removed {lines} with the key {described} from {file}. Sessions already \
                 opened with that key are not ended.\n"
            ))
        }
        Ok(KeyOutcome::NotThere) => auth.failed(format!(
            "There is no key with fingerprint {described} in {file}; nothing was changed. \
             user_list with user={user} shows the keys that are there.\n"
        )),
        Ok(KeyOutcome::NoFile) => auth.failed(format!(
            "{user} has no authorized_keys file ({file}); there is nothing to remove.\n"
        )),
        Err(why) => auth.failed(format!(
            "Not changed: {why}.\n(The file would be {file}.)\n"
        )),
    }
}

// ---------------------------------------------------------------------------------------
// The account databases
// ---------------------------------------------------------------------------------------

/// One line of /etc/passwd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// The accounts in passwd-format text. Lines that do not parse (comments, NIS `+`
/// entries, damaged lines) are skipped.
pub fn parse_passwd(text: &str) -> Vec<Account> {
    let mut accounts = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let [name, _password, uid, gid, gecos, home, shell] = fields.as_slice() else {
            continue;
        };
        if name.is_empty() || name.starts_with(['#', '+', '-']) {
            continue;
        }
        let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse()) else {
            continue;
        };
        accounts.push(Account {
            name: name.to_string(),
            uid,
            gid,
            gecos: gecos.to_string(),
            home: home.to_string(),
            shell: shell.to_string(),
        });
    }
    accounts
}

/// One line of /etc/group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// The groups in group-format text. Lines that do not parse are skipped.
pub fn parse_group(text: &str) -> Vec<GroupEntry> {
    let mut groups = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let [name, _password, gid, members] = fields.as_slice() else {
            continue;
        };
        if name.is_empty() || name.starts_with(['#', '+', '-']) {
            continue;
        }
        let Ok(gid) = gid.parse() else {
            continue;
        };
        groups.push(GroupEntry {
            name: name.to_string(),
            gid,
            members: members
                .split(',')
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .collect(),
        });
    }
    groups
}

/// What the password field of a shadow entry says, as `passwd -S` would report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordState {
    /// A usable password is set.
    Set,
    /// Password login is not possible (the field starts with `!` or `*`).
    Locked,
    /// The field is empty: no password is needed.
    None,
}

impl PasswordState {
    fn as_str(self) -> &'static str {
        match self {
            PasswordState::Set => "set",
            PasswordState::Locked => "locked",
            PasswordState::None => "none",
        }
    }
}

/// What is kept of one line of /etc/shadow.
///
/// AIDEV-NOTE: the password hash is deliberately NOT a field of this type. It is looked
/// at once, in `parse_shadow`, to derive `state` and `bare_lock`, and dropped there; so
/// nothing built from a `Shadow` (output, error text, debug text) can ever contain it.
/// Do not add the hash, or the raw line, to this struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shadow {
    pub state: PasswordState,
    /// The field is exactly `!`: there is no password behind the lock, so `usermod
    /// --unlock` refuses (it would leave an account that needs no password).
    pub bare_lock: bool,
    /// Day (since 1970-01-01) the password was last changed; 0 means it must be changed
    /// at the next login.
    pub last_change: Option<i64>,
    /// Days after which the password must be changed.
    pub max_days: Option<i64>,
    /// Day (since 1970-01-01) on which the account expires.
    pub expires: Option<i64>,
}

/// The entries in shadow-format text, by account name.
pub fn parse_shadow(text: &str) -> HashMap<String, Shadow> {
    let mut entries = HashMap::new();
    for line in text.lines() {
        let mut fields = line.split(':');
        let (Some(name), Some(hash)) = (fields.next(), fields.next()) else {
            continue;
        };
        if name.is_empty() || name.starts_with(['#', '+', '-']) {
            continue;
        }
        let state = if hash.is_empty() {
            PasswordState::None
        } else if hash.starts_with(['!', '*']) {
            PasswordState::Locked
        } else {
            PasswordState::Set
        };
        let bare_lock = hash == "!";
        let mut number = || fields.next().and_then(|field| field.parse::<i64>().ok());
        let last_change = number();
        let _min_days = number();
        let max_days = number();
        let _warn_days = number();
        let _inactive_days = number();
        let expires = number();
        entries.insert(
            name.to_string(),
            Shadow {
                state,
                bare_lock,
                last_change,
                max_days,
                expires,
            },
        );
    }
    entries
}

// ---------------------------------------------------------------------------------------
// Base64 (only what SSH keys and their fingerprints need)
// ---------------------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648), with or without the trailing `=` padding.
pub fn b64_encode(bytes: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let group = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        // A chunk of n bytes fills n + 1 of the four characters.
        for position in 0..4 {
            if position <= chunk.len() {
                let sextet = (group >> (18 - 6 * position)) & 63;
                let symbol = usize::try_from(sextet)
                    .ok()
                    .and_then(|index| B64_ALPHABET.get(index))
                    .copied()
                    .unwrap_or(b'A');
                out.push(char::from(symbol));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64. Strict: only the 64 alphabet characters, padding either
/// complete or absent, and no stray bits after the last byte. `None` for anything else.
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let data = match bytes {
        [rest @ .., b'=', b'='] => rest,
        [rest @ .., b'='] => rest,
        _ => bytes,
    };
    let padding = bytes.len() - data.len();
    if padding > 0 && !bytes.len().is_multiple_of(4) {
        return None;
    }
    // Two leftover characters carry one byte, three carry two; one carries nothing.
    match (data.len() % 4, padding) {
        (0, 0) | (2, 0) | (2, 2) | (3, 0) | (3, 1) => {}
        _ => return None,
    }
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 2);
    let mut pending: u32 = 0;
    let mut bits: u32 = 0;
    for &symbol in data {
        let value = match symbol {
            b'A'..=b'Z' => symbol - b'A',
            b'a'..=b'z' => symbol - b'a' + 26,
            b'0'..=b'9' => symbol - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        pending = (pending << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(pending >> bits).ok()?);
            pending &= (1 << bits) - 1;
        }
    }
    if pending != 0 {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------
// authorized_keys lines
// ---------------------------------------------------------------------------------------

/// Key types that may appear in an authorized_keys file.
const KEY_TYPES: [&str; 16] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-dss",
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
];

/// Key types user_modify will add: plain public keys of the kinds current OpenSSH accepts.
const ADDABLE_KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

const MAX_KEY_BLOB_BYTES: usize = 8 * 1024;
const MAX_KEY_COMMENT_CHARS: usize = 200;

/// One key from an authorized_keys file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLine {
    /// The NAMES of the options in front of the key (`command`, `from`, `no-pty`...).
    /// Their values are not kept: a forced command may contain anything.
    pub options: Vec<String>,
    pub key_type: String,
    /// The decoded key data.
    pub blob: Vec<u8>,
    pub comment: String,
}

/// What one line of an authorized_keys file is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// Empty, or a comment.
    Blank,
    Key(KeyLine),
    /// Neither: sshd would ignore it.
    Invalid,
}

/// The byte ranges of the fields of a line: separated by spaces or tabs, except inside
/// double quotes (where `\"` does not end the quoted part), as sshd reads them.
fn field_ranges(line: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut quoted = false;
    let mut escaped = false;
    for (at, c) in line.char_indices() {
        let separator = !quoted && (c == ' ' || c == '\t');
        match (start, separator) {
            (None, false) => start = Some(at),
            (Some(from), true) => {
                ranges.push((from, at));
                start = None;
            }
            _ => {}
        }
        if separator {
            continue;
        }
        if escaped {
            escaped = false;
        } else if c == '\\' && quoted {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        }
    }
    if let Some(from) = start {
        ranges.push((from, line.len()));
    }
    ranges
}

/// The names of the options in an options field such as
/// `command="/bin/x a,b",from="10.0.0.1",no-pty`.
fn option_names(spec: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut current = String::new();
    let mut in_name = true;
    let mut quoted = false;
    let mut escaped = false;
    let mut finish = |name: &mut String| {
        let plain = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        names.push(if plain {
            std::mem::take(name)
        } else {
            name.clear();
            "?".to_string()
        });
    };
    for c in spec.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' && quoted {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == ',' && !quoted {
            finish(&mut current);
            in_name = true;
        } else if c == '=' && !quoted {
            in_name = false;
        } else if in_name && !quoted {
            current.push(c);
        }
    }
    finish(&mut current);
    names
}

/// The key type named inside the key data itself (its first length-prefixed string).
fn embedded_type(blob: &[u8]) -> Option<&str> {
    let length = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?);
    let length = usize::try_from(length).ok().filter(|l| *l <= 64)?;
    std::str::from_utf8(blob.get(4..4 + length)?).ok()
}

/// The length-prefixed fields that make up SSH key data, if the data is exactly a
/// sequence of such fields with nothing left over.
fn blob_fields(blob: &[u8]) -> Option<Vec<&[u8]>> {
    let mut fields = Vec::new();
    let mut rest = blob;
    while !rest.is_empty() {
        let (length, after) = rest.split_first_chunk::<4>()?;
        let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
        if length > after.len() {
            return None;
        }
        let (field, remaining) = after.split_at(length);
        fields.push(field);
        rest = remaining;
    }
    Some(fields)
}

/// Whether `blob` is exactly one public key of `key_type`, for the types that can be
/// added: the right fields, of the right sizes, and nothing after them.
///
/// AIDEV-NOTE: sshd ignores an authorized_keys line whose data is not a well-formed key
/// of the type it names. Without this check such a line would be written and reported
/// as "can now log in with it". The layouts are those of RFC 4253 (RSA), RFC 5656
/// (ECDSA), RFC 8709 (Ed25519) and OpenSSH's PROTOCOL.u2f (the sk- types).
fn is_whole_key(key_type: &str, blob: &[u8]) -> bool {
    let Some(fields) = blob_fields(blob) else {
        return false;
    };
    // An uncompressed point on the curve: 0x04, then two coordinates.
    let point = |field: &[u8], coordinate: usize| {
        field.len() == 1 + 2 * coordinate && field.first() == Some(&4)
    };
    match (key_type, fields.as_slice()) {
        ("ssh-ed25519", [_, key]) => key.len() == 32,
        ("sk-ssh-ed25519@openssh.com", [_, key, application]) => {
            key.len() == 32 && !application.is_empty()
        }
        // exponent, then modulus: 1024 to 16384 bits (with an optional leading zero)
        ("ssh-rsa", [_, exponent, modulus]) => {
            (1..=9).contains(&exponent.len()) && (128..=2049).contains(&modulus.len())
        }
        ("ecdsa-sha2-nistp256", [_, curve, q]) => *curve == b"nistp256" && point(q, 32),
        ("ecdsa-sha2-nistp384", [_, curve, q]) => *curve == b"nistp384" && point(q, 48),
        ("ecdsa-sha2-nistp521", [_, curve, q]) => *curve == b"nistp521" && point(q, 66),
        ("sk-ecdsa-sha2-nistp256@openssh.com", [_, curve, q, application]) => {
            *curve == b"nistp256" && point(q, 32) && !application.is_empty()
        }
        _ => false,
    }
}

/// Reads one line of an authorized_keys file.
pub fn parse_key_line(line: &str) -> Line {
    let line = line.trim_end_matches(['\r', '\n']);
    let ranges = field_ranges(line);
    let field = |index: usize| {
        ranges
            .get(index)
            .and_then(|(from, to)| line.get(*from..*to))
    };
    let Some(first) = field(0) else {
        return Line::Blank;
    };
    if first.starts_with('#') {
        return Line::Blank;
    }
    // The key type is the first field, or the second when options come first.
    let Some(at) = (0..2).find(|i| field(*i).is_some_and(|f| KEY_TYPES.contains(&f))) else {
        return Line::Invalid;
    };
    let (Some(key_type), Some(data), Some((_, data_end))) =
        (field(at), field(at + 1), ranges.get(at + 1))
    else {
        return Line::Invalid;
    };
    let Some(blob) = b64_decode(data) else {
        return Line::Invalid;
    };
    // AIDEV-NOTE: sshd checks that the data really is a key of the type the line names;
    // a line that fails that is not a key, whatever it looks like.
    if blob.len() > MAX_KEY_BLOB_BYTES || embedded_type(&blob) != Some(key_type) {
        return Line::Invalid;
    }
    let options = if at == 1 {
        option_names(first)
    } else {
        Vec::new()
    };
    Line::Key(KeyLine {
        options,
        key_type: key_type.to_string(),
        blob,
        comment: line.get(*data_end..).unwrap_or("").trim().to_string(),
    })
}

/// A key's fingerprint as `ssh-keygen -l` prints it: `SHA256:` and the unpadded base64
/// of the SHA-256 of the key data.
pub fn fingerprint(blob: &[u8]) -> String {
    format!(
        "SHA256:{}",
        b64_encode(Sha256::digest(blob).as_slice(), false)
    )
}

/// Checks a key given to add_key: exactly one plain public key, with no options.
///
/// AIDEV-NOTE: options are refused outright. They are how a key is given a forced
/// command, port forwarding or an environment; a caller allowed to add a key is not
/// thereby allowed to choose what that key may do beyond a normal login. The line that
/// is finally written is rebuilt from the parts returned here, never copied from input.
pub fn check_new_key(text: &str) -> Result<KeyLine, String> {
    const FORM: &str = "the key must be one public key line: TYPE BASE64 [comment]";
    let key = match parse_key_line(text.trim()) {
        Line::Key(key) => key,
        Line::Blank => return Err(FORM.to_string()),
        Line::Invalid => {
            return Err(format!(
                "{FORM} (the type must be one that OpenSSH accepts and the data must be a valid key of that type)"
            ));
        }
    };
    if !key.options.is_empty() {
        return Err(format!(
            "{FORM}; options in front of the key (such as command= or from=) are not accepted"
        ));
    }
    if !ADDABLE_KEY_TYPES.contains(&key.key_type.as_str()) {
        return Err(format!(
            "keys of type {} cannot be added (accepted: {})",
            key.key_type,
            ADDABLE_KEY_TYPES.join(", ")
        ));
    }
    if !is_whole_key(&key.key_type, &key.blob) {
        return Err(format!(
            "the data is not a complete {} key (it is cut short, has something after its \
             end, or is not of that type): sshd would ignore it",
            key.key_type
        ));
    }
    let printable = key.comment.chars().all(|c| (' '..='~').contains(&c));
    if !printable || key.comment.chars().count() > MAX_KEY_COMMENT_CHARS {
        return Err(format!(
            "the key's comment must be plain printable ASCII, at most {MAX_KEY_COMMENT_CHARS} characters"
        ));
    }
    Ok(key)
}

/// Checks a fingerprint argument: `SHA256:` and 43 base64 characters.
pub fn check_fingerprint(text: &str) -> Result<(), String> {
    let well_formed = text.strip_prefix("SHA256:").is_some_and(|digest| {
        digest.len() == 43 && digest.bytes().all(|b| B64_ALPHABET.contains(&b))
    });
    if well_formed {
        Ok(())
    } else {
        Err(
            "the fingerprint must be in the form ssh-keygen -l prints: SHA256: followed by 43 \
             characters (user_list shows the fingerprints of a user's keys)"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolResult};
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const ROLES: &str = r#"
[roles.admin]
allow = ["@all"]
[roles.viewer]
allow = ["user.view"]
[roles.alice_only]
allow = ["user.view:alice", "user.modify:alice"]
[roles.nothing]
allow = ["system.view"]
[unix_users.adam]
roles = ["admin"]
[unix_users.vera]
roles = ["viewer"]
[unix_users.al]
roles = ["alice_only"]
[unix_users.ned]
roles = ["nothing"]
"#;

    /// A pretend host: account databases and home directories in a temporary directory,
    /// stand-in commands, and callers with different grants.
    struct World {
        dir: tempfile::TempDir,
        fake: FakeBins,
        host: Arc<Host>,
        sink: MemorySink,
    }

    fn standard_bins() -> FakeBins {
        FakeBins::new()
            .add(
                "who",
                "alice    pts/0        2026-11-20 10:00 (10.0.0.9)\n",
                0,
            )
            .add(
                "last",
                "alice    pts/0        10.0.0.9         Fri Nov 20 10:00   still logged in\n",
                0,
            )
            .add(
                "lastb",
                "mallory  ssh:notty    203.0.113.7      Fri Nov 20 09:59 - 09:59  (00:00)\n",
                0,
            )
            .add(
                "sudo",
                "User alice may run the following commands on this host:\n    (ALL) NOPASSWD: /usr/bin/app --password=hunter2\n",
                0,
            )
            .add("usermod", "", 0)
            .add("gpasswd", "", 0)
    }

    fn world() -> World {
        world_with(standard_bins(), "")
    }

    fn world_with(fake: FakeBins, extra_config: &str) -> World {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        std::fs::create_dir_all(format!("{root}/etc")).unwrap();
        for user in ["alice", "bob", "carol"] {
            std::fs::create_dir_all(format!("{root}/home/{user}")).unwrap();
        }
        let passwd = format!(
            "root:x:0:0:root:{root}/home/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
             nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
             alice:x:1001:1001:Alice Example,,,:{root}/home/alice:/bin/bash\n\
             bob:x:1002:1002::{root}/home/bob:/bin/zsh\n\
             carol:x:1003:1003::{root}/home/carol:/usr/sbin/nologin\n\
             dora:x:1004:1004::{root}/home/dora:/bin/bash\n"
        );
        std::fs::write(format!("{root}/etc/passwd"), passwd).unwrap();
        std::fs::write(
            format!("{root}/etc/group"),
            "root:x:0:\nsudo:x:27:alice\ndevs:x:1500:alice,bob\nalice:x:1001:\nbob:x:1002:\n\
             carol:x:1003:\nwww-data:x:33:\n",
        )
        .unwrap();
        std::fs::write(
            format!("{root}/etc/shadow"),
            "root:*:19000:0:99999:7:::\n\
             alice:$6$SALTSALT$HASHHASHHASH:19800:0:90:7::40000:\n\
             bob:!$6$SALTSALT$LOCKEDHASH:19000:0:99999:7::1:\n\
             carol:!:19000:0:99999:7:::\n",
        )
        .unwrap();
        let config = format!("{}{ROLES}{extra_config}", fake.config_only());
        let (host, sink) = host(&config);
        World {
            dir,
            fake,
            host,
            sink,
        }
    }

    impl World {
        fn path(&self, relative: &str) -> PathBuf {
            self.dir.path().join(relative)
        }

        fn env(&self) -> Env {
            Env {
                passwd: self.path("etc/passwd"),
                group: self.path("etc/group"),
                shadow: self.path("etc/shadow"),
                // the tests cannot create files owned by another user
                file_owner: Some((
                    rustix::process::getuid().as_raw(),
                    rustix::process::getgid().as_raw(),
                )),
            }
        }

        async fn list(&self, caller: &str, args: Value) -> ToolResult {
            let tool = find(tools_with(self.env()), "user_list");
            call(&self.host, caller, &tool, args).await
        }

        async fn modify(&self, caller: &str, args: Value) -> ToolResult {
            self.modify_in(self.env(), caller, args).await
        }

        async fn modify_in(&self, env: Env, caller: &str, args: Value) -> ToolResult {
            let tool = find(tools_with(env), "user_modify");
            call(&self.host, caller, &tool, args).await
        }

        /// The names in alice's ~/.ssh, sorted.
        fn ssh_entries(&self, user: &str) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(self.path(&format!("home/{user}/.ssh")))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        fn keys_file(&self, user: &str) -> PathBuf {
            self.path(&format!("home/{user}/.ssh/authorized_keys"))
        }

        /// The row of the accounts table for `user`, split into its columns.
        async fn row(&self, args: Value, user: &str) -> Option<Vec<String>> {
            let text = ok_text(self.list("adam", args).await);
            text.lines()
                .map(|line| {
                    line.split_whitespace()
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .find(|columns| columns.first().is_some_and(|name| name == user))
        }

        /// Writes alice's authorized_keys file (creating ~/.ssh).
        fn write_keys(&self, user: &str, content: &str) -> PathBuf {
            let ssh = self.path(&format!("home/{user}/.ssh"));
            std::fs::create_dir_all(&ssh).unwrap();
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = ssh.join("authorized_keys");
            std::fs::write(&file, content).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            file
        }
    }

    fn denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn invalid(result: ToolResult) -> String {
        match result {
            Err(ToolError::Invalid(message)) => message,
            other => panic!("expected the arguments to be rejected, got {other:?}"),
        }
    }

    fn failed(result: ToolResult) -> String {
        match result {
            Err(ToolError::Failed(message)) => message,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// The text of a result that reports an operation that did not succeed.
    fn error_text(result: ToolResult) -> String {
        match result {
            Ok(output) if output.is_error() => output.into_parts().0,
            other => panic!("expected an unsuccessful result, got {other:?}"),
        }
    }

    // ---- user_list ------------------------------------------------------------------

    #[tokio::test]
    async fn the_list_shows_people_and_root_but_system_accounts_only_when_asked() {
        let w = world();
        let text = ok_text(w.list("adam", json!({})).await);
        let names: Vec<&str> = text
            .lines()
            .skip(1)
            .take_while(|line| !line.trim().is_empty() && !line.starts_with('['))
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        assert_eq!(names, ["root", "alice", "bob", "carol", "dora"], "{text}");

        let all = ok_text(w.list("adam", json!({"system": true})).await);
        for name in ["daemon", "www-data", "nobody", "alice"] {
            assert!(all.lines().any(|l| l.starts_with(name)), "{name}: {all}");
        }
    }

    #[tokio::test]
    async fn a_row_shows_groups_shell_password_state_and_sudo_group_membership() {
        let w = world();
        assert_eq!(
            w.row(json!({}), "alice").await.unwrap(),
            [
                "alice",
                "1001",
                "alice,sudo,devs",
                "/bin/bash",
                "set",
                "group"
            ]
        );
        assert_eq!(
            w.row(json!({}), "bob").await.unwrap(),
            ["bob", "1002", "bob,devs", "/bin/zsh", "locked", "-"]
        );
        assert_eq!(w.row(json!({}), "carol").await.unwrap()[4], "locked");
        assert_eq!(w.row(json!({}), "root").await.unwrap()[4], "locked");
        // no line in the shadow file for this account
        assert_eq!(w.row(json!({}), "dora").await.unwrap()[4], "?");
        // a primary group that has no name is shown by number
        assert_eq!(w.row(json!({}), "dora").await.unwrap()[2], "1004");
        assert_eq!(
            w.row(json!({"system": true}), "www-data").await.unwrap()[2],
            "www-data"
        );
    }

    #[tokio::test]
    async fn no_output_ever_contains_a_password_hash() {
        let w = world();
        let mut texts = vec![
            ok_text(w.list("adam", json!({})).await),
            ok_text(w.list("adam", json!({"system": true})).await),
            ok_text(w.list("adam", json!({"user": "alice"})).await),
            ok_text(w.list("adam", json!({"user": "bob"})).await),
            format!("{:?}", w.list("adam", json!({"user": "ghost"})).await),
        ];
        // a damaged shadow file must not be quoted in an error either
        std::fs::write(
            w.path("etc/shadow"),
            b"alice:$6$SALTSALT$HASHHASHHASH\n\xff\xfe",
        )
        .unwrap();
        texts.push(ok_text(w.list("adam", json!({})).await));
        texts.push(ok_text(w.list("adam", json!({"user": "alice"})).await));
        for text in texts {
            for secret in ["HASH", "SALT", "$6$"] {
                assert!(!text.contains(secret), "{secret} leaked: {text}");
            }
        }
    }

    #[tokio::test]
    async fn without_a_readable_shadow_file_the_password_state_is_unknown() {
        let w = world();
        std::fs::remove_file(w.path("etc/shadow")).unwrap();
        assert_eq!(w.row(json!({}), "alice").await.unwrap()[4], "?");
        let text = ok_text(w.list("adam", json!({})).await);
        assert!(text.contains("shadow"), "{text}");
        let one = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(one.contains("Password:  ?"), "{one}");
    }

    #[tokio::test]
    async fn the_list_ends_with_who_is_logged_in_and_recent_and_failed_logins() {
        let w = world();
        let text = ok_text(w.list("adam", json!({})).await);
        for wanted in [
            "Logged in now",
            "pts/0        2026-11-20 10:00",
            "Recent logins",
            "still logged in",
            "Failed logins",
            // mallory is not an account here: the name is masked, the rest is shown
            "(unknown) ssh:notty    203.0.113.7",
        ] {
            assert!(text.contains(wanted), "{wanted:?} missing: {text}");
        }
        assert!(!text.contains("mallory"), "{text}");
        assert_eq!(w.fake.calls("last"), [["-n", "10"]]);
        assert_eq!(w.fake.calls("lastb"), [["-n", "10"]]);

        ok_text(w.list("adam", json!({"logins": 3})).await);
        assert_eq!(w.fake.calls("last")[1], ["-n", "3"]);
    }

    #[test]
    fn names_in_the_failed_login_log_are_masked_unless_they_are_accounts() {
        let known = ["alice".to_string(), "longusername".to_string()];
        let text = "alice    ssh:notty    203.0.113.7   Fri Nov 20 09:59 - 09:59  (00:00)\n\
                    hunter2  ssh:notty    203.0.113.9   Fri Nov 20 09:58 - 09:58  (00:00)\n\
                    longuser ssh:notty    203.0.113.9   Fri Nov 20 09:57 - 09:57  (00:00)\n\
                    alic     tty1                       Fri Nov 20 09:56 - 09:56  (00:00)\n\
                    my pass  pts/3        10.0.0.4      Fri Nov 20 09:55 - 09:55  (00:00)\n\
                    a much longer pass phrase ssh:notty 10.0.0.4 Fri Nov 20 09:54\n\
                    \x20        ssh:notty    10.0.0.5      Fri Nov 20 09:53 - 09:53  (00:00)\n\
                    secret in a line of some other shape\n\
                    \n\
                    btmp begins Sun Nov  1 00:00:01 2026\n";
        assert_eq!(
            mask_unknown_names(text, &known),
            "alice    ssh:notty    203.0.113.7   Fri Nov 20 09:59 - 09:59  (00:00)\n\
             (unknown) ssh:notty    203.0.113.9   Fri Nov 20 09:58 - 09:58  (00:00)\n\
             longuser ssh:notty    203.0.113.9   Fri Nov 20 09:57 - 09:57  (00:00)\n\
             (unknown) tty1                       Fri Nov 20 09:56 - 09:56  (00:00)\n\
             (unknown) pts/3        10.0.0.4      Fri Nov 20 09:55 - 09:55  (00:00)\n\
             (unknown) ssh:notty 10.0.0.4 Fri Nov 20 09:54\n\
             \x20        ssh:notty    10.0.0.5      Fri Nov 20 09:53 - 09:53  (00:00)\n\
             (a line in a format that is not recognised is not shown)\n\
             \n\
             btmp begins Sun Nov  1 00:00:01 2026\n"
        );
        // a line cut off without a line end is treated the same way
        assert_eq!(
            mask_unknown_names("hunter2  ssh:notty", &known),
            "(unknown) ssh:notty"
        );
        assert_eq!(
            mask_unknown_names("hunter2", &known),
            "(a line in a format that is not recognised is not shown)\n"
        );
        // a "name" that happens to look like a terminal is still a name
        assert_eq!(
            mask_unknown_names("ttypass1 ssh:notty    10.0.0.6\nconsole  tty2\n", &known),
            "(unknown) ssh:notty    10.0.0.6\n(unknown) tty2\n"
        );
    }

    #[tokio::test]
    async fn failed_logins_never_show_what_was_typed_as_a_user_name() {
        // People type their password where the user name belongs; the failed-login log
        // then holds it as a "user name".
        let fake = FakeBins::new().add(
            "lastb",
            "alice    ssh:notty    203.0.113.7   Fri Nov 20 09:59 - 09:59  (00:00)\n\
             hunter2  ssh:notty    203.0.113.9   Fri Nov 20 09:58 - 09:58  (00:00)\n\
             www-data ssh:notty    203.0.113.9   Fri Nov 20 09:57 - 09:57  (00:00)\n",
            0,
        );
        let w = world_with(fake, "");
        let text = ok_text(w.list("adam", json!({})).await);
        assert!(!text.contains("hunter2"), "{text}");
        assert!(
            text.contains("(unknown) ssh:notty    203.0.113.9"),
            "{text}"
        );
        assert!(text.contains("alice    ssh:notty"), "{text}");
        assert!(text.contains("www-data ssh:notty"), "{text}");
    }

    #[test]
    fn a_users_files_may_belong_to_the_user_or_to_root_and_nobody_else() {
        let owner = Owner {
            uid: 1001,
            gid: 1001,
        };
        assert!(owner.accepts(1001));
        assert!(owner.accepts(0));
        assert!(!owner.accepts(1002));
        assert!(!owner.accepts(1));
    }

    #[tokio::test]
    async fn a_missing_account_program_is_a_clear_failure() {
        let w = world_with(FakeBins::new(), "[users]\ngroups = [\"devs\"]\n");
        let message = failed(
            w.modify("adam", json!({"user": "alice", "action": "lock"}))
                .await,
        );
        assert!(message.contains("usermod"), "{message}");
        let message = failed(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "add_group", "group": "devs"}),
            )
            .await,
        );
        assert!(message.contains("gpasswd"), "{message}");
    }

    #[tokio::test]
    async fn logins_zero_leaves_the_login_history_out() {
        let w = world();
        let text = ok_text(w.list("adam", json!({"logins": 0})).await);
        assert!(text.contains("Logged in now"), "{text}");
        assert!(!text.contains("Recent logins"), "{text}");
        assert_eq!(w.fake.calls("last").len(), 0);
        assert_eq!(w.fake.calls("lastb").len(), 0);
    }

    #[tokio::test]
    async fn a_missing_or_failing_login_program_is_a_note_not_an_error() {
        let fake = FakeBins::new().add_script(
            "lastb",
            "echo 'lastb: cannot open /var/log/btmp' >&2; exit 1",
        );
        let w = world_with(fake, "");
        let text = ok_text(w.list("adam", json!({})).await);
        assert!(text.contains("alice"), "{text}");
        assert!(text.contains("[who is not available"), "{text}");
        assert!(text.contains("[last is not available"), "{text}");
        assert!(text.contains("cannot open /var/log/btmp"), "{text}");
    }

    #[tokio::test]
    async fn listing_needs_an_unscoped_grant_and_a_named_user_a_grant_that_covers_it() {
        let w = world();
        // no user.view at all
        denied(w.list("ned", json!({})).await);
        denied(w.list("ned", json!({"user": "alice"})).await);
        // user.view for everyone
        ok_text(w.list("vera", json!({})).await);
        ok_text(w.list("vera", json!({"user": "bob"})).await);
        // user.view for alice only
        denied(w.list("al", json!({})).await);
        ok_text(w.list("al", json!({"user": "alice"})).await);
        let message = denied(w.list("al", json!({"user": "bob"})).await);
        assert!(message.contains("user.view"), "{message}");
        // the refusals are in the audit trail with the user as the resource
        let records = w.sink.records();
        let last = records.last().unwrap();
        assert_eq!(last["decision"], "deny");
        assert_eq!(last["resource"], "bob");
    }

    #[tokio::test]
    async fn an_unknown_user_is_only_reported_to_a_caller_allowed_to_ask() {
        let w = world();
        let message = failed(w.list("adam", json!({"user": "ghost"})).await);
        assert!(
            message.contains("ghost") && message.contains("no account"),
            "{message}"
        );
        // someone not allowed to view that name learns nothing about whether it exists
        denied(w.list("al", json!({"user": "ghost"})).await);
        assert_eq!(
            denied(w.list("al", json!({"user": "ghost"})).await),
            denied(w.list("al", json!({"user": "bob"})).await).replace("bob", "ghost")
        );
    }

    #[tokio::test]
    async fn a_user_name_must_be_a_plain_account_name() {
        let w = world();
        for bad in [
            "-x",
            "a b",
            "../etc",
            "alice:x",
            "",
            "x".repeat(33).as_str(),
        ] {
            invalid(w.list("adam", json!({"user": bad})).await);
        }
        assert_eq!(
            w.sink.records().len(),
            0,
            "nothing should have been attempted"
        );
    }

    #[tokio::test]
    async fn one_user_is_shown_in_detail() {
        let w = world();
        let text = ok_text(w.list("adam", json!({"user": "alice"})).await);
        for wanted in [
            "alice (uid 1001)",
            "Alice Example",
            "alice (gid 1001); also in: sudo, devs",
            "/home/alice",
            "/bin/bash",
            "Password:  set; last changed 2024-03-18; must be changed every 90 days",
            "Account:   expires 2079-07-08",
        ] {
            assert!(text.contains(wanted), "{wanted:?} missing: {text}");
        }
        assert!(
            !text.contains("Alice Example,"),
            "only the name part of the GECOS field: {text}"
        );

        let bob = ok_text(w.list("adam", json!({"user": "bob"})).await);
        assert!(bob.contains("Password:  locked"), "{bob}");
        assert!(bob.contains("no maximum age"), "{bob}");
        assert!(
            bob.contains("EXPIRED") && bob.contains("1970-01-02"),
            "{bob}"
        );
        let carol = ok_text(w.list("adam", json!({"user": "carol"})).await);
        assert!(carol.contains("does not expire"), "{carol}");
    }

    #[tokio::test]
    async fn one_users_sudo_rules_are_shown_with_secrets_masked() {
        let w = world();
        let text = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(text.contains("may run the following commands"), "{text}");
        assert!(text.contains("NOPASSWD: /usr/bin/app"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert_eq!(w.fake.calls("sudo"), [["-n", "-l", "-U", "alice"]]);
        // and that user's own logins
        assert_eq!(w.fake.calls("last"), [["-n", "10", "--", "alice"]]);
        assert_eq!(w.fake.calls("lastb").len(), 0);
        assert_eq!(w.fake.calls("who").len(), 0);
    }

    #[tokio::test]
    async fn one_users_ssh_keys_are_listed_by_fingerprint_with_option_names_only() {
        let w = world();
        w.write_keys(
            "alice",
            &format!(
                "# my keys\n{ED_KEY}\n\n\
                 command=\"/usr/local/bin/backup --token=abc123\",from=\"10.0.0.1\" {EC_KEY}\n\
                 this is not a key\n"
            ),
        );
        let text = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(
            text.contains(&format!("ssh-ed25519  {ED_FP}  alice@laptop")),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "ecdsa-sha2-nistp256  {EC_FP}  backup key  [options: command, from]"
            )),
            "{text}"
        );
        assert!(text.contains("1 line is not a valid key"), "{text}");
        // neither the key data nor what an option says
        assert!(!text.contains("AAAAC3Nza"), "{text}");
        assert!(
            !text.contains("abc123") && !text.contains("/usr/local/bin/backup"),
            "{text}"
        );

        let bob = ok_text(w.list("adam", json!({"user": "bob"})).await);
        assert!(bob.contains("no authorized_keys file"), "{bob}");
    }

    #[tokio::test]
    async fn an_authorized_keys_file_reached_through_a_link_is_not_read() {
        let w = world();
        // someone else's keys, which alice's files point at
        let elsewhere = w.write_keys("bob", &format!("{ED2_KEY}\n"));

        // the file itself is a symbolic link
        let ssh = w.path("home/alice/.ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ssh.join("authorized_keys")).unwrap();
        let text = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(text.contains("symbolic link"), "{text}");
        assert!(!text.contains(ED2_FP), "{text}");

        // ~/.ssh is a symbolic link to another directory
        std::fs::remove_dir_all(&ssh).unwrap();
        std::os::unix::fs::symlink(w.path("home/bob/.ssh"), &ssh).unwrap();
        let text = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(text.contains("not read"), "{text}");
        assert!(!text.contains(ED2_FP), "{text}");

        // a second hard link to a file
        std::fs::remove_file(&ssh).unwrap();
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::hard_link(&elsewhere, ssh.join("authorized_keys")).unwrap();
        let text = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(text.contains("hard link"), "{text}");
        assert!(!text.contains(ED2_FP), "{text}");
    }

    #[tokio::test]
    async fn an_oversized_authorized_keys_file_is_not_read() {
        let w = world();
        w.write_keys("alice", &format!("{ED_KEY}\n{}", "#\n".repeat(600_000)));
        let text = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(text.contains("too large"), "{text}");
        assert!(!text.contains(ED_FP), "{text}");
    }

    // Throwaway keys made with ssh-keygen for these tests; the fingerprints are what
    // `ssh-keygen -l` printed for them.
    const ED_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEEMFFrsQGPhc70Zj1bsJbAZ8BVbtRaZFmlLls9h/AAm alice@laptop";
    const ED_FP: &str = "SHA256:W27rM7wG5BL9jFWYPvRPhYeSRhNRelZA+z0jXSWHD4A";
    const EC_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGHbKq2G27+ClzMX2CogrU2AGvvA5jjsG6Q/fnDpZGZ7PEXazrHnFigRD41SBKUd2Te2JiN/dPv2m+WlhkZkMi8= backup key";
    const EC_FP: &str = "SHA256:kYP5ptmeHrSknir9d2X1T6RQnq+DdCBJGY4NCN7bvtU";
    const ED2_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDy/Ik6geHgDSe7FE4BxpzNyhqs7Oen+vaHORbeHct3c second@host";
    const ED2_FP: &str = "SHA256:0PdkQDr7YbeESOtiWBQNg2lDgCxhTqFiq55z+dp78hM";

    #[test]
    fn base64_follows_rfc_4648() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff, 0xfe], "+//+"),
        ];
        for (bytes, text) in vectors {
            assert_eq!(b64_encode(bytes, true), *text, "encoding {bytes:?}");
            assert_eq!(
                b64_decode(text).as_deref(),
                Some(*bytes),
                "decoding {text:?}"
            );
            let bare = text.trim_end_matches('=');
            assert_eq!(b64_encode(bytes, false), bare);
            // padding may be left off, as long as what is there is a whole encoding
            assert_eq!(
                b64_decode(bare).as_deref(),
                Some(*bytes),
                "decoding {bare:?}"
            );
        }
    }

    #[test]
    fn base64_rejects_anything_that_is_not_a_clean_encoding() {
        for bad in [
            "Zg=",     // wrong amount of padding
            "Zg===",   // too much padding
            "Z",       // a single character encodes nothing
            "Zm9v=",   // padding where none belongs
            "Zm=9v",   // padding in the middle
            "Zm9v Zg", // white space
            "Zm9v\n",  // a line end
            "Zm_v",    // the URL alphabet
            "Zh==",    // non-zero bits after the last byte
            "Zm9=",    // non-zero bits after the last byte
            "Zmé=",    // not ASCII
        ] {
            assert_eq!(b64_decode(bad), None, "{bad:?} should not decode");
        }
    }

    #[test]
    fn passwd_lines_become_accounts_and_bad_lines_are_skipped() {
        let text = "root:x:0:0:root:/root:/bin/bash\n\
                    # a comment\n\
                    alice:x:1001:1001:Alice Example,,,:/home/alice:/bin/zsh\n\
                    broken:x:notanumber:1:::\n\
                    short:x:5\n\
                    +::::::\n\
                    \n\
                    svc:x:999:998::/var/lib/svc:/usr/sbin/nologin\n";
        let accounts = parse_passwd(text);
        let names: Vec<&str> = accounts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["root", "alice", "svc"]);
        assert_eq!(
            accounts[1],
            Account {
                name: "alice".to_string(),
                uid: 1001,
                gid: 1001,
                gecos: "Alice Example,,,".to_string(),
                home: "/home/alice".to_string(),
                shell: "/bin/zsh".to_string(),
            }
        );
    }

    #[test]
    fn group_lines_become_groups_with_their_members() {
        let text = "root:x:0:\nsudo:x:27:alice,bob\ndevs:x:1500:alice\nbad:x:nope:x\nempty:x:7:\n";
        let groups = parse_group(text);
        let seen: Vec<(&str, u32, Vec<&str>)> = groups
            .iter()
            .map(|g| {
                (
                    g.name.as_str(),
                    g.gid,
                    g.members.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("root", 0, vec![]),
                ("sudo", 27, vec!["alice", "bob"]),
                ("devs", 1500, vec!["alice"]),
                ("empty", 7, vec![]),
            ]
        );
    }

    #[test]
    fn shadow_lines_are_reduced_to_what_may_be_shown() {
        let text = "root:*:19000:0:99999:7:::\n\
                    alice:$6$salt$hashhashhash:19800:0:90:7::20454:\n\
                    bob:!$6$salt$lockedhash:19000:0:99999:7:::\n\
                    carol:!:19000:0:99999:7:::\n\
                    dave::19000::::::\n\
                    erin:!!:0:::::1:\n\
                    odd\n";
        let shadow = parse_shadow(text);
        let state = |name: &str| shadow.get(name).map(|s| s.state);
        assert_eq!(state("root"), Some(PasswordState::Locked));
        assert_eq!(state("alice"), Some(PasswordState::Set));
        assert_eq!(state("bob"), Some(PasswordState::Locked));
        assert_eq!(state("carol"), Some(PasswordState::Locked));
        assert_eq!(state("dave"), Some(PasswordState::None));
        assert_eq!(state("erin"), Some(PasswordState::Locked));
        assert_eq!(state("odd"), None);

        let alice = &shadow["alice"];
        assert_eq!(
            (alice.last_change, alice.max_days, alice.expires),
            (Some(19800), Some(90), Some(20454))
        );
        assert_eq!(shadow["dave"].max_days, None);
        assert_eq!(shadow["erin"].expires, Some(1));
        // only a field that is nothing but the lock mark cannot be unlocked
        assert!(shadow["carol"].bare_lock);
        assert!(!shadow["bob"].bare_lock);
        assert!(!shadow["erin"].bare_lock);
        assert!(!shadow["root"].bare_lock);
        // AIDEV-NOTE: nothing derived from the file may carry the hash itself
        let shown = format!("{shadow:?}");
        assert!(!shown.contains("hash"), "{shown}");
        assert!(!shown.contains("salt"), "{shown}");
    }

    #[test]
    fn a_key_line_gives_its_type_fingerprint_comment_and_option_names() {
        let Line::Key(key) = parse_key_line(ED_KEY) else {
            panic!("a plain key line should parse");
        };
        assert_eq!(key.key_type, "ssh-ed25519");
        assert_eq!(fingerprint(&key.blob), ED_FP);
        assert_eq!(key.comment, "alice@laptop");
        assert_eq!(key.options, Vec::<String>::new());

        let Line::Key(key) = parse_key_line(EC_KEY) else {
            panic!("an ecdsa key line should parse");
        };
        assert_eq!(fingerprint(&key.blob), EC_FP);
        assert_eq!(key.comment, "backup key");

        // options: quoted values may hold spaces, commas and escaped quotes
        let line = format!(
            "command=\"/usr/bin/rsync --server, \\\"x\\\" ssh-rsa\",from=\"10.0.0.1,10.0.0.2\",no-pty  {ED2_KEY}"
        );
        let Line::Key(key) = parse_key_line(&line) else {
            panic!("a key line with options should parse");
        };
        assert_eq!(key.options, ["command", "from", "no-pty"]);
        assert_eq!(fingerprint(&key.blob), ED2_FP);
        assert_eq!(key.comment, "second@host");

        // no comment at all
        let bare: Vec<&str> = ED_KEY.split(' ').take(2).collect();
        let Line::Key(key) = parse_key_line(&bare.join(" ")) else {
            panic!("a key line without a comment should parse");
        };
        assert_eq!(key.comment, "");
    }

    #[test]
    fn lines_that_are_not_keys_are_told_apart_from_blank_ones() {
        assert!(matches!(parse_key_line(""), Line::Blank));
        assert!(matches!(parse_key_line("   \t"), Line::Blank));
        assert!(matches!(
            parse_key_line("# ssh-ed25519 AAAA note"),
            Line::Blank
        ));
        for bad in [
            "ssh-ed25519",
            "ssh-ed25519 not-base64!! comment",
            "ssh-unknown AAAAC3NzaC1lZDI1NTE5AAAAIEEMFFrsQGPhc70Zj1bsJbAZ8BVbtRaZFmlLls9h/AAm",
            // the key data says ed25519 but the line claims rsa
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIEEMFFrsQGPhc70Zj1bsJbAZ8BVbtRaZFmlLls9h/AAm",
            "root:x:0:0:root:/root:/bin/bash",
            "two options ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEEMFFrsQGPhc70Zj1bsJbAZ8BVbtRaZFmlLls9h/AAm",
        ] {
            assert!(matches!(parse_key_line(bad), Line::Invalid), "{bad:?}");
        }
    }

    const RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzp+SJrblV2fNndjUM+BoTxBPtDz7VuqpOx5/GrxH4RVdE2tPxXxFOLi/TeQy3q52707HkBJ+WfkmbCtJdxhdObBQhDfyemHZrlKhgkBQfiGMJofP+vQocefYDYr27FwnQ16PfZ6vksarGqMVDaXiL1WINMmVCcd6fGmJv/KvCmQ+v5tnsHJUsP9vDzru6YgmuVFs1QEN0xuODCxW6ujtEj0ef1xQ7LRTbrb3ZxKa2tFLo0I7URZCrMYhR68Jia7Pl9OSP2TYwTbDg8ll0eCqC38gH61T+045BYCgLB5dwN/akwEsRqgKb36IcIaG3s6vzVAI+wjSJFxE6bUsTT6NR test@rsa";
    const P256_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHUmFABJkZd7SvwZA4aXYY2lo/ksmHhBstsl3GAzvqzSYznca+59XcYfljt+ZteVDPKhvWPuYamNvPYL6sXRTYU= test@p256";
    const P384_KEY: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBDXouQP+z88243KL7wL0fe+JMjVF9P6QBlG0W3pUgh2relddULkl91WTGhFGCq5UB9u3g4zZv6zaXoFeoVhbnIlrdvUcSIt+G/txecEKnmuEX07W9duTHU9xOCnkH9MpkQ== test@p384";
    const P521_KEY: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBADDhUKRPP9NFNJGlIDExtXZwlZBplLV01dNf09JxG9aUDz5G5mbf2atO1/5k9NNwkY5BWpLjL8AWAgaLpAKtJ7/kQHb6Ac8miAlt3lnmeIU9iBHnR3qeldDTtIUw26KoP3x2TMvSEG7AohjLLlHCfds6YaErcGaQ4+y0yo4y680QHaTpg== test@p521";

    /// `key` with its data replaced by `change(data)`.
    fn with_blob(key: &str, change: impl Fn(&mut Vec<u8>)) -> String {
        let mut words = key.split(' ');
        let (kind, data) = (words.next().unwrap(), words.next().unwrap());
        let mut blob = b64_decode(data).unwrap();
        change(&mut blob);
        format!("{kind} {} test", b64_encode(&blob, true))
    }

    #[test]
    fn a_key_to_add_must_be_a_whole_key_of_its_type() {
        // real keys of every type that can be added
        for key in [ED_KEY, RSA_KEY, P256_KEY, P384_KEY, P521_KEY] {
            assert!(check_new_key(key).is_ok(), "{key}");
        }
        // AIDEV-NOTE: sshd ignores a line whose data is not exactly a key of its type.
        // Accepting one would report "can now log in" for a key that never will.
        for key in [ED_KEY, RSA_KEY, P256_KEY] {
            // data after the end of the key
            let junk = with_blob(key, |blob| blob.extend_from_slice(b"junk"));
            assert!(check_new_key(&junk).is_err(), "trailing data: {key}");
            // a key cut short
            let short = with_blob(key, |blob| blob.truncate(blob.len() - 3));
            assert!(check_new_key(&short).is_err(), "cut short: {key}");
        }
        // only the type string, with nothing behind it
        let empty = with_blob(ED_KEY, |blob| blob.truncate(4 + "ssh-ed25519".len()));
        assert!(check_new_key(&empty).is_err());
        // a curve that does not belong to the type it is given under
        let wrong_curve = P384_KEY.replacen("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", 1);
        assert!(check_new_key(&wrong_curve).is_err());
    }

    #[test]
    fn a_key_to_add_must_be_one_plain_valid_key() {
        let key = check_new_key(ED_KEY).unwrap();
        assert_eq!(fingerprint(&key.blob), ED_FP);
        assert_eq!(key.comment, "alice@laptop");

        let errors = [
            // options are how a key is given powers (or a forced command): not accepted
            format!("no-pty {ED_KEY}"),
            format!("command=\"/bin/sh\" {ED_KEY}"),
            "ssh-ed25519 AAAA".to_string(),
            "ssh-ed25519".to_string(),
            "hello".to_string(),
            String::new(),
            // a certificate is not a key to authorize
            "ssh-ed25519-cert-v01@openssh.com AAAAC3NzaC1lZDI1NTE5AAAAIEEMFFrsQGPhc70Zj1bsJbAZ8BVbtRaZFmlLls9h/AAm".to_string(),
            // comments are plain printable ASCII
            format!("{} caf\u{e9}", ED_KEY.rsplit_once(' ').unwrap().0),
        ];
        for bad in errors {
            assert!(check_new_key(&bad).is_err(), "{bad:?} should be refused");
        }

        // a DSA key and a certificate, each a well-formed line of its type: readable in a
        // file, but not something to add
        for key_type in ["ssh-dss", "ssh-ed25519-cert-v01@openssh.com"] {
            let mut blob = u32::try_from(key_type.len())
                .unwrap()
                .to_be_bytes()
                .to_vec();
            blob.extend_from_slice(key_type.as_bytes());
            blob.extend_from_slice(&[7; 40]);
            let line = format!("{key_type} {}", b64_encode(&blob, true));
            assert!(matches!(parse_key_line(&line), Line::Key(_)), "{line}");
            let error = check_new_key(&line).unwrap_err();
            assert!(error.contains("cannot be added"), "{error}");
        }
    }

    #[test]
    fn a_fingerprint_argument_must_look_like_one() {
        assert!(check_fingerprint(ED_FP).is_ok());
        for bad in [
            "W27rM7wG5BL9jFWYPvRPhYeSRhNRelZA+z0jXSWHD4A",
            "MD5:aa:bb",
            "SHA256:short",
            "SHA256:W27rM7wG5BL9jFWYPvRPhYeSRhNRelZA+z0jXSWHD4A=",
            "SHA256:W27rM7wG5BL9jFWYPvRPhYeSRhNRelZA+z0jXSWHD4!",
        ] {
            assert!(check_fingerprint(bad).is_err(), "{bad:?}");
        }
    }

    // ---- user_modify: accounts and groups ---------------------------------------------

    /// A host whose configuration allows group and key changes.
    fn managed() -> World {
        world_with(
            standard_bins(),
            "[users]\ngroups = [\"devs\"]\nmanage_ssh_keys = true\n",
        )
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[tokio::test]
    async fn lock_locks_the_password_and_expires_the_account() {
        let w = world();
        let text = ok_text(
            w.modify("adam", json!({"user": "alice", "action": "lock"}))
                .await,
        );
        assert_eq!(
            w.fake.calls("usermod"),
            [["--lock", "--expiredate", "1", "--", "alice"]]
        );
        assert!(text.contains("alice is locked"), "{text}");
        assert!(
            text.contains("sessions"),
            "should say running sessions are not ended: {text}"
        );
        let records = w.sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["resource"], "alice");
        assert_eq!(records[0]["decision"], "allow");
    }

    #[tokio::test]
    async fn lock_says_when_it_replaces_an_expiry_date_the_account_already_had() {
        let w = world();
        // alice's account was set to expire on day 40000; locking overwrites that
        let text = ok_text(
            w.modify("adam", json!({"user": "alice", "action": "lock"}))
                .await,
        );
        assert!(text.contains("2079-07-08"), "{text}");
        // carol's had none: nothing to say
        let text = ok_text(
            w.modify("adam", json!({"user": "carol", "action": "lock"}))
                .await,
        );
        assert!(!text.contains("expiry date of"), "{text}");
    }

    #[tokio::test]
    async fn unlock_unlocks_the_password_and_clears_the_expiry() {
        let w = world();
        let text = ok_text(
            w.modify("adam", json!({"user": "bob", "action": "unlock"}))
                .await,
        );
        assert_eq!(
            w.fake.calls("usermod"),
            [["--unlock", "--expiredate", "", "--", "bob"]]
        );
        assert!(text.contains("bob is unlocked"), "{text}");
    }

    #[tokio::test]
    async fn unlock_leaves_alone_an_expiry_date_that_no_lock_here_set() {
        // AIDEV-NOTE: alice's account has a real expiry date (a contractor's last day,
        // say). Only the mark that `lock` itself sets (day 1) is ours to clear: clearing
        // any expiry would quietly turn an account that ends into one that never does.
        let w = world();
        let text = ok_text(
            w.modify("adam", json!({"user": "alice", "action": "unlock"}))
                .await,
        );
        assert_eq!(w.fake.calls("usermod"), [["--unlock", "--", "alice"]]);
        assert!(text.contains("2079-07-08"), "{text}");
        assert!(text.contains("left as it is"), "{text}");
    }

    #[tokio::test]
    async fn unlock_of_an_account_without_a_password_only_clears_the_mark_a_lock_set() {
        // carol's password field is just "!": usermod --unlock would refuse, because it
        // would leave an account that needs no password.
        let w = world();
        // She is not marked as expired either, so there is nothing to undo.
        let output = w
            .modify("adam", json!({"user": "carol", "action": "unlock"}))
            .await
            .unwrap();
        assert!(output.is_error(), "{output:?}");
        assert!(output.text().contains("nothing to unlock"), "{output:?}");
        assert_eq!(w.fake.calls("usermod"), Vec::<Vec<String>>::new());

        // Locked here (expiry day 1): only that mark is cleared.
        std::fs::write(w.path("etc/shadow"), "carol:!:19000:0:99999:7::1:\n").unwrap();
        let text = ok_text(
            w.modify("adam", json!({"user": "carol", "action": "unlock"}))
                .await,
        );
        assert_eq!(
            w.fake.calls("usermod"),
            [["--expiredate", "", "--", "carol"]]
        );
        assert!(text.contains("has no password"), "{text}");

        // when the shadow file cannot be read, nothing is known about the expiry: it is
        // left alone and usermod decides about the password
        std::fs::remove_file(w.path("etc/shadow")).unwrap();
        ok_text(
            w.modify("adam", json!({"user": "carol", "action": "unlock"}))
                .await,
        );
        assert_eq!(w.fake.calls("usermod")[1], ["--unlock", "--", "carol"]);
    }

    #[tokio::test]
    async fn a_failing_usermod_is_reported_as_an_error_with_what_it_said() {
        let fake = FakeBins::new().add_script(
            "usermod",
            "echo 'usermod: cannot lock /etc/passwd; try again later.' >&2; exit 10",
        );
        let w = world_with(fake, "");
        let text = error_text(
            w.modify("adam", json!({"user": "alice", "action": "lock"}))
                .await,
        );
        assert!(text.contains("cannot lock /etc/passwd"), "{text}");
        assert!(text.contains("FAILED"), "{text}");
    }

    #[tokio::test]
    async fn a_protected_account_is_refused_before_anything_else() {
        let w = world_with(
            standard_bins(),
            "[users]\nprotected = [\"root\", \"deploy*\"]\n",
        );
        for user in ["root", "deployer"] {
            let message = denied(
                w.modify("adam", json!({"user": user, "action": "lock"}))
                    .await,
            );
            assert!(message.contains("users.protected"), "{message}");
        }
        assert_eq!(w.fake.calls("usermod").len(), 0);
        let records = w.sink.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["decision"], "deny");
        assert_eq!(records[0]["resource"], "root");
        assert!(
            records[0]["reason"]
                .as_str()
                .unwrap()
                .contains("users.protected")
        );
    }

    #[tokio::test]
    async fn the_superuser_can_never_be_modified_whatever_the_configuration_says() {
        let w = world_with(
            standard_bins(),
            "[users]\nprotected = []\nmin_uid = 1\ngroups = [\"devs\"]\nmanage_ssh_keys = true\n",
        );
        for args in [
            json!({"user": "root", "action": "lock"}),
            json!({"user": "root", "action": "unlock"}),
            json!({"user": "root", "action": "add_group", "group": "devs"}),
            json!({"user": "root", "action": "add_key", "key": ED_KEY}),
            json!({"user": "root", "action": "remove_key", "fingerprint": ED_FP}),
        ] {
            let message = denied(w.modify("adam", args).await);
            // the rule of its own, not the min_uid rule that happens to cover uid 0 too
            assert!(message.contains("superuser"), "{message}");
        }
        assert_eq!(w.fake.calls("usermod").len(), 0);
        assert_eq!(w.fake.calls("gpasswd").len(), 0);
        assert!(!w.path("home/root").exists());
        let last = w.sink.records().pop().unwrap();
        assert_eq!(last["decision"], "deny");
    }

    #[tokio::test]
    async fn system_accounts_cannot_be_modified() {
        let w = world();
        let message = denied(
            w.modify("adam", json!({"user": "www-data", "action": "lock"}))
                .await,
        );
        assert!(message.contains("users.min_uid"), "{message}");
        // "nobody" is above every min_uid but is not a person either
        let message = denied(
            w.modify("adam", json!({"user": "nobody", "action": "lock"}))
                .await,
        );
        assert!(message.contains("nobody"), "{message}");
        assert_eq!(w.fake.calls("usermod").len(), 0);

        // the floor is the operator's to move
        let lower = world_with(standard_bins(), "[users]\nmin_uid = 10\n");
        ok_text(
            lower
                .modify("adam", json!({"user": "www-data", "action": "lock"}))
                .await,
        );
        denied(
            lower
                .modify("adam", json!({"user": "daemon", "action": "lock"}))
                .await,
        );
    }

    #[tokio::test]
    async fn modifying_needs_a_grant_that_covers_the_user() {
        let w = world();
        denied(
            w.modify("ned", json!({"user": "alice", "action": "lock"}))
                .await,
        );
        denied(
            w.modify("vera", json!({"user": "alice", "action": "lock"}))
                .await,
        );
        let message = denied(
            w.modify("al", json!({"user": "bob", "action": "lock"}))
                .await,
        );
        assert!(message.contains("user.modify"), "{message}");
        assert_eq!(w.fake.calls("usermod").len(), 0);
        ok_text(
            w.modify("al", json!({"user": "alice", "action": "lock"}))
                .await,
        );
        assert_eq!(w.fake.calls("usermod").len(), 1);
    }

    #[tokio::test]
    async fn an_unknown_account_is_only_reported_to_a_caller_allowed_to_modify_it() {
        let w = world();
        let message = failed(
            w.modify("adam", json!({"user": "ghost", "action": "lock"}))
                .await,
        );
        assert!(message.contains("no account named ghost"), "{message}");
        denied(
            w.modify("al", json!({"user": "ghost", "action": "lock"}))
                .await,
        );
        assert_eq!(w.fake.calls("usermod").len(), 0);
    }

    #[tokio::test]
    async fn each_action_takes_exactly_its_own_arguments() {
        let w = managed();
        for args in [
            json!({"user": "-alice", "action": "lock"}),
            json!({"user": "alice", "action": "add_group"}),
            json!({"user": "alice", "action": "remove_group"}),
            json!({"user": "alice", "action": "add_group", "group": "bad group"}),
            json!({"user": "alice", "action": "add_group", "group": "-x"}),
            json!({"user": "alice", "action": "add_key"}),
            json!({"user": "alice", "action": "remove_key"}),
            json!({"user": "alice", "action": "remove_key", "fingerprint": "nonsense"}),
            json!({"user": "alice", "action": "add_key", "key": "nonsense"}),
            // an argument that belongs to another action is a mistake, not something to ignore
            json!({"user": "alice", "action": "lock", "group": "devs"}),
            json!({"user": "alice", "action": "add_group", "group": "devs", "key": ED_KEY}),
            json!({"user": "alice", "action": "add_key", "key": ED_KEY, "fingerprint": ED_FP}),
            json!({"user": "alice", "action": "delete"}),
            json!({"action": "lock"}),
        ] {
            invalid(w.modify("adam", args).await);
        }
        assert_eq!(w.sink.records().len(), 0);
        assert_eq!(w.fake.calls("usermod").len(), 0);
        assert_eq!(w.fake.calls("gpasswd").len(), 0);
    }

    #[tokio::test]
    async fn group_membership_can_be_changed_only_for_the_groups_the_host_lists() {
        // by default no group is listed
        let w = world();
        let message = denied(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "add_group", "group": "devs"}),
            )
            .await,
        );
        assert!(message.contains("users.groups"), "{message}");

        let w = managed();
        let text = ok_text(
            w.modify(
                "adam",
                json!({"user": "carol", "action": "add_group", "group": "devs"}),
            )
            .await,
        );
        assert!(text.contains("carol") && text.contains("devs"), "{text}");
        ok_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "remove_group", "group": "devs"}),
            )
            .await,
        );
        assert_eq!(
            w.fake.calls("gpasswd"),
            [["-a", "carol", "devs"], ["-d", "alice", "devs"]]
        );
        // a group that would hand out privileges is simply not on the list
        for group in ["sudo", "root", "docker"] {
            let message = denied(
                w.modify(
                    "adam",
                    json!({"user": "carol", "action": "add_group", "group": group}),
                )
                .await,
            );
            assert!(message.contains("users.groups"), "{message}");
        }
        assert_eq!(w.fake.calls("gpasswd").len(), 2);
    }

    // ---- user_modify: SSH keys --------------------------------------------------------

    #[tokio::test]
    async fn keys_cannot_be_changed_unless_the_host_allows_it() {
        let w = world();
        for args in [
            json!({"user": "alice", "action": "add_key", "key": ED_KEY}),
            json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
        ] {
            let message = denied(w.modify("adam", args).await);
            assert!(message.contains("users.manage_ssh_keys"), "{message}");
        }
        assert!(!w.path("home/alice/.ssh").exists());
    }

    #[tokio::test]
    async fn add_key_creates_the_directory_and_file_with_private_permissions() {
        let w = managed();
        let text = ok_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "add_key", "key": ED_KEY}),
            )
            .await,
        );
        assert_eq!(
            std::fs::read_to_string(w.keys_file("alice")).unwrap(),
            format!("{ED_KEY}\n")
        );
        assert_eq!(mode_of(&w.path("home/alice/.ssh")), 0o700);
        assert_eq!(mode_of(&w.keys_file("alice")), 0o600);
        assert_eq!(w.ssh_entries("alice"), ["authorized_keys"]);
        assert!(text.contains(ED_FP), "{text}");
        assert!(text.contains("alice"), "{text}");
        // and user_list now shows it
        let listed = ok_text(w.list("adam", json!({"user": "alice"})).await);
        assert!(listed.contains(ED_FP), "{listed}");
    }

    #[tokio::test]
    async fn add_key_appends_one_line_and_keeps_what_was_there() {
        let w = managed();
        // no line end after the last line, a comment, and unusual permissions
        let before = format!("# keys\n{ED_KEY}");
        let file = w.write_keys("alice", &before);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        ok_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "add_key", "key": format!("  {EC_KEY}  ")}),
            )
            .await,
        );
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{before}\n{EC_KEY}\n")
        );
        assert_eq!(mode_of(&file), 0o644, "the file's permissions are kept");
        assert_eq!(w.ssh_entries("alice"), ["authorized_keys"]);
    }

    #[tokio::test]
    async fn add_key_refuses_a_key_that_is_already_there() {
        let w = managed();
        let before = format!("no-pty {ED_KEY}\n");
        let file = w.write_keys("alice", &before);
        let key = ED_KEY.rsplit_once(' ').unwrap().0;
        let text = error_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "add_key", "key": format!("{key} another-name")}),
            )
            .await,
        );
        assert!(text.contains("already"), "{text}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[tokio::test]
    async fn add_key_refuses_a_key_line_that_carries_options() {
        let w = managed();
        let message = invalid(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "add_key",
                       "key": format!("command=\"/bin/sh\" {ED_KEY}")}),
            )
            .await,
        );
        assert!(message.contains("options"), "{message}");
        assert!(!w.path("home/alice/.ssh").exists());
    }

    #[tokio::test]
    async fn key_changes_do_not_follow_a_symbolic_link_for_the_ssh_directory() {
        let w = managed();
        let target = w.path("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("authorized_keys"), format!("{ED_KEY}\n")).unwrap();
        std::os::unix::fs::symlink(&target, w.path("home/alice/.ssh")).unwrap();

        let text = error_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "add_key", "key": EC_KEY}),
            )
            .await,
        );
        assert!(text.contains("symbolic link"), "{text}");
        let text = error_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
            )
            .await,
        );
        assert!(text.contains("symbolic link"), "{text}");
        // what the link points at is exactly as it was
        assert_eq!(
            std::fs::read_to_string(target.join("authorized_keys")).unwrap(),
            format!("{ED_KEY}\n")
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn key_changes_do_not_follow_a_symbolic_link_for_the_file() {
        let w = managed();
        let target = w.path("victim");
        std::fs::write(&target, format!("{ED_KEY}\n")).unwrap();
        let ssh = w.path("home/alice/.ssh");
        std::fs::create_dir(&ssh).unwrap();
        std::os::unix::fs::symlink(&target, ssh.join("authorized_keys")).unwrap();

        for args in [
            json!({"user": "alice", "action": "add_key", "key": EC_KEY}),
            json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
        ] {
            let text = error_text(w.modify("adam", args).await);
            assert!(text.contains("symbolic link"), "{text}");
        }
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            format!("{ED_KEY}\n")
        );
        // the link is still a link, and nothing was left behind
        assert!(
            std::fs::symlink_metadata(ssh.join("authorized_keys"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(w.ssh_entries("alice"), ["authorized_keys"]);
    }

    #[tokio::test]
    async fn key_changes_refuse_a_file_with_a_second_hard_link() {
        let w = managed();
        let target = w.path("victim");
        std::fs::write(&target, format!("{ED_KEY}\n")).unwrap();
        let ssh = w.path("home/alice/.ssh");
        std::fs::create_dir(&ssh).unwrap();
        std::fs::hard_link(&target, ssh.join("authorized_keys")).unwrap();

        for args in [
            json!({"user": "alice", "action": "add_key", "key": EC_KEY}),
            json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
        ] {
            let text = error_text(w.modify("adam", args).await);
            assert!(text.contains("hard link"), "{text}");
        }
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            format!("{ED_KEY}\n")
        );
        assert_eq!(std::fs::metadata(&target).unwrap().nlink(), 2);
    }

    #[tokio::test]
    async fn key_changes_refuse_anything_that_is_not_a_regular_file() {
        let w = managed();
        let ssh = w.path("home/alice/.ssh");
        std::fs::create_dir(&ssh).unwrap();
        let add = json!({"user": "alice", "action": "add_key", "key": ED_KEY});

        // a directory where the file should be
        std::fs::create_dir(ssh.join("authorized_keys")).unwrap();
        let text = error_text(w.modify("adam", add.clone()).await);
        assert!(text.contains("not a regular file"), "{text}");
        std::fs::remove_dir(ssh.join("authorized_keys")).unwrap();

        // a FIFO: opening it must not hang, and nothing is written to it
        nix::unistd::mkfifo(
            &ssh.join("authorized_keys"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let text = error_text(w.modify("adam", add.clone()).await);
        assert!(text.contains("not a regular file"), "{text}");
        std::fs::remove_file(ssh.join("authorized_keys")).unwrap();

        // ~/.ssh itself is a file
        std::fs::remove_dir(&ssh).unwrap();
        std::fs::write(&ssh, "not a directory").unwrap();
        let text = error_text(w.modify("adam", add).await);
        assert!(text.contains(".ssh"), "{text}");
        assert_eq!(std::fs::read_to_string(&ssh).unwrap(), "not a directory");
    }

    #[tokio::test]
    async fn key_changes_refuse_an_oversized_file() {
        let w = managed();
        let before = format!("{ED_KEY}\n{}", "#\n".repeat(600_000));
        let file = w.write_keys("alice", &before);
        for args in [
            json!({"user": "alice", "action": "add_key", "key": EC_KEY}),
            json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
        ] {
            let text = error_text(w.modify("adam", args).await);
            assert!(text.contains("too large"), "{text}");
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[tokio::test]
    async fn key_changes_need_a_real_home_directory_that_belongs_to_the_user() {
        let w = managed();
        // dora's home directory does not exist
        let text = error_text(
            w.modify(
                "adam",
                json!({"user": "dora", "action": "add_key", "key": ED_KEY}),
            )
            .await,
        );
        assert!(text.contains("home directory"), "{text}");
        assert!(!w.path("home/dora").exists());

        // a home directory that is itself a symbolic link is not followed
        std::os::unix::fs::symlink(w.path("home/bob"), w.path("home/dora")).unwrap();
        let text = error_text(
            w.modify(
                "adam",
                json!({"user": "dora", "action": "add_key", "key": ED_KEY}),
            )
            .await,
        );
        assert!(text.contains("home directory"), "{text}");
        assert!(!w.path("home/bob/.ssh").exists());

        // a home directory owned by someone other than the user (or root)
        let mut env = w.env();
        let (uid, gid) = env.file_owner.unwrap();
        env.file_owner = Some((uid + 1, gid));
        let text = error_text(
            w.modify_in(
                env,
                "adam",
                json!({"user": "alice", "action": "add_key", "key": ED_KEY}),
            )
            .await,
        );
        assert!(text.contains("not owned by"), "{text}");
        assert!(!w.path("home/alice/.ssh").exists());
    }

    #[tokio::test]
    async fn key_changes_refuse_an_ssh_directory_or_file_owned_by_someone_else() {
        let w = managed();
        let before = format!("{ED_KEY}\n");
        let file = w.write_keys("alice", &before);
        // Seen from an account with another uid, alice's files belong to "someone else".
        let mut env = w.env();
        let (uid, gid) = env.file_owner.unwrap();
        env.file_owner = Some((uid + 1, gid));
        for args in [
            json!({"user": "alice", "action": "add_key", "key": EC_KEY}),
            json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
        ] {
            let text = error_text(w.modify_in(env.clone(), "adam", args).await);
            assert!(text.contains("not owned by"), "{text}");
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[tokio::test]
    async fn remove_key_removes_only_the_matching_lines_and_keeps_the_rest_byte_for_byte() {
        let w = managed();
        let before = format!(
            "# header comment\r\n\
             {ED_KEY}\n\
             \n\
             from=\"10.0.0.1\",command=\"/usr/bin/true\" {EC_KEY}\n\
             this line is not a key\n\
             \tno-pty  {ED_KEY}   \n\
             {ED2_KEY}"
        );
        let file = w.write_keys("alice", &before);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        let text = ok_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
            )
            .await,
        );
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!(
                "# header comment\r\n\
                 \n\
                 from=\"10.0.0.1\",command=\"/usr/bin/true\" {EC_KEY}\n\
                 this line is not a key\n\
                 {ED2_KEY}"
            )
        );
        assert!(text.contains("2 lines"), "{text}");
        assert!(text.contains(ED_FP), "{text}");
        assert_eq!(mode_of(&file), 0o640);
        assert_eq!(w.ssh_entries("alice"), ["authorized_keys"]);

        // a key behind options is found by its fingerprint as well
        ok_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "remove_key", "fingerprint": EC_FP}),
            )
            .await,
        );
        let after = std::fs::read_to_string(&file).unwrap();
        assert!(!after.contains("ecdsa"), "{after}");
        assert!(after.contains(ED2_KEY), "{after}");
    }

    #[tokio::test]
    async fn remove_key_fails_when_there_is_nothing_to_remove() {
        let w = managed();
        // no ~/.ssh at all
        let text = error_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
            )
            .await,
        );
        assert!(text.contains("no authorized_keys file"), "{text}");
        assert!(
            !w.path("home/alice/.ssh").exists(),
            "removing must not create anything"
        );

        // a file without that key
        let before = format!("{ED2_KEY}\n");
        let file = w.write_keys("alice", &before);
        let text = error_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
            )
            .await,
        );
        assert!(text.contains("no key with fingerprint"), "{text}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[tokio::test]
    async fn removing_the_last_key_leaves_an_empty_file() {
        let w = managed();
        let file = w.write_keys("alice", &format!("{ED_KEY}\n"));
        ok_text(
            w.modify(
                "adam",
                json!({"user": "alice", "action": "remove_key", "fingerprint": ED_FP}),
            )
            .await,
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
    }

    #[test]
    fn a_new_ssh_directory_is_only_handed_over_if_it_is_the_one_just_made() {
        // What `open_ssh_dir` checks before it changes the owner of a directory it has
        // just created: ours, private, and empty.
        let dir = tempfile::tempdir().unwrap();
        let me = rustix::process::geteuid().as_raw();
        let fresh = dir.path().join("fresh");
        std::fs::create_dir(&fresh).unwrap();
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o700)).unwrap();
        let open = |path: &std::path::Path| std::fs::File::open(path).unwrap();
        assert!(is_fresh_private_dir(&open(&fresh), me));
        // not ours
        assert!(!is_fresh_private_dir(&open(&fresh), me + 1));
        // open to others
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(!is_fresh_private_dir(&open(&fresh), me));
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o700)).unwrap();
        // not empty
        std::fs::write(fresh.join("something"), "x").unwrap();
        assert!(!is_fresh_private_dir(&open(&fresh), me));
    }
}
