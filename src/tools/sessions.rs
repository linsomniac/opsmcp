//! Ending a user's login sessions (session_terminate).
//!
//! AIDEV-NOTE: locking an account (user_modify) refuses new logins but leaves the
//! sessions that are already open; this is the other half. It ends sessions and changes
//! nothing lasting. The same accounts are off limits as for user_modify, plus the one
//! opsmcp itself runs as.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::args::{Args, Param};
use super::process::parse_uid;
use super::unitres::property_blocks;
use super::users::{Account, parse_passwd};
use super::{
    Ctx, Tool, ToolError, ToolResult, blocking, command_ok, command_text, format_table,
    one_line_cell, required,
};
use crate::config::is_account_name;
use crate::exec::CmdOutput;
use crate::glob::glob_match;
use crate::policy::Access;
use crate::timefmt::human_duration;

/// Where the account database and /proc are, who the server runs as, and how long to
/// wait for sessions to end. A parameter so that tests can run against a temporary
/// directory; the server always uses `Env::system()`.
#[derive(Clone, Debug)]
pub struct Env {
    pub passwd: PathBuf,
    pub proc: PathBuf,
    /// The uid opsmcp runs as: that account's sessions are never ended.
    pub own_uid: u32,
    /// How long to wait, after asking, for the sessions to be gone.
    pub settle: Duration,
}

impl Env {
    pub fn system() -> Env {
        Env {
            passwd: PathBuf::from("/etc/passwd"),
            proc: PathBuf::from("/proc"),
            own_uid: rustix::process::geteuid().as_raw(),
            settle: Duration::from_secs(3),
        }
    }
}

const ACTIONS: [&str; 2] = ["list", "terminate"];
/// The "nobody" account: above every `min_uid`, but not a person.
const NOBODY_UID: u32 = 65534;
/// The most sessions whose details are looked up for a listing.
const MAX_DETAILED: usize = 20;
/// The account database is small; this is only a bound.
const MAX_PASSWD_BYTES: u64 = 16 << 20;
/// The most entries of /proc looked at when counting a user's processes.
const MAX_PROC_ENTRIES: usize = 1_000_000;
/// How often to look, while waiting for sessions to end.
const POLL: Duration = Duration::from_millis(250);
const SESSION_PROPERTIES: [&str; 10] = [
    "Id",
    "Name",
    "User",
    "Class",
    "Type",
    "State",
    "Remote",
    "RemoteHost",
    "TTY",
    "Timestamp",
];

pub fn tools() -> Vec<Tool> {
    tools_with(Env::system())
}

/// The tool, working on the account database and /proc named by `env`.
pub fn tools_with(env: Env) -> Vec<Tool> {
    let env = Arc::new(env);
    vec![Tool::new(
        "session_terminate",
        "End a user's login sessions (loginctl terminate-user): every process in them is \
         stopped. Use it after locking an account with user_modify, which leaves the \
         sessions that are already open, or for an account that has been compromised. \
         action=list shows the user's sessions first; session ends just one of them. The \
         superuser, system accounts and the accounts this host's configuration protects \
         cannot be touched. Nothing lasting is changed: the user can log in again unless \
         the account is locked. Only accounts in the local passwd file are handled.",
        Access::Write,
        "user.session",
        vec![
            Param::str("user", "The account whose sessions to list or end")
                .max_len(32)
                .required(),
            Param::choice(
                "action",
                "list: show the user's sessions; terminate: end them",
                &ACTIONS,
            )
            .required(),
            Param::str(
                "session",
                "A session id as list shows it: act on that one session only",
            )
            .max_len(32),
        ],
        move |ctx, args| session_terminate(env.clone(), ctx, args),
    )]
}

// ---- parsing ---------------------------------------------------------------------------

/// One row of `loginctl list-sessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub uid: u32,
    pub user: String,
}

/// A session id as logind writes them: a short word of letters, digits, `_` and `-`.
///
/// AIDEV-NOTE: ids reach loginctl's command line, from the caller and from loginctl's
/// own listing alike, so both are held to this: nothing that starts with `-` (an
/// option), no spaces, nothing else.
pub fn is_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && !id.starts_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The sessions in `loginctl list-sessions --no-legend` output. Its columns have grown
/// over the years, but the first three have always been the session, the uid and the
/// user name; nothing else is taken from it. Rows of any other shape are skipped.
pub fn parse_sessions(text: &str) -> Vec<SessionRow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(id), Some(uid), Some(user)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(uid) = uid.parse() else {
            continue;
        };
        if is_session_id(id) {
            rows.push(SessionRow {
                id: id.to_string(),
                uid,
                user: user.to_string(),
            });
        }
    }
    rows
}

/// How many processes have `uid` as their real uid. File I/O: call it from a blocking
/// job.
pub fn count_processes(proc: &Path, uid: u32) -> usize {
    let Ok(entries) = std::fs::read_dir(proc) else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten().take(MAX_PROC_ENTRIES) {
        let name = entry.file_name();
        let is_pid = name
            .to_str()
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !is_pid {
            continue;
        }
        // A process can exit between the listing and the read: then it does not count.
        if read_capped(&entry.path().join("status"), 16 * 1024)
            .is_some_and(|status| parse_uid(&status) == Some(uid))
        {
            count += 1;
        }
    }
    count
}

/// At most `max` bytes of a file as text. `None` if it cannot be read.
fn read_capped(path: &Path, max: u64) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(max).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

/// The account named `user` in the passwd file, and, if ANOTHER name for the same uid
/// matches one of the `protected` patterns, that pattern.
///
/// AIDEV-NOTE: `users.protected` lists account names, but logind keeps sessions by uid,
/// and `terminate-user` is given the uid. Two names can share a uid, so a name that is
/// not protected may be a second name for an account that is: the sessions it would end
/// are the protected account's.
fn find_account(
    passwd: &Path,
    user: &str,
    protected: &[String],
) -> Result<(Account, Option<String>), ToolError> {
    let text = read_capped(passwd, MAX_PASSWD_BYTES)
        .ok_or_else(|| ToolError::Failed(format!("cannot read {}", passwd.display())))?;
    let accounts = parse_passwd(&text);
    let Some(uid) = accounts
        .iter()
        .find(|account| account.name == user)
        .map(|account| account.uid)
    else {
        return Err(ToolError::Failed(format!(
            "there is no account named {user} in {} (accounts from LDAP or sssd cannot be \
             handled here)",
            passwd.display()
        )));
    };
    let shared = accounts
        .iter()
        .filter(|account| account.uid == uid && account.name != user)
        .find_map(|account| {
            protected
                .iter()
                .find(|pattern| glob_match(pattern, &account.name))
                .cloned()
        });
    accounts
        .into_iter()
        .find(|account| account.name == user)
        .map(|account| (account, shared))
        .ok_or_else(|| ToolError::Internal("the account vanished from the list".to_string()))
}

// ---- loginctl --------------------------------------------------------------------------

async fn loginctl(ctx: &Ctx, argv: Vec<String>) -> Result<CmdOutput, ToolError> {
    ctx.run(ctx.command("loginctl")?.args(argv)).await
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| word.to_string()).collect()
}

/// The open sessions of the user with this uid.
///
/// AIDEV-NOTE: sessions are matched by uid, not by name. The uid is the one the passwd
/// file gives for the account, which is also what every refusal below was decided on.
/// (Two account names that share a uid share their sessions, as they share everything.)
async fn sessions_of(ctx: &Ctx, uid: u32) -> Result<Vec<SessionRow>, ToolError> {
    let out = loginctl(ctx, words(&["list-sessions", "--no-legend", "--no-pager"])).await?;
    if !command_ok(&out) {
        return Err(ToolError::Failed(format!(
            "cannot list login sessions: {}",
            command_text(&out).trim()
        )));
    }
    Ok(parse_sessions(&String::from_utf8_lossy(&out.stdout))
        .into_iter()
        .filter(|row| row.uid == uid)
        .collect())
}

/// `loginctl show-session` for these properties of these sessions, as one map per
/// session that answered.
///
/// AIDEV-NOTE: one `--property=` argument per property. loginctl prints NOTHING for a
/// comma-separated list (unlike systemctl), which would make every session look as if
/// it belonged to nobody.
async fn show_sessions(
    ctx: &Ctx,
    properties: &[&str],
    ids: &[String],
) -> Result<Vec<BTreeMap<String, String>>, ToolError> {
    let mut argv = vec!["show-session".to_string()];
    argv.extend(properties.iter().map(|p| format!("--property={p}")));
    argv.push("--".to_string());
    argv.extend(ids.iter().cloned());
    let out = loginctl(ctx, argv).await?;
    // A session that ended a moment ago makes loginctl exit non-zero after printing the
    // others; what it did print is still good.
    Ok(property_blocks(&String::from_utf8_lossy(&out.stdout)))
}

/// Checks that `id` is an open session of this account. The refusal is the same whether
/// the session is someone else's or does not exist, so it says nothing about other
/// people's sessions.
///
/// AIDEV-NOTE: the check and the `terminate-session` that follows are two commands, so
/// in principle the session could end and its id be given to someone else's new session
/// in between. logind numbers sessions upwards and does not hand an id out again while
/// the machine is up, so this cannot happen in practice; if that ever changes, this is
/// the place to look.
async fn check_owner(
    ctx: &Ctx,
    id: &str,
    account: &Account,
    ending: bool,
) -> Result<(), ToolError> {
    let blocks = show_sessions(ctx, &["Name", "User"], &[id.to_string()]).await?;
    let owner = blocks
        .first()
        .and_then(|block| block.get("User"))
        .and_then(|uid| uid.parse::<u32>().ok());
    if owner == Some(account.uid) {
        return Ok(());
    }
    let nothing = if ending { "; nothing was ended" } else { "" };
    Err(ToolError::Failed(format!(
        "{id} is not an open session of {}{nothing}",
        account.name
    )))
}

/// The table of sessions for a listing.
async fn session_table(ctx: &Ctx, uid: u32, ids: &[String]) -> Result<String, ToolError> {
    let detailed: Vec<String> = ids.iter().take(MAX_DETAILED).cloned().collect();
    let blocks = show_sessions(ctx, &SESSION_PROPERTIES, &detailed).await?;
    let mut rows = Vec::new();
    for id in &detailed {
        // Only what loginctl says about this very session, and only if it still belongs
        // to this user (ids are reused once a session has ended).
        let block = blocks.iter().find(|block| {
            block.get("Id") == Some(id)
                && block.get("User").and_then(|u| u.parse::<u32>().ok()) == Some(uid)
        });
        let field = |name: &str| -> String {
            match block.and_then(|block| block.get(name)) {
                Some(value) if !value.is_empty() => one_line_cell(value),
                Some(_) => "-".to_string(),
                None => "?".to_string(),
            }
        };
        let from = match block
            .and_then(|block| block.get("Remote"))
            .map(String::as_str)
        {
            Some("yes") => match field("RemoteHost").as_str() {
                "-" | "?" => "remote".to_string(),
                host => host.to_string(),
            },
            Some(_) => "local".to_string(),
            None => "?".to_string(),
        };
        rows.push(vec![
            id.clone(),
            field("Class"),
            field("Type"),
            field("State"),
            field("TTY"),
            from,
            field("Timestamp"),
        ]);
    }
    let mut text = format_table(
        &["SESSION", "CLASS", "TYPE", "STATE", "TTY", "FROM", "SINCE"],
        &rows,
        &[false; 7],
    );
    if ids.len() > detailed.len() {
        text.push_str(&format!(
            "[{} more sessions not shown: {}]\n",
            ids.len() - detailed.len(),
            ids.iter()
                .skip(MAX_DETAILED)
                .take(50)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(text)
}

/// Waits, for at most `settle`, until none of `targets` is an open session any more.
/// Returns the targets that are still open and every session the user still has; `None`
/// if the sessions could not be listed.
async fn wait_until_gone(
    ctx: &Ctx,
    uid: u32,
    targets: &[String],
    settle: Duration,
) -> Option<(Vec<String>, Vec<String>)> {
    let deadline = Instant::now() + settle;
    loop {
        let open: Vec<String> = sessions_of(ctx, uid)
            .await
            .ok()?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let still: Vec<String> = targets
            .iter()
            .filter(|target| open.contains(target))
            .cloned()
            .collect();
        let left = deadline.saturating_duration_since(Instant::now());
        if still.is_empty() || left.is_zero() {
            return Some((still, open));
        }
        tokio::time::sleep(POLL.min(left)).await;
    }
}

fn counted_sessions(count: usize) -> String {
    match count {
        1 => "the only login session".to_string(),
        count => format!("all {count} login sessions"),
    }
}

/// What is said about the processes the user still has.
async fn processes_line(ctx: &Ctx, env: &Arc<Env>, account: &Account) -> String {
    let (proc, uid) = (env.proc.clone(), account.uid);
    let user = &account.name;
    match blocking(ctx.clone(), move || Ok(count_processes(&proc, uid))).await {
        Ok(0) => format!("No process owned by {user} is left running.\n"),
        Ok(count) => {
            let (processes, are) = if count == 1 {
                ("process", "is")
            } else {
                ("processes", "are")
            };
            format!(
                "{count} {processes} owned by {user} {are} still running (started outside a \
                 login session, left in the background, or still shutting down): \
                 process_list shows them and process_signal can stop them.\n"
            )
        }
        Err(_) => format!("[the processes still owned by {user} could not be counted]\n"),
    }
}

async fn session_terminate(env: Arc<Env>, ctx: Ctx, args: Args) -> ToolResult {
    let user = required(&args, "user")?;
    if !is_account_name(user) {
        return Err(ToolError::Invalid(format!(
            "{user:?} is not a user name (letters, digits and _ . - only, at most 32 characters)"
        )));
    }
    let user = user.to_string();
    let ending = required(&args, "action")? == "terminate";
    let session = match args.str("session") {
        Some(id) if is_session_id(id) => Some(id.to_string()),
        Some(id) => {
            return Err(ToolError::Invalid(format!(
                "{id:?} is not a session id (letters, digits, _ and - only, as list shows them)"
            )));
        }
        None => None,
    };

    // The limits that hold whatever the caller has been granted.
    let limits = &ctx.cfg().users;
    if let Some(pattern) = limits.protected.iter().find(|p| glob_match(p, &user)) {
        let reason =
            format!("{user} is a protected account on this host (users.protected: {pattern})");
        return Err(ctx.deny(Some(&user), &reason));
    }
    // AIDEV-NOTE: a local or SSH caller is known by their Unix user name, and this call
    // runs inside one of that user's sessions. Ending them all would kill the call
    // before it could answer, and usually is not what was meant. One named session is
    // the caller's own decision.
    if ending && session.is_none() && ctx.principal().name == user {
        let reason = format!(
            "{user} is the account this call is made from: ending all of its sessions would \
             end this call too (name one session, or call from another account)"
        );
        return Err(ctx.deny(Some(&user), &reason));
    }

    let auth = ctx.authorize(Some(&user))?;

    // Only now is anything looked up, so that a caller without the grant learns nothing
    // about which accounts exist.
    let (passwd, wanted) = (env.passwd.clone(), user.clone());
    let protected = limits.protected.clone();
    let (account, shared_with_protected) = blocking(ctx.clone(), move || {
        find_account(&passwd, &wanted, &protected)
    })
    .await?;
    let refusal = if account.uid == 0 {
        Some(format!(
            "{user} has uid 0: the superuser's sessions are never ended through opsmcp"
        ))
    } else if account.uid == NOBODY_UID {
        Some(format!(
            "{user} is the 'nobody' account, not a person's account"
        ))
    } else if account.uid < limits.min_uid {
        Some(format!(
            "{user} is a system account (uid {} is below users.min_uid = {})",
            account.uid, limits.min_uid
        ))
    } else if account.uid == env.own_uid {
        Some(format!(
            "{user} is the account opsmcp runs as: ending its sessions would end opsmcp itself"
        ))
    } else if let Some(pattern) = shared_with_protected {
        // (the other account is not named: the caller asked about this one)
        Some(format!(
            "{user} has the same uid ({}) as a protected account on this host \
             (users.protected: {pattern}): sessions belong to the uid, so these are that \
             account's sessions too",
            account.uid
        ))
    } else {
        None
    };
    if let Some(reason) = refusal {
        return Err(ctx.deny(Some(&user), &reason));
    }
    let who = format!("{user} (uid {})", account.uid);

    let open: Vec<String> = sessions_of(&ctx, account.uid)
        .await?
        .into_iter()
        .map(|row| row.id)
        .collect();
    if let Some(id) = &session {
        check_owner(&ctx, id, &account, ending).await?;
    }

    if !ending {
        return match &session {
            Some(id) => {
                let table = session_table(&ctx, account.uid, std::slice::from_ref(id)).await?;
                auth.ok(format!("{who}: session {id}.\n{table}"))
            }
            None if open.is_empty() => auth.ok(format!("{who} has no login sessions.\n")),
            None => {
                let table = session_table(&ctx, account.uid, &open).await?;
                let sessions = if open.len() == 1 {
                    "1 login session".to_string()
                } else {
                    format!("{} login sessions", open.len())
                };
                auth.ok(format!("{who} has {sessions}.\n{table}"))
            }
        };
    }

    // ---- terminate ----
    let (targets, argv, what) = match &session {
        Some(id) => (
            vec![id.clone()],
            words(&["terminate-session", "--no-ask-password", "--", id]),
            format!("session {id} of {who}"),
        ),
        None => {
            if open.is_empty() {
                let processes = processes_line(&ctx, &env, &account).await;
                return auth.ok(format!(
                    "{who} has no login sessions: nothing was ended.\n{processes}"
                ));
            }
            (
                open.clone(),
                // by uid: the very account every check above was made on
                words(&[
                    "terminate-user",
                    "--no-ask-password",
                    "--",
                    &account.uid.to_string(),
                ]),
                format!(
                    "{} of {who}: {}",
                    counted_sessions(open.len()),
                    open.join(", ")
                ),
            )
        }
    };
    let out = loginctl(&ctx, argv).await?;
    if !command_ok(&out) {
        return auth.failed(format!("{}Ending {what}: FAILED.\n", command_text(&out)));
    }

    let mut text = String::new();
    match wait_until_gone(&ctx, account.uid, &targets, env.settle).await {
        Some((still, left)) if still.is_empty() => {
            text.push_str(&format!("Ended {what}.\n"));
            if left.is_empty() {
                text.push_str(&format!("No session of {user} is left.\n"));
            } else {
                text.push_str(&format!(
                    "Sessions of {user} still open: {}.\n",
                    left.join(", ")
                ));
            }
        }
        Some((still, _)) => text.push_str(&format!(
            "Asked systemd to end {what}; still open after {}: {}. Processes that ignore \
             the request are killed after a time: list the sessions again shortly.\n",
            human_duration(env.settle.as_secs()),
            still.join(", ")
        )),
        None => text.push_str(&format!(
            "Asked systemd to end {what}.\n[which sessions are left could not be checked]\n"
        )),
    }
    text.push_str(&processes_line(&ctx, &env, &account).await);
    text.push_str(&format!(
        "Nothing lasting was changed: {user} can log in again. To prevent that, lock the \
         account with user_modify (action lock).\n"
    ));
    auth.ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::policy::Access;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // ---- parsing -----------------------------------------------------------------------

    #[test]
    fn a_session_id_is_a_short_plain_word() {
        for good in ["1", "189", "c2", "session_7", "a-b", &"9".repeat(32)] {
            assert!(is_session_id(good), "{good:?}");
        }
        for bad in [
            "",
            "-1",
            "--all",
            "1;id",
            "a b",
            "1/2",
            "é",
            &"9".repeat(33),
        ] {
            assert!(!is_session_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn sessions_are_read_from_the_first_three_columns() {
        // systemd 257 and later: SESSION UID USER SEAT LEADER CLASS TTY IDLE SINCE
        let new = "189 1000 alice -     2530613 user    pts/63 yes 3h 43min ago\n\
                   \x20\x202 1000 alice seat0 2627    user    tty2   no  -\n\
                   \x20\x203 1001 bob   -     2640    manager -      no  -\n";
        let row = |id: &str, uid: u32, user: &str| SessionRow {
            id: id.to_string(),
            uid,
            user: user.to_string(),
        };
        assert_eq!(
            parse_sessions(new),
            [
                row("189", 1000, "alice"),
                row("2", 1000, "alice"),
                row("3", 1001, "bob")
            ]
        );
        // older systemd: SESSION UID USER SEAT TTY
        let old = "     c1   1000 alice seat0 tty1\n      7   1001 bob         pts/0\n";
        assert_eq!(
            parse_sessions(old),
            [row("c1", 1000, "alice"), row("7", 1001, "bob")]
        );
        // anything that is not a session row is skipped, as is an id we would not pass on
        let junk = "\n2 sessions listed.\nx;id 1000 alice\n-9 1000 alice\n12 abc alice\n12\n";
        assert_eq!(parse_sessions(junk), Vec::<SessionRow>::new());
    }

    fn put(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn status(uid: u32) -> String {
        format!(
            "Name:\tbash\nUmask:\t0022\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t100\t100\t100\t100\n"
        )
    }

    #[test]
    fn processes_are_counted_by_their_real_uid() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        put(proc, "100/status", &status(4242));
        put(proc, "101/status", &status(4242));
        put(proc, "200/status", &status(4300));
        // not processes: no number, or nothing to read
        put(proc, "self/status", &status(4242));
        put(proc, "sys/kernel/x", "1");
        std::fs::create_dir(proc.join("300")).unwrap();
        assert_eq!(count_processes(proc, 4242), 2);
        assert_eq!(count_processes(proc, 4300), 1);
        assert_eq!(count_processes(proc, 9), 0);
        assert_eq!(count_processes(&proc.join("missing"), 4242), 0);
    }

    // ---- the tool ----------------------------------------------------------------------

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        toor:x:0:0:second root:/root:/bin/bash\n\
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
        alice:x:4242:4242:Alice:/home/alice:/bin/bash\n\
        bob:x:4300:4300:Bob:/home/bob:/bin/bash\n\
        carol:x:4400:4400:Carol:/home/carol:/bin/bash\n\
        svc-deploy:x:4500:4500:Deploys:/srv/deploy:/bin/bash\n\
        deployer:x:4500:4500:Another name for uid 4500:/srv/deploy:/bin/bash\n\
        opsd:x:7777:7777:the server:/var/lib/opsd:/usr/sbin/nologin\n\
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";

    /// A host with accounts, processes and a stand-in loginctl that remembers what it
    /// was told to end.
    struct World {
        dir: tempfile::TempDir,
        fake: FakeBins,
        host: Arc<Host>,
        audit: MemorySink,
        settle: Duration,
    }

    /// The stand-in loginctl. alice (4242) has sessions 12 (remote), 14 (local) and 3 (her
    /// service manager); bob (4300) has session 20. `terminate-user` and
    /// `terminate-session` are remembered in `state`, and `list-sessions` leaves out
    /// what was ended, unless `sticky`, in which case nothing ever ends. With `failing`
    /// the terminate commands fail.
    fn loginctl(state: &Path, sticky: bool, failing: bool) -> String {
        let state = state.display();
        let sticky = if sticky { "1" } else { "0" };
        let failing = if failing { "1" } else { "0" };
        format!(
            r#"
state='{state}'
sticky={sticky}
failing={failing}
session() {{
  case "$1" in
    12) printf 'Id=12\nName=alice\nUser=4242\nTimestamp=Fri 2026-11-20 07:05:55 UTC\nTTY=pts/1\nRemote=yes\nRemoteHost=10.0.0.5\nType=tty\nClass=user\nState=active\n' ;;
    14) printf 'Id=14\nName=alice\nUser=4242\nTimestamp=Thu 2026-11-19 09:00:00 UTC\nTTY=tty2\nRemote=no\nRemoteHost=\nType=tty\nClass=user\nState=online\n' ;;
    3) printf 'Id=3\nName=alice\nUser=4242\nTimestamp=Thu 2026-11-19 09:00:01 UTC\nTTY=\nRemote=no\nRemoteHost=\nType=unspecified\nClass=manager\nState=active\n' ;;
    20) printf 'Id=20\nName=bob\nUser=4300\nTimestamp=Fri 2026-11-20 08:00:00 UTC\nTTY=pts/3\nRemote=yes\nRemoteHost=10.0.0.9\nType=tty\nClass=user\nState=active\n' ;;
    *) echo "Failed to get path for session '$1': No session '$1' known" >&2; exit 1 ;;
  esac
}}
verb=
for a; do
  case "$a" in
    list-sessions|show-session|terminate-user|terminate-session) verb=$a; break ;;
  esac
done
for last; do :; done
case "$verb" in
  list-sessions)
    if [ ! -e "$state/user-4242" ]; then
      [ -e "$state/session-12" ] || echo " 12 4242 alice - 1001 user pts/1 no -"
      [ -e "$state/session-14" ] || echo " 14 4242 alice seat0 1002 user tty2 no -"
      [ -e "$state/session-3" ] || echo "  3 4242 alice - 900 manager - no -"
    fi
    echo " 20 4300 bob - 1003 user pts/3 no -"
    echo "x;id 4242 alice - 1 user - no -" ;;
  show-session)
    seen=0; first=1
    for a; do
      if [ "$seen" = 1 ]; then
        [ "$first" = 1 ] || echo
        first=0
        session "$a"
      elif [ "$a" = "--" ]; then
        seen=1
      fi
    done ;;
  terminate-user|terminate-session)
    if [ "$failing" = 1 ]; then echo "Failed to terminate: Access denied" >&2; exit 1; fi
    if [ "$sticky" = 0 ]; then
      if [ "$verb" = terminate-user ]; then : > "$state/user-$last"; else : > "$state/session-$last"; fi
    fi ;;
esac
"#
        )
    }

    fn world_with(sticky: bool, failing: bool, settle: Duration) -> World {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("state")).unwrap();
        put(root, "passwd", PASSWD);
        put(root, "proc/100/status", &status(4242));
        put(root, "proc/101/status", &status(4242));
        put(root, "proc/200/status", &status(4300));
        let fake =
            FakeBins::new().add_script("loginctl", &loginctl(&root.join("state"), sticky, failing));
        let (host, audit) = host(&format!(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.alice_only]
allow = ["user.session:alice"]
[unix_users.adam]
roles = ["admin"]
[unix_users.alice]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[unix_users.sam]
roles = ["alice_only"]
[users]
protected = ["root", "svc-*"]
{}"#,
            fake.config_only()
        ));
        World {
            dir,
            fake,
            host,
            audit,
            settle,
        }
    }

    fn world() -> World {
        world_with(false, false, Duration::ZERO)
    }

    impl World {
        fn env(&self) -> Env {
            Env {
                passwd: self.dir.path().join("passwd"),
                proc: self.dir.path().join("proc"),
                own_uid: 7777,
                settle: self.settle,
            }
        }

        async fn run(&self, user: &str, arguments: Value) -> ToolResult {
            let tool = find(tools_with(self.env()), "session_terminate");
            call(&self.host, user, &tool, arguments).await
        }

        /// The runs of loginctl whose first argument is `verb`.
        fn runs(&self, verb: &str) -> Vec<Vec<String>> {
            self.fake
                .calls("loginctl")
                .into_iter()
                .filter(|argv| argv.first().is_some_and(|a| a == verb))
                .collect()
        }

        fn last_record(&self) -> Value {
            self.audit.records().last().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn listing_shows_only_the_named_users_sessions() {
        let w = world();
        let text = ok_text(
            w.run("adam", json!({"user": "alice", "action": "list"}))
                .await,
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "alice (uid 4242) has 3 login sessions.", "{text}");
        assert!(
            lines[1].starts_with("SESSION") && lines[1].contains("FROM"),
            "{text}"
        );
        assert!(
            lines[2].starts_with("12 ")
                && lines[2].contains("pts/1")
                && lines[2].contains("10.0.0.5")
                && lines[2].contains("Fri 2026-11-20 07:05:55 UTC"),
            "{text}"
        );
        assert!(
            lines[3].starts_with("14 ") && lines[3].contains("tty2") && lines[3].contains("local"),
            "{text}"
        );
        assert!(
            lines[4].starts_with("3 ") && lines[4].contains("manager"),
            "{text}"
        );
        // nothing of anyone else's
        assert!(!text.contains("bob"), "{text}");
        assert!(!text.contains("pts/3"), "{text}");
        assert!(!text.contains("10.0.0.9"), "{text}");
        assert_eq!(
            w.runs("list-sessions"),
            [strings(&["list-sessions", "--no-legend", "--no-pager"])]
        );
        // one run for the details; only ids that look like ids are passed on
        let shows = w.runs("show-session");
        assert_eq!(shows.len(), 1);
        assert_eq!(
            shows[0][shows[0].len() - 4..],
            strings(&["--", "12", "14", "3"])
        );
        assert!(
            shows[0].contains(&"--property=RemoteHost".to_string()),
            "{shows:?}"
        );
        assert_eq!(w.runs("terminate-user"), Vec::<Vec<String>>::new());
        assert_eq!(w.runs("terminate-session"), Vec::<Vec<String>>::new());
        assert_eq!(w.last_record()["resource"], "alice");
        assert_eq!(w.last_record()["decision"], "allow");
    }

    #[tokio::test]
    async fn terminating_ends_every_session_of_the_user_by_uid() {
        let w = world();
        let text = ok_text(
            w.run("adam", json!({"user": "alice", "action": "terminate"}))
                .await,
        );
        assert_eq!(
            w.runs("terminate-user"),
            [strings(&[
                "terminate-user",
                "--no-ask-password",
                "--",
                "4242"
            ])]
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0], "Ended all 3 login sessions of alice (uid 4242): 12, 14, 3.",
            "{text}"
        );
        assert!(text.contains("No session of alice is left."), "{text}");
        assert!(
            text.contains("2 processes owned by alice are still running"),
            "{text}"
        );
        assert!(text.contains("process_signal"), "{text}");
        // what was and was not changed
        assert!(text.contains("alice can log in again"), "{text}");
        assert!(text.contains("user_modify"), "{text}");
        assert_eq!(w.runs("terminate-session"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn one_session_can_be_ended_after_checking_whose_it_is() {
        let w = world();
        let text = ok_text(
            w.run(
                "adam",
                json!({"user": "alice", "action": "terminate", "session": "12"}),
            )
            .await,
        );
        assert_eq!(
            w.runs("show-session")[0],
            strings(&[
                "show-session",
                "--property=Name",
                "--property=User",
                "--",
                "12"
            ])
        );
        assert_eq!(
            w.runs("terminate-session"),
            [strings(&[
                "terminate-session",
                "--no-ask-password",
                "--",
                "12"
            ])]
        );
        assert_eq!(w.runs("terminate-user"), Vec::<Vec<String>>::new());
        assert!(
            text.starts_with("Ended session 12 of alice (uid 4242).\n"),
            "{text}"
        );
        assert!(
            text.contains("Sessions of alice still open: 14, 3."),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_session_of_someone_else_or_of_nobody_is_never_ended() {
        let w = world();
        // 20 is bob's; 99 does not exist. The answer is the same, so it says nothing
        // about other people's sessions.
        let mut messages = Vec::new();
        for session in ["20", "99"] {
            let result = w
                .run(
                    "adam",
                    json!({"user": "alice", "action": "terminate", "session": session}),
                )
                .await;
            match result {
                Err(ToolError::Failed(message)) => {
                    assert!(message.contains("nothing was ended"), "{message}");
                    messages.push(message.replace(session, "N"));
                }
                other => panic!("{session}: expected a failure, got {other:?}"),
            }
        }
        assert_eq!(messages[0], messages[1]);
        assert_eq!(w.runs("terminate-session"), Vec::<Vec<String>>::new());
        // the same when only listing
        let result = w
            .run(
                "adam",
                json!({"user": "alice", "action": "list", "session": "20"}),
            )
            .await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    #[tokio::test]
    async fn listing_one_session_shows_just_that_one() {
        let w = world();
        let text = ok_text(
            w.run(
                "adam",
                json!({"user": "alice", "action": "list", "session": "14"}),
            )
            .await,
        );
        assert!(text.contains("tty2"), "{text}");
        assert!(!text.contains("pts/1"), "{text}");
        assert!(!text.contains("manager"), "{text}");
    }

    #[tokio::test]
    async fn names_and_session_ids_are_checked_before_anything_runs() {
        let w = world();
        for user in ["", "-x", "a b", "alice;id", "../alice", "root\nalice"] {
            let result = w.run("adam", json!({"user": user, "action": "list"})).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{user:?}: {result:?}"
            );
        }
        for session in ["", "-1", "--all", "12;id", "1 2", "é"] {
            let result = w
                .run(
                    "adam",
                    json!({"user": "alice", "action": "terminate", "session": session}),
                )
                .await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{session:?}: {result:?}"
            );
        }
        assert_eq!(w.fake.calls("loginctl"), Vec::<Vec<String>>::new());
        assert_eq!(w.audit.records().len(), 0);
    }

    #[tokio::test]
    async fn protected_accounts_are_refused_whatever_the_grant() {
        let w = world();
        for user in ["root", "svc-deploy"] {
            for action in ["list", "terminate"] {
                match w.run("adam", json!({"user": user, "action": action})).await {
                    Err(ToolError::Denied(message)) => {
                        assert!(message.contains("protected"), "{message}");
                    }
                    other => panic!("{user}: expected a refusal, got {other:?}"),
                }
                let record = w.last_record();
                assert_eq!(record["decision"], "deny");
                assert_eq!(record["resource"], user);
                assert!(
                    record["reason"]
                        .as_str()
                        .unwrap()
                        .contains("users.protected"),
                    "{record}"
                );
            }
        }
        assert_eq!(w.fake.calls("loginctl"), Vec::<Vec<String>>::new());
    }

    /// AIDEV-NOTE: `users.protected` lists NAMES, but logind ends sessions by uid. A
    /// second name for a protected account's uid must not be a way to its sessions.
    #[tokio::test]
    async fn another_name_for_a_protected_accounts_uid_is_refused_too() {
        let w = world();
        // deployer is not protected by name, but it is uid 4500, which is svc-deploy's
        for action in ["list", "terminate"] {
            match w
                .run("adam", json!({"user": "deployer", "action": action}))
                .await
            {
                Err(ToolError::Denied(message)) => {
                    assert!(
                        message.contains("same uid") && message.contains("users.protected"),
                        "{message}"
                    );
                    // the protected account is not named to the caller
                    assert!(!message.contains("svc-deploy"), "{message}");
                }
                other => panic!("{action}: expected a refusal, got {other:?}"),
            }
            let record = w.last_record();
            assert_eq!(record["decision"], "deny");
            assert_eq!(record["resource"], "deployer");
        }
        assert_eq!(w.fake.calls("loginctl"), Vec::<Vec<String>>::new());
        // an account that shares its uid with nobody protected is unaffected
        ok_text(
            w.run("adam", json!({"user": "bob", "action": "list"}))
                .await,
        );
    }

    #[tokio::test]
    async fn the_superuser_system_accounts_and_the_server_itself_are_refused() {
        let w = world();
        let cases = [
            // a second uid-0 account is still the superuser, whatever it is called
            ("toor", "uid 0"),
            ("daemon", "system account"),
            ("nobody", "nobody"),
            ("opsd", "opsmcp itself"),
        ];
        for (user, why) in cases {
            match w
                .run("adam", json!({"user": user, "action": "terminate"}))
                .await
            {
                Err(ToolError::Denied(message)) => {
                    assert!(message.contains(why), "{user}: {message}");
                }
                other => panic!("{user}: expected a refusal, got {other:?}"),
            }
            let record = w.last_record();
            assert_eq!(record["decision"], "deny");
            assert_eq!(record["resource"], user);
        }
        assert_eq!(w.fake.calls("loginctl"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn an_unknown_account_is_a_failure_only_for_a_caller_who_may_ask() {
        let w = world();
        match w
            .run("adam", json!({"user": "dave", "action": "list"}))
            .await
        {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("no account named dave"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(w.last_record()["decision"], "allow");
        // sam may act on alice only: for anyone else the answer is the same refusal,
        // whether or not the account exists
        for user in ["dave", "bob"] {
            let result = w.run("sam", json!({"user": user, "action": "list"})).await;
            assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
            assert_eq!(w.last_record()["decision"], "deny");
        }
        assert_eq!(w.fake.calls("loginctl"), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_grant_for_one_user_covers_that_user_only_and_readers_never() {
        let w = world();
        ok_text(
            w.run("sam", json!({"user": "alice", "action": "list"}))
                .await,
        );
        ok_text(
            w.run("sam", json!({"user": "alice", "action": "terminate"}))
                .await,
        );
        let result = w
            .run("sam", json!({"user": "bob", "action": "terminate"}))
            .await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        // a read-only role holds no write permission, even for listing through this tool
        for action in ["list", "terminate"] {
            let result = w
                .run("rita", json!({"user": "alice", "action": action}))
                .await;
            assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        }
        assert_eq!(w.runs("terminate-user").len(), 1);
    }

    #[tokio::test]
    async fn a_user_without_sessions_has_nothing_to_end() {
        let w = world();
        let text = ok_text(
            w.run("adam", json!({"user": "carol", "action": "terminate"}))
                .await,
        );
        assert!(
            text.starts_with("carol (uid 4400) has no login sessions: nothing was ended.\n"),
            "{text}"
        );
        assert_eq!(w.runs("terminate-user"), Vec::<Vec<String>>::new());
        let text = ok_text(
            w.run("adam", json!({"user": "carol", "action": "list"}))
                .await,
        );
        assert_eq!(text, "carol (uid 4400) has no login sessions.\n");
    }

    #[tokio::test]
    async fn sessions_that_are_slow_to_end_are_reported_as_still_open() {
        let w = world_with(true, false, Duration::from_millis(300));
        let started = std::time::Instant::now();
        let output = w
            .run("adam", json!({"user": "alice", "action": "terminate"}))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!output.is_error(), "{}", output.text());
        let first = output.text().lines().next().unwrap().to_string();
        assert!(
            first.starts_with("Asked systemd to end all 3 login sessions of alice (uid 4242)")
                && first.contains("still open")
                && first.contains("12, 14, 3"),
            "{first}"
        );
        assert_eq!(w.runs("terminate-user").len(), 1);
        // it looked more than once before giving up
        assert!(w.runs("list-sessions").len() >= 3);
    }

    #[tokio::test]
    async fn a_refusal_by_systemd_is_an_error_result() {
        let w = world_with(false, true, Duration::ZERO);
        let output = w
            .run("adam", json!({"user": "alice", "action": "terminate"}))
            .await
            .unwrap();
        assert!(output.is_error());
        assert!(output.text().contains("Access denied"), "{}", output.text());
        assert!(output.text().contains("FAILED"), "{}", output.text());
        assert!(!output.text().contains("Ended"), "{}", output.text());
    }

    #[tokio::test]
    async fn without_loginctl_the_tool_says_so() {
        let w = world();
        let fake = FakeBins::new().add("true", "", 0);
        let (host, _audit) = host(&format!(
            "[roles.admin]\nallow = [\"@all\"]\n[unix_users.adam]\nroles = [\"admin\"]\n{}",
            fake.config_only()
        ));
        let tool = find(tools_with(w.env()), "session_terminate");
        let result = call(
            &host,
            "adam",
            &tool,
            json!({"user": "alice", "action": "list"}),
        )
        .await;
        match result {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("loginctl"), "{message}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_caller_cannot_end_every_session_of_the_account_they_are_calling_from() {
        let w = world();
        // the caller IS alice (a local or SSH caller is known by their Unix user name)
        match w
            .run("alice", json!({"user": "alice", "action": "terminate"}))
            .await
        {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("this call"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(w.last_record()["decision"], "deny");
        assert_eq!(w.runs("terminate-user"), Vec::<Vec<String>>::new());
        // one named session of their own is their call to make, as is listing
        ok_text(
            w.run(
                "alice",
                json!({"user": "alice", "action": "terminate", "session": "14"}),
            )
            .await,
        );
        ok_text(
            w.run("alice", json!({"user": "alice", "action": "list"}))
                .await,
        );
        assert_eq!(w.runs("terminate-session").len(), 1);
    }

    #[test]
    fn the_tool_is_a_write_tool_with_its_own_permission() {
        let tools = tools();
        let tags: Vec<(&str, Access, &str)> = tools
            .iter()
            .map(|t| (t.name.as_str(), t.access, t.permission.as_str()))
            .collect();
        assert_eq!(tags, [("session_terminate", Access::Write, "user.session")]);
    }
}
