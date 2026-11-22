//! Replacing a configuration file safely: backup, replace in one step, optional check,
//! and putting the old content back when the check fails.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::args::{Args, Param};
use super::checks::{self, CHECKS, Check, Outcome};
use super::fs::{Names, check_limits, pin};
use super::paths::{check_absolute, lexical, within};
use super::{
    Authorized, CallClock, Ctx, Tool, ToolError, ToolResult, blocking, format_table, required,
};
use crate::config::Config;
use crate::exec::Cmd;
use crate::glob::glob_match;
use crate::policy::Access;
use crate::timefmt::now_secs;
use crate::timefmt::utc_parts;
use crate::token::sha256_hex;

/// Largest file that is edited, and largest content that is written.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// How many backups of one file are kept.
const KEEP_BACKUPS: usize = 20;
/// Room kept in the output for config_edit's own lines when a check's output is shown.
const OWN_LINES: usize = 1536;

const ACTIONS: [&str; 4] = ["replace", "write", "restore", "backups"];
const MODES: [&str; 3] = ["0644", "0640", "0600"];

/// Paths config_edit never writes, unless the operator turns the built-in lists off
/// with `fs.default_deny = false`. (The never-READABLE list of `fs.rs` applies as well:
/// what may not be read may not be written.)
///
/// AIDEV-NOTE: this is a safety net, not the access control. The access control is
/// `fs.write_roots` (empty by default) plus the caller's grants, and whoever may write
/// under /etc/cron.d, /etc/systemd or a service's hook directory can become root: no
/// list can enumerate every such place. What IS listed are the files that decide who
/// someone is and what they may do, which have tools of their own (user_modify) or
/// should never be edited by a machine: accounts, sudo, PAM, the loader, SSH keys, and
/// opsmcp's own configuration.
pub const NEVER_WRITTEN: &[&str] = &[
    "/etc/opsmcp/**",
    "/etc/passwd*",
    "/etc/group*",
    "/etc/shadow*",
    "/etc/gshadow*",
    "/etc/subuid*",
    "/etc/subgid*",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/etc/pam.d/**",
    "/etc/security/**",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/**",
    "**/.ssh/**",
    "**/authorized_keys*",
    "**/authorized_keys*/**",
];

/// One edit at a time on the whole host: two calls changing the same file must not
/// interleave their read, backup and replace.
///
/// AIDEV-NOTE: a call waits for its turn in `config_edit`, the part of the call that
/// ends when the call is cut off, and hands the turn (an owned guard) to the task that
/// makes the edit. Waiting inside that task would let an edit whose caller had long
/// been told "timed out" be made later, with nobody left to see what it did.
static ONE_AT_A_TIME: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

fn edit_lock() -> Arc<tokio::sync::Mutex<()>> {
    ONE_AT_A_TIME
        .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

pub fn tools() -> Vec<Tool> {
    let checks: Vec<&str> = CHECKS.iter().map(|check| check.name).collect();
    vec![Tool::new(
        "config_edit",
        "Change a configuration file safely. replace swaps one piece of text for another \
         (the text to find must occur exactly once: read the file with fs_read first); \
         write replaces the whole content, or creates the file when create is set; restore \
         puts a backup back; backups lists them. The previous content is always kept as a \
         backup, the file is replaced in one step (never left half written) and keeps its \
         owner, permissions, ACL and security label. With validate, the service's own configuration check runs \
         afterwards and the change is undone if it fails. Only files under the directories \
         this host's configuration allows can be written, and never account, sudo, PAM or \
         SSH key files. One call carries at most about 3000 bytes: make a larger change as \
         several replace calls. Only the file on disk changes: reload or restart the \
         service afterwards, and note that configuration management will overwrite a file \
         it manages.",
        Access::Write,
        "fs.write",
        vec![
            Param::str("path", "Absolute path of the file")
                .max_len(4096)
                .required(),
            Param::choice(
                "action",
                "replace: swap one text for another; write: replace the whole content; \
                 restore: put a backup back; backups: list this file's backups",
                &ACTIONS,
            )
            .required(),
            Param::text(
                "find",
                "replace: the exact text to replace, line breaks included. It must occur \
                 exactly once in the file, so include enough of what surrounds it",
                3000,
            ),
            Param::text(
                "replace_with",
                "replace: the text to put in its place (empty to delete the text)",
                3000,
            ),
            Param::text("content", "write: the whole new content of the file", 3000),
            Param::bool(
                "create",
                "write: the file may not exist yet, and is then created",
            ),
            Param::choice(
                "mode",
                "write with create: permissions of a file that is created (default 0644). \
                 A file that exists keeps its own",
                &MODES,
            ),
            Param::choice(
                "validate",
                "Run this configuration check (as config_validate does, and needing the \
                 same permission for it) after the change, and put the old content back if \
                 it fails",
                &checks,
            ),
            Param::str(
                "backup",
                "restore: the name of the backup to put back, as the backups action lists \
                 them (default: the newest)",
            )
            .max_len(32),
            Param::bool(
                "dry_run",
                "Check everything and report what would be done, without changing anything",
            ),
        ],
        config_edit,
    )]
}

// ---------------------------------------------------------------------------------------
// What was asked for
// ---------------------------------------------------------------------------------------

enum Action {
    Replace {
        find: String,
        with: String,
    },
    Write {
        content: String,
        create: bool,
        mode: u32,
    },
    Restore {
        backup: Option<String>,
    },
    Backups,
}

struct Request {
    /// The directory the file is in, and the file's name in it, as the caller wrote them.
    parent: String,
    name: String,
    action: Action,
    check: Option<&'static Check>,
    dry_run: bool,
}

/// Splits a path into the directory and the plain file name in it.
fn split_path(path: &str) -> Result<(String, String), ToolError> {
    check_absolute(path)?;
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name.is_empty() || name == "." || name == ".." || name.len() > 255 {
        return Err(ToolError::Invalid(format!(
            "{path:?} does not name a file (it must end in a file name, not in /, . or ..)"
        )));
    }
    let parent = if parent.is_empty() { "/" } else { parent };
    Ok((parent.to_string(), name.to_string()))
}

fn request(args: &Args) -> Result<Request, ToolError> {
    let (parent, name) = split_path(required(args, "path")?)?;
    let action = required(args, "action")?;
    // An argument that belongs to another action is a mistake worth pointing out: a
    // `content` that was silently ignored by `replace` would be a change that was not made.
    let applies: &[&str] = match action {
        "replace" => &["find", "replace_with", "validate", "dry_run"],
        "write" => &["content", "create", "mode", "validate", "dry_run"],
        "restore" => &["backup", "validate", "dry_run"],
        _ => &[],
    };
    for other in [
        "find",
        "replace_with",
        "content",
        "create",
        "mode",
        "validate",
        "backup",
        "dry_run",
    ] {
        // A flag that is false asks for nothing: agents often send every flag.
        let given = args.str(other).is_some() || args.bool(other) == Some(true);
        if given && !applies.contains(&other) {
            return Err(ToolError::Invalid(format!(
                "{other} does not apply to action {action}"
            )));
        }
    }
    let text = |name: &str| {
        args.str(name)
            .map(str::to_string)
            .ok_or_else(|| ToolError::Invalid(format!("action {action} needs {name}")))
    };
    let action = match action {
        "replace" => {
            let find = text("find")?;
            if find.is_empty() {
                return Err(ToolError::Invalid(
                    "find is empty: give the text to replace".to_string(),
                ));
            }
            Action::Replace {
                find,
                with: text("replace_with")?,
            }
        }
        "write" => {
            let create = args.bool("create").unwrap_or(false);
            let mode = match args.str("mode") {
                Some(_) if !create => {
                    return Err(ToolError::Invalid(
                        "mode only applies together with create: a file that exists keeps \
                         its permissions"
                            .to_string(),
                    ));
                }
                Some("0640") => 0o640,
                Some("0600") => 0o600,
                _ => 0o644,
            };
            Action::Write {
                content: text("content")?,
                create,
                mode,
            }
        }
        "restore" => {
            let backup = args.str("backup").map(str::to_string);
            if let Some(backup) = &backup
                && !is_backup_name(backup)
            {
                return Err(ToolError::Invalid(format!(
                    "{backup:?} is not the name of a backup (the backups action lists them)"
                )));
            }
            Action::Restore { backup }
        }
        _ => Action::Backups,
    };
    Ok(Request {
        parent,
        name,
        action,
        check: args.str("validate").and_then(checks::find_check),
        dry_run: args.bool("dry_run").unwrap_or(false),
    })
}

// ---------------------------------------------------------------------------------------
// Where the file is, and whether it may be written
// ---------------------------------------------------------------------------------------

/// If `real` is a path config_edit never writes, the reason.
fn never_written(cfg: &Config, real: &str) -> Option<String> {
    if cfg.fs.default_deny
        && let Some(pattern) = NEVER_WRITTEN
            .iter()
            .find(|pattern| glob_match(pattern, real))
    {
        return Some(format!(
            "{real} matches the never-written pattern {pattern}"
        ));
    }
    // AIDEV-NOTE: these two hold whatever the configuration says. The audit trail must
    // not be rewritten by the calls it records, and a backup that could be edited would
    // let `restore` install content that was never in the file.
    let path = Path::new(real);
    let same = |other: &Path| {
        path == other || std::fs::canonicalize(other).is_ok_and(|other| path == other)
    };
    if cfg.audit.file.as_deref().is_some_and(same) {
        return Some(format!("{real} is this server's audit log"));
    }
    let backups = &cfg.fs.backup_dir;
    if path.starts_with(backups)
        || std::fs::canonicalize(backups).is_ok_and(|backups| path.starts_with(backups))
    {
        return Some(format!(
            "{real} is in the directory where config_edit keeps its backups"
        ));
    }
    None
}

/// Whether the caller could read `real` with fs_read: it is in a readable directory and
/// the caller holds `fs.read` on it. (The never-readable patterns have been applied to
/// every path that gets this far.)
fn may_read(ctx: &Ctx, real: &str) -> bool {
    let roots = &ctx.cfg().fs.read_roots;
    let real_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    (within(real, roots) || within(real, &real_roots)) && ctx.holds_read_on("fs.read", real)
}

/// The file to edit: the open directory it is in, its name there, and its real path.
struct Target {
    dir: File,
    name: String,
    real: String,
}

/// Pins the directory, applies the host-wide limits and asks the policy.
///
/// AIDEV-NOTE: the PARENT directory is what gets pinned (links on the way to it are
/// resolved by the kernel, once); the file's real path is that directory's real path
/// plus the name, and every check is made on it. The name itself is never resolved: a
/// file that is a symbolic link is refused later, not followed.
fn locate(ctx: &Ctx, request: &Request) -> Result<(Target, Authorized), ToolError> {
    let roots = &ctx.cfg().fs.write_roots;
    let join = |dir: &str| {
        if dir == "/" {
            format!("/{}", request.name)
        } else {
            format!("{dir}/{}", request.name)
        }
    };
    let opened = match pin(ctx, &request.parent, true, roots, "fs.write_roots") {
        Ok(opened) => opened,
        Err(ToolError::Failed(problem)) => {
            // AIDEV-NOTE: the directory cannot be opened (it does not exist, say). The
            // path as written still goes through every test before that is said, so
            // "no such directory" is only told to a caller whose grant covers the path:
            // it must not show which directories exist to one whose grant does not.
            let path = join(&lexical(&request.parent));
            check_limits(ctx, &path, &path, roots, "fs.write_roots")?;
            if let Some(reason) = never_written(ctx.cfg(), &path) {
                return Err(ctx.deny(Some(&path), &reason));
            }
            ctx.authorize(Some(&path))?;
            return Err(ToolError::Failed(problem));
        }
        Err(other) => return Err(other),
    };
    let real = join(&opened.real);
    check_limits(ctx, &real, &real, roots, "fs.write_roots")?;
    if let Some(reason) = never_written(ctx.cfg(), &real) {
        return Err(ctx.deny(Some(&real), &reason));
    }
    // The grant first; only then anything about what is there.
    let auth = ctx.authorize(Some(&real))?;
    if !opened.meta.is_dir() {
        return Err(ToolError::Failed(format!(
            "{} is not a directory",
            opened.real
        )));
    }
    let dir = opened
        .reopen_read()
        .map_err(|e| ToolError::Failed(format!("{}: {e}", opened.real)))?;
    let target = Target {
        dir,
        name: request.name.clone(),
        real,
    };
    Ok((target, auth))
}

// ---------------------------------------------------------------------------------------
// Reading and replacing the file
// ---------------------------------------------------------------------------------------
//
// AIDEV-NOTE: SECURITY-CRITICAL. The server is usually root, and the directory may be
// one that somebody else can write to (a service's own configuration directory). The
// rules are those of the authorized_keys code in `users.rs`, and all have tests:
//
//   * Nothing is opened, created, renamed or removed by path. The directory is pinned
//     once; everything after that is done relative to that open directory (`openat`,
//     `renameat`, `linkat`, `unlinkat`), and owner and permissions are set on an open
//     descriptor. A name swapped for something else under us cannot redirect a write.
//   * No symbolic link is followed: the file must be a real regular file with exactly
//     one name (a second hard link could be another file that would silently stop
//     being the same file).
//   * The file is never modified in place. The new content goes to a new file made with
//     O_CREAT|O_EXCL in the same directory, which takes the OWNER AND PERMISSIONS OF THE
//     FILE IT REPLACES and is then renamed over it: a reader sees the old content or
//     the new, never half of each, and a private file stays private.
//   * A file is created only if its name is still free (`linkat` fails otherwise), and
//     replaced only if the name still refers to the file that was read.

/// The file as it is now.
struct Existing {
    content: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    stamp: Stamp,
    /// The extended attributes the file that replaces it must carry: its ACL, its
    /// security label, and whatever else was attached to it.
    xattrs: Vec<Xattr>,
}

/// One state of one file: which file it is, how long, and when it was last written.
/// Two equal stamps mean nobody has replaced or rewritten the file in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    ino: u64,
    size: u64,
    mtime: (i64, i64),
}

fn stamp_of(meta: &std::fs::Metadata) -> Stamp {
    Stamp {
        ino: meta.ino(),
        size: meta.len(),
        mtime: (meta.mtime(), meta.mtime_nsec()),
    }
}

/// The stamp of the regular file `name` in the open directory, if that is what is there
/// (a link is not followed).
fn stamp_at(dir: &File, name: &str) -> Option<Stamp> {
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let pinned = File::from(rustix::fs::openat(dir, name, flags, Mode::empty()).ok()?);
    let meta = pinned.metadata().ok()?;
    meta.is_file().then(|| stamp_of(&meta))
}

/// Owner and permissions for the file that is installed.
#[derive(Clone, Copy)]
struct Attrs {
    mode: u32,
    uid: u32,
    gid: u32,
}

fn os_error(error: Errno) -> std::io::Error {
    std::io::Error::from(error)
}

// ---------------------------------------------------------------------------------------
// Extended attributes: ACLs and security labels
// ---------------------------------------------------------------------------------------
//
// AIDEV-NOTE: a file is replaced by a NEW file, so everything the old one carried besides
// its content has to be put on the new one, not only owner and mode. Two of those things
// decide who may use the file, and both live in extended attributes:
//   - the POSIX ACL (`system.posix_acl_access`). With an ACL the group bits of the mode
//     are the ACL's mask, not the group's rights: a replacement that copied the mode alone
//     would give the group what the mask allowed and drop the named entries.
//   - the security label (`security.selinux`, `security.SMACK64`). A file whose label was
//     set by hand would fall back to its directory's default, and a confined service
//     could lose (or gain) access to it.
// The other way round matters as well: a directory with a default ACL hands every new
// file an ACL, which the old file may not have had. So the new file is made to carry
// exactly what the old one did: missing attributes are added, differing ones set, and
// surplus ones removed. If that cannot be done the edit is refused; a security attribute
// is never changed silently.

/// One extended attribute: its name and its value.
type Xattr = (String, Vec<u8>);

/// Most bytes of attribute names read from one file.
const MAX_XATTR_NAMES: usize = 64 * 1024;
/// Most bytes of one attribute's value (the kernel's own limit).
const MAX_XATTR_VALUE: usize = 64 * 1024;
/// Most attributes carried over; a configuration file has a handful at most.
const MAX_XATTRS: usize = 64;

/// What is done with an attribute of the file being replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carry {
    /// Put on the new file with the same value.
    Yes,
    /// Left to the system: its value belongs to the old content or to directories.
    No,
    /// The file is not one to edit.
    Refuse,
}

/// Decides by name. Anything not known to be wrong for the new file is carried: a label
/// or ACL scheme this code has never heard of is still somebody's access rule.
fn carry(name: &str) -> Carry {
    match name {
        // File capabilities are privileges of a program, like the set-user-id bit.
        "security.capability" => Carry::Refuse,
        // Integrity measurements and signatures are of the OLD content; the kernel
        // writes its own for the new file where the policy asks for one.
        "security.ima" | "security.evm" => Carry::No,
        // The default ACL is a directory's.
        "system.posix_acl_default" => Carry::No,
        _ => Carry::Yes,
    }
}

/// Whether an error from an attribute call means "this filesystem has no such thing".
fn no_attributes_here(error: Errno) -> bool {
    error == Errno::NOTSUP || error == Errno::OPNOTSUPP || error == Errno::NOSYS
}

/// The names of the extended attributes of an open file. A filesystem without extended
/// attributes has none.
fn xattr_names(file: &File) -> Result<Vec<String>, String> {
    let problem = |e: Errno| format!("its extended attributes cannot be listed: {}", os_error(e));
    // The list can grow between asking for its size and reading it; try a few times.
    for _ in 0..4 {
        let size = match rustix::fs::flistxattr_query(file) {
            Ok(size) => size,
            Err(e) if no_attributes_here(e) => return Ok(Vec::new()),
            Err(e) => return Err(problem(e)),
        };
        if size == 0 {
            return Ok(Vec::new());
        }
        if size > MAX_XATTR_NAMES {
            return Err(
                "has more extended attributes than are carried over; it is left alone".to_string(),
            );
        }
        let mut list = vec![0u8; size];
        match rustix::fs::flistxattr(file, list.as_mut_slice()) {
            Ok(length) => {
                list.truncate(length);
                return Ok(list
                    .split(|byte| *byte == 0)
                    .filter(|name| !name.is_empty())
                    .map(|name| String::from_utf8_lossy(name).into_owned())
                    .collect());
            }
            Err(Errno::RANGE) => continue,
            Err(e) if no_attributes_here(e) => return Ok(Vec::new()),
            Err(e) => return Err(problem(e)),
        }
    }
    Err("its extended attributes keep changing; it is left alone".to_string())
}

/// The value of one extended attribute of an open file; `None` if it has gone.
fn xattr_value(file: &File, name: &str) -> Result<Option<Vec<u8>>, String> {
    let problem = |e: Errno| {
        format!(
            "its extended attribute {name} cannot be read: {}",
            os_error(e)
        )
    };
    for _ in 0..4 {
        let size = match rustix::fs::fgetxattr_query(file, name) {
            Ok(size) => size,
            Err(Errno::NODATA) => return Ok(None),
            Err(e) => return Err(problem(e)),
        };
        if size > MAX_XATTR_VALUE {
            return Err(format!(
                "its extended attribute {name} is larger than is carried over; it is left alone"
            ));
        }
        if size == 0 {
            return Ok(Some(Vec::new()));
        }
        let mut value = vec![0u8; size];
        match rustix::fs::fgetxattr(file, name, value.as_mut_slice()) {
            Ok(length) => {
                value.truncate(length);
                return Ok(Some(value));
            }
            Err(Errno::RANGE) => continue,
            Err(Errno::NODATA) => return Ok(None),
            Err(e) => return Err(problem(e)),
        }
    }
    Err(format!(
        "its extended attribute {name} keeps changing; it is left alone"
    ))
}

/// The attributes of the file being replaced that its replacement must carry.
fn carried_xattrs(file: &File) -> Result<Vec<Xattr>, String> {
    let mut carried = Vec::new();
    for name in xattr_names(file)? {
        match carry(&name) {
            Carry::No => {}
            Carry::Refuse => {
                return Err(
                    "has file capabilities: that is a program's privilege, not a \
                     configuration file, and it is left alone"
                        .to_string(),
                );
            }
            Carry::Yes => {
                if let Some(value) = xattr_value(file, &name)? {
                    carried.push((name, value));
                }
            }
        }
    }
    if carried.len() > MAX_XATTRS {
        return Err(
            "has more extended attributes than are carried over; it is left alone".to_string(),
        );
    }
    Ok(carried)
}

/// Makes the new file carry exactly the attributes in `wanted`.
fn settle_xattrs(new: &File, wanted: &[Xattr]) -> Result<(), String> {
    let flags = rustix::fs::XattrFlags::empty();
    // What the new file was given when it was created: a default label, and an ACL if
    // its directory hands one out.
    for name in xattr_names(new)? {
        // A security label is the system's to assign; one is never taken off a file.
        if carry(&name) != Carry::Yes || name.starts_with("security.") {
            continue;
        }
        if !wanted.iter().any(|(wanted_name, _)| *wanted_name == name) {
            rustix::fs::fremovexattr(new, name.as_str()).map_err(|e| {
                format!(
                    "has no {name} attribute, and the one its directory gives new files \
                     cannot be taken off the new file ({}); nothing was written",
                    os_error(e)
                )
            })?;
        }
    }
    for (name, value) in wanted {
        // Often the new file already has it: a label inherited from the same directory.
        // Then nothing is set, and no right to relabel is needed.
        if xattr_value(new, name)?.as_ref() == Some(value) {
            continue;
        }
        rustix::fs::fsetxattr(new, name.as_str(), value, flags).map_err(|e| {
            format!(
                "its extended attribute {name} cannot be carried over to the new file ({}); \
                 nothing was written",
                os_error(e)
            )
        })?;
    }
    Ok(())
}

fn too_large() -> String {
    format!(
        "is too large to edit (more than {} KiB); it is left alone",
        MAX_FILE_BYTES / 1024
    )
}

/// Reads the file `name` in the open directory, if there is one. Errors are worded to
/// follow the file's path.
fn read_existing(dir: &File, name: &str) -> Result<Option<Existing>, String> {
    // Looked at before it is opened: opening a device can have effects of its own.
    let stat = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(format!("cannot be examined: {}", os_error(e))),
    };
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => {}
        FileType::Symlink => {
            return Err(
                "is a symbolic link, and links are not followed: edit the file it points \
                 to (fs_stat shows where that is)"
                    .to_string(),
            );
        }
        FileType::Directory => return Err("is a directory, not a regular file".to_string()),
        _ => return Err("is not a regular file".to_string()),
    }
    // NOFOLLOW and NONBLOCK: whatever the name has become since, it is not followed and
    // cannot hang the server.
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => {
            return Err("is a symbolic link, and links are not followed".to_string());
        }
        Err(e) => return Err(format!("cannot be opened: {}", os_error(e))),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot be examined: {e}"))?;
    if !meta.is_file() {
        return Err("is not a regular file".to_string());
    }
    if meta.nlink() != 1 {
        return Err(
            "has more than one hard link (it is also another file); it is left alone".to_string(),
        );
    }
    if meta.mode() & 0o7000 != 0 {
        return Err(
            "has the set-user-id, set-group-id or sticky bit: that is not a configuration \
             file, and it is left alone"
                .to_string(),
        );
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(too_large());
    }
    let mut content = Vec::new();
    (&file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|e| format!("cannot be read: {e}"))?;
    if content.len() as u64 > MAX_FILE_BYTES {
        return Err(too_large());
    }
    let xattrs = carried_xattrs(&file)?;
    Ok(Some(Existing {
        content,
        mode: meta.mode() & 0o777,
        uid: meta.uid(),
        gid: meta.gid(),
        stamp: stamp_of(&meta),
        xattrs,
    }))
}

/// Occurrences are not counted beyond this: "many" is all that needs saying.
const MAX_COUNTED: usize = 100;

/// How often `find` occurs in `text` (at most `MAX_COUNTED + 1` are counted), and where
/// it occurs first.
///
/// AIDEV-NOTE: occurrences that OVERLAP count. `str::matches` would find "aa" once in
/// "aaa", and replace would then change the first of two places the text is in.
fn occurrences(text: &str, find: &str) -> (usize, Option<usize>) {
    let mut count = 0usize;
    let mut first = None;
    let mut from = 0usize;
    while count <= MAX_COUNTED
        && let Some(found) = text.get(from..).and_then(|rest| rest.find(find))
    {
        let at = from.saturating_add(found);
        count = count.saturating_add(1);
        first.get_or_insert(at);
        // The next one may start one character further on.
        let step = text
            .get(at..)
            .and_then(|rest| rest.chars().next())
            .map_or(1, char::len_utf8);
        from = at.saturating_add(step);
    }
    (count, first)
}

/// How much of a file's name is kept in the name of the temporary file beside it.
const TEMP_STEM_BYTES: usize = 200;

/// The name of the temporary file that becomes `name`.
///
/// AIDEV-NOTE: a file name may be 255 BYTES long, and the temporary name adds 21 to
/// what it keeps of the name. The name is therefore cut by bytes (on a character
/// boundary), not by characters: a hundred characters can be four hundred bytes.
fn temp_name(name: &str, random: &str) -> String {
    let mut end = name.len().min(TEMP_STEM_BYTES);
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    let short = name.get(..end).unwrap_or("");
    format!(".{short}.opsmcp-{random}.tmp")
}

/// The content as text, or why it is not text.
fn text_of(content: &[u8]) -> Result<&str, String> {
    if content.contains(&0) {
        return Err("looks like a binary file (it has NUL bytes); it is left alone".to_string());
    }
    std::str::from_utf8(content)
        .map_err(|_| "is not valid UTF-8 text; it is left alone".to_string())
}

/// What the name must be when the new file is put in place.
#[derive(Clone, Copy)]
enum Slot {
    /// Still the file in this state: the one that was read (or installed).
    Holds(Stamp),
    /// Still free.
    Free,
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut random = vec![0u8; bytes];
    getrandom::fill(&mut random).map_err(|e| format!("cannot get random bytes: {e}"))?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Puts `content` in place as `name` in the open directory, in one step. Returns the
/// stamp of the file now there.
///
/// AIDEV-NOTE: the file put in place is a NEW file. It gets the old one's owner, group
/// and permission bits, and with `carried` the old one's extended attributes too (its
/// ACL, its security label: see "Extended attributes" above). `carried` is `None` only
/// for a file that did not exist before: that one keeps what its directory gives new
/// files, as a file made by hand would. What is NOT kept: the inode number, the times,
/// and integrity signatures (`security.ima`, `security.evm`), which are of the old
/// content.
fn install(
    dir: &File,
    name: &str,
    content: &[u8],
    attrs: Attrs,
    slot: Slot,
    carried: Option<&[Xattr]>,
) -> Result<Stamp, String> {
    let temp = temp_name(name, &random_hex(4)?);
    // AIDEV-NOTE: a replacement starts out closed (0600) and is opened up to the old
    // file's mode at the end. A file that did not exist before is CREATED with the mode
    // asked for instead, because that is the only way to get what a file made by hand
    // gets: where the directory has a default ACL, the kernel combines it with the mode
    // given at creation and the stricter wins. Setting the mode afterwards would
    // override the ACL's entry for others and leave the file more open than the
    // directory makes its files.
    let wanted_mode = attrs.mode & 0o777;
    let first_mode = if carried.is_some() {
        0o600
    } else {
        wanted_mode
    };
    // EXCL: the file is new and ours; an existing name (or a link) is never written to.
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = rustix::fs::openat(dir, temp.as_str(), flags, Mode::from_raw_mode(first_mode))
        .map(File::from)
        .map_err(|e| format!("cannot create a file next to it: {}", os_error(e)))?;
    let placed = (|| -> Result<Stamp, String> {
        let io = |e: std::io::Error| format!("cannot write the new content: {e}");
        file.write_all(content).map_err(io)?;
        // Owner first, then permissions: the file is never more open than it will be.
        std::os::unix::fs::fchown(&file, Some(attrs.uid), Some(attrs.gid))
            .map_err(|e| format!("cannot give the new file its owner: {e}"))?;
        let set_mode = |file: &File| {
            rustix::fs::fchmod(file, Mode::from_raw_mode(wanted_mode))
                .map_err(|e| format!("cannot set the new file's permissions: {}", os_error(e)))
        };
        match carried {
            // Attributes before the mode: with an ACL the mode's group bits are the
            // ACL's mask, so the mode set last is exactly the old file's.
            Some(carried) => {
                settle_xattrs(&file, carried)?;
                set_mode(&file)?;
            }
            // A new file. If its directory gave it an ACL, the kernel has already put
            // mode and ACL together and that stands. Otherwise the process's umask may
            // have taken bits off: set exactly the mode asked for.
            None => {
                let has_acl = xattr_names(&file)?
                    .iter()
                    .any(|name| name == "system.posix_acl_access");
                if !has_acl {
                    set_mode(&file)?;
                }
            }
        }
        file.sync_all().map_err(io)?;
        // Renaming or linking a file changes neither its length nor when it was written.
        let stamp = stamp_of(&file.metadata().map_err(io)?);
        match slot {
            Slot::Holds(expected) => {
                // AIDEV-NOTE: not atomic with the rename, but it narrows the window in
                // which somebody else's change to the file would be lost to an instant.
                if stamp_at(dir, name) != Some(expected) {
                    return Err(
                        "was changed by someone else while it was being edited; nothing \
                         was written"
                            .to_string(),
                    );
                }
                rustix::fs::renameat(dir, temp.as_str(), dir, name)
                    .map_err(|e| format!("cannot put the new content in place: {}", os_error(e)))?;
            }
            Slot::Free => {
                // A hard link fails if the name is taken, where a rename would replace
                // whatever had appeared there.
                match rustix::fs::linkat(dir, temp.as_str(), dir, name, AtFlags::empty()) {
                    Ok(()) => {}
                    Err(Errno::EXIST) => {
                        return Err(
                            "appeared while it was being created; nothing was written".to_string()
                        );
                    }
                    Err(e) => return Err(format!("cannot create it: {}", os_error(e))),
                }
                let _ = rustix::fs::unlinkat(dir, temp.as_str(), AtFlags::empty());
            }
        }
        Ok(stamp)
    })();
    if placed.is_err() {
        let _ = rustix::fs::unlinkat(dir, temp.as_str(), AtFlags::empty());
    }
    // Best effort: make the rename itself durable.
    let _ = dir.sync_all();
    placed
}

// ---------------------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------------------

/// The name of a backup made at `unix_secs`: `yyyymmddThhmmssZ-xxxx`, the last part
/// being a counter in hexadecimal. See `Store::save` for how names stay in order.
fn backup_name(unix_secs: i64, counter: &str) -> String {
    let t = utc_parts(unix_secs);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z-{counter}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

fn is_backup_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
    };
    bytes.len() == 21
        && digits(0..8)
        && bytes.get(8) == Some(&b'T')
        && digits(9..15)
        && bytes.get(15..17) == Some(b"Z-")
        && bytes.get(17..21).is_some_and(|hex| {
            hex.iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        })
}

/// The name that sorts directly after `name`: the same time, the counter one higher.
fn next_backup_name(name: &str) -> Result<String, String> {
    let full = || "cannot find a free name for the backup".to_string();
    let (stem, counter) = name.split_at_checked(17).ok_or_else(full)?;
    let counter = u16::from_str_radix(counter, 16).map_err(|_| full())?;
    let next = counter.checked_add(1).ok_or_else(full)?;
    Ok(format!("{stem}{next:04x}"))
}

/// When a backup was made, from its name, for people.
fn backup_time(name: &str) -> String {
    match (
        name.get(0..4),
        name.get(4..6),
        name.get(6..8),
        name.get(9..11),
        name.get(11..13),
        name.get(13..15),
    ) {
        (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) => {
            format!("{y}-{mo}-{d} {h}:{mi}:{s} UTC")
        }
        _ => "?".to_string(),
    }
}

/// The backups of one file: a directory of its own under `fs.backup_dir`.
struct Store {
    dir: File,
}

/// A directory only the server's own user can change.
fn is_own_private_dir(dir: &File) -> bool {
    let euid = rustix::process::geteuid().as_raw();
    dir.metadata()
        .is_ok_and(|meta| meta.is_dir() && meta.uid() == euid && meta.mode() & 0o022 == 0)
}

/// Opens the backups of the file whose real path is `real`. With `create`, missing
/// directories are made (private to the server's user); otherwise `Ok(None)` says there
/// are no backups.
///
/// AIDEV-NOTE: backups hold configuration, secrets included, and `restore` installs
/// what it finds here. So the directory must belong to the user the server runs as and
/// be closed to everyone else's writes, links are not followed into it, and (see
/// `never_written`) the tool refuses to edit anything inside it.
fn open_store(base: &Path, real: &str, create: bool) -> Result<Option<Store>, String> {
    let shown = base.display();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if create {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(base)
            .map_err(|e| format!("cannot create the backup directory {shown}: {e}"))?;
    }
    let unusable = format!(
        "the backup directory {shown} must be a directory that belongs to the user opsmcp \
         runs as and that nobody else can write to; nothing was changed"
    );
    let top = match rustix::fs::open(base, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) if !create => return Ok(None),
        Err(_) => return Err(unusable),
    };
    if !is_own_private_dir(&top) {
        return Err(unusable);
    }
    // One directory per file, named by a digest of the file's path: any path fits, and
    // no path can climb out.
    let digest = sha256_hex(real.as_bytes());
    let sub = digest.get(..16).unwrap_or(&digest);
    if create {
        match rustix::fs::mkdirat(&top, sub, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => {
                return Err(format!(
                    "cannot create a directory in {shown}: {}",
                    os_error(e)
                ));
            }
        }
    }
    let dir = match rustix::fs::openat(&top, sub, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) if !create => return Ok(None),
        Err(_) => return Err(unusable),
    };
    if !is_own_private_dir(&dir) {
        return Err(unusable);
    }
    if create {
        // For people looking at the directory: which file these are backups of.
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if let Ok(fd) = rustix::fs::openat(&dir, "path", flags, Mode::from_raw_mode(0o600)) {
            let _ = File::from(fd).write_all(format!("{real}\n").as_bytes());
        }
    }
    Ok(Some(Store { dir }))
}

impl Store {
    /// Saves `content` as a new backup and returns its name.
    ///
    /// AIDEV-NOTE: names must sort in the order the backups were made, because "the
    /// newest backup" is what a restore takes, and a restore itself makes one. The time
    /// in the name is whole seconds and the clock can be set back, so a new name is the
    /// current time with counter 0000, or, when that would not sort after every backup
    /// there is, the newest existing name with its counter raised by one.
    fn save(&self, content: &[u8]) -> Result<String, String> {
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut name = backup_name(now_secs(), "0000");
        if let Some((newest, _)) = self.list()?.last()
            && *newest >= name
        {
            name = next_backup_name(newest)?;
        }
        // A name that has been taken since the list was read is passed over.
        for _ in 0..16 {
            let mode = Mode::from_raw_mode(0o600);
            let fd = match rustix::fs::openat(&self.dir, name.as_str(), flags, mode) {
                Ok(fd) => fd,
                Err(Errno::EXIST) => {
                    name = next_backup_name(&name)?;
                    continue;
                }
                Err(e) => return Err(format!("cannot create the backup: {}", os_error(e))),
            };
            let mut file = File::from(fd);
            let written = file.write_all(content).and_then(|()| file.sync_all());
            if let Err(e) = written {
                let _ = rustix::fs::unlinkat(&self.dir, name.as_str(), AtFlags::empty());
                return Err(format!("cannot write the backup: {e}"));
            }
            let _ = self.dir.sync_all();
            return Ok(name);
        }
        Err("cannot find a free name for the backup".to_string())
    }

    /// The name of a backup holding `content`: the newest one if that is exactly it,
    /// otherwise a new one.
    ///
    /// AIDEV-NOTE: a backup is taken before every change, also one that is then not
    /// kept (a failed check, a file that changed meanwhile). The current content is the
    /// same each time such a change is retried, so without this an agent retrying a
    /// refused change twenty times would fill the store with twenty copies of one
    /// content and push every earlier version out.
    fn keep(&self, content: &[u8]) -> Result<String, String> {
        if let Some((newest, size)) = self.list()?.last()
            && *size == content.len() as u64
            && self.read(newest).is_ok_and(|kept| kept == content)
        {
            return Ok(newest.clone());
        }
        self.save(content)
    }

    /// The backups there are, oldest first, with their sizes.
    fn list(&self) -> Result<Vec<(String, u64)>, String> {
        let entries = Dir::read_from(&self.dir)
            .map_err(|e| format!("cannot read the backups: {}", os_error(e)))?;
        let mut backups = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_backup_name(&name) {
                continue;
            }
            let size = rustix::fs::statat(&self.dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .ok()
                .filter(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile)
                .map(|stat| u64::try_from(stat.st_size).unwrap_or(0));
            if let Some(size) = size {
                backups.push((name, size));
            }
        }
        backups.sort();
        Ok(backups)
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        let flags =
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let file = rustix::fs::openat(&self.dir, name, flags, Mode::empty())
            .map(File::from)
            .map_err(|e| format!("cannot open backup {name}: {}", os_error(e)))?;
        let usable = file
            .metadata()
            .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_FILE_BYTES);
        if !usable {
            return Err(format!("backup {name} is not usable"));
        }
        let mut content = Vec::new();
        (&file)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|e| format!("cannot read backup {name}: {e}"))?;
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err(format!("backup {name} is not usable"));
        }
        Ok(content)
    }

    /// Removes the oldest backups beyond the newest `keep`.
    fn prune(&self, keep: usize) {
        let Ok(backups) = self.list() else { return };
        let extra = backups.len().saturating_sub(keep);
        for (name, _) in backups.iter().take(extra) {
            let _ = rustix::fs::unlinkat(&self.dir, name.as_str(), AtFlags::empty());
        }
    }
}

// ---------------------------------------------------------------------------------------
// One edit
// ---------------------------------------------------------------------------------------

/// "3 lines, 40 bytes".
fn size_text(content: &[u8]) -> String {
    let breaks = content.iter().filter(|byte| **byte == b'\n').count();
    let lines = breaks + usize::from(content.last().is_some_and(|last| *last != b'\n'));
    format!(
        "{lines} {}, {} bytes",
        if lines == 1 { "line" } else { "lines" },
        content.len()
    )
}

/// What is needed to take a change back.
struct Undo {
    target: Target,
    previous: Option<Existing>,
    /// The file that was installed.
    installed: Stamp,
    /// The backup holding the previous content.
    backup: Option<String>,
}

/// Where one call stands after its blocking part.
enum Step {
    /// Finished: the text and whether it is a success.
    Done(Authorized, String, bool),
    /// The file was changed. With a check, the change is kept only if it passes.
    Changed(Box<Changed>),
}

struct Changed {
    auth: Authorized,
    text: String,
    undo: Undo,
    check: Option<(&'static str, Cmd)>,
    /// The file's backups, when old ones are still to be dropped: that is done once the
    /// change is known to be kept.
    store: Option<Store>,
}

/// A change that has been worked out and is ready to be made.
struct Change {
    new: Vec<u8>,
    previous: Option<Existing>,
    /// Owner and permissions when there is no previous file to take them from.
    fresh: Attrs,
    /// "Replaced the text at line 2 of /etc/x." and its dry-run counterpart.
    done: String,
    would: String,
}

/// Makes a worked-out change: backup, then the new content in one step.
fn make(
    ctx: &Ctx,
    request: &Request,
    target: Target,
    auth: Authorized,
    change: Change,
    readable: bool,
    check: Option<(&'static str, Cmd)>,
) -> Result<Step, ToolError> {
    let failed = |problem: String| ToolError::Failed(format!("{}: {problem}", target.real));
    if change.new.len() as u64 > MAX_FILE_BYTES {
        return Err(failed(format!(
            "the new content would be too large (more than {} KiB); nothing was changed",
            MAX_FILE_BYTES / 1024
        )));
    }
    // AIDEV-NOTE: what the file was like before is only reported to a caller who could
    // have read it. `fs.write` without `fs.read` is a combination the policy allows, and
    // then nothing about the old content is told, not even its length in lines.
    let sizes = match &change.previous {
        Some(previous) if readable => format!(
            "Before: {}; after: {}.\n",
            size_text(&previous.content),
            size_text(&change.new)
        ),
        _ => format!("After: {}.\n", size_text(&change.new)),
    };
    let ragged = if change.new.last().is_some_and(|last| *last != b'\n') {
        "[the new content does not end with a line break]\n"
    } else {
        ""
    };
    if request.dry_run {
        let mut text = format!(
            "Dry run: nothing was changed.\n{}\n{sizes}{ragged}",
            change.would
        );
        if let Some((name, _)) = &check {
            text.push_str(&format!(
                "The {name} check would be run afterwards, and the change undone if it failed.\n"
            ));
        }
        return Ok(Step::Done(auth, text, true));
    }

    // The backup first: no backup, no change.
    let (backup, store) = match &change.previous {
        Some(previous) => {
            let store = open_store(&ctx.cfg().fs.backup_dir, &target.real, true)
                .map_err(ToolError::Failed)?
                .ok_or_else(|| ToolError::Failed("the backup directory is missing".to_string()))?;
            let name = store.keep(&previous.content).map_err(ToolError::Failed)?;
            (Some(name), Some(store))
        }
        None => (None, None),
    };
    let (attrs, slot, carried) = match &change.previous {
        Some(previous) => (
            Attrs {
                mode: previous.mode,
                uid: previous.uid,
                gid: previous.gid,
            },
            Slot::Holds(previous.stamp),
            Some(previous.xattrs.as_slice()),
        ),
        None => (change.fresh, Slot::Free, None),
    };
    let installed =
        install(&target.dir, &target.name, &change.new, attrs, slot, carried).map_err(failed)?;
    // AIDEV-NOTE: old backups are dropped only when a change is KEPT. A change that
    // fails its check (or never gets as far as this line) must not cost an old version.
    let store = match (&check, store) {
        (None, Some(store)) => {
            store.prune(KEEP_BACKUPS);
            None
        }
        (_, store) => store,
    };

    let mut text = format!("{}\n{sizes}{ragged}", change.done);
    if change.previous.is_none() {
        // A new file takes its permissions from the mode asked for AND from its
        // directory (see `install`). Say so when the two differ, so that the line
        // above, which names the mode asked for, does not mislead.
        let asked = attrs.mode & 0o777;
        let actual =
            rustix::fs::statat(&target.dir, target.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .ok()
                .map(|stat| stat.st_mode & 0o777);
        if let Some(actual) = actual.filter(|actual| *actual != asked) {
            text.push_str(&format!(
                "[the directory gives new files an access list (ACL): its permissions are \
                 {actual:04o}, not the {asked:04o} asked for]\n"
            ));
        }
    }
    match &backup {
        Some(name) => text.push_str(&format!(
            "The previous content is kept as backup {name} (action=restore puts it back).\n"
        )),
        None => text.push_str("There was no earlier content, so there is no backup.\n"),
    }
    text.push_str(
        "The file on disk has changed, and stays changed across a reboot; the service that \
         reads it has to be reloaded or restarted to use it.\n",
    );
    let undo = Undo {
        target,
        previous: change.previous,
        installed,
        backup,
    };
    Ok(Step::Changed(Box::new(Changed {
        auth,
        text,
        undo,
        check,
        store,
    })))
}

/// The blocking part of a call: everything up to and including the change itself.
fn apply(ctx: &Ctx, request: &Request) -> Result<Step, ToolError> {
    let (target, auth) = locate(ctx, request)?;
    let real = target.real.clone();
    let failed = |problem: String| ToolError::Failed(format!("{real}: {problem}"));
    // AIDEV-NOTE: a check reads the service's real configuration and shows what the
    // checker says about it, so asking for one here needs the grant config_validate
    // needs. Otherwise `fs.write` on one file would run every built-in check (and get
    // around a deny on config.validate). Refused before anything is looked at or changed.
    if let Some(check) = request.check
        && !ctx.holds_read_on("config.validate", check.name)
    {
        let reason = format!(
            "validate={0} needs config.validate on {0} as well",
            check.name
        );
        return Err(ctx.deny(Some(&real), &reason));
    }
    // A check that cannot be run is found out now, before anything is changed.
    let check = match request.check {
        Some(check) => Some((check.name, checks::check_command(ctx, check)?)),
        None => None,
    };
    let readable = may_read(ctx, &real);
    let dir_meta = target
        .dir
        .metadata()
        .map_err(|e| failed(format!("its directory cannot be examined: {e}")))?;
    // A file that is created belongs to whoever owns the directory it is in.
    let fresh = |mode: u32| Attrs {
        mode,
        uid: dir_meta.uid(),
        gid: dir_meta.gid(),
    };
    let owner_text = |attrs: Attrs| {
        let mut names = Names::default();
        let user = names.user(attrs.uid).to_string();
        let group = names.group(attrs.gid);
        format!("mode {:04o}, owner {user}:{group}", attrs.mode)
    };

    match &request.action {
        Action::Backups => {
            let store =
                open_store(&ctx.cfg().fs.backup_dir, &real, false).map_err(ToolError::Failed)?;
            let backups = match &store {
                Some(store) => store.list().map_err(ToolError::Failed)?,
                None => Vec::new(),
            };
            if backups.is_empty() {
                return Ok(Step::Done(
                    auth,
                    format!("There is no backup of {real}.\n"),
                    true,
                ));
            }
            let rows: Vec<Vec<String>> = backups
                .iter()
                .rev()
                .map(|(name, size)| vec![name.clone(), size.to_string(), backup_time(name)])
                .collect();
            let mut text = format!("Backups of {real}, newest first:\n");
            text.push_str(&format_table(
                &["BACKUP", "BYTES", "TAKEN"],
                &rows,
                &[false, true, false],
            ));
            Ok(Step::Done(auth, text, true))
        }

        Action::Replace { find, with } => {
            // AIDEV-NOTE: `replace` answers "does this text occur in the file, and once?".
            // Asked often enough, that question reads the file. So it is only answered
            // for a caller who could have read the file with fs_read anyway.
            if !readable {
                return Err(ctx.deny(
                    Some(&real),
                    "replace tells whether a text occurs in the file, so it needs fs.read \
                     on the file as well as fs.write, and the file inside fs.read_roots; \
                     action=write, which replaces the whole content, does not",
                ));
            }
            let previous = read_existing(&target.dir, &target.name)
                .map_err(failed)?
                .ok_or_else(|| failed("there is no such file".to_string()))?;
            let text = text_of(&previous.content).map_err(failed)?;
            let at = match occurrences(text, find) {
                (1, Some(at)) => at,
                (0, _) | (_, None) => {
                    return Err(failed(
                        "the text to find does not occur in it; nothing was changed (read \
                         the file again: it may have changed)"
                            .to_string(),
                    ));
                }
                (times, _) => {
                    let times = if times > MAX_COUNTED {
                        format!("more than {MAX_COUNTED}")
                    } else {
                        times.to_string()
                    };
                    return Err(failed(format!(
                        "the text to find occurs {times} times; nothing was changed. \
                         Include more of what surrounds it, so that it occurs once"
                    )));
                }
            };
            if find == with {
                return Ok(Step::Done(
                    auth,
                    format!(
                        "The text to find and its replacement are the same: nothing was \
                         changed in {real}.\n"
                    ),
                    true,
                ));
            }
            let (before, rest) = text.split_at(at);
            let after = rest.get(find.len()..).unwrap_or("");
            let line = before.matches('\n').count() + 1;
            let change = Change {
                new: format!("{before}{with}{after}").into_bytes(),
                previous: Some(previous),
                fresh: fresh(0o644),
                done: format!("Replaced the text at line {line} of {real}."),
                would: format!("Would replace the text at line {line} of {real}."),
            };
            make(ctx, request, target, auth, change, readable, check)
        }

        Action::Write {
            content,
            create,
            mode,
        } => {
            let previous = read_existing(&target.dir, &target.name).map_err(failed)?;
            let change = match previous {
                Some(previous) => {
                    text_of(&previous.content).map_err(failed)?;
                    if readable && previous.content == content.as_bytes() {
                        return Ok(Step::Done(
                            auth,
                            format!(
                                "{real} already has exactly this content: nothing was changed.\n"
                            ),
                            true,
                        ));
                    }
                    Change {
                        new: content.clone().into_bytes(),
                        previous: Some(previous),
                        fresh: fresh(0o644),
                        done: format!("Replaced the content of {real}."),
                        would: format!("Would replace the content of {real}."),
                    }
                }
                None if !create => {
                    return Err(failed(
                        "there is no such file; pass create to make it".to_string(),
                    ));
                }
                None => {
                    let attrs = fresh(*mode);
                    Change {
                        new: content.clone().into_bytes(),
                        previous: None,
                        fresh: attrs,
                        done: format!("Created {real} ({}).", owner_text(attrs)),
                        would: format!("Would create {real} ({}).", owner_text(attrs)),
                    }
                }
            };
            make(ctx, request, target, auth, change, readable, check)
        }

        Action::Restore { backup } => {
            let store =
                open_store(&ctx.cfg().fs.backup_dir, &real, false).map_err(ToolError::Failed)?;
            let backups = match &store {
                Some(store) => store.list().map_err(ToolError::Failed)?,
                None => Vec::new(),
            };
            let name = match backup {
                Some(name) => backups
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .map(|(name, _)| name.clone())
                    .ok_or_else(|| failed(format!("there is no backup named {name}")))?,
                None => backups
                    .last()
                    .map(|(name, _)| name.clone())
                    .ok_or_else(|| {
                        failed("there is no backup of it; nothing was changed".to_string())
                    })?,
            };
            let Some(store) = store else {
                return Err(failed("there is no backup of it".to_string()));
            };
            let content = store.read(&name).map_err(ToolError::Failed)?;
            let previous = read_existing(&target.dir, &target.name).map_err(failed)?;
            let change = match previous {
                Some(previous) => {
                    if readable && previous.content == content {
                        return Ok(Step::Done(
                            auth,
                            format!(
                                "{real} already has the content of backup {name}: nothing \
                                 was changed.\n"
                            ),
                            true,
                        ));
                    }
                    Change {
                        new: content,
                        previous: Some(previous),
                        fresh: fresh(0o600),
                        done: format!("Restored {real} from backup {name}."),
                        would: format!("Would restore {real} from backup {name}."),
                    }
                }
                None => {
                    // What permissions the file had is not recorded: the closed choice.
                    let attrs = fresh(0o600);
                    let how = format!(
                        "The file no longer existed; its earlier permissions are not known, \
                         so it gets {}",
                        owner_text(attrs)
                    );
                    Change {
                        new: content,
                        previous: None,
                        fresh: attrs,
                        done: format!("Restored {real} from backup {name}. {how}."),
                        would: format!("Would restore {real} from backup {name}. {how}."),
                    }
                }
            };
            make(ctx, request, target, auth, change, readable, check)
        }
    }
}

/// Why a change could not be taken back.
#[derive(Debug, PartialEq, Eq)]
enum RevertError {
    /// The file is no longer the one this call put in place: someone else replaced or
    /// rewrote it during the check. It is left as it is, and what is there is theirs.
    Replaced,
    /// Taking it back failed: what this call wrote is still in place.
    Failed(String),
}

/// Takes a change back: the previous content, or no file where there was none. Says
/// what was done.
fn revert(undo: &Undo) -> Result<&'static str, RevertError> {
    let target = &undo.target;
    match &undo.previous {
        Some(previous) => {
            let attrs = Attrs {
                mode: previous.mode,
                uid: previous.uid,
                gid: previous.gid,
            };
            let ours = || stamp_at(&target.dir, &target.name) == Some(undo.installed);
            if !ours() {
                return Err(RevertError::Replaced);
            }
            install(
                &target.dir,
                &target.name,
                &previous.content,
                attrs,
                Slot::Holds(undo.installed),
                Some(previous.xattrs.as_slice()),
            )
            // (the file may have been replaced between the look above and the attempt)
            .map_err(|problem| {
                if ours() {
                    RevertError::Failed(problem)
                } else {
                    RevertError::Replaced
                }
            })?;
            Ok("the previous content is back in place")
        }
        None => {
            let ours = stamp_at(&target.dir, &target.name) == Some(undo.installed);
            if !ours {
                return Err(RevertError::Replaced);
            }
            rustix::fs::unlinkat(&target.dir, target.name.as_str(), AtFlags::empty()).map_err(
                |e| RevertError::Failed(format!("it could not be removed: {}", os_error(e))),
            )?;
            let _ = target.dir.sync_all();
            Ok("the new file was removed")
        }
    }
}

async fn config_edit(ctx: Ctx, args: Args) -> ToolResult {
    let request = request(&args)?;
    let clock = CallClock::start(&ctx);
    // Waiting for another edit to finish happens HERE, where being cut off simply ends
    // the wait: a call that gives up in the queue changes nothing, now or later.
    let turn = edit_lock().lock_owned().await;
    if clock.next().is_none() {
        // The wait used up the call. Starting now would mean a change made after the
        // caller has been told that the call ran out of time.
        return Err(ToolError::Failed(
            "no time was left in this call once the edit before it had finished; nothing \
             was changed. Try again."
                .to_string(),
        ));
    }
    // AIDEV-NOTE: the edit runs as a task of its own, and this call only waits for it.
    // A call can be cut off at any point where it waits (its time limit, a client that
    // goes away). If the edit were part of the call, being cut off between the replace
    // and the end of the check would leave an unchecked, perhaps invalid, configuration
    // in place with nobody left to undo it. As a task it always runs to its end.
    tokio::spawn(edit(ctx, request, clock, turn))
        .await
        .map_err(|e| ToolError::Internal(format!("config_edit task failed: {e}")))?
}

/// One whole edit: the change, the check, and the undoing of a change that failed it.
/// `_turn` is this edit's turn (see `ONE_AT_A_TIME`), held until the edit is over.
async fn edit(
    ctx: Ctx,
    request: Request,
    clock: CallClock,
    _turn: tokio::sync::OwnedMutexGuard<()>,
) -> ToolResult {
    let step = {
        let ctx = ctx.clone();
        blocking(ctx.clone(), move || apply(&ctx, &request)).await?
    };
    let changed = match step {
        Step::Done(auth, text, success) => return auth.done(text, success),
        Step::Changed(changed) => *changed,
    };
    let Changed {
        auth,
        text,
        undo,
        check,
        store,
    } = changed;
    let Some((name, cmd)) = check else {
        return auth.ok(text);
    };

    // AIDEV-NOTE: from the replace above until the verdict below, the new content is
    // live on disk: a reload of the service in that moment loads it, checked or not.
    // The checks read the service's real configuration, so it cannot be checked
    // anywhere else first. The check gets what is left of the call (`CallClock` keeps
    // time back), so that the call is not cut off before a failed change is undone.
    let verdict = match clock.next() {
        Some(limit) => checks::run_check(&ctx, cmd.timeout(limit), OWN_LINES)
            .await
            .unwrap_or_else(|_| {
                (
                    "Result: unknown (the check could not be run)\n".to_string(),
                    Outcome::Unknown,
                )
            }),
        None => (
            "Result: unknown (no time was left in this call to run the check)\n".to_string(),
            Outcome::Unknown,
        ),
    };
    let (said, outcome) = verdict;
    if outcome == Outcome::Valid {
        // Kept: now the oldest backups beyond those that are kept can go. Best effort.
        if let Some(store) = store {
            let _ = blocking(ctx.clone(), move || {
                store.prune(KEEP_BACKUPS);
                Ok(())
            })
            .await;
        }
        return auth.ok(format!("{text}Check ({name}): {said}"));
    }

    // Not valid, or no verdict: the old state comes back. A busy server must not be
    // the reason an invalid configuration stays in place, so this is tried a few times.
    let real = undo.target.real.clone();
    let backup = undo.backup.clone();
    let undo = Arc::new(undo);
    let mut reverted = Err(RevertError::Failed(
        "the server was too busy to undo it".to_string(),
    ));
    for attempt in 0..5 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let undo = undo.clone();
        if let Ok(outcome) = blocking(ctx.clone(), move || Ok(revert(&undo))).await {
            reverted = outcome;
            break;
        }
    }
    let no_verdict = outcome == Outcome::Unknown;
    auth.failed(not_kept_text(
        &real,
        name,
        no_verdict,
        &reverted,
        backup.as_deref(),
        &said,
    ))
}

/// What to say about a change that did not pass its check. `no_verdict`: the check did
/// not say "invalid", it said nothing (it did not finish, or could not be run).
///
/// AIDEV-NOTE: the first line is what an agent acts on, so it must be true in each case:
/// a check without a verdict has not "failed" the content, and when someone else
/// replaced the file during the check, what is in place is theirs, not the content this
/// call wrote.
fn not_kept_text(
    real: &str,
    name: &str,
    no_verdict: bool,
    reverted: &Result<&'static str, RevertError>,
    backup: Option<&str>,
    said: &str,
) -> String {
    let first = match reverted {
        Ok(what) if no_verdict => format!(
            "NOT KEPT: the {name} check gave no verdict on the new content of {real} (it did \
             not finish, or could not be run), so the change was undone: {what}."
        ),
        Ok(what) => {
            format!("NOT KEPT: the new content of {real} failed the {name} check, and {what}.")
        }
        Err(RevertError::Failed(problem)) => {
            let rescue = match backup {
                Some(backup) => format!(
                    " The previous content is in backup {backup}: action=restore puts it back."
                ),
                None => " There was no file before: remove it by hand.".to_string(),
            };
            if no_verdict {
                format!(
                    "REVERT FAILED: the {name} check gave no verdict on the new content of \
                     {real}, and the change could NOT be undone: {problem}. The new, unchecked \
                     content is still in place.{rescue}"
                )
            } else {
                format!(
                    "REVERT FAILED: the new content of {real} failed the {name} check and \
                     could NOT be undone: {problem}. The new, invalid content is still in \
                     place.{rescue}"
                )
            }
        }
        Err(RevertError::Replaced) => {
            let what = if no_verdict {
                format!("the {name} check gave no verdict on the new content of {real}")
            } else {
                format!("the new content of {real} failed the {name} check")
            };
            let rescue = match backup {
                Some(backup) => format!(
                    " The content from before this call is in backup {backup}: action=restore \
                     puts it back."
                ),
                None => " There was no file before this call.".to_string(),
            };
            format!(
                "REVERT SKIPPED: {what}, but the file was changed by someone else during the \
                 check, so it was left as it is. What is there now is what they wrote, and \
                 it has not been checked.{rescue}"
            )
        }
    };
    format!("{first}\nCheck ({name}): {said}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{FakeBins, call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const APP_CONF: &str = "# app\nlisten = 8080\nworkers = 4\n";

    /// A temporary site and a host whose configuration lets its `etc` be written:
    ///   etc/app/app.conf (0640), other.conf, link.conf -> app.conf,
    ///   hard.conf = hard2.conf, authorized_keys, server.key
    ///   etc/applink -> app, etc/.ssh/config
    ///   outside/x.conf; backups go to base/backups
    /// erin may write, read and run every check; walt may only write; cora may write
    /// and run the nginx check; nora may write and read app.conf only; rita may only read.
    struct Site {
        _dir: tempfile::TempDir,
        base: PathBuf,
        etc: String,
        host: Arc<Host>,
        audit: MemorySink,
        fake: FakeBins,
    }

    fn site() -> Site {
        site_with(true, "")
    }

    fn site_with(writable: bool, extra_fs: &str) -> Site {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let etc = base.join("etc");
        std::fs::create_dir_all(etc.join("app")).unwrap();
        std::fs::create_dir_all(etc.join(".ssh")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        let app = etc.join("app");
        std::fs::write(app.join("app.conf"), APP_CONF).unwrap();
        std::fs::set_permissions(app.join("app.conf"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        std::fs::write(app.join("other.conf"), "other = 1\n").unwrap();
        std::os::unix::fs::symlink("app.conf", app.join("link.conf")).unwrap();
        std::fs::write(app.join("hard.conf"), "hard = 1\n").unwrap();
        std::fs::hard_link(app.join("hard.conf"), app.join("hard2.conf")).unwrap();
        std::fs::write(app.join("authorized_keys"), "ssh-ed25519 AAAA\n").unwrap();
        std::fs::write(app.join("server.key"), "PRIVATE\n").unwrap();
        std::os::unix::fs::symlink("app", etc.join("applink")).unwrap();
        std::fs::write(etc.join(".ssh/config"), "Host *\n").unwrap();
        std::fs::write(base.join("outside/x.conf"), "x = 1\n").unwrap();

        let etc = etc.to_string_lossy().into_owned();
        // A stand-in for `nginx -t`: the configuration is invalid while app.conf has a
        // line containing BROKEN, the check warns (and passes) for a line containing
        // WARNME, and it never ends while there is one containing HANG. (Stand-ins have
        // shell built-ins only.)
        let fake = FakeBins::new().add_script(
            "nginx",
            &format!(
                "while IFS= read -r line; do case \"$line\" in *BROKEN*) \
                 echo \"nginx: [emerg] unexpected BROKEN in app.conf\"; exit 1;; \
                 *WARNME*) echo \"nginx: [warn] conflicting server name\";; \
                 *HANG*) while :; do :; done;; esac; \
                 done < '{etc}/app/app.conf'\necho 'syntax is ok'\nexit 0"
            ),
        );
        let roots = if writable {
            format!("write_roots = [\"{etc}\"]\nread_roots = [\"{etc}\"]\n")
        } else {
            String::new()
        };
        let config = format!(
            r#"
[roles.editor]
allow = ["fs.write", "fs.read", "config.validate"]
[roles.blind]
allow = ["fs.write"]
[roles.checker]
allow = ["fs.write", "config.validate:nginx"]
[roles.narrow]
allow = ["fs.write:{etc}/app/app.conf", "fs.read:{etc}/app/app.conf"]
[roles.reader]
allow = ["@read"]
[unix_users.erin]
roles = ["editor"]
[unix_users.walt]
roles = ["blind"]
[unix_users.cora]
roles = ["checker"]
[unix_users.nora]
roles = ["narrow"]
[unix_users.rita]
roles = ["reader"]
[fs]
{roots}backup_dir = "{}/backups"
{extra_fs}
{}"#,
            base.display(),
            fake.config_only()
        );
        let (host, audit) = host(&config);
        Site {
            _dir: dir,
            base,
            etc,
            host,
            audit,
            fake,
        }
    }

    impl Site {
        fn path(&self, rest: &str) -> String {
            format!("{}/{rest}", self.etc)
        }

        fn app(&self) -> String {
            self.path("app/app.conf")
        }

        fn read(&self, rest: &str) -> String {
            std::fs::read_to_string(self.path(rest)).unwrap()
        }

        async fn edit(&self, user: &str, arguments: Value) -> ToolResult {
            call(&self.host, user, &find(tools(), "config_edit"), arguments).await
        }

        /// Every backup file there is, as (file name, content).
        fn backups(&self) -> Vec<(String, String)> {
            let mut found = Vec::new();
            let Ok(stores) = std::fs::read_dir(self.base.join("backups")) else {
                return found;
            };
            for store in stores.flatten() {
                for file in std::fs::read_dir(store.path()).unwrap().flatten() {
                    let name = file.file_name().to_string_lossy().into_owned();
                    if name != "path" {
                        found.push((name, std::fs::read_to_string(file.path()).unwrap()));
                    }
                }
            }
            found.sort();
            found
        }

        /// The names in a directory that look like something config_edit left behind.
        fn leftovers(&self, rest: &str) -> Vec<String> {
            std::fs::read_dir(self.path(rest))
                .unwrap()
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.contains(".opsmcp-"))
                .collect()
        }
    }

    fn mode_of(path: &str) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }

    fn failed_text(result: ToolResult) -> String {
        match result {
            Ok(output) if output.is_error() => output.into_parts().0,
            other => panic!("expected a result that says it failed, got {other:?}"),
        }
    }

    fn failure(result: ToolResult) -> String {
        match result {
            Err(ToolError::Failed(message)) => message,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    fn denial(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    fn replace(path: &str, find: &str, with: &str) -> Value {
        json!({"path": path, "action": "replace", "find": find, "replace_with": with})
    }

    // -- replace -------------------------------------------------------------------------

    #[tokio::test]
    async fn replace_changes_the_one_place_and_keeps_the_rest() {
        let s = site();
        let tool = find(tools(), "config_edit");
        assert_eq!(
            (tool.access, tool.permission.as_str()),
            (Access::Write, "fs.write")
        );
        let text = ok_text(
            s.edit(
                "erin",
                replace(&s.app(), "listen = 8080", "listen = 9090\nbacklog = 64"),
            )
            .await,
        );
        assert_eq!(
            s.read("app/app.conf"),
            "# app\nlisten = 9090\nbacklog = 64\nworkers = 4\n"
        );
        // owner and permissions are those of the file that was replaced
        assert_eq!(mode_of(&s.app()), 0o640);
        assert!(
            text.contains(&format!("at line 2 of {}", s.app())),
            "{text}"
        );
        assert!(
            text.contains("Before: 3 lines, 32 bytes; after: 4 lines, 45 bytes."),
            "{text}"
        );
        // the previous content is kept, and named
        let backups = s.backups();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].1, APP_CONF);
        assert!(text.contains(&backups[0].0), "{text}");
        // nothing of ours is left lying about
        assert_eq!(s.leftovers("app"), Vec::<String>::new());
        // one audited decision, on the file's real path
        let records = s.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["resource"], s.app());
        assert_eq!(records[0]["decision"], "allow");
    }

    #[tokio::test]
    async fn replace_needs_the_text_to_occur_exactly_once() {
        let s = site();
        let message = failure(s.edit("erin", replace(&s.app(), "listen = 80 ", "x")).await);
        assert!(message.contains("does not occur"), "{message}");
        // "= " occurs on two lines
        let message = failure(s.edit("erin", replace(&s.app(), " = ", " : ")).await);
        assert!(message.contains("occurs 2 times"), "{message}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert!(s.backups().is_empty());
        // replacing text with itself changes nothing and says so
        let text = ok_text(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 4"))
                .await,
        );
        assert!(text.contains("nothing was changed"), "{text}");
        assert!(s.backups().is_empty());
    }

    #[tokio::test]
    async fn replace_can_delete_text_and_span_lines() {
        let s = site();
        ok_text(
            s.edit(
                "erin",
                replace(&s.app(), "listen = 8080\nworkers = 4\n", ""),
            )
            .await,
        );
        assert_eq!(s.read("app/app.conf"), "# app\n");
    }

    #[tokio::test]
    async fn replace_tells_whether_text_occurs_so_it_needs_the_right_to_read() {
        let s = site();
        // walt may write but not read: `replace` would let him test guesses about what
        // the file says
        let message = denial(
            s.edit("walt", replace(&s.app(), "listen = 8080", "x"))
                .await,
        );
        assert!(message.contains("fs.read"), "{message}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        let records = s.audit.records();
        assert_eq!(records.last().unwrap()["decision"], "deny");
        // replacing the whole content tells him nothing, and is allowed
        let text = ok_text(
            s.edit(
                "walt",
                json!({"path": s.app(), "action": "write", "content": "listen = 1\n"}),
            )
            .await,
        );
        assert_eq!(s.read("app/app.conf"), "listen = 1\n");
        // ... and the result says nothing about what was there: not its text, not its
        // length in lines
        assert!(!text.contains("8080"), "{text}");
        assert!(!text.contains("3 lines"), "{text}");
        assert!(text.contains("After: 1 line, 11 bytes."), "{text}");
    }

    // -- write ---------------------------------------------------------------------------

    #[tokio::test]
    async fn write_replaces_the_whole_content_and_backs_up_the_old() {
        let s = site();
        let text = ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "listen = 1\n\tindented\n"}),
            )
            .await,
        );
        assert_eq!(s.read("app/app.conf"), "listen = 1\n\tindented\n");
        assert_eq!(mode_of(&s.app()), 0o640);
        assert_eq!(s.backups().len(), 1);
        assert_eq!(s.backups()[0].1, APP_CONF);
        assert!(
            text.contains("Before: 3 lines, 32 bytes; after: 2 lines, 21 bytes."),
            "{text}"
        );
        // the old text itself is never echoed
        assert!(!text.contains("8080"), "{text}");
        // the same content again: nothing to do
        let text = ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "listen = 1\n\tindented\n"}),
            )
            .await,
        );
        assert!(text.contains("nothing was changed"), "{text}");
        assert_eq!(s.backups().len(), 1);
    }

    #[tokio::test]
    async fn write_creates_a_file_only_when_told_it_may() {
        let s = site();
        let new = s.path("app/new.conf");
        let message = failure(
            s.edit(
                "erin",
                json!({"path": new, "action": "write", "content": "a = 1\n"}),
            )
            .await,
        );
        assert!(message.contains("create"), "{message}");
        assert!(!Path::new(&new).exists());

        let text = ok_text(
            s.edit(
                "erin",
                json!({"path": new, "action": "write", "content": "a = 1\n", "create": true}),
            )
            .await,
        );
        assert_eq!(std::fs::read_to_string(&new).unwrap(), "a = 1\n");
        assert_eq!(mode_of(&new), 0o644);
        // it belongs to whoever owns the directory
        let dir = std::fs::metadata(s.path("app")).unwrap();
        let made = std::fs::metadata(&new).unwrap();
        assert_eq!((made.uid(), made.gid()), (dir.uid(), dir.gid()));
        assert!(text.contains("Created"), "{text}");
        assert!(text.contains("0644"), "{text}");
        // nothing was there before, so nothing was backed up
        assert!(s.backups().is_empty());
        assert_eq!(s.leftovers("app"), Vec::<String>::new());

        let private = s.path("app/private.conf");
        ok_text(
            s.edit(
                "erin",
                json!({"path": private, "action": "write", "content": "k = v\n",
                       "create": true, "mode": "0600"}),
            )
            .await,
        );
        assert_eq!(mode_of(&private), 0o600);
        // `create` on a file that exists simply replaces its content, keeping its mode
        ok_text(
            s.edit(
                "erin",
                json!({"path": private, "action": "write", "content": "k = w\n",
                       "create": true, "mode": "0644"}),
            )
            .await,
        );
        assert_eq!(std::fs::read_to_string(&private).unwrap(), "k = w\n");
        assert_eq!(mode_of(&private), 0o600);
    }

    // -- what is refused -----------------------------------------------------------------

    #[tokio::test]
    async fn a_symbolic_link_is_not_edited() {
        let s = site();
        let message = failure(
            s.edit(
                "erin",
                replace(&s.path("app/link.conf"), "listen = 8080", "x"),
            )
            .await,
        );
        assert!(message.contains("symbolic link"), "{message}");
        // and where it points is not said
        assert!(!message.contains("app.conf"), "{message}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        let message = failure(
            s.edit(
                "erin",
                json!({"path": s.path("app/link.conf"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert!(message.contains("symbolic link"), "{message}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert!(
            std::fs::symlink_metadata(s.path("app/link.conf"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[tokio::test]
    async fn a_linked_directory_on_the_way_resolves_to_the_real_path() {
        let s = site();
        // nora's grant names the real file; she reaches it through the linked directory
        ok_text(
            s.edit(
                "nora",
                replace(&s.path("applink/app.conf"), "workers = 4", "workers = 8"),
            )
            .await,
        );
        assert_eq!(
            s.read("app/app.conf"),
            "# app\nlisten = 8080\nworkers = 8\n"
        );
        let records = s.audit.records();
        assert_eq!(records[0]["resource"], s.app());
        // a link that leads out of the writable directories is judged by where it leads
        std::os::unix::fs::symlink("../outside", s.path("exit")).unwrap();
        let message = denial(
            s.edit(
                "erin",
                json!({"path": s.path("exit/x.conf"), "action": "write", "content": "x = 2\n"}),
            )
            .await,
        );
        assert!(message.contains("fs.write_roots"), "{message}");
        assert_eq!(
            std::fs::read_to_string(s.base.join("outside/x.conf")).unwrap(),
            "x = 1\n"
        );
    }

    #[tokio::test]
    async fn a_file_with_a_second_hard_link_is_left_alone() {
        let s = site();
        let message = failure(
            s.edit("erin", replace(&s.path("app/hard.conf"), "1", "2"))
                .await,
        );
        assert!(message.contains("hard link"), "{message}");
        assert_eq!(s.read("app/hard.conf"), "hard = 1\n");
        assert_eq!(s.read("app/hard2.conf"), "hard = 1\n");
    }

    #[tokio::test]
    async fn nothing_outside_the_writable_directories_is_written() {
        let s = site();
        let outside = s.base.join("outside/x.conf");
        let message = denial(
            s.edit(
                "erin",
                json!({"path": outside, "action": "write", "content": "x = 2\n"}),
            )
            .await,
        );
        assert!(message.contains("fs.write_roots"), "{message}");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "x = 1\n");
        // a path that does not exist out there gets the same answer
        let message = denial(
            s.edit(
                "erin",
                json!({"path": "/nonexistent-opsmcp-test/a.conf", "action": "write",
                       "content": "x\n", "create": true}),
            )
            .await,
        );
        assert!(message.contains("fs.write_roots"), "{message}");
        assert_eq!(s.audit.records().last().unwrap()["decision"], "deny");
    }

    #[tokio::test]
    async fn a_host_that_names_no_writable_directory_writes_nothing() {
        let s = site_with(false, "");
        for arguments in [
            replace(&s.app(), "listen = 8080", "x"),
            json!({"path": s.app(), "action": "write", "content": "x\n"}),
            json!({"path": s.app(), "action": "restore"}),
            json!({"path": s.app(), "action": "backups"}),
        ] {
            let message = denial(s.edit("erin", arguments).await);
            assert!(message.contains("fs.write_roots"), "{message}");
        }
        assert_eq!(s.read("app/app.conf"), APP_CONF);
    }

    #[tokio::test]
    async fn the_never_written_paths_are_refused_whatever_the_grant() {
        let s = site();
        for rest in ["app/authorized_keys", ".ssh/config"] {
            let message = denial(
                s.edit(
                    "erin",
                    json!({"path": s.path(rest), "action": "write", "content": "x\n"}),
                )
                .await,
            );
            assert!(message.starts_with("Refused:"), "{rest}: {message}");
        }
        // a private key is never readable, and so never written either
        let message = denial(
            s.edit(
                "erin",
                json!({"path": s.path("app/server.key"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert!(message.contains("never-readable"), "{message}");
        assert_eq!(s.read("app/authorized_keys"), "ssh-ed25519 AAAA\n");
        assert_eq!(s.read("app/server.key"), "PRIVATE\n");
        assert_eq!(s.read(".ssh/config"), "Host *\n");
    }

    #[test]
    fn the_never_written_list_covers_accounts_privilege_and_opsmcp_itself() {
        let cfg = crate::config::Config::parse("[audit]\nfile = \"/var/log/opsmcp/audit.jsonl\"\n")
            .unwrap();
        for path in [
            "/etc/opsmcp/config.toml",
            "/etc/passwd",
            "/etc/passwd-",
            "/etc/group",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/subuid",
            "/etc/subgid",
            "/etc/sudoers",
            "/etc/sudoers.d/90-ops",
            "/etc/pam.d/sshd",
            "/etc/security/limits.conf",
            "/etc/ld.so.preload",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d/x.conf",
            "/home/ann/.ssh/config",
            "/root/.ssh/authorized_keys",
            "/etc/ssh/authorized_keys/ann",
            "/srv/keys/authorized_keys2",
            // always, whatever fs.default_deny says:
            "/var/log/opsmcp/audit.jsonl",
            "/var/backups/opsmcp",
            "/var/backups/opsmcp/0123456789abcdef/20260101T000000Z-ab12",
        ] {
            assert!(
                never_written(&cfg, path).is_some(),
                "{path} must never be written"
            );
        }
        for path in [
            "/etc/nginx/nginx.conf",
            "/etc/ssh/sshd_config",
            "/etc/haproxy/haproxy.cfg",
            "/etc/cron.d/backup",
            "/etc/systemd/system/app.service",
            "/var/backups/opsmcp-notes.txt",
            "/var/log/opsmcp/audit.jsonl.1",
        ] {
            assert_eq!(never_written(&cfg, path), None, "{path}");
        }
        // with the built-in lists switched off, only opsmcp's own trail and backups stay
        let open = crate::config::Config::parse(
            "[fs]\ndefault_deny = false\n[audit]\nfile = \"/var/log/opsmcp/audit.jsonl\"\n",
        )
        .unwrap();
        assert_eq!(never_written(&open, "/etc/sudoers"), None);
        assert!(never_written(&open, "/var/log/opsmcp/audit.jsonl").is_some());
        assert!(never_written(&open, "/var/backups/opsmcp/x/y").is_some());
    }

    #[tokio::test]
    async fn the_backup_directory_cannot_be_edited_through_the_tool() {
        // a host whose writable directories include where the backups go
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(base.join("backups/abc")).unwrap();
        std::fs::write(base.join("backups/abc/20260101T000000Z-ab12"), "old\n").unwrap();
        let config = format!(
            "[roles.editor]\nallow = [\"fs.write\", \"fs.read\"]\n[unix_users.erin]\nroles = [\"editor\"]\n\
             [fs]\nwrite_roots = [\"{0}\"]\nread_roots = [\"{0}\"]\nbackup_dir = \"{0}/backups\"\n",
            base.display()
        );
        let (host, _audit) = host(&config);
        let target = base.join("backups/abc/20260101T000000Z-ab12");
        let result = call(
            &host,
            "erin",
            &find(tools(), "config_edit"),
            json!({"path": target, "action": "write", "content": "forged\n"}),
        )
        .await;
        let message = denial(result);
        assert!(message.contains("backups"), "{message}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old\n");
    }

    #[tokio::test]
    async fn the_caller_needs_a_grant_that_covers_the_file() {
        let s = site();
        // rita may read everything and write nothing
        let message = denial(s.edit("rita", replace(&s.app(), "workers = 4", "x")).await);
        assert!(message.contains("fs.write"), "{message}");
        // nora may edit app.conf only; what she is told about another file does not
        // depend on whether it exists
        let exists = denial(
            s.edit(
                "nora",
                json!({"path": s.path("app/other.conf"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        let missing = denial(
            s.edit(
                "nora",
                json!({"path": s.path("app/nothing.conf"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert_eq!(
            exists.replace("other.conf", "FILE"),
            missing.replace("nothing.conf", "FILE")
        );
        assert_eq!(s.read("app/other.conf"), "other = 1\n");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        // the same for a symbolic link she has no grant for: no word about what it is
        let message = denial(
            s.edit(
                "nora",
                json!({"path": s.path("app/link.conf"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert!(!message.contains("symbolic"), "{message}");
    }

    #[tokio::test]
    async fn only_plain_text_files_of_a_sane_size_are_edited() {
        let s = site();
        std::fs::write(s.path("app/latin1.conf"), b"name = caf\xe9\n").unwrap();
        let message = failure(
            s.edit("erin", replace(&s.path("app/latin1.conf"), "name", "n"))
                .await,
        );
        assert!(message.contains("UTF-8"), "{message}");
        std::fs::write(s.path("app/binary.conf"), b"a\x00b\n").unwrap();
        let message = failure(
            s.edit(
                "erin",
                json!({"path": s.path("app/binary.conf"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert!(message.contains("binary"), "{message}");
        assert_eq!(
            std::fs::read(s.path("app/binary.conf")).unwrap(),
            b"a\x00b\n"
        );

        std::fs::write(s.path("app/huge.conf"), "#\n".repeat(600_000)).unwrap();
        let message = failure(
            s.edit(
                "erin",
                json!({"path": s.path("app/huge.conf"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert!(message.contains("too large"), "{message}");

        // a file that is exactly at the limit cannot be made larger
        std::fs::write(
            s.path("app/full.conf"),
            format!("b{}", "a".repeat(1024 * 1024 - 1)),
        )
        .unwrap();
        let message = failure(
            s.edit("erin", replace(&s.path("app/full.conf"), "b", "bb"))
                .await,
        );
        assert!(message.contains("too large"), "{message}");

        // set-user-id and friends have no place on a configuration file
        std::fs::write(s.path("app/suid.conf"), "x = 1\n").unwrap();
        std::fs::set_permissions(
            s.path("app/suid.conf"),
            std::fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        let message = failure(
            s.edit("erin", replace(&s.path("app/suid.conf"), "1", "2"))
                .await,
        );
        assert!(message.contains("set-user-id"), "{message}");

        // a directory, a FIFO: not files
        let message = failure(
            s.edit(
                "erin",
                json!({"path": s.path("app"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert!(message.contains("not a regular file"), "{message}");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            s.path("app/pipe.conf").as_str(),
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        let message = failure(
            s.edit(
                "erin",
                json!({"path": s.path("app/pipe.conf"), "action": "write", "content": "x\n"}),
            )
            .await,
        );
        assert!(message.contains("not a regular file"), "{message}");
        assert!(s.backups().is_empty());
    }

    #[tokio::test]
    async fn unusable_arguments_are_rejected_before_anything_is_looked_at() {
        let s = site();
        let app = s.app();
        for bad in [
            // what each action needs
            json!({"path": app, "action": "replace", "find": "x"}),
            json!({"path": app, "action": "replace", "replace_with": "x"}),
            json!({"path": app, "action": "replace", "find": "", "replace_with": "x"}),
            json!({"path": app, "action": "write"}),
            // and what belongs to another action
            json!({"path": app, "action": "replace", "find": "a", "replace_with": "b", "content": "c"}),
            json!({"path": app, "action": "write", "content": "c", "find": "a"}),
            json!({"path": app, "action": "write", "content": "c", "mode": "0600"}),
            json!({"path": app, "action": "write", "content": "c", "backup": "20260101T000000Z-ab12"}),
            json!({"path": app, "action": "restore", "content": "c"}),
            json!({"path": app, "action": "restore", "create": true}),
            json!({"path": app, "action": "backups", "dry_run": true}),
            json!({"path": app, "action": "backups", "validate": "nginx"}),
            // names
            json!({"path": app, "action": "restore", "backup": "../../etc/passwd"}),
            json!({"path": app, "action": "restore", "backup": "20260101T000000Z"}),
            json!({"path": "etc/app.conf", "action": "write", "content": "c"}),
            json!({"path": format!("{}/app/", s.etc), "action": "write", "content": "c"}),
            json!({"path": format!("{}/app/.", s.etc), "action": "write", "content": "c"}),
            json!({"path": format!("{}/app/..", s.etc), "action": "write", "content": "c"}),
            json!({"path": app, "action": "append", "content": "c"}),
            json!({"path": app, "action": "write", "content": "c", "validate": "nosuchcheck"}),
            json!({"path": app, "action": "write", "content": "a\u{0}b"}),
            json!({"action": "write", "content": "c"}),
        ] {
            assert!(
                matches!(
                    s.edit("erin", bad.clone()).await,
                    Err(ToolError::Invalid(_))
                ),
                "{bad}"
            );
        }
        assert!(s.audit.records().is_empty());
        assert_eq!(s.read("app/app.conf"), APP_CONF);
    }

    // -- backups and restore -------------------------------------------------------------

    #[tokio::test]
    async fn restore_puts_the_previous_content_back() {
        let s = site();
        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8"))
                .await,
        );
        let text = ok_text(
            s.edit("erin", json!({"path": s.app(), "action": "restore"}))
                .await,
        );
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert_eq!(mode_of(&s.app()), 0o640);
        assert!(text.contains("Restored"), "{text}");
        // what was replaced by the restore was itself kept, so a restore can be undone
        assert_eq!(s.backups().len(), 2);
        ok_text(
            s.edit("erin", json!({"path": s.app(), "action": "restore"}))
                .await,
        );
        assert_eq!(
            s.read("app/app.conf"),
            "# app\nlisten = 8080\nworkers = 8\n"
        );
    }

    #[tokio::test]
    async fn restore_can_name_the_backup_to_take() {
        let s = site();
        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 5"))
                .await,
        );
        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 5", "workers = 6"))
                .await,
        );
        let first = s
            .backups()
            .into_iter()
            .find(|(_, content)| content == APP_CONF)
            .unwrap()
            .0;
        ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "restore", "backup": first}),
            )
            .await,
        );
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        let message = failure(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "restore", "backup": "20200101T000000Z-0000"}),
            )
            .await,
        );
        assert!(message.contains("no backup"), "{message}");
    }

    #[tokio::test]
    async fn restore_without_a_backup_fails_and_changes_nothing() {
        let s = site();
        let message = failure(
            s.edit("erin", json!({"path": s.app(), "action": "restore"}))
                .await,
        );
        assert!(message.contains("no backup"), "{message}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        // asking did not create the backup directory
        assert!(!s.base.join("backups").exists());
    }

    #[tokio::test]
    async fn restore_recreates_a_deleted_file_as_a_private_one() {
        let s = site();
        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8"))
                .await,
        );
        std::fs::remove_file(s.app()).unwrap();
        let text = ok_text(
            s.edit("erin", json!({"path": s.app(), "action": "restore"}))
                .await,
        );
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        // its old permissions are not known: the safe choice, and the result says so
        assert_eq!(mode_of(&s.app()), 0o600);
        assert!(text.contains("0600"), "{text}");
    }

    #[tokio::test]
    async fn the_backups_of_a_file_can_be_listed() {
        let s = site();
        let text = ok_text(
            s.edit("erin", json!({"path": s.app(), "action": "backups"}))
                .await,
        );
        assert!(text.contains("no backup"), "{text}");
        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 5"))
                .await,
        );
        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 5", "workers = 6"))
                .await,
        );
        let text = ok_text(
            s.edit("erin", json!({"path": s.app(), "action": "backups"}))
                .await,
        );
        for (name, _) in s.backups() {
            assert!(text.contains(&name), "{name}: {text}");
        }
        assert!(text.contains("  32  "), "{text}");
        // another file's backups are not among them
        ok_text(
            s.edit("erin", replace(&s.path("app/other.conf"), "1", "2"))
                .await,
        );
        let text = ok_text(
            s.edit("erin", json!({"path": s.app(), "action": "backups"}))
                .await,
        );
        assert_eq!(
            text.lines().filter(|line| line.contains("Z-")).count(),
            2,
            "{text}"
        );
    }

    #[tokio::test]
    async fn only_the_newest_backups_of_a_file_are_kept() {
        let s = site();
        for n in 0..(KEEP_BACKUPS + 3) {
            ok_text(
                s.edit(
                    "erin",
                    json!({"path": s.app(), "action": "write", "content": format!("n = {n}\n")}),
                )
                .await,
            );
        }
        assert_eq!(s.backups().len(), KEEP_BACKUPS);
    }

    #[tokio::test]
    async fn the_backup_directory_must_be_the_servers_own() {
        let s = site();
        std::fs::create_dir(s.base.join("backups")).unwrap();
        std::fs::set_permissions(
            s.base.join("backups"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let message = failure(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8"))
                .await,
        );
        assert!(message.contains("backup"), "{message}");
        // no backup, so no change
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert_eq!(s.leftovers("app"), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_new_backup_directory_is_private() {
        let s = site();
        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8"))
                .await,
        );
        assert_eq!(mode_of(&s.base.join("backups").to_string_lossy()), 0o700);
        for store in std::fs::read_dir(s.base.join("backups")).unwrap().flatten() {
            assert_eq!(mode_of(&store.path().to_string_lossy()), 0o700);
            // the store says which file it belongs to
            assert_eq!(
                std::fs::read_to_string(store.path().join("path")).unwrap(),
                format!("{}\n", s.app())
            );
            for file in std::fs::read_dir(store.path()).unwrap().flatten() {
                assert_eq!(mode_of(&file.path().to_string_lossy()), 0o600);
            }
        }
    }

    #[test]
    fn backup_names_carry_the_time_and_nothing_else_is_taken_for_one() {
        assert_eq!(backup_name(0, "0000"), "19700101T000000Z-0000");
        assert_eq!(backup_name(1_795_000_000, "00ff"), "20261118T110640Z-00ff");
        for good in ["19700101T000000Z-0000", "20261118T144640Z-beef"] {
            assert!(is_backup_name(good), "{good}");
        }
        for bad in [
            "",
            "path",
            "20261118T144640Z",
            "20261118T144640Z-BEEF",
            "20261118T144640Z-beef0",
            "20261118T144640Z_beef",
            "2026111xT144640Z-beef",
            "20261118 144640Z-beef",
            "../../../../etc/passwd..",
            ".20261118T144640Z-bee",
        ] {
            assert!(!is_backup_name(bad), "{bad}");
        }
        assert_eq!(
            backup_time("20261118T144640Z-beef"),
            "2026-11-18 14:46:40 UTC"
        );
        assert_eq!(
            next_backup_name("20261118T144640Z-00ff").unwrap(),
            "20261118T144640Z-0100"
        );
        assert!(next_backup_name("20261118T144640Z-ffff").is_err());
    }

    #[test]
    fn backups_made_in_the_same_second_keep_the_order_they_were_made_in() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap().join("backups");
        let store = open_store(&base, "/etc/app.conf", true).unwrap().unwrap();
        let mut made = Vec::new();
        for n in 0..8 {
            made.push(store.save(format!("{n}\n").as_bytes()).unwrap());
        }
        let listed: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(listed, made);
        for (n, name) in made.iter().enumerate() {
            assert_eq!(store.read(name).unwrap(), format!("{n}\n").into_bytes());
        }
        // pruning drops the oldest
        store.prune(3);
        let left: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(left, made[5..]);
        // a name that is not a backup's is never read, whatever is there
        assert!(
            open_store(&base, "/etc/other.conf", false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_backup_made_after_the_clock_went_back_still_sorts_last() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap().join("backups");
        let store = open_store(&base, "/etc/app.conf", true).unwrap().unwrap();
        // a backup that claims to be from far in the future
        let later = "29990101T000000Z-0007";
        std::fs::write(
            base.join(&sha256_hex(b"/etc/app.conf")[..16]).join(later),
            "future\n",
        )
        .unwrap();
        let name = store.save(b"now\n").unwrap();
        assert_eq!(name, "29990101T000000Z-0008");
        assert_eq!(store.list().unwrap().last().unwrap().0, name);
    }

    // -- dry run -------------------------------------------------------------------------

    #[tokio::test]
    async fn a_dry_run_reports_and_changes_nothing() {
        let s = site();
        let mut arguments = replace(&s.app(), "workers = 4", "workers = 8\nthreads = 2");
        arguments["dry_run"] = json!(true);
        arguments["validate"] = json!("nginx");
        let text = ok_text(s.edit("erin", arguments).await);
        assert!(text.starts_with("Dry run: nothing was changed."), "{text}");
        assert!(text.contains("at line 3"), "{text}");
        assert!(text.contains("after: 4 lines, 44 bytes"), "{text}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert!(!s.base.join("backups").exists());
        // a dry run still finds out that the text is not there
        let mut arguments = replace(&s.app(), "absent", "x");
        arguments["dry_run"] = json!(true);
        failure(s.edit("erin", arguments).await);

        let new = s.path("app/new.conf");
        let text = ok_text(
            s.edit(
                "erin",
                json!({"path": new, "action": "write", "content": "a\n", "create": true,
                       "dry_run": true}),
            )
            .await,
        );
        assert!(text.starts_with("Dry run: nothing was changed."), "{text}");
        assert!(!Path::new(&new).exists());
    }

    // -- validate ------------------------------------------------------------------------

    #[tokio::test]
    async fn a_change_that_passes_its_check_is_kept() {
        let s = site();
        let mut arguments = replace(&s.app(), "workers = 4", "workers = 8");
        arguments["validate"] = json!("nginx");
        let text = ok_text(s.edit("erin", arguments).await);
        assert_eq!(
            s.read("app/app.conf"),
            "# app\nlisten = 8080\nworkers = 8\n"
        );
        assert!(text.contains("Result: valid"), "{text}");
        assert!(text.contains("syntax is ok"), "{text}");
    }

    #[tokio::test]
    async fn a_change_that_fails_its_check_is_undone_byte_for_byte() {
        let s = site();
        let before = std::fs::read(s.app()).unwrap();
        let mut arguments = replace(&s.app(), "workers = 4", "workers = BROKEN");
        arguments["validate"] = json!("nginx");
        let text = failed_text(s.edit("erin", arguments).await);
        assert!(text.starts_with("NOT KEPT:"), "{text}");
        assert!(text.contains("unexpected BROKEN"), "{text}");
        assert!(text.contains("Result: INVALID"), "{text}");
        assert_eq!(std::fs::read(s.app()).unwrap(), before);
        assert_eq!(mode_of(&s.app()), 0o640);
        assert_eq!(s.leftovers("app"), Vec::<String>::new());
        // the same for a whole new content, and for a restore of a bad backup
        let text = failed_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "BROKEN\n",
                       "validate": "nginx"}),
            )
            .await,
        );
        assert!(text.starts_with("NOT KEPT:"), "{text}");
        assert_eq!(std::fs::read(s.app()).unwrap(), before);
    }

    /// The whole tool, on a file that has an ACL and an attribute of its own: a change
    /// that is kept, a change that is undone, and a restore all leave them as they were.
    #[tokio::test]
    async fn an_edit_an_undone_edit_and_a_restore_all_keep_the_files_acl() {
        let s = site();
        if !attributes_work(Path::new(&s.path("app"))) {
            return;
        }
        let app = PathBuf::from(s.app());
        assert!(set_attr(&app, "system.posix_acl_access", &sample_acl()));
        assert!(set_attr(&app, "user.opsmcp.note", b"kept"));
        let unchanged = |when: &str| {
            assert_eq!(
                attr(&app, "system.posix_acl_access"),
                Some(sample_acl()),
                "{when}"
            );
            assert_eq!(
                attr(&app, "user.opsmcp.note"),
                Some(b"kept".to_vec()),
                "{when}"
            );
            assert_eq!(mode_of(&s.app()), 0o640, "{when}");
        };

        ok_text(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8"))
                .await,
        );
        assert!(s.read("app/app.conf").contains("workers = 8"));
        unchanged("after a change that was kept");

        let mut broken = replace(&s.app(), "workers = 8", "workers = BROKEN");
        broken["validate"] = json!("nginx");
        let text = failed_text(s.edit("erin", broken).await);
        assert!(text.starts_with("NOT KEPT:"), "{text}");
        unchanged("after a change that was undone");

        // back to the first backup: the content from before the first change
        let backups = ok_text(
            s.edit("erin", json!({"path": s.app(), "action": "backups"}))
                .await,
        );
        let oldest = backups
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .rfind(|name| is_backup_name(name))
            .unwrap()
            .to_string();
        ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "restore", "backup": oldest}),
            )
            .await,
        );
        assert!(s.read("app/app.conf").contains("workers = 4"));
        unchanged("after a restore");
    }

    #[tokio::test]
    async fn creating_a_file_says_when_the_directory_made_it_stricter_than_asked() {
        let s = site();
        if !attributes_work(Path::new(&s.path("app"))) {
            return;
        }
        let directory = File::open(s.path("app")).unwrap();
        rustix::fs::fsetxattr(
            &directory,
            "system.posix_acl_default",
            &sample_acl(),
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        let new = s.path("app/extra.conf");
        let text = ok_text(
            s.edit(
                "erin",
                json!({"path": new, "action": "write", "content": "a = 1\n", "create": true}),
            )
            .await,
        );
        assert_eq!(mode_of(&new), 0o640);
        assert!(
            text.contains("its permissions are 0640, not the 0644 asked for"),
            "{text}"
        );
        // without such a directory nothing of the kind is said
        let plain = site();
        let new = plain.path("app/extra.conf");
        let text = ok_text(
            plain
                .edit(
                    "erin",
                    json!({"path": new, "action": "write", "content": "a = 1\n", "create": true}),
                )
                .await,
        );
        assert_eq!(mode_of(&new), 0o644);
        assert!(!text.contains("not the"), "{text}");
    }

    #[tokio::test]
    async fn a_new_file_that_fails_its_check_is_removed() {
        let s = site();
        // the check reads app.conf, so break that by hand and add a file under check
        std::fs::write(s.app(), "BROKEN already\n").unwrap();
        let new = s.path("app/extra.conf");
        let text = failed_text(
            s.edit(
                "erin",
                json!({"path": new, "action": "write", "content": "a = 1\n", "create": true,
                       "validate": "nginx"}),
            )
            .await,
        );
        assert!(text.starts_with("NOT KEPT:"), "{text}");
        assert!(text.contains("removed"), "{text}");
        assert!(!Path::new(&new).exists());
        assert_eq!(s.leftovers("app"), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_check_that_cannot_run_is_found_out_before_anything_changes() {
        let s = site();
        // haproxy is not installed on this (stand-in) host
        let mut arguments = replace(&s.app(), "workers = 4", "workers = 8");
        arguments["validate"] = json!("haproxy");
        let message = failure(s.edit("erin", arguments).await);
        assert!(message.contains("haproxy"), "{message}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert!(s.backups().is_empty());
    }

    #[tokio::test]
    async fn a_restore_is_checked_and_undone_like_any_other_change() {
        let s = site();
        std::fs::write(s.app(), "BROKEN = 1\n").unwrap();
        // good content now, with the broken one as the backup
        ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "ok = 1\n"}),
            )
            .await,
        );
        let text = failed_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "restore", "validate": "nginx"}),
            )
            .await,
        );
        assert!(text.starts_with("NOT KEPT:"), "{text}");
        assert_eq!(s.read("app/app.conf"), "ok = 1\n");
    }

    #[tokio::test]
    async fn a_check_that_does_not_finish_counts_as_failed() {
        // (A long call limit: the call may first wait its turn behind other tests' edits.
        // The check still gets one second, the limit for a command.)
        let s = site_with(
            true,
            "[limits]\ncall_timeout_secs = 60\ncommand_timeout_secs = 1\n",
        );
        let mut arguments = replace(&s.app(), "workers = 4", "workers = HANG");
        arguments["validate"] = json!("nginx");
        let text = failed_text(s.edit("erin", arguments).await);
        assert!(text.starts_with("NOT KEPT:"), "{text}");
        assert!(text.contains("Result: unknown"), "{text}");
        // no verdict is not the same as a failed check, and the first line says which
        let first = text.lines().next().unwrap();
        assert!(first.contains("gave no verdict"), "{first}");
        assert!(!first.contains("failed the"), "{first}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
    }

    #[tokio::test]
    async fn a_call_that_is_cut_off_still_undoes_a_change_that_fails_its_check() {
        // The check hangs until its one-second limit; the caller gives up before that,
        // but only once the change has been made: a call that is cut off while it still
        // waits its turn changes nothing at all (see the tests for that below).
        let s = site_with(
            true,
            "[limits]\ncall_timeout_secs = 60\ncommand_timeout_secs = 1\n",
        );
        let mut arguments = replace(&s.app(), "workers = 4", "workers = HANG");
        arguments["validate"] = json!("nginx");
        {
            let call = s.edit("erin", arguments);
            tokio::pin!(call);
            let mut made = false;
            for _ in 0..3000 {
                tokio::select! {
                    result = &mut call => panic!("the call should still have been running: {result:?}"),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
                if s.read("app/app.conf").contains("HANG") {
                    made = true;
                    break;
                }
            }
            assert!(made, "the change was never made");
            // the call is dropped here, in the middle of the check
        }
        // The change is taken back when the check has ended, although nobody is waiting
        // for the answer any more.
        let mut undone = false;
        for _ in 0..300 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if s.read("app/app.conf") == APP_CONF {
                undone = true;
                break;
            }
        }
        assert!(undone, "the unchecked change was not taken back");
        assert_eq!(s.backups().len(), 1);
        assert_eq!(s.backups()[0].1, APP_CONF);
        assert_eq!(s.leftovers("app"), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_missing_directory_is_only_reported_to_a_caller_who_may_write_there() {
        let s = site();
        let arguments = json!({"path": s.path("nodir/x.conf"), "action": "write",
                               "content": "x\n", "create": true});
        // erin's grant covers the path: she is told what is wrong
        let message = failure(s.edit("erin", arguments.clone()).await);
        assert!(message.contains("No such file"), "{message}");
        // nora's does not: the answer is the one she gets for any path outside her grant
        let message = denial(s.edit("nora", arguments).await);
        assert!(message.contains("fs.write"), "{message}");
        assert!(!message.contains("No such"), "{message}");
    }

    #[tokio::test]
    async fn a_caller_who_may_not_read_learns_nothing_from_writing_the_same_content() {
        let s = site();
        // for erin, writing what is already there is recognised ...
        let same = json!({"path": s.app(), "action": "write", "content": APP_CONF});
        let text = ok_text(s.edit("erin", same.clone()).await);
        assert!(text.contains("nothing was changed"), "{text}");
        // ... for walt it is not: "it already says that" would confirm a guess
        let text = ok_text(s.edit("walt", same).await);
        assert!(text.contains("Replaced the content"), "{text}");
        assert!(!text.contains("Before"), "{text}");
        // and a restore tells him no more
        let text = ok_text(
            s.edit("walt", json!({"path": s.app(), "action": "restore"}))
                .await,
        );
        assert!(text.contains("Restored"), "{text}");
        assert!(!text.contains("Before"), "{text}");
    }

    #[tokio::test]
    async fn two_edits_at_once_both_happen() {
        let s = site();
        let (one, two) = tokio::join!(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8")),
            s.edit(
                "erin",
                replace(&s.path("app/other.conf"), "other = 1", "other = 2")
            ),
        );
        ok_text(one);
        ok_text(two);
        assert_eq!(
            s.read("app/app.conf"),
            "# app\nlisten = 8080\nworkers = 8\n"
        );
        assert_eq!(s.read("app/other.conf"), "other = 2\n");
        // and two on the same file one after the other, never interleaved
        let (one, two) = tokio::join!(
            s.edit("erin", replace(&s.app(), "listen = 8080", "listen = 1")),
            s.edit("erin", replace(&s.app(), "workers = 8", "workers = 2")),
        );
        ok_text(one);
        ok_text(two);
        assert_eq!(s.read("app/app.conf"), "# app\nlisten = 1\nworkers = 2\n");
    }

    // -- found in review -----------------------------------------------------------------

    /// AIDEV-NOTE: the checks read the service's REAL configuration (visudo names every
    /// sudoers file, logrotate prints its whole configuration, checkers echo the lines
    /// they dislike). Running one through config_edit must need what config_validate
    /// needs, or `fs.write` on one file would be a way around a missing grant there.
    #[tokio::test]
    async fn validate_needs_the_grant_that_config_validate_needs() {
        let s = site();
        // walt may write, but holds no config.validate
        let mut arguments = json!({"path": s.app(), "action": "write", "content": "x = 1\n"});
        arguments["validate"] = json!("nginx");
        let message = denial(s.edit("walt", arguments.clone()).await);
        assert!(
            message.contains("validate=nginx needs config.validate on nginx as well"),
            "{message}"
        );
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert!(s.backups().is_empty());
        assert!(s.fake.calls("nginx").is_empty());
        let last = s.audit.records().last().unwrap().clone();
        assert_eq!(last["decision"], "deny");
        assert_eq!(last["resource"], s.app());
        // a dry run and a restore are refused the same way
        arguments["dry_run"] = json!(true);
        denial(s.edit("walt", arguments).await);
        denial(
            s.edit(
                "walt",
                json!({"path": s.app(), "action": "restore", "validate": "nginx"}),
            )
            .await,
        );
        assert!(s.fake.calls("nginx").is_empty());
        // without validate, walt's write goes through as before
        ok_text(
            s.edit(
                "walt",
                json!({"path": s.app(), "action": "write", "content": "x = 1\n"}),
            )
            .await,
        );

        // cora holds config.validate for nginx and for nothing else
        let mut arguments = json!({"path": s.app(), "action": "write", "content": "y = 1\n"});
        arguments["validate"] = json!("nginx");
        let text = ok_text(s.edit("cora", arguments.clone()).await);
        assert!(text.contains("Result: valid"), "{text}");
        arguments["content"] = json!("z = 1\n");
        arguments["validate"] = json!("sshd");
        let message = denial(s.edit("cora", arguments).await);
        assert!(message.contains("config.validate on sshd"), "{message}");
        assert_eq!(s.read("app/app.conf"), "y = 1\n");
    }

    /// AIDEV-NOTE: a call that gave up while it waited for another edit to finish must
    /// not make its change later, when nobody is left to see the result.
    #[tokio::test]
    async fn a_call_dropped_while_waiting_for_its_turn_changes_nothing() {
        let s = site();
        // another edit is in progress: this test holds the turn
        let turn = edit_lock().lock_owned().await;
        let cut_off = tokio::time::timeout(
            Duration::from_millis(300),
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8")),
        )
        .await;
        assert!(
            cut_off.is_err(),
            "the call should have been waiting for its turn"
        );
        drop(turn);
        // nobody waits for the answer any more, and nothing may happen now
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert!(s.backups().is_empty());
        assert_eq!(s.leftovers("app"), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_call_whose_time_ran_out_in_the_queue_changes_nothing() {
        let s = site_with(
            true,
            "[limits]\ncall_timeout_secs = 4\ncommand_timeout_secs = 1\n",
        );
        let turn = edit_lock().lock_owned().await;
        let (result, ()) = tokio::join!(
            s.edit("erin", replace(&s.app(), "workers = 4", "workers = 8")),
            async move {
                // 3 of the call's 4 seconds can be used: hold the turn for most of them
                tokio::time::sleep(Duration::from_millis(2600)).await;
                drop(turn);
            }
        );
        let message = failure(result);
        assert!(message.contains("no time was left"), "{message}");
        assert!(message.contains("nothing was changed"), "{message}");
        assert_eq!(s.read("app/app.conf"), APP_CONF);
        assert!(s.backups().is_empty());
    }

    /// AIDEV-NOTE: a backup is taken before every change, kept or not. An agent that
    /// retries a change the check keeps refusing must not push every earlier version of
    /// the file out of the twenty that are kept.
    #[tokio::test]
    async fn failed_attempts_do_not_push_good_backups_out() {
        let s = site();
        ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "ok = 1\n"}),
            )
            .await,
        );
        for _ in 0..(KEEP_BACKUPS + 3) {
            let text = failed_text(
                s.edit(
                    "erin",
                    json!({"path": s.app(), "action": "write", "content": "BROKEN\n",
                           "validate": "nginx"}),
                )
                .await,
            );
            assert!(text.starts_with("NOT KEPT:"), "{text}");
        }
        let kept: Vec<String> = s
            .backups()
            .into_iter()
            .map(|(_, content)| content)
            .collect();
        // the original, and the content the failed attempts started from: once each
        assert_eq!(kept, [APP_CONF.to_string(), "ok = 1\n".to_string()]);
    }

    #[tokio::test]
    async fn old_backups_are_only_dropped_once_a_change_is_kept() {
        let s = site();
        for n in 0..KEEP_BACKUPS {
            ok_text(
                s.edit(
                    "erin",
                    json!({"path": s.app(), "action": "write", "content": format!("n = {n}\n")}),
                )
                .await,
            );
        }
        assert_eq!(s.backups().len(), KEEP_BACKUPS);
        assert_eq!(s.backups()[0].1, APP_CONF);
        // a change that is not kept adds its backup and drops none
        failed_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "BROKEN\n",
                       "validate": "nginx"}),
            )
            .await,
        );
        assert_eq!(s.backups().len(), KEEP_BACKUPS + 1);
        assert_eq!(s.backups()[0].1, APP_CONF);
        // the next change that is kept brings the number back down
        ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "kept = 1\n",
                       "validate": "nginx"}),
            )
            .await,
        );
        assert_eq!(s.backups().len(), KEEP_BACKUPS);
        assert_ne!(s.backups()[0].1, APP_CONF);
    }

    #[test]
    fn occurrences_are_counted_with_overlap() {
        assert_eq!(occurrences("aaa\n", "aa"), (2, Some(0)));
        assert_eq!(occurrences("abab", "ab"), (2, Some(0)));
        assert_eq!(occurrences("xaby", "ab"), (1, Some(1)));
        assert_eq!(occurrences("xyz", "ab"), (0, None));
        assert_eq!(occurrences("", "a"), (0, None));
        // by whole characters: a match never starts inside one
        assert_eq!(occurrences("ééé", "éé"), (2, Some(0)));
        assert_eq!(occurrences("aéa", "a"), (2, Some(0)));
    }

    #[tokio::test]
    async fn text_that_overlaps_itself_does_not_count_as_occurring_once() {
        let s = site();
        std::fs::write(s.app(), "aaa\n").unwrap();
        let message = failure(s.edit("erin", replace(&s.app(), "aa", "X")).await);
        assert!(message.contains("occurs 2 times"), "{message}");
        assert_eq!(s.read("app/app.conf"), "aaa\n");
        assert!(s.backups().is_empty());
    }

    /// Agents often send every flag, the ones that do not apply as false.
    #[tokio::test]
    async fn a_false_flag_of_another_action_is_not_a_mistake() {
        let s = site();
        ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "backups", "dry_run": false, "create": false}),
            )
            .await,
        );
        let mut arguments = replace(&s.app(), "workers = 4", "workers = 8");
        arguments["create"] = json!(false);
        arguments["dry_run"] = json!(false);
        ok_text(s.edit("erin", arguments).await);
        assert_eq!(
            s.read("app/app.conf"),
            "# app\nlisten = 8080\nworkers = 8\n"
        );
        // a flag that is set where it means nothing is still pointed out
        let mut arguments = replace(&s.app(), "workers = 8", "workers = 9");
        arguments["create"] = json!(true);
        assert!(matches!(
            s.edit("erin", arguments).await,
            Err(ToolError::Invalid(_))
        ));
    }

    #[test]
    fn the_first_line_says_what_the_check_said_and_what_is_in_place_now() {
        let said = "Result: INVALID (exit 1)\n";
        let first = |text: &str| text.lines().next().unwrap().to_string();
        let back = Ok("the previous content is back in place");
        let text = not_kept_text("/etc/x", "nginx", false, &back, Some("B1"), said);
        assert_eq!(
            first(&text),
            "NOT KEPT: the new content of /etc/x failed the nginx check, and the previous \
             content is back in place."
        );
        assert!(
            text.ends_with("Check (nginx): Result: INVALID (exit 1)\n"),
            "{text}"
        );

        // no verdict is not a failed check
        let line = first(&not_kept_text(
            "/etc/x",
            "nginx",
            true,
            &back,
            Some("B1"),
            said,
        ));
        assert!(
            line.starts_with(
                "NOT KEPT: the nginx check gave no verdict on the new content of /etc/x"
            ),
            "{line}"
        );
        assert!(!line.contains("failed the"), "{line}");
        assert!(
            line.contains("the previous content is back in place"),
            "{line}"
        );

        // the undoing failed: the new content is still there
        let stuck = Err(RevertError::Failed("no space left on device".to_string()));
        let line = first(&not_kept_text(
            "/etc/x",
            "nginx",
            false,
            &stuck,
            Some("B1"),
            said,
        ));
        assert!(line.starts_with("REVERT FAILED:"), "{line}");
        assert!(line.contains("no space left on device"), "{line}");
        assert!(line.contains("still in place"), "{line}");
        assert!(line.contains("backup B1"), "{line}");
        let line = first(&not_kept_text("/etc/x", "nginx", true, &stuck, None, said));
        assert!(line.starts_with("REVERT FAILED:"), "{line}");
        assert!(line.contains("gave no verdict"), "{line}");
        assert!(line.contains("unchecked"), "{line}");
        assert!(line.contains("remove it by hand"), "{line}");

        // someone else replaced the file during the check: what is there now is theirs,
        // and saying that this call's content is still in place would be untrue
        let theirs = Err(RevertError::Replaced);
        let line = first(&not_kept_text(
            "/etc/x",
            "nginx",
            false,
            &theirs,
            Some("B1"),
            said,
        ));
        assert!(line.starts_with("REVERT SKIPPED:"), "{line}");
        assert!(line.contains("someone else"), "{line}");
        assert!(!line.contains("still in place"), "{line}");
        assert!(line.contains("backup B1"), "{line}");
    }

    #[test]
    fn the_temporary_name_fits_in_a_file_name_whatever_the_name() {
        assert_eq!(
            temp_name("a.conf", "0123abcd"),
            ".a.conf.opsmcp-0123abcd.tmp"
        );
        for name in [
            "x".repeat(255),
            "漢".repeat(85),
            "é".repeat(127),
            format!("{}é", "a".repeat(199)),
            format!("{}漢", "a".repeat(198)),
        ] {
            let temp = temp_name(&name, "0123abcd");
            assert!(temp.len() <= 255, "{} bytes for {name:?}", temp.len());
            assert!(
                temp.starts_with('.') && temp.ends_with(".opsmcp-0123abcd.tmp"),
                "{temp}"
            );
        }
    }

    /// 80 characters of three bytes each are a valid name of 240 bytes; the first 100
    /// CHARACTERS of a name were once kept, which made the temporary name too long.
    #[test]
    fn a_file_with_a_long_name_of_wide_characters_can_be_replaced() {
        let (dir, open) = scratch("x\n");
        let name = "漢".repeat(80);
        std::fs::write(dir.path().join(&name), "old\n").unwrap();
        let old = read_existing(&open, &name).unwrap().unwrap();
        install(
            &open,
            &name,
            b"new\n",
            own(0o644),
            Slot::Holds(old.stamp),
            None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(&name)).unwrap(),
            "new\n"
        );
        assert_eq!(names_in(dir.path()), ["a.conf".to_string(), name]);
    }

    #[tokio::test]
    async fn a_change_whose_check_only_warns_is_kept_and_the_warning_shown() {
        let s = site();
        let text = ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "WARNME = 1\n",
                       "validate": "nginx"}),
            )
            .await,
        );
        assert_eq!(s.read("app/app.conf"), "WARNME = 1\n");
        assert!(
            text.contains("Check (nginx): Result: valid, with warnings"),
            "{text}"
        );
        assert!(text.contains("conflicting server name"), "{text}");
    }

    // -- the pieces ----------------------------------------------------------------------

    /// A directory with one file in it, opened the way a target's directory is.
    fn scratch(content: &str) -> (tempfile::TempDir, File) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.conf"), content).unwrap();
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let open = File::from(rustix::fs::open(dir.path(), flags, Mode::empty()).unwrap());
        (dir, open)
    }

    fn own(mode: u32) -> Attrs {
        Attrs {
            mode,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
        }
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn install_replaces_the_file_that_was_read_and_leaves_nothing_else() {
        let (dir, open) = scratch("old\n");
        let old = read_existing(&open, "a.conf").unwrap().unwrap();
        let stamp = install(
            &open,
            "a.conf",
            b"new\n",
            own(0o640),
            Slot::Holds(old.stamp),
            None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.conf")).unwrap(),
            "new\n"
        );
        assert_eq!(mode_of(&dir.path().join("a.conf").to_string_lossy()), 0o640);
        assert_eq!(names_in(dir.path()), ["a.conf"]);
        // what it returns is the file now there
        assert_eq!(stamp_at(&open, "a.conf"), Some(stamp));
        assert_ne!(stamp.ino, old.stamp.ino);
    }

    // ---- extended attributes: ACLs, labels ----

    /// A POSIX ACL as the kernel stores it in `system.posix_acl_access`: owner `rw-`,
    /// the named user 12345 `r--`, group `r--`, mask `r--`, others nothing.
    fn sample_acl() -> Vec<u8> {
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (0x01u16, 6u16, u32::MAX),
            (0x02, 4, 12345),
            (0x04, 4, u32::MAX),
            (0x10, 4, u32::MAX),
            (0x20, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(perm.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        acl
    }

    fn set_attr(path: &Path, name: &str, value: &[u8]) -> bool {
        let file = File::open(path).unwrap();
        rustix::fs::fsetxattr(&file, name, value, rustix::fs::XattrFlags::empty()).is_ok()
    }

    fn attr(path: &Path, name: &str) -> Option<Vec<u8>> {
        let file = File::open(path).unwrap();
        let size = rustix::fs::fgetxattr_query(&file, name).ok()?;
        let mut value = vec![0u8; size];
        let got = rustix::fs::fgetxattr(&file, name, value.as_mut_slice()).ok()?;
        value.truncate(got);
        Some(value)
    }

    /// Whether this test directory's filesystem takes user attributes and ACLs from an
    /// ordinary user (ext4, xfs and btrfs do; some tmpfs do not). Where it does not, the
    /// tests below have nothing to check and say so.
    fn attributes_work(dir: &Path) -> bool {
        let probe = dir.join(".attribute-probe");
        std::fs::write(&probe, "x").unwrap();
        let works = set_attr(&probe, "user.opsmcp.probe", b"1")
            && set_attr(&probe, "system.posix_acl_access", &sample_acl());
        std::fs::remove_file(&probe).unwrap();
        if !works {
            eprintln!("skipped: this filesystem takes no user attributes or ACLs");
        }
        works
    }

    #[test]
    fn which_attributes_are_carried_over_is_decided_by_name() {
        // the ones that decide who may do what with the file
        assert_eq!(carry("system.posix_acl_access"), Carry::Yes);
        assert_eq!(carry("security.selinux"), Carry::Yes);
        assert_eq!(carry("security.SMACK64"), Carry::Yes);
        assert_eq!(carry("system.nfs4_acl"), Carry::Yes);
        // and whatever else the owner or root attached
        assert_eq!(carry("user.comment"), Carry::Yes);
        assert_eq!(carry("trusted.backup"), Carry::Yes);
        // bound to the content, so the old value would be wrong for the new file
        assert_eq!(carry("security.ima"), Carry::No);
        assert_eq!(carry("security.evm"), Carry::No);
        // a file that carries privileges is not a configuration file
        assert_eq!(carry("security.capability"), Carry::Refuse);
    }

    /// AIDEV-NOTE: the reason this matters. With an ACL, the group bits of the mode are
    /// the ACL's mask, not the group's rights. A replacement that copied only the mode
    /// would turn `group::r--, mask::rw-` into "group may write", and drop the named
    /// entries: the new file would be open to other people than the old one.
    #[test]
    fn the_new_file_keeps_the_acl_and_the_attributes_of_the_old_one() {
        let (dir, open) = scratch("old\n");
        if !attributes_work(dir.path()) {
            return;
        }
        let path = dir.path().join("a.conf");
        assert!(set_attr(&path, "system.posix_acl_access", &sample_acl()));
        assert!(set_attr(&path, "user.opsmcp.note", b"kept"));
        let old = read_existing(&open, "a.conf").unwrap().unwrap();
        assert_eq!(old.mode, 0o640);
        assert!(
            old.xattrs
                .iter()
                .any(|(name, value)| name == "system.posix_acl_access" && *value == sample_acl()),
            "{:?}",
            old.xattrs
        );

        let attrs = Attrs {
            mode: old.mode,
            uid: old.uid,
            gid: old.gid,
        };
        let stamp = install(
            &open,
            "a.conf",
            b"new\n",
            attrs,
            Slot::Holds(old.stamp),
            Some(&old.xattrs),
        )
        .unwrap();
        // a new file, with the old one's ACL and attributes, byte for byte
        assert_ne!(stamp.ino, old.stamp.ino);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
        assert_eq!(attr(&path, "system.posix_acl_access"), Some(sample_acl()));
        assert_eq!(attr(&path, "user.opsmcp.note"), Some(b"kept".to_vec()));
        assert_eq!(mode_of(&path.to_string_lossy()), 0o640);
    }

    #[test]
    fn an_acl_the_directory_would_hand_out_is_not_added_to_a_file_that_had_none() {
        let (dir, open) = scratch("old\n");
        if !attributes_work(dir.path()) {
            return;
        }
        let path = dir.path().join("a.conf");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // from now on, files created in this directory inherit an ACL
        let directory = File::open(dir.path()).unwrap();
        rustix::fs::fsetxattr(
            &directory,
            "system.posix_acl_default",
            &sample_acl(),
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        let old = read_existing(&open, "a.conf").unwrap().unwrap();
        assert!(old.xattrs.is_empty(), "{:?}", old.xattrs);

        let attrs = Attrs {
            mode: old.mode,
            uid: old.uid,
            gid: old.gid,
        };
        install(
            &open,
            "a.conf",
            b"new\n",
            attrs,
            Slot::Holds(old.stamp),
            Some(&old.xattrs),
        )
        .unwrap();
        // the replacement is as closed as the file it replaces
        assert_eq!(attr(&path, "system.posix_acl_access"), None);
        assert_eq!(mode_of(&path.to_string_lossy()), 0o600);
    }

    /// AIDEV-NOTE: found against a real directory with a default ACL of `other::---`: a
    /// file created there with mode 0644 came out readable by everyone, where a file
    /// made by hand with the same mode is not (the kernel takes the mode and the
    /// directory's default ACL together, and the stricter of the two wins).
    #[test]
    fn a_created_file_is_no_more_open_than_its_directory_makes_new_files() {
        let (dir, open) = scratch("old\n");
        if !attributes_work(dir.path()) {
            return;
        }
        // new files here: owner rw-, a named user r--, group r--, others nothing
        let directory = File::open(dir.path()).unwrap();
        rustix::fs::fsetxattr(
            &directory,
            "system.posix_acl_default",
            &sample_acl(),
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        install(&open, "new.conf", b"made\n", own(0o644), Slot::Free, None).unwrap();
        let path = dir.path().join("new.conf");
        // 0644 asked for, others get nothing: as `touch` with mode 0644 would give
        assert_eq!(mode_of(&path.to_string_lossy()), 0o640);
        // and it carries the ACL the directory hands out, named entry included
        let acl = attr(&path, "system.posix_acl_access").unwrap();
        assert!(
            acl.windows(4).any(|id| id == 12345u32.to_le_bytes()),
            "{acl:?}"
        );
        // a stricter mode than the directory's is kept as asked
        install(&open, "tight.conf", b"made\n", own(0o600), Slot::Free, None).unwrap();
        assert_eq!(
            mode_of(&dir.path().join("tight.conf").to_string_lossy()),
            0o600
        );
    }

    #[test]
    fn without_a_default_acl_a_created_file_gets_exactly_the_mode_asked_for() {
        let (dir, open) = scratch("old\n");
        for (name, mode) in [
            ("a644.conf", 0o644),
            ("a640.conf", 0o640),
            ("a600.conf", 0o600),
        ] {
            install(&open, name, b"made\n", own(mode), Slot::Free, None).unwrap();
            assert_eq!(
                mode_of(&dir.path().join(name).to_string_lossy()),
                mode,
                "{name}"
            );
        }
    }

    #[test]
    fn install_does_not_overwrite_a_file_that_changed_since_it_was_read() {
        // rewritten in place: the same file, another content
        let (dir, open) = scratch("old\n");
        let old = read_existing(&open, "a.conf").unwrap().unwrap();
        std::fs::write(dir.path().join("a.conf"), "someone else's change\n").unwrap();
        let problem = install(
            &open,
            "a.conf",
            b"new\n",
            own(0o644),
            Slot::Holds(old.stamp),
            None,
        )
        .unwrap_err();
        assert!(problem.contains("changed by someone else"), "{problem}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.conf")).unwrap(),
            "someone else's change\n"
        );
        assert_eq!(names_in(dir.path()), ["a.conf"]);

        // replaced by another file of the same length
        let (dir, open) = scratch("old\n");
        let old = read_existing(&open, "a.conf").unwrap().unwrap();
        std::fs::write(dir.path().join("b.conf"), "NEW\n").unwrap();
        std::fs::rename(dir.path().join("b.conf"), dir.path().join("a.conf")).unwrap();
        assert!(
            install(
                &open,
                "a.conf",
                b"new\n",
                own(0o644),
                Slot::Holds(old.stamp),
                None
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.conf")).unwrap(),
            "NEW\n"
        );

        // removed, or turned into a link
        let (dir, open) = scratch("old\n");
        let old = read_existing(&open, "a.conf").unwrap().unwrap();
        std::fs::remove_file(dir.path().join("a.conf")).unwrap();
        assert!(
            install(
                &open,
                "a.conf",
                b"new\n",
                own(0o644),
                Slot::Holds(old.stamp),
                None
            )
            .is_err()
        );
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("a.conf")).unwrap();
        assert!(
            install(
                &open,
                "a.conf",
                b"new\n",
                own(0o644),
                Slot::Holds(old.stamp),
                None
            )
            .is_err()
        );
        assert_eq!(names_in(dir.path()), ["a.conf"]);
        assert!(
            std::fs::symlink_metadata(dir.path().join("a.conf"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn install_creates_a_file_only_while_its_name_is_free() {
        let (dir, open) = scratch("old\n");
        let stamp = install(&open, "new.conf", b"made\n", own(0o600), Slot::Free, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("new.conf")).unwrap(),
            "made\n"
        );
        assert_eq!(
            mode_of(&dir.path().join("new.conf").to_string_lossy()),
            0o600
        );
        assert_eq!(stamp_at(&open, "new.conf"), Some(stamp));
        // exactly one name: the temporary one is gone
        assert_eq!(
            std::fs::metadata(dir.path().join("new.conf"))
                .unwrap()
                .nlink(),
            1
        );
        assert_eq!(names_in(dir.path()), ["a.conf", "new.conf"]);

        // a name that is taken, by a file or by a link (even a dangling one), is not replaced
        let problem = install(&open, "a.conf", b"x\n", own(0o644), Slot::Free, None).unwrap_err();
        assert!(problem.contains("appeared"), "{problem}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.conf")).unwrap(),
            "old\n"
        );
        std::os::unix::fs::symlink("nowhere", dir.path().join("link.conf")).unwrap();
        assert!(install(&open, "link.conf", b"x\n", own(0o644), Slot::Free, None).is_err());
        assert!(!dir.path().join("nowhere").exists());
        assert_eq!(names_in(dir.path()), ["a.conf", "link.conf", "new.conf"]);
    }

    #[test]
    fn a_change_is_taken_back_only_if_the_file_is_still_the_one_installed() {
        let target = |open: File, real: &Path| Target {
            dir: open,
            name: "a.conf".to_string(),
            real: real.join("a.conf").to_string_lossy().into_owned(),
        };
        // a replaced file: the old content comes back
        let (dir, open) = scratch("old\n");
        let previous = read_existing(&open, "a.conf").unwrap().unwrap();
        let installed = install(
            &open,
            "a.conf",
            b"new\n",
            own(0o644),
            Slot::Holds(previous.stamp),
            None,
        )
        .unwrap();
        let undo = Undo {
            target: target(open, dir.path()),
            previous: Some(previous),
            installed,
            backup: None,
        };
        assert_eq!(revert(&undo), Ok("the previous content is back in place"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.conf")).unwrap(),
            "old\n"
        );
        // a second attempt finds a file that is not the one installed, and leaves it
        assert_eq!(revert(&undo), Err(RevertError::Replaced));

        // a created file: it goes
        let (dir, open) = scratch("old\n");
        std::fs::remove_file(dir.path().join("a.conf")).unwrap();
        let installed = install(&open, "a.conf", b"new\n", own(0o644), Slot::Free, None).unwrap();
        let undo = Undo {
            target: target(open, dir.path()),
            previous: None,
            installed,
            backup: None,
        };
        assert_eq!(revert(&undo), Ok("the new file was removed"));
        assert!(!dir.path().join("a.conf").exists());

        // ... unless someone has put another file there meanwhile
        let (dir, open) = scratch("old\n");
        std::fs::remove_file(dir.path().join("a.conf")).unwrap();
        let installed = install(&open, "a.conf", b"new\n", own(0o644), Slot::Free, None).unwrap();
        std::fs::remove_file(dir.path().join("a.conf")).unwrap();
        std::fs::write(dir.path().join("a.conf"), "theirs\n").unwrap();
        let undo = Undo {
            target: target(open, dir.path()),
            previous: None,
            installed,
            backup: None,
        };
        assert_eq!(revert(&undo), Err(RevertError::Replaced));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.conf")).unwrap(),
            "theirs\n"
        );
    }

    #[test]
    fn the_size_of_a_content_counts_a_last_line_without_a_break() {
        assert_eq!(size_text(b""), "0 lines, 0 bytes");
        assert_eq!(size_text(b"a\n"), "1 line, 2 bytes");
        assert_eq!(size_text(b"a"), "1 line, 1 bytes");
        assert_eq!(size_text(b"a\nb"), "2 lines, 3 bytes");
        assert_eq!(size_text(b"a\n\n"), "2 lines, 3 bytes");
    }

    #[test]
    fn a_path_splits_into_its_directory_and_a_plain_name() {
        let ok = |path: &str| split_path(path).unwrap();
        assert_eq!(
            ok("/etc/nginx/nginx.conf"),
            ("/etc/nginx".to_string(), "nginx.conf".to_string())
        );
        assert_eq!(ok("/hosts"), ("/".to_string(), "hosts".to_string()));
        assert_eq!(
            ok("/etc/a/../b/c.conf"),
            ("/etc/a/../b".to_string(), "c.conf".to_string())
        );
        for bad in ["etc/x", "", "/", "/etc/", "/etc/.", "/etc/..", "x"] {
            assert!(split_path(bad).is_err(), "{bad:?}");
        }
        assert!(split_path(&format!("/etc/{}", "a".repeat(256))).is_err());
    }

    #[tokio::test]
    async fn the_result_notes_a_missing_final_line_break() {
        let s = site();
        let text = ok_text(
            s.edit(
                "erin",
                json!({"path": s.app(), "action": "write", "content": "a = 1"}),
            )
            .await,
        );
        assert!(text.contains("does not end with a line break"), "{text}");
        assert!(text.contains("after: 1 line, 5 bytes"), "{text}");
    }
}
