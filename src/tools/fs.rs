//! Looking at the filesystem: list a directory, stat a path, read a file.
//!
//! Three layers decide what can be seen, all applied to the REAL path (links resolved,
//! see `paths`): the directories the host's configuration opens up (`fs.list_roots`,
//! `fs.read_roots`), the never-readable patterns below, and the caller's own grants.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;

use nix::unistd::{Gid, Group, Uid, User};

use super::args::{Args, Param};
use super::paths::{Opened, lexical, open_path, within};
use super::{Ctx, Tool, ToolError, ToolResult, blocking, format_rows, required};
use crate::config::FsCfg;
use crate::glob::glob_match;
use crate::policy::Access;
use crate::sanitize::{clean_text, fit_prefix};
use crate::timefmt::{human_bytes, rfc3339_utc};

/// Paths whose content is never shown and which are never listed, unless the operator
/// turns this list off with `fs.default_deny = false`.
///
/// AIDEV-NOTE: this is a safety net for the obvious secrets, not the access control. The
/// access control is `fs.read_roots` (empty by default) plus the caller's grants.
pub const DEFAULT_DENY: &[&str] = &[
    // account and authentication databases
    "/etc/shadow*",
    "/etc/gshadow*",
    "/etc/security/opasswd*",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/etc/krb5.keytab",
    "**/*.keytab",
    // opsmcp's own configuration and keys
    "/etc/opsmcp/**",
    // private keys and key stores
    "/etc/ssh/*_key",
    "/etc/ssl/private/**",
    "/etc/pki/**/private/**",
    "**/*.key",
    "**/*key.pem",
    "**/privkey*.pem",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/id_rsa*",
    "**/id_dsa*",
    "**/id_ecdsa*",
    "**/id_ed25519*",
    // per-user credentials and histories
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/.aws/**",
    "**/.kube/**",
    "**/.docker/config.json",
    "**/.netrc",
    "**/.pgpass",
    "**/.my.cnf",
    "**/.git-credentials",
    "**/.vault-token",
    "**/.*_history",
    // application secrets in their usual places
    "**/.env",
    "**/.env.*",
    "**/.htpasswd*",
    "**/*.kdbx",
    "/etc/postfix/sasl_passwd*",
    "/etc/wpa_supplicant/**",
    "/etc/pgbouncer/userlist.txt",
    "/etc/libvirt/secrets/**",
    // network secrets
    "/etc/wireguard/**",
    "/etc/ipsec.secrets",
    "/etc/ppp/*-secrets",
    "/etc/NetworkManager/system-connections/**",
    "/etc/kubernetes/pki/**",
    "/etc/kubernetes/*.conf",
    // kernel interfaces that expose memory, environments or keys
    "/proc/kcore",
    "/proc/kmsg",
    "/proc/keys",
    "/proc/*/environ",
    "/proc/*/mem",
    "/proc/*/maps",
    "/proc/*/smaps",
    "/proc/*/pagemap",
    "/proc/*/stack",
    "/proc/*/auxv",
    "/proc/*/cmdline",
    "/proc/*/task/**",
    "/proc/*/fd/**",
    "/proc/*/root/**",
    "/proc/*/cwd/**",
    "/sys/kernel/security/**",
    "/sys/kernel/debug/**",
    "/sys/kernel/tracing/**",
    "/sys/firmware/efi/efivars/**",
];

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "fs_list",
            "List a directory: type, permissions, owner, size, modification time and name of \
             each entry. Use an absolute path.",
            Access::Read,
            "fs.view",
            vec![
                Param::str("path", "Absolute path of the directory")
                    .max_len(4096)
                    .required(),
                Param::int("limit", "Most entries to show (default 200)", 1, 2000),
            ],
            fs_list,
        ),
        Tool::new(
            "fs_stat",
            "Show metadata for one path (type, permissions, owner, size, times). A symbolic \
             link is described itself, with its target; it is not followed.",
            Access::Read,
            "fs.view",
            vec![Param::str("path", "Absolute path").max_len(4096).required()],
            fs_stat,
        ),
        Tool::new(
            "fs_read",
            "Read a text file. Only files under the directories this host's configuration \
             allows can be read, and never private keys or password databases. For log files \
             use log_read instead. Large files are read in pieces with offset and max_bytes.",
            Access::Read,
            "fs.read",
            vec![
                Param::str("path", "Absolute path of the file")
                    .max_len(4096)
                    .required(),
                Param::int("offset", "Byte offset to start at (default 0)", 0, i64::MAX),
                Param::int(
                    "max_bytes",
                    "Most bytes to return (default: the server's output limit)",
                    1,
                    16 << 20,
                ),
            ],
            fs_read,
        ),
    ]
}

/// If `real` matches a never-readable pattern, that pattern.
pub fn denied_by(cfg: &FsCfg, real: &str) -> Option<String> {
    let built_in: &[&str] = if cfg.default_deny { DEFAULT_DENY } else { &[] };
    built_in
        .iter()
        .copied()
        .chain(cfg.deny.iter().map(String::as_str))
        .find(|pattern| glob_match(pattern, real))
        .map(str::to_string)
}

/// True when `real` lies in one of the configured directories. A configured directory
/// may itself be reached through a link (/var/run, a moved /var/log...), so the path is
/// compared with where each one really is as well as with how it was written.
pub(super) fn inside(real: &str, roots: &[PathBuf]) -> bool {
    let real_roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    within(real, roots) || within(real, &real_roots)
}

/// Pins a caller-supplied path for a tool that is limited to `roots`.
///
/// A path that cannot be opened and that is, as written, outside those directories gets
/// the same refusal as one that exists there. Otherwise "no such file" versus "refused"
/// would let a caller find out what exists anywhere on the host.
pub fn pin(
    ctx: &Ctx,
    path: &str,
    follow: bool,
    roots: &[PathBuf],
    setting: &str,
) -> Result<Opened, ToolError> {
    match open_path(path, follow) {
        Err(ToolError::Failed(_)) if !inside(&lexical(path), roots) => {
            let reason =
                format!("{path} is outside the directories that {setting} allows on this host");
            Err(ctx.deny(Some(path), &reason))
        }
        other => other,
    }
}

/// The host-wide limits on a path: it must be inside one of `roots` and must not be a
/// never-readable path. A refusal is audited.
pub fn check_limits(
    ctx: &Ctx,
    real: &str,
    resource: &str,
    roots: &[PathBuf],
    setting: &str,
) -> Result<(), ToolError> {
    if !inside(real, roots) {
        let reason =
            format!("{real} is outside the directories that {setting} allows on this host");
        return Err(ctx.deny(Some(resource), &reason));
    }
    if let Some(pattern) = denied_by(&ctx.cfg().fs, resource) {
        let reason = format!("{real} matches the never-readable pattern {pattern}");
        return Err(ctx.deny(Some(resource), &reason));
    }
    Ok(())
}

/// `ls -l` style type and permission string for a raw `st_mode`.
pub fn mode_string(mode: u32) -> String {
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o010000 => 'p',
        0o140000 => 's',
        0o060000 => 'b',
        0o020000 => 'c',
        _ => '-',
    };
    let mut out = String::with_capacity(10);
    out.push(kind);
    // user, group, other: each with its special bit (setuid, setgid, sticky)
    for (shift, special_bit, special_char) in [(6, 0o4000, 's'), (3, 0o2000, 's'), (0, 0o1000, 't')]
    {
        let bits = (mode >> shift) & 0o7;
        out.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        out.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        out.push(match (bits & 0o1 != 0, mode & special_bit != 0) {
            (true, true) => special_char,
            (false, true) => special_char.to_ascii_uppercase(),
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    out
}

fn kind_name(meta: &std::fs::Metadata) -> &'static str {
    let kind = meta.file_type();
    if kind.is_file() {
        "regular file"
    } else if kind.is_dir() {
        "directory"
    } else if kind.is_symlink() {
        "symbolic link"
    } else if kind.is_fifo() {
        "FIFO"
    } else if kind.is_socket() {
        "socket"
    } else if kind.is_block_device() {
        "block device"
    } else if kind.is_char_device() {
        "character device"
    } else {
        "special file"
    }
}

/// Looks up user and group names, remembering answers for the length of one listing.
#[derive(Default)]
pub struct Names {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

impl Names {
    pub fn user(&mut self, uid: u32) -> &str {
        self.users
            .entry(uid)
            .or_insert_with(|| match User::from_uid(Uid::from_raw(uid)) {
                Ok(Some(user)) => user.name,
                _ => uid.to_string(),
            })
    }

    pub fn group(&mut self, gid: u32) -> &str {
        self.groups
            .entry(gid)
            .or_insert_with(|| match Group::from_gid(Gid::from_raw(gid)) {
                Ok(Some(group)) => group.name,
                _ => gid.to_string(),
            })
    }
}

/// The resource name of a directory: its real path with a trailing slash, so that a
/// grant like `/var/log/**` covers the directory itself as well as what is in it.
pub fn dir_resource(real: &str) -> String {
    if real.ends_with('/') {
        real.to_string()
    } else {
        format!("{real}/")
    }
}

/// One line of a directory listing.
pub struct Entry {
    pub mode: String,
    pub owner: String,
    pub group: String,
    pub size: u64,
    pub modified: String,
    /// The name, with `/` after a directory or ` -> target` after a link.
    pub name: String,
}

/// Lays out directory entries in aligned columns.
pub fn format_listing(entries: &[Entry]) -> String {
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            vec![
                e.mode.clone(),
                e.owner.clone(),
                e.group.clone(),
                e.size.to_string(),
                e.modified.clone(),
                e.name.clone(),
            ]
        })
        .collect();
    format_rows(&rows, &[false, false, false, true, false, false])
}

/// Formats the entries of a pinned directory, sorted by name, at most `limit` of them.
pub fn list_directory(opened: &Opened, limit: usize) -> Result<String, ToolError> {
    /// Entries read from one directory before giving up on seeing all of it.
    const MAX_SCANNED: usize = 20_000;
    let reader = std::fs::read_dir(opened.dir_path())
        .map_err(|e| ToolError::Failed(format!("{}: {e}", opened.real)))?;
    let mut entries = Vec::new();
    let mut more_unread = false;
    for entry in reader.flatten() {
        if entries.len() >= MAX_SCANNED {
            more_unread = true;
            break;
        }
        entries.push(entry);
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut names = Names::default();
    let mut listed = Vec::new();
    for entry in entries.iter().take(limit) {
        let name = entry.file_name().to_string_lossy().into_owned();
        // DirEntry::metadata does not follow links: a link is shown as a link.
        let Ok(meta) = entry.metadata() else {
            listed.push(Entry {
                mode: "??????????".to_string(),
                owner: "?".to_string(),
                group: "?".to_string(),
                size: 0,
                modified: "?".to_string(),
                name,
            });
            continue;
        };
        let suffix = if meta.is_dir() {
            "/".to_string()
        } else if meta.file_type().is_symlink() {
            match std::fs::read_link(entry.path()) {
                Ok(target) => format!(" -> {}", target.display()),
                Err(_) => String::new(),
            }
        } else {
            String::new()
        };
        listed.push(Entry {
            mode: mode_string(meta.mode()),
            owner: names.user(meta.uid()).to_string(),
            group: names.group(meta.gid()).to_string(),
            size: meta.len(),
            modified: rfc3339_utc(meta.mtime()),
            name: format!("{name}{suffix}"),
        });
    }
    let mut out = format!(
        "{} ({} entries)\n",
        dir_resource(&opened.real),
        entries.len()
    );
    out.push_str(&format_listing(&listed));
    if entries.len() > limit {
        out.push_str(&format!(
            "[{} more entries not shown; raise limit to see them]\n",
            entries.len() - limit
        ));
    }
    if more_unread {
        out.push_str(&format!(
            "[the directory has more than {MAX_SCANNED} entries; only the first {MAX_SCANNED} read were sorted]\n"
        ));
    }
    Ok(out)
}

async fn fs_list(ctx: Ctx, args: Args) -> ToolResult {
    let path = required(&args, "path")?.to_string();
    let limit = usize::try_from(args.int("limit").unwrap_or(200)).unwrap_or(200);
    blocking(ctx.clone(), move || {
        let opened = pin(&ctx, &path, true, &ctx.cfg().fs.list_roots, "fs.list_roots")?;
        let resource = resource_of(&opened);
        check_limits(
            &ctx,
            &opened.real,
            &resource,
            &ctx.cfg().fs.list_roots,
            "fs.list_roots",
        )?;
        // AIDEV-NOTE: the caller's grant is checked BEFORE saying what kind of thing the
        // path is. Otherwise "that is a file, not a directory" would tell a caller about
        // paths its grant does not cover.
        let auth = ctx.authorize(Some(&resource))?;
        if !opened.meta.is_dir() {
            return Err(ToolError::Invalid(format!(
                "{} is a {}, not a directory",
                opened.real,
                kind_name(&opened.meta)
            )));
        }
        auth.ok(list_directory(&opened, limit)?)
    })
    .await
}

/// The name a pinned path goes by in grants: directories get a trailing slash.
fn resource_of(opened: &Opened) -> String {
    if opened.meta.is_dir() {
        dir_resource(&opened.real)
    } else {
        opened.real.clone()
    }
}

async fn fs_stat(ctx: Ctx, args: Args) -> ToolResult {
    let path = required(&args, "path")?.to_string();
    blocking(ctx.clone(), move || {
        // Not following: a link is described as the link it is.
        let opened = pin(
            &ctx,
            &path,
            false,
            &ctx.cfg().fs.list_roots,
            "fs.list_roots",
        )?;
        let resource = resource_of(&opened);
        check_limits(
            &ctx,
            &opened.real,
            &resource,
            &ctx.cfg().fs.list_roots,
            "fs.list_roots",
        )?;
        let auth = ctx.authorize(Some(&resource))?;

        let meta = &opened.meta;
        let mut names = Names::default();
        let mut kind = kind_name(meta).to_string();
        if meta.file_type().is_symlink()
            && let Some(target) = opened.link_target()
        {
            kind.push_str(&format!(" -> {target}"));
        }
        let owner = names.user(meta.uid()).to_string();
        let group = names.group(meta.gid()).to_string();
        let text = format!(
            "path:     {}\n\
             type:     {kind}\n\
             mode:     {} ({:04o})\n\
             owner:    {owner} ({})   group: {group} ({})\n\
             size:     {} bytes ({})\n\
             modified: {}\n\
             changed:  {}\n\
             accessed: {}\n\
             inode:    {}   links: {}   device: {}:{}\n",
            opened.real,
            mode_string(meta.mode()),
            meta.mode() & 0o7777,
            meta.uid(),
            meta.gid(),
            meta.len(),
            human_bytes(meta.len()),
            rfc3339_utc(meta.mtime()),
            rfc3339_utc(meta.ctime()),
            rfc3339_utc(meta.atime()),
            meta.ino(),
            meta.nlink(),
            rustix::fs::major(meta.dev()),
            rustix::fs::minor(meta.dev()),
        );
        auth.ok(text)
    })
    .await
}

async fn fs_read(ctx: Ctx, args: Args) -> ToolResult {
    let path = required(&args, "path")?.to_string();
    let offset = u64::try_from(args.int("offset").unwrap_or(0)).unwrap_or(0);
    // What is shown must fit the output budget AFTER cleaning (which can lengthen it).
    let budget = ctx.output_budget();
    let max_bytes = match args.int("max_bytes") {
        Some(n) => usize::try_from(n).unwrap_or(budget).min(budget),
        None => budget,
    };
    blocking(ctx.clone(), move || {
        let opened = pin(&ctx, &path, true, &ctx.cfg().fs.read_roots, "fs.read_roots")?;
        let real = opened.real.clone();
        let resource = resource_of(&opened);
        check_limits(
            &ctx,
            &real,
            &resource,
            &ctx.cfg().fs.read_roots,
            "fs.read_roots",
        )?;
        if !opened.meta.is_file() {
            return Err(ToolError::Invalid(format!(
                "{real} is a {}, not a regular file",
                kind_name(&opened.meta)
            )));
        }
        let auth = ctx.authorize(Some(&resource))?;

        let failed = |e: std::io::Error| ToolError::Failed(format!("{real}: {e}"));
        let mut file = opened.reopen_read().map_err(failed)?;
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).map_err(failed)?;
        }
        let mut data = Vec::new();
        file.take(max_bytes as u64 + 1)
            .read_to_end(&mut data)
            .map_err(failed)?;
        let more_unread = data.len() > max_bytes;
        data.truncate(max_bytes);
        if data.contains(&0) {
            return Err(ToolError::Failed(format!(
                "{real} looks like a binary file ({} bytes); its content is not shown",
                opened.meta.len()
            )));
        }

        // AIDEV-NOTE: the piece shown is sized by its CLEANED length, and the offset to
        // continue from is where the shown bytes really end. Sizing by raw bytes let the
        // final cut drop the end of a piece (and the note saying where to continue)
        // whenever cleaning made the text longer, leaving part of the file unreachable.
        // The read may have stopped part-way through a character: leave that for the
        // next piece instead of showing half of it now.
        let mut usable = data.len();
        if more_unread
            && let Err(e) = std::str::from_utf8(&data)
            && e.error_len().is_none()
            && e.valid_up_to() > 0
        {
            usable = e.valid_up_to();
        }
        let mut shown = fit_prefix(&data[..usable], budget);
        if shown < data.len() || more_unread {
            // More follows: end on a whole line when that does not cost much.
            if let Some(newline) = data[..shown].iter().rposition(|b| *b == b'\n')
                && newline + 1 >= shown / 2
            {
                shown = newline + 1;
            }
        }
        let more = more_unread || shown < data.len();
        let end = offset + shown as u64;
        let mut text = format!(
            "# {real}: {} bytes, modified {}; showing bytes {offset}-{end}\n",
            opened.meta.len(),
            rfc3339_utc(opened.meta.mtime()),
        );
        text.push_str(&clean_text(&data[..shown]));
        if more {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!("[more follows; continue with offset={end}]\n"));
        }
        auth.ok(text)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{call, find, host, ok_text};
    use crate::tools::{Host, Output};
    use serde_json::json;
    use std::path::Path;
    use std::sync::Arc;

    #[test]
    fn mode_string_matches_ls() {
        let cases: &[(u32, &str)] = &[
            (0o100644, "-rw-r--r--"),
            (0o100755, "-rwxr-xr-x"),
            (0o040755, "drwxr-xr-x"),
            (0o120777, "lrwxrwxrwx"),
            (0o104755, "-rwsr-xr-x"),
            (0o102644, "-rw-r-Sr--"),
            (0o041777, "drwxrwxrwt"),
            (0o041776, "drwxrwxrwT"),
            (0o010600, "prw-------"),
            (0o140755, "srwxr-xr-x"),
            (0o060660, "brw-rw----"),
            (0o020620, "crw--w----"),
        ];
        for (mode, want) in cases {
            assert_eq!(mode_string(*mode), *want, "mode {mode:o}");
        }
    }

    #[test]
    fn format_listing_keeps_columns_aligned_whatever_the_name_lengths() {
        let row = |mode: &str, owner: &str, group: &str, size: u64, name: &str| Entry {
            mode: mode.to_string(),
            owner: owner.to_string(),
            group: group.to_string(),
            size,
            modified: "2026-11-19T12:34:56Z".to_string(),
            name: name.to_string(),
        };
        let text = format_listing(&[
            row("drwxr-sr-x", "root", "systemd-journal", 4096, "journal/"),
            row("-rw-rw-r--", "root", "utmp", 292_292, "lastlog"),
            row("-rw-------", "a-very-long-user-name", "root", 7, "x"),
        ]);
        let want = [
            "drwxr-sr-x  root                   systemd-journal    4096  2026-11-19T12:34:56Z  journal/",
            "-rw-rw-r--  root                   utmp             292292  2026-11-19T12:34:56Z  lastlog",
            "-rw-------  a-very-long-user-name  root                  7  2026-11-19T12:34:56Z  x",
        ];
        assert_eq!(text, format!("{}\n", want.join("\n")));
    }

    #[test]
    fn the_built_in_patterns_cover_the_obvious_secrets_and_nothing_ordinary() {
        let cfg = FsCfg::default();
        for secret in [
            "/etc/shadow",
            "/etc/shadow-",
            "/etc/sudoers.d/admins",
            "/etc/ssh/ssh_host_ed25519_key",
            "/etc/ssl/private/server.pem",
            "/etc/pki/tls/private/localhost.key",
            "/etc/letsencrypt/live/example.com/privkey.pem",
            "/home/sean/.ssh/id_ed25519",
            "/home/sean/.ssh/authorized_keys",
            "/root/.bash_history",
            "/root/.aws/credentials",
            "/srv/app/tls/server.key",
            "/etc/opsmcp/config.toml",
            "/proc/1234/environ",
            "/proc/1234/task/1235/environ",
            "/proc/kcore",
            "/etc/postfix/sasl_passwd",
            "/etc/postfix/sasl_passwd.db",
            "/etc/wpa_supplicant/wpa_supplicant.conf",
            "/var/www/site/.htpasswd",
            "/srv/app/.env",
            "/srv/app/.env.production",
            "/home/sean/.git-credentials",
            "/root/.vault-token",
            "/home/sean/passwords.kdbx",
            "/etc/pgbouncer/userlist.txt",
        ] {
            assert!(
                denied_by(&cfg, secret).is_some(),
                "{secret} should be off limits"
            );
        }
        for ordinary in [
            "/etc/hosts",
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_host_ed25519_key.pub",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/letsencrypt/live/example.com/fullchain.pem",
            "/proc/1234/status",
            "/proc/meminfo",
            "/sys/kernel/mm/transparent_hugepage/enabled",
            "/var/log/syslog",
            "/etc/haproxy/haproxy.cfg",
        ] {
            assert_eq!(
                denied_by(&cfg, ordinary),
                None,
                "{ordinary} should be readable"
            );
        }
    }

    #[test]
    fn extra_patterns_add_to_the_built_in_ones_unless_those_are_switched_off() {
        let mut cfg = FsCfg {
            deny: vec!["/srv/secrets/**".to_string()],
            ..FsCfg::default()
        };
        assert_eq!(
            denied_by(&cfg, "/srv/secrets/db.env"),
            Some("/srv/secrets/**".to_string())
        );
        assert!(denied_by(&cfg, "/etc/shadow").is_some());
        cfg.default_deny = false;
        assert!(denied_by(&cfg, "/srv/secrets/db.env").is_some());
        assert_eq!(denied_by(&cfg, "/etc/shadow"), None);
    }

    /// A temporary tree and a host whose configuration opens it up:
    ///   root/public/hello.txt, root/public/big.txt, root/private/plan.txt,
    ///   root/server.key, root/blob.bin, root/escape -> ../outside.txt, outside.txt
    struct Tree {
        _dir: tempfile::TempDir,
        root: String,
        outside: String,
        host: Arc<Host>,
        audit: MemorySink,
    }

    fn tree() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let root = base.join("root");
        std::fs::create_dir_all(root.join("public")).unwrap();
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::write(root.join("public/hello.txt"), "hello world\n").unwrap();
        std::fs::write(root.join("public/big.txt"), "0123456789".repeat(10)).unwrap();
        std::fs::write(root.join("private/plan.txt"), "the plan\n").unwrap();
        std::fs::write(root.join("server.key"), "PRIVATE KEY\n").unwrap();
        std::fs::write(root.join("blob.bin"), b"\x7fELF\x00\x00\x01").unwrap();
        std::fs::write(base.join("outside.txt"), "outside\n").unwrap();
        std::os::unix::fs::symlink("../outside.txt", root.join("escape")).unwrap();

        let root = root.to_string_lossy().into_owned();
        let config = format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.narrow]
allow = ["fs.view", "fs.read:{root}/public/**"]
[roles.scoped]
allow = ["fs.view:{root}/public/**"]
[unix_users.rita]
roles = ["reader"]
[unix_users.nora]
roles = ["narrow"]
[unix_users.sam]
roles = ["scoped"]
[fs]
list_roots = ["{root}"]
read_roots = ["{root}"]
"#
        );
        let (host, audit) = host(&config);
        Tree {
            outside: base.join("outside.txt").to_string_lossy().into_owned(),
            _dir: dir,
            root,
            host,
            audit,
        }
    }

    impl Tree {
        async fn run(&self, user: &str, tool: &str, arguments: serde_json::Value) -> ToolResult {
            call(&self.host, user, &find(tools(), tool), arguments).await
        }

        fn path(&self, rest: &str) -> String {
            format!("{}/{rest}", self.root)
        }

        fn last_decision(&self) -> serde_json::Value {
            self.audit.records().last().unwrap().clone()
        }
    }

    fn denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_read_returns_the_content_of_an_allowed_file() {
        let t = tree();
        let text = ok_text(
            t.run(
                "rita",
                "fs_read",
                json!({"path": t.path("public/hello.txt")}),
            )
            .await,
        );
        assert!(text.contains(&t.path("public/hello.txt")), "{text}");
        assert!(text.ends_with("hello world\n"), "{text}");
        let record = t.last_decision();
        assert_eq!(record["decision"], "allow");
        assert_eq!(record["resource"], t.path("public/hello.txt"));
    }

    #[tokio::test]
    async fn a_directory_configured_through_a_link_still_works() {
        let t = tree();
        let alias = format!("{}-alias", t.root);
        std::os::unix::fs::symlink(&t.root, &alias).unwrap();
        let config = format!(
            "[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n\
             [fs]\nlist_roots = [\"{alias}\"]\nread_roots = [\"{alias}\"]\n"
        );
        let (host, _audit) = host(&config);
        let read = find(tools(), "fs_read");
        // by the configured name and by the real one
        ok_text(
            call(
                &host,
                "rita",
                &read,
                json!({"path": format!("{alias}/public/hello.txt")}),
            )
            .await,
        );
        ok_text(
            call(
                &host,
                "rita",
                &read,
                json!({"path": t.path("public/hello.txt")}),
            )
            .await,
        );
        // and it still bounds what can be read
        denied(call(&host, "rita", &read, json!({"path": t.outside})).await);
    }

    #[tokio::test]
    async fn fs_read_reads_a_large_file_in_pieces() {
        let t = tree();
        let big = t.path("public/big.txt");
        let first = ok_text(
            t.run("rita", "fs_read", json!({"path": big, "max_bytes": 30}))
                .await,
        );
        assert!(first.contains("012345678901234567890123456789"), "{first}");
        assert!(
            !first.contains("0123456789012345678901234567890"),
            "{first}"
        );
        assert!(
            first.contains("offset=30"),
            "should say how to continue: {first}"
        );
        let last = ok_text(
            t.run("rita", "fs_read", json!({"path": big, "offset": 95}))
                .await,
        );
        assert!(
            last.ends_with("56789\n") || last.ends_with("56789"),
            "{last}"
        );
        assert!(!last.contains("offset="), "nothing more to read: {last}");
    }

    /// Reads a whole file by following the "continue with offset=N" notes, and returns
    /// the pieces of content (each without its header and notes).
    async fn read_all(t: &Tree, path: &str, max_bytes: Option<u64>) -> Vec<String> {
        let mut pieces = Vec::new();
        let mut offset = 0u64;
        for _ in 0..50 {
            let mut arguments = json!({"path": path, "offset": offset});
            if let Some(max) = max_bytes {
                arguments["max_bytes"] = json!(max);
            }
            let text = ok_text(t.run("rita", "fs_read", arguments).await);
            assert!(text.len() <= 64 * 1024, "a piece is {} bytes", text.len());
            let body: Vec<&str> = text
                .lines()
                .skip(1)
                .filter(|l| !l.starts_with("[more follows"))
                .collect();
            pieces.push(body.join("\n"));
            match text
                .rsplit("offset=")
                .next()
                .filter(|_| text.contains("[more follows"))
            {
                Some(rest) => {
                    offset = rest
                        .trim_end_matches(|c: char| !c.is_ascii_digit())
                        .parse()
                        .unwrap()
                }
                None => return pieces,
            }
        }
        panic!("the file never ended");
    }

    #[tokio::test]
    async fn fs_read_can_always_be_continued_even_when_cleaning_makes_the_text_longer() {
        let t = tree();
        // coloured log lines: every ESC byte becomes four characters when shown
        let path = t.path("public/coloured.txt");
        let line = "\u{1b}[31mERROR\u{1b}[0m something failed\n";
        std::fs::write(&path, line.repeat(3000)).unwrap(); // about 96 KB
        let pieces = read_all(&t, &path, None).await;
        assert!(pieces.len() >= 2, "it cannot have fitted in one piece");
        let lines: usize = pieces.iter().map(|p| p.matches("ERROR").count()).sum();
        assert_eq!(
            lines, 3000,
            "every line must be reachable, none lost between pieces"
        );
    }

    #[tokio::test]
    async fn fs_read_never_splits_a_character_between_pieces() {
        let t = tree();
        let path = t.path("public/accents.txt");
        std::fs::write(&path, "\u{e9}".repeat(1000)).unwrap(); // 2000 bytes
        let pieces = read_all(&t, &path, Some(1001)).await;
        let all: String = pieces.concat();
        assert_eq!(
            all,
            "\u{e9}".repeat(1000),
            "no character may be damaged or dropped"
        );
    }

    #[tokio::test]
    async fn fs_read_refuses_a_file_outside_the_configured_directories() {
        let t = tree();
        let message = denied(t.run("rita", "fs_read", json!({"path": t.outside})).await);
        assert!(message.contains("fs.read_roots"), "{message}");
        assert_eq!(t.last_decision()["decision"], "deny");
        assert_eq!(t.last_decision()["resource"], t.outside);
    }

    #[tokio::test]
    async fn outside_the_configured_directories_a_missing_path_looks_like_any_other() {
        let t = tree();
        // whether or not the path exists, the answer is the same refusal
        for path in ["/nonexistent-zzz/secret", "/etc/no-such-file-zzz"] {
            for tool in ["fs_read", "fs_stat"] {
                let message = denied(t.run("nora", tool, json!({"path": path})).await);
                assert!(message.contains("fs."), "{tool} {path}: {message}");
            }
        }
        // inside them, a missing file is simply reported as missing
        let result = t
            .run(
                "rita",
                "fs_read",
                json!({"path": t.path("public/absent.txt")}),
            )
            .await;
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    #[tokio::test]
    async fn fs_read_refuses_a_link_that_leads_outside() {
        let t = tree();
        let message = denied(
            t.run("rita", "fs_read", json!({"path": t.path("escape")}))
                .await,
        );
        assert!(message.contains("fs.read_roots"), "{message}");
        // the audit trail names what the link really pointed at
        assert_eq!(t.last_decision()["resource"], t.outside);
        // and ".." does not get around it either
        let dotted = t.path("public/../../outside.txt");
        denied(t.run("rita", "fs_read", json!({"path": dotted})).await);
    }

    #[tokio::test]
    async fn fs_read_refuses_a_never_readable_file_even_inside_an_allowed_directory() {
        let t = tree();
        let message = denied(
            t.run("rita", "fs_read", json!({"path": t.path("server.key")}))
                .await,
        );
        assert!(message.contains("**/*.key"), "{message}");
    }

    #[tokio::test]
    async fn fs_read_honours_a_grant_limited_to_part_of_the_tree() {
        let t = tree();
        ok_text(
            t.run(
                "nora",
                "fs_read",
                json!({"path": t.path("public/hello.txt")}),
            )
            .await,
        );
        denied(
            t.run(
                "nora",
                "fs_read",
                json!({"path": t.path("private/plan.txt")}),
            )
            .await,
        );
        // through a link, the grant is checked against where the link leads
        std::os::unix::fs::symlink("../private/plan.txt", Path::new(&t.path("public/shortcut")))
            .unwrap();
        denied(
            t.run(
                "nora",
                "fs_read",
                json!({"path": t.path("public/shortcut")}),
            )
            .await,
        );
    }

    #[tokio::test]
    async fn fs_read_rejects_directories_binary_files_and_relative_paths() {
        let t = tree();
        assert!(matches!(
            t.run("rita", "fs_read", json!({"path": t.path("public")}))
                .await,
            Err(ToolError::Invalid(_))
        ));
        match t
            .run("rita", "fs_read", json!({"path": t.path("blob.bin")}))
            .await
        {
            Err(ToolError::Failed(message)) => assert!(message.contains("binary"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(matches!(
            t.run("rita", "fs_read", json!({"path": "public/hello.txt"}))
                .await,
            Err(ToolError::Invalid(_))
        ));
        assert!(matches!(
            t.run("rita", "fs_read", json!({"path": t.path("absent.txt")}))
                .await,
            Err(ToolError::Failed(_))
        ));
    }

    #[tokio::test]
    async fn fs_list_shows_entries_with_their_type_and_link_targets() {
        let t = tree();
        let text = ok_text(t.run("rita", "fs_list", json!({"path": t.root})).await);
        let line = |name: &str| -> String {
            text.lines()
                .find(|l| l.contains(name))
                .unwrap_or_else(|| panic!("no line for {name} in {text}"))
                .to_string()
        };
        assert!(line("public/").starts_with('d'), "{text}");
        assert!(line("server.key").starts_with("-rw"), "{text}");
        assert!(line("escape").starts_with('l'), "{text}");
        assert!(
            line("escape").ends_with("escape -> ../outside.txt"),
            "{text}"
        );
        assert!(line("blob.bin").contains(" 7 "), "size in bytes: {text}");
        assert_eq!(t.last_decision()["resource"], format!("{}/", t.root));
    }

    #[tokio::test]
    async fn fs_list_stops_at_the_limit_and_says_how_many_were_left_out() {
        let t = tree();
        let text = ok_text(
            t.run("rita", "fs_list", json!({"path": t.root, "limit": 2}))
                .await,
        );
        assert!(
            text.contains("blob.bin") && text.contains("escape"),
            "{text}"
        );
        assert!(!text.contains("server.key"), "{text}");
        assert!(text.contains("3 more"), "{text}");
    }

    #[tokio::test]
    async fn fs_list_does_not_say_what_a_path_outside_the_callers_grant_is() {
        let t = tree();
        // sam may only look under public/. Asked about a file elsewhere, the answer is a
        // refusal, not "that is a file": what kind of thing it is is not sam's to learn.
        let message = denied(
            t.run("sam", "fs_list", json!({"path": t.path("blob.bin")}))
                .await,
        );
        assert!(message.contains("fs.view"), "{message}");
        assert_eq!(t.last_decision()["decision"], "deny");
        // inside the grant, the caller is told why a file cannot be listed
        match t
            .run(
                "sam",
                "fs_list",
                json!({"path": t.path("public/hello.txt")}),
            )
            .await
        {
            Err(ToolError::Invalid(message)) => {
                assert!(message.contains("not a directory"), "{message}")
            }
            other => panic!("expected an invalid-argument error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_list_refuses_directories_outside_the_configured_ones() {
        let t = tree();
        let parent = Path::new(&t.root)
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let message = denied(t.run("rita", "fs_list", json!({"path": parent})).await);
        assert!(message.contains("fs.list_roots"), "{message}");
        assert!(matches!(
            t.run(
                "rita",
                "fs_list",
                json!({"path": t.path("public/hello.txt")})
            )
            .await,
            Err(ToolError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn fs_stat_describes_a_link_without_following_it() {
        let t = tree();
        let text = ok_text(
            t.run("rita", "fs_stat", json!({"path": t.path("escape")}))
                .await,
        );
        assert!(text.contains("symbolic link -> ../outside.txt"), "{text}");
        assert_eq!(t.last_decision()["resource"], t.path("escape"));

        let text = ok_text(
            t.run(
                "rita",
                "fs_stat",
                json!({"path": t.path("public/hello.txt")}),
            )
            .await,
        );
        assert!(text.contains("regular file"), "{text}");
        assert!(text.contains("12 bytes"), "{text}");
        assert!(text.contains("-rw"), "{text}");
    }

    #[tokio::test]
    async fn a_caller_without_the_permission_gets_nothing() {
        let t = tree();
        // nora has fs.view and a scoped fs.read, but no log or other permissions;
        // a scoped read grant must not let her read elsewhere
        let result: Result<Output, ToolError> = t
            .run("nora", "fs_read", json!({"path": t.path("server.key")}))
            .await;
        denied(result);
    }
}
