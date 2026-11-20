//! Kernel tunables: read and change sysctl values (/proc/sys), and write selected files
//! under /sys.
//!
//! Reading is governed by the `sysctl.view` permission. Changing anything additionally
//! needs the host's configuration to list the key (`kernel.writable_sysctls`,
//! `kernel.writable_sysfs`); both lists are empty by default.

use std::io::{Read, Write};
use std::path::Path;

use super::args::{Args, Param};
use super::paths::{Opened, open_path};
use super::{Ctx, Tool, ToolError, ToolResult, blocking, required};
use crate::glob::glob_match;
use crate::policy::Access;

const SYSCTL_ROOT: &str = "/proc/sys";
const SYSFS_ROOT: &str = "/sys";
/// Most values returned when a whole subtree is asked for.
const MAX_VALUES: usize = 500;

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "sysctl_get",
            "Read kernel parameters (sysctl): one value such as vm.swappiness, or every \
             value under a prefix such as net.ipv4.tcp.",
            Access::Read,
            "sysctl.view",
            vec![
                Param::str(
                    "name",
                    "Parameter or prefix, e.g. vm.swappiness or net.core",
                )
                .max_len(255)
                .required(),
            ],
            |ctx: Ctx, args: Args| async move {
                let name = required(&args, "name")?.to_string();
                blocking(ctx.clone(), move || {
                    sysctl_get_at(&ctx, Path::new(SYSCTL_ROOT), &name)
                })
                .await
            },
        ),
        Tool::new(
            "sysctl_set",
            "Change a kernel parameter (sysctl) on the running system. Only parameters the \
             host's configuration lists as changeable can be set. The change is not written \
             to /etc/sysctl.d and does not survive a reboot.",
            Access::Write,
            "sysctl.modify",
            vec![
                Param::str("name", "Parameter, e.g. vm.swappiness")
                    .max_len(255)
                    .required(),
                Param::str("value", "New value").max_len(256).required(),
            ],
            |ctx: Ctx, args: Args| async move {
                let name = required(&args, "name")?.to_string();
                let value = required(&args, "value")?.to_string();
                blocking(ctx.clone(), move || {
                    sysctl_set_at(&ctx, Path::new(SYSCTL_ROOT), &name, &value)
                })
                .await
            },
        ),
        Tool::new(
            "sysfs_set",
            "Write a value to a file under /sys on the running system (for example the \
             transparent hugepage mode). Only files the host's configuration lists as \
             writable can be set; read them with fs_read. The change does not survive a reboot.",
            Access::Write,
            "sysfs.modify",
            vec![
                Param::str("path", "Absolute path under /sys")
                    .max_len(4096)
                    .required(),
                Param::str("value", "Value to write")
                    .max_len(256)
                    .required(),
            ],
            |ctx: Ctx, args: Args| async move {
                let path = required(&args, "path")?.to_string();
                let value = required(&args, "value")?.to_string();
                blocking(ctx.clone(), move || {
                    sysfs_set_at(&ctx, Path::new(SYSFS_ROOT), &path, &value)
                })
                .await
            },
        ),
    ]
}

/// Turns a sysctl name into its path components. Dots separate components
/// (`net.ipv4.ip_forward`); if the name contains a slash, slashes do instead, which is
/// how a component with a dot in it is written (`net/ipv4/conf/eth0.100/rp_filter`).
pub fn sysctl_components(name: &str) -> Result<Vec<String>, ToolError> {
    let invalid = || {
        ToolError::Invalid(format!(
            "{name:?} is not a sysctl name (for example vm.swappiness)"
        ))
    };
    let allowed = |c: char| c.is_ascii_alphanumeric() || "_.:@/-".contains(c);
    if name.is_empty() || !name.chars().all(allowed) {
        return Err(invalid());
    }
    let separator = if name.contains('/') { '/' } else { '.' };
    let parts: Vec<String> = name.split(separator).map(str::to_string).collect();
    if parts.iter().any(|p| p.is_empty() || p == "." || p == "..") {
        return Err(invalid());
    }
    Ok(parts)
}

/// Pins `path` and checks that it REALLY lies under `root` (links resolved). Returns the
/// pin and the real path relative to the root.
///
/// AIDEV-NOTE: /proc/sys and /sys are the only trees these tools may touch, and a write
/// here runs as root. The check is on the real path, so neither ".." nor a symbolic link
/// can turn a "sysctl" into a write somewhere else.
fn pin_under(
    ctx: &Ctx,
    root: &Path,
    path: &Path,
    shown: &str,
) -> Result<(Opened, String), ToolError> {
    let real_root = std::fs::canonicalize(root)
        .map_err(|e| ToolError::Failed(format!("{}: {e}", root.display())))?;
    let opened = open_path(&path.to_string_lossy(), true).map_err(|e| match e {
        // say it in the caller's terms, not as a path under our root
        ToolError::Failed(_) => ToolError::Failed(format!("{shown}: no such parameter or file")),
        other => other,
    })?;
    match Path::new(&opened.real).strip_prefix(&real_root) {
        Ok(relative) => {
            let relative = relative.to_string_lossy().into_owned();
            Ok((opened, relative))
        }
        Err(_) => {
            let reason = format!("{shown} leads outside {}", root.display());
            Err(ctx.deny(Some(shown), &reason))
        }
    }
}

/// The content of a small kernel file, on one line. `None` if it cannot be read (some
/// parameters are write-only).
fn read_small(file: std::fs::File) -> Option<String> {
    let mut data = Vec::new();
    file.take(4096).read_to_end(&mut data).ok()?;
    Some(
        String::from_utf8_lossy(&data)
            .trim_end()
            .replace('\n', "; "),
    )
}

/// `read_small` for a directory entry met while walking. Never follows a link.
fn read_entry(path: &Path) -> Option<String> {
    use rustix::fs::{Mode, OFlags};
    let flags =
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC;
    read_small(std::fs::File::from(
        rustix::fs::open(path, flags, Mode::empty()).ok()?,
    ))
}

/// `read_small` for a pinned file.
fn read_pinned(opened: &Opened) -> Option<String> {
    read_small(opened.reopen_read().ok()?)
}

/// What a walk over part of /proc/sys found.
#[derive(Default)]
struct Walk {
    /// `key = value` lines, in name order.
    lines: Vec<String>,
    /// Values left out because the caller's role denies them.
    hidden: usize,
}

/// Collects `key = value` for every readable file under a pinned directory. Links are
/// not followed. Keys for which `is_denied` is true are counted, not shown.
fn walk(dir: &Path, key: &str, depth: usize, is_denied: &dyn Fn(&str) -> bool, found: &mut Walk) {
    if depth > 8 || found.lines.len() >= MAX_VALUES {
        return;
    }
    let Ok(reader) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = reader.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if found.lines.len() >= MAX_VALUES {
            return;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_key = format!("{key}.{name}");
        // DirEntry::file_type does not follow links, so a link is neither of these.
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                walk(&entry.path(), &child_key, depth + 1, is_denied, found)
            }
            Ok(kind) if kind.is_file() => {
                if is_denied(&child_key) {
                    found.hidden += 1;
                } else if let Some(value) = read_entry(&entry.path()) {
                    found.lines.push(format!("{child_key} = {value}"));
                }
            }
            _ => {}
        }
    }
}

fn listed(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|pattern| glob_match(pattern, name))
}

/// Replaces the content of a pinned kernel file. Returns the value before and after.
fn write_value(opened: &Opened, value: &str) -> std::io::Result<(String, String)> {
    let current = || read_pinned(opened).unwrap_or_else(|| "(not readable)".to_string());
    let old = current();
    let mut file = opened.reopen_overwrite()?;
    file.write_all(format!("{value}\n").as_bytes())?;
    drop(file);
    Ok((old, current()))
}

const NOT_PERSISTENT: &str =
    "This changes the running kernel only: it is not saved and will not survive a reboot.";

/// Reads one sysctl, or every one under a prefix. `root` is /proc/sys.
pub fn sysctl_get_at(ctx: &Ctx, root: &Path, name: &str) -> ToolResult {
    let components = sysctl_components(name)?;
    let shown = components.join(".");
    let path = components
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part));
    let (opened, relative) = pin_under(ctx, root, &path, &shown)?;
    // The key as the kernel has it, which is what grants are written against.
    let key = relative.replace('/', ".");
    let auth = ctx.authorize(Some(&key))?;

    if !opened.meta.is_dir() {
        let value = read_pinned(&opened)
            .ok_or_else(|| ToolError::Failed(format!("{key} cannot be read")))?;
        return auth.ok(format!("{key} = {value}\n"));
    }
    // The prefix itself was authorized above. A deny written for one key below it
    // (which does not match the prefix) still has to hold: such values are left out.
    let mut found = Walk::default();
    walk(
        &opened.dir_path(),
        &key,
        0,
        &|leaf| ctx.is_denied(leaf),
        &mut found,
    );
    let mut text = found.lines.join("\n");
    text.push('\n');
    if found.hidden > 0 {
        text.push_str(&format!(
            "[{} value(s) not shown: your role does not allow them]\n",
            found.hidden
        ));
    }
    if found.lines.len() >= MAX_VALUES {
        text.push_str(&format!(
            "[stopped at {MAX_VALUES} values; ask for a narrower prefix]\n"
        ));
    }
    auth.ok(text)
}

/// Changes one sysctl. `root` is /proc/sys.
pub fn sysctl_set_at(ctx: &Ctx, root: &Path, name: &str, value: &str) -> ToolResult {
    let components = sysctl_components(name)?;
    let shown = components.join(".");
    let path = components
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part));
    let (opened, relative) = pin_under(ctx, root, &path, &shown)?;
    let key = relative.replace('/', ".");
    if !opened.meta.is_file() {
        return Err(ToolError::Invalid(format!(
            "{key} is a group of parameters, not one parameter"
        )));
    }
    if !listed(&ctx.cfg().kernel.writable_sysctls, &key) {
        let reason = format!("{key} is not listed in kernel.writable_sysctls on this host");
        return Err(ctx.deny(Some(&key), &reason));
    }
    let auth = ctx.authorize(Some(&key))?;
    let (old, new) =
        write_value(&opened, value).map_err(|e| ToolError::Failed(format!("{key}: {e}")))?;
    auth.ok(format!("{key}: {old} -> {new}\n{NOT_PERSISTENT}\n"))
}

/// Writes one file under /sys. `root` is /sys; `path` is the absolute path as the caller
/// names it (under /sys).
pub fn sysfs_set_at(ctx: &Ctx, root: &Path, path: &str, value: &str) -> ToolResult {
    let rest = path
        .strip_prefix("/sys/")
        .filter(|rest| {
            !rest
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        })
        .ok_or_else(|| {
            ToolError::Invalid(format!("{path:?} is not a plain absolute path under /sys/"))
        })?;
    let (opened, relative) = pin_under(ctx, root, &root.join(rest), path)?;
    // The file's real location, written as a /sys path: what the host's list and the
    // caller's grant are matched against.
    let real = format!("/sys/{relative}");
    if !opened.meta.is_file() {
        return Err(ToolError::Invalid(format!("{real} is not a file")));
    }
    if !listed(&ctx.cfg().kernel.writable_sysfs, &real) {
        let reason = format!("{real} is not listed in kernel.writable_sysfs on this host");
        return Err(ctx.deny(Some(&real), &reason));
    }
    let auth = ctx.authorize(Some(&real))?;
    let (old, new) =
        write_value(&opened, value).map_err(|e| ToolError::Failed(format!("{real}: {e}")))?;
    auth.ok(format!("{real}: {old} -> {new}\n{NOT_PERSISTENT}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{call, ctx, find, host, ok_text};
    use crate::tools::{Host, Output};
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn sysctl_components_split_on_dots_or_on_slashes() {
        let cases: &[(&str, &[&str])] = &[
            ("vm.swappiness", &["vm", "swappiness"]),
            (
                "net.ipv4.conf.all.rp_filter",
                &["net", "ipv4", "conf", "all", "rp_filter"],
            ),
            (
                "net/ipv4/conf/eth0.100/rp_filter",
                &["net", "ipv4", "conf", "eth0.100", "rp_filter"],
            ),
            ("kernel", &["kernel"]),
        ];
        for (name, want) in cases {
            let got = sysctl_components(name).unwrap();
            assert_eq!(got, *want, "{name}");
        }
    }

    #[test]
    fn sysctl_components_reject_anything_that_could_leave_the_tree() {
        for bad in [
            "",
            ".",
            "..",
            "vm..swappiness",
            "../etc/passwd",
            "vm/../../etc",
            "/vm/swappiness",
            "vm/",
            "vm swappiness",
            "vm;x",
            "a/./b",
        ] {
            assert!(
                sysctl_components(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    /// A stand-in for /proc/sys and /sys in a temporary directory:
    ///   procsys/vm/{swappiness=60, overcommit_memory=0}, procsys/net/ipv4/ip_forward=0,
    ///   procsys/vm/escape -> ../../outside,  sys/kernel/mm/thp/enabled, outside
    struct Tree {
        dir: tempfile::TempDir,
        host: Arc<Host>,
        audit: MemorySink,
    }

    fn tree() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("procsys/vm")).unwrap();
        std::fs::create_dir_all(base.join("procsys/net/ipv4")).unwrap();
        std::fs::create_dir_all(base.join("sys/kernel/mm/thp")).unwrap();
        std::fs::write(base.join("procsys/vm/swappiness"), "60\n").unwrap();
        std::fs::write(base.join("procsys/vm/overcommit_memory"), "0\n").unwrap();
        std::fs::write(base.join("procsys/net/ipv4/ip_forward"), "0\n").unwrap();
        std::fs::write(base.join("sys/kernel/mm/thp/enabled"), "always\n").unwrap();
        std::fs::write(base.join("sys/kernel/mm/thp/defrag"), "madvise\n").unwrap();
        std::fs::write(base.join("outside"), "untouched\n").unwrap();
        std::os::unix::fs::symlink("../../outside", base.join("procsys/vm/escape")).unwrap();
        std::os::unix::fs::symlink("../../../../outside", base.join("sys/kernel/mm/thp/escape"))
            .unwrap();
        let (host, audit) = host(
            r#"
[roles.admin]
allow = ["@all"]
[roles.reader]
allow = ["@read"]
[roles.tuner]
allow = ["sysctl.view:vm.*", "sysctl.modify:vm.swappiness", "sysfs.modify:/sys/kernel/mm/thp/enabled"]
[unix_users.adam]
roles = ["admin"]
[unix_users.rita]
roles = ["reader"]
[roles.partial]
allow = ["sysctl.view"]
deny = ["sysctl.view:vm.swappiness"]
[unix_users.tina]
roles = ["tuner"]
[unix_users.pat]
roles = ["partial"]
[kernel]
writable_sysctls = ["vm.swappiness", "vm.escape", "net.ipv4.*"]
writable_sysfs = ["/sys/kernel/mm/thp/enabled", "/sys/kernel/mm/thp/escape"]
"#,
        );
        Tree { dir, host, audit }
    }

    impl Tree {
        fn procsys(&self) -> PathBuf {
            self.dir.path().join("procsys")
        }
        fn sys(&self) -> PathBuf {
            self.dir.path().join("sys")
        }
        fn content(&self, rest: &str) -> String {
            std::fs::read_to_string(self.dir.path().join(rest)).unwrap()
        }
        fn get(&self, user: &str, name: &str) -> ToolResult {
            sysctl_get_at(
                &ctx(&self.host, user, "sysctl.view", Access::Read),
                &self.procsys(),
                name,
            )
        }
        fn set(&self, user: &str, name: &str, value: &str) -> ToolResult {
            sysctl_set_at(
                &ctx(&self.host, user, "sysctl.modify", Access::Write),
                &self.procsys(),
                name,
                value,
            )
        }
        fn sysfs(&self, user: &str, path: &str, value: &str) -> ToolResult {
            sysfs_set_at(
                &ctx(&self.host, user, "sysfs.modify", Access::Write),
                &self.sys(),
                path,
                value,
            )
        }
    }

    fn denied(result: ToolResult) -> String {
        match result {
            Err(ToolError::Denied(message)) => message,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn sysctl_get_reads_one_value() {
        let t = tree();
        assert_eq!(
            ok_text(t.get("rita", "vm.swappiness")),
            "vm.swappiness = 60\n"
        );
        assert_eq!(
            t.audit.records().last().unwrap()["resource"],
            "vm.swappiness"
        );
    }

    #[test]
    fn sysctl_get_reads_everything_under_a_prefix_in_order() {
        let t = tree();
        assert_eq!(
            ok_text(t.get("rita", "vm")),
            "vm.overcommit_memory = 0\nvm.swappiness = 60\n",
            "the link that leads out of the tree must not be followed"
        );
        let all = ok_text(t.get("rita", "net"));
        assert_eq!(all, "net.ipv4.ip_forward = 0\n");
    }

    #[test]
    fn sysctl_get_leaves_denied_values_out_of_a_prefix_listing() {
        let t = tree();
        // pat may view sysctls, except vm.swappiness
        denied(t.get("pat", "vm.swappiness"));
        let text = ok_text(t.get("pat", "vm"));
        assert!(text.starts_with("vm.overcommit_memory = 0\n"), "{text}");
        assert!(
            !text.contains("swappiness = 60"),
            "a denied value was shown: {text}"
        );
        assert!(
            text.contains("1 value"),
            "should say something was left out: {text}"
        );
    }

    #[test]
    fn sysctl_get_refuses_what_is_missing_outside_or_not_granted() {
        let t = tree();
        assert!(matches!(
            t.get("rita", "vm.nonexistent"),
            Err(ToolError::Failed(_))
        ));
        // a link inside /proc/sys that leads elsewhere
        denied(t.get("rita", "vm.escape"));
        // tina may only view vm.*
        ok_text(t.get("tina", "vm.swappiness"));
        denied(t.get("tina", "net.ipv4.ip_forward"));
    }

    #[test]
    fn sysctl_set_changes_a_listed_and_granted_key_and_reports_old_and_new() {
        let t = tree();
        let text = ok_text(t.set("tina", "vm.swappiness", "10"));
        assert!(text.contains("vm.swappiness: 60 -> 10"), "{text}");
        assert!(
            text.contains("reboot"),
            "should say the change is not persistent: {text}"
        );
        assert_eq!(t.content("procsys/vm/swappiness"), "10\n");
        let record = t.audit.records().last().unwrap().clone();
        assert_eq!(
            (record["decision"].as_str(), record["resource"].as_str()),
            (Some("allow"), Some("vm.swappiness"))
        );
    }

    #[test]
    fn sysctl_set_refuses_keys_the_host_does_not_list_even_for_an_admin() {
        let t = tree();
        let message = denied(t.set("adam", "vm.overcommit_memory", "1"));
        assert!(message.contains("kernel.writable_sysctls"), "{message}");
        assert_eq!(t.content("procsys/vm/overcommit_memory"), "0\n");
        assert_eq!(t.audit.records().last().unwrap()["decision"], "deny");
    }

    #[test]
    fn sysctl_set_refuses_keys_the_caller_is_not_granted() {
        let t = tree();
        // listed by the host (net.ipv4.*) but tina's grant is for vm.swappiness only
        denied(t.set("tina", "net.ipv4.ip_forward", "1"));
        assert_eq!(t.content("procsys/net/ipv4/ip_forward"), "0\n");
        // rita has no write permission at all
        denied(t.set("rita", "vm.swappiness", "1"));
        assert_eq!(t.content("procsys/vm/swappiness"), "60\n");
    }

    #[test]
    fn sysctl_set_never_writes_through_a_link_out_of_the_tree() {
        let t = tree();
        // "vm.escape" is even on the host's list; it is still not a file in /proc/sys
        denied(t.set("adam", "vm.escape", "pwned"));
        assert_eq!(t.content("outside"), "untouched\n");
    }

    #[test]
    fn sysctl_set_only_sets_single_values_not_directories() {
        let t = tree();
        let result = t.set("adam", "net.ipv4", "1");
        assert!(matches!(result, Err(ToolError::Invalid(_))), "{result:?}");
    }

    #[test]
    fn sysfs_set_writes_a_listed_and_granted_file() {
        let t = tree();
        let text = ok_text(t.sysfs("tina", "/sys/kernel/mm/thp/enabled", "never"));
        assert!(text.contains("always -> never"), "{text}");
        assert_eq!(t.content("sys/kernel/mm/thp/enabled"), "never\n");
        assert_eq!(
            t.audit.records().last().unwrap()["resource"],
            "/sys/kernel/mm/thp/enabled"
        );
    }

    #[test]
    fn sysfs_set_refuses_unlisted_ungranted_and_outside_paths() {
        let t = tree();
        // not on the host's list
        let message = denied(t.sysfs("adam", "/sys/kernel/mm/thp/defrag", "never"));
        assert!(message.contains("kernel.writable_sysfs"), "{message}");
        assert_eq!(t.content("sys/kernel/mm/thp/defrag"), "madvise\n");
        // on the list, but rita has no such permission
        denied(t.sysfs("rita", "/sys/kernel/mm/thp/enabled", "never"));
        assert_eq!(t.content("sys/kernel/mm/thp/enabled"), "always\n");
        // on the list, but really a link out of /sys
        denied(t.sysfs("adam", "/sys/kernel/mm/thp/escape", "pwned"));
        assert_eq!(t.content("outside"), "untouched\n");
        // not under /sys at all
        for path in [
            "/etc/passwd",
            "/sys/../etc/passwd",
            "sys/kernel",
            "/sysfoo/x",
        ] {
            let result: Result<Output, ToolError> = t.sysfs("adam", path, "x");
            assert!(result.is_err(), "{path}: {result:?}");
        }
        assert_eq!(t.content("outside"), "untouched\n");
    }

    #[tokio::test]
    async fn sysctl_get_reads_the_real_kernel() {
        let (host, _audit) =
            host("[roles.r]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"r\"]\n");
        let tool = find(tools(), "sysctl_get");
        assert_eq!(
            ok_text(call(&host, "rita", &tool, json!({"name": "kernel.ostype"})).await),
            "kernel.ostype = Linux\n"
        );
    }
}
