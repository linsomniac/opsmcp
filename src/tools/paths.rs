//! Opening files named by a caller without being tricked by links or races.
//!
//! AIDEV-NOTE: the pattern used by every tool that takes a path:
//!   1. `open_path` opens it with O_PATH. That has no side effects (it does not really
//!      open a device or block on a FIFO) and pins the file: the descriptor refers to
//!      one inode from here on, whatever happens to the name.
//!   2. The descriptor tells us the file's real path (links resolved) and its type.
//!      ALL checks (configured directories, deny patterns, the caller's grants) are made
//!      on that real path, never on the name the caller gave.
//!   3. `reopen_read` / `reopen_write` / `dir_path` then work through the descriptor,
//!      so what is read or written is exactly what was checked.

use std::fs::{File, Metadata};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

use super::ToolError;

/// A file pinned by an O_PATH descriptor.
#[derive(Debug)]
pub struct Opened {
    handle: File,
    /// The real absolute path, with every link resolved.
    pub real: String,
    pub meta: Metadata,
}

/// Pins `path`. With `follow` false a final symbolic link is itself pinned rather than
/// what it points to.
pub fn open_path(path: &str, follow: bool) -> Result<Opened, ToolError> {
    check_absolute(path)?;
    let failed = |e: std::io::Error| ToolError::Failed(format!("{path}: {e}"));
    let mut flags = OFlags::PATH | OFlags::CLOEXEC;
    if !follow {
        flags |= OFlags::NOFOLLOW;
    }
    let handle =
        File::from(rustix::fs::open(path, flags, Mode::empty()).map_err(|e| failed(e.into()))?);
    let meta = handle.metadata().map_err(failed)?;
    // The kernel's own record of where this descriptor points: the path with every
    // link and ".." already resolved.
    let link = rustix::fs::readlink(format!("/proc/self/fd/{}", handle.as_raw_fd()), Vec::new())
        .map_err(|e| failed(e.into()))?;
    let real = link.to_string_lossy().into_owned();
    if !real.starts_with('/') {
        return Err(ToolError::Failed(format!(
            "{path}: cannot determine its real path"
        )));
    }
    // AIDEV-NOTE: the path the kernel reports only means something if, from here, it
    // leads back to this same file. It does not when the file has been deleted (the
    // kernel appends " (deleted)", which would slip past a pattern like **/*.key), or
    // when the file is in another mount namespace, reached through /proc/PID/root or
    // /proc/PID/cwd: the kernel then reports the path as seen INSIDE that namespace, so
    // a container's /etc/app.conf would pass for the host's. Every check made later is
    // on this path, so a path that does not lead back is refused here, for every tool.
    let flags = OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let leads_back = rustix::fs::open(real.as_str(), flags, Mode::empty())
        .ok()
        .and_then(|fd| File::from(fd).metadata().ok())
        .is_some_and(|again| again.dev() == meta.dev() && again.ino() == meta.ino());
    if !leads_back {
        return Err(ToolError::Failed(format!(
            "{path}: its real location cannot be established (it has been deleted, or it \
             is in another mount namespace such as a container's)"
        )));
    }
    Ok(Opened { handle, real, meta })
}

impl Opened {
    /// Opens the pinned file for reading. Never blocks on a FIFO or a device.
    pub fn reopen_read(&self) -> std::io::Result<File> {
        self.reopen(OFlags::RDONLY)
    }

    fn reopen(&self, access: OFlags) -> std::io::Result<File> {
        // Opening /proc/self/fd/N opens the inode the descriptor is pinned to. NONBLOCK
        // so that a FIFO, a device or a blocking kernel file cannot hang the server.
        let flags = access | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        Ok(File::from(rustix::fs::open(
            self.dir_path(),
            flags,
            Mode::empty(),
        )?))
    }

    /// Opens the pinned file to replace its content (as `echo value > file` does). The
    /// file must already exist: a pin never creates anything.
    pub fn reopen_overwrite(&self) -> std::io::Result<File> {
        self.reopen(OFlags::WRONLY | OFlags::TRUNC)
    }

    /// A path that refers to the pinned directory itself, for listing it.
    pub fn dir_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd()))
    }

    /// Where a pinned symbolic link points.
    pub fn link_target(&self) -> Option<String> {
        let target = rustix::fs::readlinkat(&self.handle, "", Vec::new()).ok()?;
        Some(target.to_string_lossy().into_owned())
    }
}

/// `path` with `.` and `..` resolved as text only. Used to decide what to say about a
/// path that could not be opened; never as a substitute for the real path.
pub fn lexical(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// True when `real` is one of `roots` or lies beneath one. Compares whole path
/// components, so `/var/logs` is not inside `/var/log`.
pub fn within(real: &str, roots: &[PathBuf]) -> bool {
    let path = Path::new(real);
    roots.iter().any(|root| path.starts_with(root))
}

/// Checks that a caller-supplied path is absolute and of sane length.
pub fn check_absolute(path: &str) -> Result<(), ToolError> {
    if !path.starts_with('/') {
        return Err(ToolError::Invalid(format!(
            "{path:?} is not an absolute path (it must start with /)"
        )));
    }
    if path.len() > 4096 {
        return Err(ToolError::Invalid("the path is too long".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;
    use std::time::{Duration, Instant};

    fn real(path: &Path) -> String {
        std::fs::canonicalize(path)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn roots(list: &[&str]) -> Vec<PathBuf> {
        list.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn within_compares_whole_components() {
        let cases: &[(&str, &[&str], bool)] = &[
            ("/var/log/syslog", &["/var/log"], true),
            ("/var/log", &["/var/log"], true),
            ("/var/log/nginx/access.log", &["/var/log"], true),
            ("/var/logs/x", &["/var/log"], false),
            ("/var/lo", &["/var/log"], false),
            ("/etc/passwd", &["/var/log", "/etc"], true),
            ("/anything/at/all", &["/"], true),
            ("/", &["/"], true),
            ("/etc/passwd", &[], false),
            ("/var/log/syslog", &["/var/log/"], true),
        ];
        for (path, list, want) in cases {
            assert_eq!(within(path, &roots(list)), *want, "{path} in {list:?}");
        }
    }

    #[test]
    fn a_plain_file_is_pinned_with_its_real_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data.txt");
        std::fs::write(&file, "hello").unwrap();
        let opened = open_path(file.to_str().unwrap(), true).unwrap();
        assert_eq!(opened.real, real(&file));
        assert!(opened.meta.is_file());
        let mut text = String::new();
        opened
            .reopen_read()
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn a_link_is_reported_as_the_file_it_points_to() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "s3cret").unwrap();
        let link = inside.join("innocent.log");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let opened = open_path(link.to_str().unwrap(), true).unwrap();
        assert_eq!(opened.real, real(&secret));
        // so a check against the directory the link sits in refuses it
        assert!(!within(
            &opened.real,
            &[std::fs::canonicalize(&inside).unwrap()]
        ));
    }

    #[test]
    fn a_link_through_a_directory_is_resolved_too() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("file"), "x").unwrap();
        let inside = dir.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        std::os::unix::fs::symlink(&outside, inside.join("sub")).unwrap();

        let opened = open_path(inside.join("sub/file").to_str().unwrap(), true).unwrap();
        assert_eq!(opened.real, real(&outside.join("file")));
        // and so is "..": the real path has none
        let dotted = format!("{}/../outside/file", inside.display());
        assert_eq!(
            open_path(&dotted, true).unwrap().real,
            real(&outside.join("file"))
        );
    }

    #[test]
    fn without_follow_a_link_is_pinned_itself() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let opened = open_path(link.to_str().unwrap(), false).unwrap();
        assert!(opened.meta.file_type().is_symlink());
        assert_eq!(opened.real, format!("{}/link", real(dir.path())));
        assert_eq!(
            opened.link_target(),
            Some(target.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn what_is_read_is_the_file_that_was_checked_even_if_the_name_is_swapped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        std::fs::write(&path, "harmless").unwrap();
        let opened = open_path(path.to_str().unwrap(), true).unwrap();

        // after the check, the name is replaced by a link to something else
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "s3cret").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&secret, &path).unwrap();

        let mut text = String::new();
        opened
            .reopen_read()
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "harmless");
    }

    #[test]
    fn a_fifo_neither_blocks_the_open_nor_the_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let started = Instant::now();
        let opened = open_path(fifo.to_str().unwrap(), true).unwrap();
        assert!(opened.meta.file_type().is_fifo());
        // a plain blocking open of a FIFO with no writer would hang here forever
        let _ = opened.reopen_read();
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_directory_can_be_listed_through_its_pin() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), "").unwrap();
        std::fs::write(dir.path().join("b"), "").unwrap();
        let opened = open_path(dir.path().to_str().unwrap(), true).unwrap();
        assert!(opened.meta.is_dir());
        let mut names: Vec<String> = std::fs::read_dir(opened.dir_path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn reopen_overwrite_replaces_the_content_of_the_pinned_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value");
        std::fs::write(&path, "abcdef").unwrap();
        let opened = open_path(path.to_str().unwrap(), true).unwrap();
        // even if the name now points elsewhere, the pinned file is what gets written
        let other = dir.path().join("other");
        std::fs::write(&other, "other").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        opened.reopen_overwrite().unwrap().write_all(b"XY").unwrap();
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "other");

        let again = dir.path().join("again");
        std::fs::write(&again, "abcdef").unwrap();
        let opened = open_path(again.to_str().unwrap(), true).unwrap();
        opened.reopen_overwrite().unwrap().write_all(b"XY").unwrap();
        assert_eq!(std::fs::read_to_string(&again).unwrap(), "XY");
    }

    #[test]
    fn a_deleted_file_reached_through_an_open_descriptor_is_refused() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        std::fs::write(&path, "PRIVATE KEY").unwrap();
        // some process holds the file open (here, this one), and then it is deleted
        let held = File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        // the kernel names such a file "/…/server.key (deleted)", which no longer looks
        // like a key file to a pattern such as **/*.key
        let through_fd = format!("/proc/self/fd/{}", held.as_raw_fd());
        let result = open_path(&through_fd, true);
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    #[test]
    fn a_file_in_another_mount_namespace_is_refused() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        // A process in its own mount namespace mounts a private filesystem over a
        // directory. Through /proc/PID/root its files are reachable from outside, but
        // the kernel reports their path as if they were at that place on the host.
        let dir = tempfile::tempdir().unwrap();
        let mount_point = real(dir.path());
        let script = "mount -t tmpfs tmpfs \"$1\" && echo secret > \"$1/hosts\" && echo ready && exec sleep 30";
        let spawned = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "sh",
                "-c",
                script,
                "sh",
                &mount_point,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = spawned else {
            eprintln!("skipped: unshare is not available");
            return;
        };
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        if line.trim() != "ready" {
            eprintln!("skipped: unprivileged mount namespaces are not permitted here");
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        let inside = format!("/proc/{}/root{mount_point}/hosts", child.id());
        let result = open_path(&inside, true);
        let _ = child.kill();
        let _ = child.wait();
        // on the host there is no such file at that path: the path cannot be trusted
        assert!(matches!(result, Err(ToolError::Failed(_))), "{result:?}");
    }

    #[test]
    fn lexical_resolves_dots_without_touching_the_filesystem() {
        let cases: &[(&str, &str)] = &[
            ("/var/log/syslog", "/var/log/syslog"),
            ("/var/log/../../etc/shadow", "/etc/shadow"),
            ("/var/./log//app/", "/var/log/app"),
            ("/../..", "/"),
            ("/", "/"),
        ];
        for (path, want) in cases {
            assert_eq!(lexical(path), *want, "{path}");
        }
    }

    #[test]
    fn a_missing_path_is_a_clear_failure() {
        match open_path("/nonexistent/file", true) {
            Err(ToolError::Failed(message)) => {
                assert!(message.contains("/nonexistent/file"), "{message}")
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn check_absolute_rejects_relative_paths() {
        assert!(check_absolute("/etc/hosts").is_ok());
        assert!(check_absolute("etc/hosts").is_err());
        assert!(check_absolute("").is_err());
        assert!(check_absolute(&format!("/{}", "x".repeat(5000))).is_err());
    }
}
