//! Finding files by name, age or size, and searching their contents.
//!
//! Two tools, because listing and reading are different permissions with different
//! allowed directories: `fs_search` looks at names and metadata (`fs.view`, inside
//! `fs.list_roots`), `fs_grep` at contents (`fs.read`, inside `fs.read_roots`).

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use nix::unistd::User;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, openat, readlinkat, statat};

use super::args::{Args, Param};
use super::fs::{
    Entry, Names, check_limits, denied_by, dir_resource, format_listing, mode_string, pin,
};
use super::{Ctx, Tool, ToolError, ToolResult, blocking, one_line_cell, required};
use crate::config::is_account_name;
use crate::glob::glob_match;
use crate::policy::Access;
use crate::sanitize::{clean_text, keep_head, redact_text};
use crate::timefmt::{now_secs, rfc3339_utc};

/// Directories nested deeper than this are never entered, whatever depth was asked for:
/// the walk keeps two descriptors open per level.
const MAX_LEVELS: usize = 32;
/// Most names read from one directory when its entries are visited in name order.
const MAX_SORTED_NAMES: usize = 50_000;
/// Most directory entries one search looks at.
const MAX_ENTRIES: u64 = 500_000;

/// fs_grep: most bytes searched in one file, files searched, and bytes searched in all.
const GREP_FILE_BYTES: u64 = 4 * 1024 * 1024;
const GREP_FILES: u64 = 5000;
const GREP_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// A file with a NUL byte this early is taken to be binary and skipped.
const BINARY_PROBE: usize = 8 * 1024;
/// Most characters of a matching line that are shown.
const LINE_CHARS: usize = 300;

const TYPES: [&str; 4] = ["any", "file", "dir", "link"];
const SORTS: [&str; 3] = ["newest", "largest", "path"];

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "fs_search",
            "Find files and directories under a directory by name, age, size, type or owner \
             (like find): for example the files changed in the last hour, or every *.conf. \
             Looks at names and metadata only; fs_grep searches contents. Symbolic links are \
             shown but never followed, and other filesystems mounted below the directory \
             are not entered.",
            Access::Read,
            "fs.view",
            vec![
                Param::str("path", "Absolute path of the directory to search")
                    .max_len(4096)
                    .required(),
                Param::str(
                    "name",
                    "Only entries whose file name matches this pattern, with * and ? as in a \
                     shell, e.g. *.conf",
                )
                .max_len(255),
                Param::int(
                    "newer_than_minutes",
                    "Only entries modified within this many minutes",
                    1,
                    527_040,
                ),
                Param::int(
                    "older_than_days",
                    "Only entries last modified more than this many days ago",
                    1,
                    3650,
                ),
                Param::int(
                    "min_size_kb",
                    "Only regular files of at least this size, in KiB",
                    1,
                    1_000_000_000,
                ),
                Param::choice("type", "Only entries of this type (default any)", &TYPES),
                Param::str(
                    "owner",
                    "Only entries owned by this user (a user name or a numeric uid)",
                )
                .max_len(32),
                Param::int(
                    "depth",
                    "How many levels down to look; 1 is the directory's own entries only \
                     (default 8)",
                    1,
                    20,
                ),
                Param::choice(
                    "sort",
                    "Which entries come first, and are kept when there are more than limit: \
                     newest (default), largest, or path",
                    &SORTS,
                ),
                Param::int("limit", "Most entries to show (default 100)", 1, 1000),
            ],
            fs_search,
        ),
        Tool::new(
            "fs_grep",
            "Search the contents of a text file, or of the files under a directory, for a \
             regular expression (like grep -rn), e.g. to find which configuration file sets \
             an option. Only files under the directories this host's configuration allows \
             to be read are searched, never private keys or password databases. Binary \
             files are skipped and symbolic links are not followed. Values that look like \
             secrets are masked in the lines shown, which is best effort. For log files \
             use log_read.",
            Access::Read,
            "fs.read",
            vec![
                Param::str("path", "Absolute path of a file or a directory")
                    .max_len(4096)
                    .required(),
                Param::str("pattern", "Regular expression to look for in each line")
                    .max_len(512)
                    .required(),
                Param::bool(
                    "ignore_case",
                    "Match without regard to upper and lower case",
                ),
                Param::str(
                    "name",
                    "In a directory: only search files whose name matches this pattern, with \
                     * and ? as in a shell, e.g. *.conf",
                )
                .max_len(255),
                Param::int(
                    "depth",
                    "In a directory: how many levels down to look; 1 is its own files only \
                     (default 5)",
                    1,
                    10,
                ),
                Param::int(
                    "limit",
                    "Most matching lines to show (default 100)",
                    1,
                    1000,
                ),
            ],
            fs_grep,
        ),
    ]
}

// ---------------------------------------------------------------------------------------
// Walking a directory tree
// ---------------------------------------------------------------------------------------

/// The few facts a search needs about a file.
#[derive(Clone, Copy, Debug)]
struct Facts {
    kind: FileType,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: i64,
    dev: u64,
}

// The fields of `Stat` have different integer types on different architectures.
#[allow(clippy::unnecessary_cast)]
fn facts_of(stat: &Stat) -> Facts {
    Facts {
        kind: FileType::from_raw_mode(stat.st_mode),
        mode: stat.st_mode as u32,
        uid: stat.st_uid as u32,
        gid: stat.st_gid as u32,
        size: u64::try_from(stat.st_size).unwrap_or(0),
        mtime: stat.st_mtime as i64,
        dev: stat.st_dev as u64,
    }
}

fn child_path(parent: &str, name: &CStr) -> String {
    let name = name.to_string_lossy();
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// What a walk may use.
struct WalkLimits {
    /// Entries this many levels below the starting directory are still visited: 1 means
    /// its own entries only.
    depth: usize,
    /// When the walk gives up and reports what it has.
    deadline: Instant,
    /// Most entries visited.
    max_entries: u64,
    /// Visit the entries of each directory in name order (which means reading the
    /// directory whole first) rather than in the order the filesystem returns them.
    sorted: bool,
}

/// How a walk ended.
#[derive(Debug, Default)]
struct WalkEnd {
    /// The deadline passed before everything had been visited.
    out_of_time: bool,
    /// `max_entries` was reached.
    too_many: bool,
    /// A directory had more entries than are sorted; the rest of it was not visited.
    overfull: bool,
    /// Directories that could not be opened or read.
    unreadable: u64,
}

/// One directory entry, as handed to the visitor of a walk.
struct Visit<'a> {
    /// The open directory the entry is in.
    dir: BorrowedFd<'a>,
    name: &'a CStr,
    /// The entry's full path.
    path: &'a str,
    facts: Facts,
}

/// What the visitor wants done next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    /// Go on to the next entry.
    Continue,
    /// The entry is a directory that may be entered.
    Enter,
    /// End the walk now.
    Stop,
}

/// The entries of one directory, yet to be visited.
enum Listing {
    Stream(Dir),
    Sorted(std::vec::IntoIter<CString>),
}

impl Listing {
    fn next(&mut self) -> Option<std::io::Result<CString>> {
        match self {
            Listing::Stream(dir) => dir.read().map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_owned())
                    .map_err(std::io::Error::from)
            }),
            Listing::Sorted(names) => names.next().map(Ok),
        }
    }
}

/// A directory being walked.
struct Frame {
    fd: OwnedFd,
    listing: Listing,
    path: String,
    /// 0 for the directory the walk started at.
    level: usize,
}

impl Frame {
    fn open(
        fd: OwnedFd,
        path: String,
        level: usize,
        sorted: bool,
        end: &mut WalkEnd,
    ) -> std::io::Result<Frame> {
        let mut dir = Dir::read_from(&fd)?;
        let listing = if sorted {
            let mut names = Vec::new();
            while let Some(entry) = dir.read() {
                let entry = entry?;
                if names.len() >= MAX_SORTED_NAMES {
                    end.overfull = true;
                    break;
                }
                names.push(entry.file_name().to_owned());
            }
            names.sort();
            Listing::Sorted(names.into_iter())
        } else {
            Listing::Stream(dir)
        };
        Ok(Frame {
            fd,
            listing,
            path,
            level,
        })
    }
}

/// Visits everything under the directory open at `root`, never following a symbolic
/// link and never leaving the filesystem `root` is on. The visitor is handed every
/// entry and says, for a directory, whether it may be entered.
///
/// AIDEV-NOTE: like the walk in `storage.rs`, this goes through directory DESCRIPTORS
/// (openat with O_NOFOLLOW from the pinned directory down). A path handed to `find` or
/// `grep` would be resolved again by name after our checks, and whoever can rename a
/// directory on the way could point it somewhere else. Here every directory entered was
/// looked up in the directory above it, so the path built for an entry is the path that
/// was walked, and that path is what the policy is asked about and what is shown.
///
/// AIDEV-NOTE: the walk runs in a blocking job, which cannot be cancelled, so it stops
/// by itself at the deadline and at `max_entries`. It keeps open descriptors per level,
/// not per entry.
fn walk(
    root: OwnedFd,
    root_path: &str,
    limits: &WalkLimits,
    visit: &mut dyn FnMut(&Visit) -> Next,
) -> std::io::Result<WalkEnd> {
    let mut end = WalkEnd::default();
    // The filesystem the walk stays on.
    let dev = facts_of(&fstat(&root)?).dev;
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    // An explicit stack rather than recursion: a deep tree cannot overflow ours.
    let first = Frame::open(root, root_path.to_string(), 0, limits.sorted, &mut end)?;
    let mut stack = vec![first];
    let mut seen = 0u64;

    while let Some(top) = stack.last_mut() {
        let name = match top.listing.next() {
            Some(Ok(name)) => name,
            Some(Err(_)) => {
                end.unreadable += 1;
                stack.pop();
                continue;
            }
            None => {
                stack.pop();
                continue;
            }
        };
        if name.as_c_str() == c"." || name.as_c_str() == c".." {
            continue;
        }
        seen += 1;
        if seen > limits.max_entries {
            end.too_many = true;
            break;
        }
        if seen.is_multiple_of(256) && Instant::now() >= limits.deadline {
            end.out_of_time = true;
            break;
        }
        // Never follows a link: a link is visited as the link it is.
        let Ok(stat) = statat(&top.fd, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue; // gone since it was listed
        };
        let facts = facts_of(&stat);
        let path = child_path(&top.path, &name);
        let next = visit(&Visit {
            dir: top.fd.as_fd(),
            name: &name,
            path: &path,
            facts,
        });
        match next {
            Next::Stop => break,
            Next::Continue => continue,
            Next::Enter => {}
        }
        let level = top.level + 1;
        // The entries of a directory at `level` are at `level + 1`.
        if facts.kind != FileType::Directory || level >= limits.depth || level >= MAX_LEVELS {
            continue;
        }
        if facts.dev != dev {
            continue; // a mount point: another filesystem
        }
        if Instant::now() >= limits.deadline {
            end.out_of_time = true;
            break;
        }
        let Ok(fd) = openat(&top.fd, name.as_c_str(), flags, Mode::empty()) else {
            end.unreadable += 1;
            continue;
        };
        // It was a directory on this filesystem a moment ago; make sure that is still
        // what was opened.
        let still = fstat(&fd).is_ok_and(|stat| {
            let now = facts_of(&stat);
            now.kind == FileType::Directory && now.dev == dev
        });
        if !still {
            continue;
        }
        match Frame::open(fd, path, level, limits.sorted, &mut end) {
            Ok(frame) => stack.push(frame),
            Err(_) => end.unreadable += 1,
        }
    }
    Ok(end)
}

/// The notes that say a walk did not see everything.
fn walk_notes(end: &WalkEnd, what: &str) -> Vec<String> {
    let mut notes = Vec::new();
    if end.out_of_time {
        notes.push(format!(
            "[the {what} stopped at its time limit and is incomplete: search a smaller \
             directory or fewer levels]"
        ));
    }
    if end.too_many {
        notes.push(format!(
            "[the {what} stopped after {MAX_ENTRIES} entries and is incomplete: search a \
             smaller directory or fewer levels]"
        ));
    }
    if end.overfull {
        notes.push(format!(
            "[a directory has more than {MAX_SORTED_NAMES} entries: only that many of them \
             were looked at]"
        ));
    }
    if end.unreadable > 0 {
        notes.push(format!(
            "[{} directories could not be read]",
            end.unreadable
        ));
    }
    notes
}

/// Checks a file-name pattern: it is matched against one name, so a `/` could never
/// match.
fn check_name_pattern(pattern: Option<&str>) -> Result<Option<String>, ToolError> {
    match pattern {
        None => Ok(None),
        Some(pattern) if pattern.is_empty() || pattern.contains('/') => {
            Err(ToolError::Invalid(format!(
                "name {pattern:?} is not usable: it is matched against the file name alone, \
                 so it cannot be empty or contain /"
            )))
        }
        Some(pattern) => Ok(Some(pattern.to_string())),
    }
}

/// Half of the time one command may take: what a walk in a blocking job gets.
fn walk_time(ctx: &Ctx) -> Duration {
    Duration::from_millis(
        ctx.cfg()
            .limits
            .command_timeout_secs
            .saturating_mul(500)
            .max(500),
    )
}

// ---------------------------------------------------------------------------------------
// fs_search
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KindFilter {
    Any,
    File,
    Dir,
    Link,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Newest,
    Largest,
    Path,
}

/// What an entry must be like to be reported.
#[derive(Debug)]
struct Criteria {
    /// Pattern over the file name.
    name: Option<String>,
    /// Modified at or after this time.
    newer_than: Option<i64>,
    /// Modified at or before this time.
    older_than: Option<i64>,
    /// A regular file of at least this many bytes.
    min_bytes: Option<u64>,
    kind: KindFilter,
    owner: Option<u32>,
}

impl Criteria {
    fn matches(&self, name: &str, facts: &Facts) -> bool {
        let kind_ok = match self.kind {
            KindFilter::Any => true,
            KindFilter::File => facts.kind == FileType::RegularFile,
            KindFilter::Dir => facts.kind == FileType::Directory,
            KindFilter::Link => facts.kind == FileType::Symlink,
        };
        kind_ok
            && self.newer_than.is_none_or(|time| facts.mtime >= time)
            && self.older_than.is_none_or(|time| facts.mtime <= time)
            // A size only means something for a regular file.
            && self
                .min_bytes
                .is_none_or(|bytes| facts.kind == FileType::RegularFile && facts.size >= bytes)
            && self.owner.is_none_or(|uid| facts.uid == uid)
            && self
                .name
                .as_deref()
                .is_none_or(|pattern| glob_match(pattern, name))
    }
}

/// One entry that matched.
#[derive(Debug)]
struct Hit {
    /// Where it stands in the order asked for: smaller comes first.
    key: i128,
    path: String,
    facts: Facts,
    /// Where a symbolic link points.
    target: Option<String>,
}

impl PartialEq for Hit {
    fn eq(&self, other: &Hit) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Hit {}

impl PartialOrd for Hit {
    fn partial_cmp(&self, other: &Hit) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hit {
    fn cmp(&self, other: &Hit) -> Ordering {
        self.key
            .cmp(&other.key)
            .then_with(|| self.path.cmp(&other.path))
    }
}

fn sort_key(sort: Sort, facts: &Facts) -> i128 {
    match sort {
        Sort::Newest => -i128::from(facts.mtime),
        Sort::Largest => -i128::from(facts.size),
        Sort::Path => 0,
    }
}

/// What a search found.
#[derive(Debug)]
struct Found {
    /// The first `limit` matches in the order asked for.
    hits: Vec<Hit>,
    /// How many entries matched in all.
    matched: u64,
    /// Something was left out, or a directory not entered, because the caller may not
    /// see it.
    withheld: bool,
    end: WalkEnd,
}

/// What the caller may be shown, as two questions about a path's resource name (a
/// directory's ends in `/`).
struct Policy<'a> {
    /// The host's configuration never shows this path to anyone.
    never_shown: &'a dyn Fn(&str) -> bool,
    /// The caller may list this directory.
    may_list: &'a dyn Fn(&str) -> bool,
}

/// Walks the directory open at `root` and keeps the `limit` first matches.
///
/// AIDEV-NOTE: an entry is visited only inside a directory the caller may list (the
/// starting directory was authorized; any other is entered only if `may_list` says so),
/// so its name is one that fs_list would have shown this caller. Paths the host's
/// configuration never shows are neither reported nor entered. What is withheld is
/// reported as a fact, never as a count: a count would say how much is behind a deny.
fn search(
    root: OwnedFd,
    root_path: &str,
    criteria: &Criteria,
    sort: Sort,
    limit: usize,
    limits: &WalkLimits,
    policy: &Policy,
) -> std::io::Result<Found> {
    let limit = limit.max(1);
    // The matches kept so far, the LAST of them (in the order asked for) on top.
    let mut kept: BinaryHeap<Hit> = BinaryHeap::new();
    let mut matched = 0u64;
    let mut withheld = false;
    let mut visit = |entry: &Visit| -> Next {
        let is_dir = entry.facts.kind == FileType::Directory;
        let resource = if is_dir {
            dir_resource(entry.path)
        } else {
            entry.path.to_string()
        };
        if (policy.never_shown)(&resource) {
            withheld = true;
            return Next::Continue;
        }
        if criteria.matches(&entry.name.to_string_lossy(), &entry.facts) {
            matched += 1;
            let key = sort_key(sort, &entry.facts);
            let ranks = kept.len() < limit
                || kept
                    .peek()
                    .is_some_and(|last| (key, entry.path) < (last.key, last.path.as_str()));
            if ranks {
                let target = (entry.facts.kind == FileType::Symlink)
                    .then(|| readlinkat(entry.dir, entry.name, Vec::new()).ok())
                    .flatten()
                    .map(|target| target.to_string_lossy().into_owned());
                kept.push(Hit {
                    key,
                    path: entry.path.to_string(),
                    facts: entry.facts,
                    target,
                });
                if kept.len() > limit {
                    kept.pop();
                }
            }
        }
        if !is_dir {
            return Next::Continue;
        }
        if (policy.may_list)(&resource) {
            Next::Enter
        } else {
            withheld = true;
            Next::Continue
        }
    };
    let end = walk(root, root_path, limits, &mut visit)?;
    Ok(Found {
        hits: kept.into_sorted_vec(),
        matched,
        withheld,
        end,
    })
}

/// The text of a search result, fitted to `budget` bytes.
fn render_search(root: &str, found: &Found, sort: Sort, budget: usize) -> String {
    let mut names = Names::default();
    let entries: Vec<Entry> = found
        .hits
        .iter()
        .map(|hit| {
            let suffix = match (&hit.target, hit.facts.kind) {
                (Some(target), _) => format!(" -> {target}"),
                (None, FileType::Directory) => "/".to_string(),
                (None, _) => String::new(),
            };
            Entry {
                mode: mode_string(hit.facts.mode),
                owner: names.user(hit.facts.uid).to_string(),
                group: names.group(hit.facts.gid).to_string(),
                size: hit.facts.size,
                modified: rfc3339_utc(hit.facts.mtime),
                name: format!("{}{suffix}", hit.path),
            }
        })
        .collect();

    let shown = u64::try_from(found.hits.len()).unwrap_or(u64::MAX);
    let mut head = format!(
        "{}: {} matching {}",
        dir_resource(root),
        found.matched,
        if found.matched == 1 {
            "entry"
        } else {
            "entries"
        }
    );
    if shown < found.matched {
        let which = match sort {
            Sort::Newest => "most recently modified",
            Sort::Largest => "largest",
            Sort::Path => "first by path",
        };
        head.push_str(&format!(
            "; the {shown} {which} are shown (raise limit or narrow the search for the rest)"
        ));
    }
    head.push('\n');

    let mut notes = walk_notes(&found.end, "search");
    if found.withheld {
        notes.push(
            "[some entries are not shown and some directories were not searched: this \
             caller may not list them]"
                .to_string(),
        );
    }
    let notes: String = notes.iter().map(|note| format!("{note}\n")).collect();
    let room = budget.saturating_sub(head.len() + notes.len() + 120);
    let (listing, dropped) = keep_head(&format_listing(&entries), room);
    let mut text = head;
    text.push_str(&listing);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more entries left out to fit the output limit; ask for fewer]\n"
        ));
    }
    text.push_str(&notes);
    text
}

/// What fs_search was asked for.
struct SearchRequest {
    name: Option<String>,
    newer_than_minutes: Option<i64>,
    older_than_days: Option<i64>,
    min_bytes: Option<u64>,
    kind: KindFilter,
    owner: Option<String>,
    depth: usize,
    sort: Sort,
    limit: usize,
}

impl SearchRequest {
    fn from_args(args: &Args) -> Result<SearchRequest, ToolError> {
        let owner = match args.str("owner") {
            Some(owner) if !is_account_name(owner) => {
                return Err(ToolError::Invalid(format!(
                    "{owner:?} is not a user name or a uid"
                )));
            }
            owner => owner.map(str::to_string),
        };
        Ok(SearchRequest {
            name: check_name_pattern(args.str("name"))?,
            newer_than_minutes: args.int("newer_than_minutes"),
            older_than_days: args.int("older_than_days"),
            min_bytes: args
                .int("min_size_kb")
                .and_then(|kb| u64::try_from(kb).ok())
                .map(|kb| kb.saturating_mul(1024)),
            kind: match args.str("type") {
                Some("file") => KindFilter::File,
                Some("dir") => KindFilter::Dir,
                Some("link") => KindFilter::Link,
                _ => KindFilter::Any,
            },
            owner,
            depth: usize::try_from(args.int("depth").unwrap_or(8)).unwrap_or(8),
            sort: match args.str("sort") {
                Some("largest") => Sort::Largest,
                Some("path") => Sort::Path,
                _ => Sort::Newest,
            },
            limit: usize::try_from(args.int("limit").unwrap_or(100)).unwrap_or(100),
        })
    }
}

/// The uid of the user an `owner` argument names: a user name, or a number.
fn owner_uid(owner: &str) -> Result<u32, ToolError> {
    if let Ok(Some(user)) = User::from_name(owner) {
        return Ok(user.uid.as_raw());
    }
    owner
        .parse::<u32>()
        .map_err(|_| ToolError::Failed(format!("there is no user named {owner} on this host")))
}

fn search_report(ctx: &Ctx, path: &str, request: &SearchRequest, time: Duration) -> ToolResult {
    // Exactly the path handling of fs_list: pin, host-wide limits, then the caller's grant.
    let roots = &ctx.cfg().fs.list_roots;
    let opened = pin(ctx, path, true, roots, "fs.list_roots")?;
    let resource = if opened.meta.is_dir() {
        dir_resource(&opened.real)
    } else {
        opened.real.clone()
    };
    check_limits(ctx, &opened.real, &resource, roots, "fs.list_roots")?;
    // The grant first, then what kind of thing the path is (see fs_list).
    let auth = ctx.authorize(Some(&resource))?;
    if !opened.meta.is_dir() {
        return Err(ToolError::Invalid(format!(
            "{} is not a directory",
            opened.real
        )));
    }
    let owner = request.owner.as_deref().map(owner_uid).transpose()?;

    let now = now_secs();
    let criteria = Criteria {
        name: request.name.clone(),
        newer_than: request
            .newer_than_minutes
            .map(|minutes| now.saturating_sub(minutes.saturating_mul(60))),
        older_than: request
            .older_than_days
            .map(|days| now.saturating_sub(days.saturating_mul(86_400))),
        min_bytes: request.min_bytes,
        kind: request.kind,
        owner,
    };
    let limits = WalkLimits {
        depth: request.depth,
        deadline: Instant::now() + time,
        max_entries: MAX_ENTRIES,
        sorted: false,
    };
    let never_shown = |resource: &str| denied_by(&ctx.cfg().fs, resource).is_some();
    let may_list = |resource: &str| ctx.permits(resource);
    let policy = Policy {
        never_shown: &never_shown,
        may_list: &may_list,
    };
    let root = opened
        .reopen_read()
        .map_err(|e| ToolError::Failed(format!("{}: {e}", opened.real)))?;
    let found = search(
        root.into(),
        &opened.real,
        &criteria,
        request.sort,
        request.limit,
        &limits,
        &policy,
    )
    .map_err(|e| ToolError::Failed(format!("{}: {e}", opened.real)))?;
    auth.ok(render_search(
        &opened.real,
        &found,
        request.sort,
        ctx.output_budget(),
    ))
}

async fn fs_search(ctx: Ctx, args: Args) -> ToolResult {
    let path = required(&args, "path")?.to_string();
    let request = SearchRequest::from_args(&args)?;
    let time = walk_time(&ctx);
    blocking(ctx.clone(), move || {
        search_report(&ctx, &path, &request, time)
    })
    .await
}

// ---------------------------------------------------------------------------------------
// fs_grep
// ---------------------------------------------------------------------------------------

/// What one fs_grep call may use.
struct GrepLimits {
    /// Most bytes searched at the start of one file.
    file_bytes: u64,
    /// Most files searched.
    files: u64,
    /// Most bytes searched in all.
    total_bytes: u64,
    /// Most matching lines reported.
    lines: usize,
    /// When to stop.
    deadline: Instant,
}

/// Why a content search ended before it had seen everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stopped {
    Lines,
    Files,
    Bytes,
    Time,
}

/// What a content search found.
#[derive(Debug, Default)]
struct Matches {
    /// `PATH:LINE: text`, ready to show.
    lines: Vec<String>,
    /// Files whose content was searched.
    searched: u64,
    bytes: u64,
    /// Files skipped because they look binary.
    binary: u64,
    /// Files of which only the start was searched.
    cut: u64,
    /// Files that could not be opened or read.
    unreadable: u64,
    /// Files or directories were passed over because the caller may not read them.
    withheld: bool,
    stopped: Option<Stopped>,
}

/// Compiles a caller-supplied pattern. The regex engine is linear-time, so a hostile
/// pattern cannot make matching slow; the size limit bounds memory.
fn compile(pattern: &str, ignore_case: bool) -> Result<regex::bytes::Regex, ToolError> {
    regex::bytes::RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| ToolError::Invalid(format!("pattern is not a valid regular expression: {e}")))
}

/// One matching line as it is shown.
///
/// AIDEV-NOTE: file content is host data and may hold secrets. The line is cleaned (no
/// control or invisible characters), then put through the same best-effort masking as
/// command lines, then cut. Masking is NOT a boundary: what protects secrets is
/// `fs.read_roots`, the never-readable patterns and the caller's grants, all applied
/// before a file is opened.
fn shown_line(path: &str, number: usize, line: &[u8]) -> String {
    let text = redact_text(&clean_text(line));
    let mut cut: String = text.chars().take(LINE_CHARS).collect();
    if cut.len() < text.len() {
        cut.push_str(" [...]");
    }
    format!(
        "{}:{number}: {cut}",
        one_line_cell(&clean_text(path.as_bytes()))
    )
}

/// Searches one open file, adding what it finds to `found`.
fn grep_file(
    mut file: impl Read,
    path: &str,
    pattern: &regex::bytes::Regex,
    limits: &GrepLimits,
    found: &mut Matches,
) {
    let left = limits.total_bytes.saturating_sub(found.bytes);
    if left == 0 {
        found.stopped = Some(Stopped::Bytes);
        return;
    }
    let most = limits.file_bytes.min(left);
    let mut data = Vec::new();
    // One byte more than is searched, to learn whether the file goes on.
    if (&mut file)
        .take(most.saturating_add(1))
        .read_to_end(&mut data)
        .is_err()
    {
        found.unreadable += 1;
        return;
    }
    let longer = u64::try_from(data.len()).unwrap_or(u64::MAX) > most;
    data.truncate(usize::try_from(most).unwrap_or(usize::MAX));
    let probe = data.len().min(BINARY_PROBE);
    if data.get(..probe).is_some_and(|start| start.contains(&0)) {
        found.binary += 1;
        return;
    }
    found.searched += 1;
    found.bytes = found
        .bytes
        .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    if longer {
        if most < limits.file_bytes {
            // It was the overall limit, not the per-file one, that cut this file short.
            found.stopped = Some(Stopped::Bytes);
        } else {
            found.cut += 1;
        }
    }
    for (index, line) in data.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if !pattern.is_match(line) {
            continue;
        }
        found.lines.push(shown_line(path, index + 1, line));
        if found.lines.len() >= limits.lines {
            found.stopped = Some(Stopped::Lines);
            return;
        }
    }
}

/// What the caller may read, as questions about a path's resource name.
struct ReadPolicy<'a> {
    /// The host's configuration never shows this path to anyone.
    never_read: &'a dyn Fn(&str) -> bool,
    /// The caller may read this file.
    may_read: &'a dyn Fn(&str) -> bool,
}

/// Searches the files under the directory open at `root`.
///
/// AIDEV-NOTE: every file is put to the same tests as a file asked for by name with
/// fs_read before it is opened: the never-readable patterns and the caller's grants, on
/// the path that was walked. (It is inside `fs.read_roots` because the walk started
/// inside them and never follows a link or leaves the filesystem.) A file that fails is
/// passed over without a trace: no name, no count.
fn grep_tree(
    root: OwnedFd,
    root_path: &str,
    pattern: &regex::bytes::Regex,
    name: Option<&str>,
    walk_limits: &WalkLimits,
    limits: &GrepLimits,
    policy: &ReadPolicy,
) -> std::io::Result<(Matches, WalkEnd)> {
    let mut found = Matches::default();
    let mut visit = |entry: &Visit| -> Next {
        match entry.facts.kind {
            FileType::Directory => {
                if (policy.never_read)(&dir_resource(entry.path)) {
                    found.withheld = true;
                    Next::Continue
                } else {
                    Next::Enter
                }
            }
            FileType::RegularFile => {
                if name.is_some_and(|glob| !glob_match(glob, &entry.name.to_string_lossy())) {
                    return Next::Continue;
                }
                if (policy.never_read)(entry.path) || !(policy.may_read)(entry.path) {
                    found.withheld = true;
                    return Next::Continue;
                }
                if Instant::now() >= limits.deadline {
                    found.stopped = Some(Stopped::Time);
                    return Next::Stop;
                }
                if found.searched >= limits.files {
                    found.stopped = Some(Stopped::Files);
                    return Next::Stop;
                }
                // NONBLOCK: nothing here can hang the server, whatever the name has
                // turned into since it was looked at.
                let flags = OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY
                    | OFlags::CLOEXEC;
                let Ok(fd) = openat(entry.dir, entry.name, flags, Mode::empty()) else {
                    found.unreadable += 1;
                    return Next::Continue;
                };
                // Still a regular file on the same filesystem: a FIFO or a device swapped
                // in under the name is not read.
                let regular = fstat(&fd).is_ok_and(|stat| {
                    let now = facts_of(&stat);
                    now.kind == FileType::RegularFile && now.dev == entry.facts.dev
                });
                if !regular {
                    return Next::Continue;
                }
                grep_file(File::from(fd), entry.path, pattern, limits, &mut found);
                if found.stopped.is_some() {
                    Next::Stop
                } else {
                    Next::Continue
                }
            }
            // Links are not followed; devices, sockets and FIFOs are not read.
            _ => Next::Continue,
        }
    };
    let end = walk(root, root_path, walk_limits, &mut visit)?;
    Ok((found, end))
}

/// The text of a content search, fitted to `budget` bytes.
fn render_grep(
    what: &str,
    pattern: &str,
    found: &Matches,
    end: Option<&WalkEnd>,
    budget: usize,
) -> String {
    let count = found.lines.len();
    let head = format!(
        "{what}: {count} matching {} for {pattern:?}\n",
        if count == 1 { "line" } else { "lines" }
    );
    let mut notes = Vec::new();
    match found.stopped {
        Some(Stopped::Lines) => notes.push(format!(
            "[stopped at {count} matching lines; there may be more: narrow the pattern or \
             raise limit]"
        )),
        Some(Stopped::Files) => notes.push(format!(
            "[stopped after {} files; the rest were not searched: search a smaller \
             directory or give a name pattern]",
            found.searched
        )),
        Some(Stopped::Bytes) => notes.push(format!(
            "[stopped after searching {} MiB; the rest was not searched: search a smaller \
             directory or give a name pattern]",
            found.bytes / (1024 * 1024)
        )),
        Some(Stopped::Time) => notes.push(
            "[stopped at the time limit; the rest was not searched: search a smaller \
             directory or give a name pattern]"
                .to_string(),
        ),
        None => {}
    }
    if let Some(end) = end {
        notes.extend(walk_notes(end, "search"));
    }
    if found.cut > 0 {
        notes.push(format!(
            "[{} files are larger than {} MiB: only their start was searched]",
            found.cut,
            GREP_FILE_BYTES / (1024 * 1024)
        ));
    }
    if found.binary > 0 {
        notes.push(format!(
            "[{} files look binary and were skipped]",
            found.binary
        ));
    }
    if found.unreadable > 0 {
        notes.push(format!("[{} files could not be read]", found.unreadable));
    }
    if found.withheld {
        notes.push(
            "[some files were not searched: this caller may not read them, or they are \
             never readable on this host]"
                .to_string(),
        );
    }
    if count > 0 {
        notes.push(
            "[values that look like secrets are masked in the lines above; that is best \
             effort]"
                .to_string(),
        );
    }
    let notes: String = notes.iter().map(|note| format!("{note}\n")).collect();
    let room = budget.saturating_sub(head.len() + notes.len() + 120);
    let lines: String = found.lines.iter().map(|line| format!("{line}\n")).collect();
    // The lines were cleaned one by one; cleaning again changes nothing.
    let (body, dropped) = keep_head(&lines, room);
    let mut text = head;
    text.push_str(&body);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if dropped > 0 {
        text.push_str(&format!(
            "[{dropped} more matching lines left out to fit the output limit; ask for fewer]\n"
        ));
    }
    text.push_str(&notes);
    text
}

/// What fs_grep was asked for.
struct GrepRequest {
    pattern_text: String,
    pattern: regex::bytes::Regex,
    name: Option<String>,
    depth: usize,
    limit: usize,
}

fn grep_report(ctx: &Ctx, path: &str, request: &GrepRequest, time: Duration) -> ToolResult {
    // The path handling of fs_read: pin, host-wide limits, then the caller's grant.
    let roots = &ctx.cfg().fs.read_roots;
    let opened = pin(ctx, path, true, roots, "fs.read_roots")?;
    let is_dir = opened.meta.is_dir();
    let resource = if is_dir {
        dir_resource(&opened.real)
    } else {
        opened.real.clone()
    };
    check_limits(ctx, &opened.real, &resource, roots, "fs.read_roots")?;
    // The grant first, then what kind of thing the path is.
    let auth = ctx.authorize(Some(&resource))?;
    if !is_dir && !opened.meta.is_file() {
        return Err(ToolError::Invalid(format!(
            "{} is neither a regular file nor a directory",
            opened.real
        )));
    }

    let failed = |e: std::io::Error| ToolError::Failed(format!("{}: {e}", opened.real));
    let limits = GrepLimits {
        file_bytes: GREP_FILE_BYTES,
        files: GREP_FILES,
        total_bytes: GREP_TOTAL_BYTES,
        lines: request.limit,
        deadline: Instant::now() + time,
    };
    let file = opened.reopen_read().map_err(failed)?;
    let budget = ctx.output_budget();
    if !is_dir {
        let mut found = Matches::default();
        grep_file(file, &opened.real, &request.pattern, &limits, &mut found);
        if found.unreadable > 0 {
            return Err(ToolError::Failed(format!(
                "{} could not be read",
                opened.real
            )));
        }
        if found.binary > 0 {
            return Err(ToolError::Failed(format!(
                "{} looks like a binary file; it was not searched",
                opened.real
            )));
        }
        return auth.ok(render_grep(
            &opened.real,
            &request.pattern_text,
            &found,
            None,
            budget,
        ));
    }

    let walk_limits = WalkLimits {
        depth: request.depth,
        deadline: limits.deadline,
        max_entries: MAX_ENTRIES,
        sorted: true,
    };
    let never_read = |resource: &str| denied_by(&ctx.cfg().fs, resource).is_some();
    let may_read = |resource: &str| ctx.permits(resource);
    let policy = ReadPolicy {
        never_read: &never_read,
        may_read: &may_read,
    };
    let (found, end) = grep_tree(
        file.into(),
        &opened.real,
        &request.pattern,
        request.name.as_deref(),
        &walk_limits,
        &limits,
        &policy,
    )
    .map_err(failed)?;
    let what = format!(
        "{} ({} {} searched)",
        dir_resource(&opened.real),
        found.searched,
        if found.searched == 1 { "file" } else { "files" }
    );
    auth.ok(render_grep(
        &what,
        &request.pattern_text,
        &found,
        Some(&end),
        budget,
    ))
}

async fn fs_grep(ctx: Ctx, args: Args) -> ToolResult {
    let path = required(&args, "path")?.to_string();
    let pattern_text = required(&args, "pattern")?.to_string();
    let request = GrepRequest {
        pattern: compile(&pattern_text, args.bool("ignore_case").unwrap_or(false))?,
        pattern_text,
        name: check_name_pattern(args.str("name"))?,
        depth: usize::try_from(args.int("depth").unwrap_or(5)).unwrap_or(5),
        limit: usize::try_from(args.int("limit").unwrap_or(100)).unwrap_or(100),
    };
    let time = walk_time(&ctx);
    blocking(ctx.clone(), move || {
        grep_report(&ctx, &path, &request, time)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::Host;
    use crate::tools::testing::{call, find, host, ok_text};
    use serde_json::{Value, json};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::SystemTime;

    /// A temporary tree and a host whose configuration opens it up:
    ///   root/etc/app.conf, db.conf, notes.txt, sub/deep.conf, alias.conf -> ../secret/plan.txt
    ///   root/logs/old.log (a year old), big.bin (binary)
    ///   root/secret/plan.txt
    ///   root/server.key (never readable), root/link -> ../outside
    ///   outside/x.conf
    struct Tree {
        _dir: tempfile::TempDir,
        root: String,
        host: Arc<Host>,
        audit: MemorySink,
    }

    fn set_age(path: &Path, days: u64) {
        let then = SystemTime::now() - Duration::from_secs(days * 86_400);
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(then).unwrap();
    }

    fn tree_with(extra_config: &str) -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let root = base.join("root");
        for sub in ["etc/sub", "logs", "secret"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::create_dir_all(base.join("outside")).unwrap();
        std::fs::write(
            root.join("etc/app.conf"),
            "# app\nlisten = 8080\ntoken=hunter2secret\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/db.conf"), "host = db1\n").unwrap();
        std::fs::write(root.join("etc/notes.txt"), "Remember the LISTEN port\n").unwrap();
        std::fs::write(root.join("etc/sub/deep.conf"), "listen = 9090\n").unwrap();
        std::os::unix::fs::symlink("../secret/plan.txt", root.join("etc/alias.conf")).unwrap();
        std::fs::write(root.join("logs/old.log"), "listen failed\n".repeat(200)).unwrap();
        set_age(&root.join("logs/old.log"), 365);
        std::fs::write(root.join("logs/big.bin"), b"listen\x00\x01\x02").unwrap();
        std::fs::write(root.join("secret/plan.txt"), "listen to nobody\n").unwrap();
        std::fs::write(root.join("server.key"), "PRIVATE listen\n").unwrap();
        std::fs::write(base.join("outside/x.conf"), "listen = 1\n").unwrap();
        std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();

        let root = root.to_string_lossy().into_owned();
        let config = format!(
            r#"
[roles.reader]
allow = ["@read"]
[roles.guarded]
allow = ["fs.view", "fs.read"]
deny = ["fs.view:{root}/secret/**", "fs.read:{root}/secret/**"]
[roles.narrow]
allow = ["fs.view:{root}/etc/**", "fs.read:{root}/etc/**"]
[roles.other]
allow = ["system.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.dana]
roles = ["guarded"]
[unix_users.nora]
roles = ["narrow"]
[unix_users.otto]
roles = ["other"]
[fs]
list_roots = ["{root}"]
read_roots = ["{root}"]
{extra_config}
"#
        );
        let (host, audit) = host(&config);
        Tree {
            _dir: dir,
            root,
            host,
            audit,
        }
    }

    fn tree() -> Tree {
        tree_with("")
    }

    impl Tree {
        fn path(&self, rest: &str) -> String {
            format!("{}/{rest}", self.root)
        }

        async fn search(&self, user: &str, arguments: Value) -> ToolResult {
            call(&self.host, user, &find(tools(), "fs_search"), arguments).await
        }

        async fn grep(&self, user: &str, arguments: Value) -> ToolResult {
            call(&self.host, user, &find(tools(), "fs_grep"), arguments).await
        }
    }

    /// The paths listed in a search result, in the order shown (the last column, with
    /// any ` -> target` kept).
    fn listed(text: &str) -> Vec<String> {
        text.lines()
            .skip(1)
            .filter(|line| !line.starts_with('['))
            .filter_map(|line| line.find(" /").map(|at| line[at + 1..].to_string()))
            .collect()
    }

    /// The `PATH:LINE` of every matching line in a grep result.
    fn matches(text: &str) -> Vec<String> {
        text.lines()
            .skip(1)
            .filter(|line| line.starts_with('/'))
            .filter_map(|line| {
                let mut parts = line.splitn(3, ':');
                Some(format!("{}:{}", parts.next()?, parts.next()?))
            })
            .collect()
    }

    fn own_user() -> String {
        User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap()
            .name
    }

    // -- the walk ------------------------------------------------------------------------

    fn open_dir(path: &str) -> OwnedFd {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        rustix::fs::open(path, flags, Mode::empty()).unwrap()
    }

    fn generous(depth: usize, sorted: bool) -> WalkLimits {
        WalkLimits {
            depth,
            deadline: Instant::now() + Duration::from_secs(30),
            max_entries: MAX_ENTRIES,
            sorted,
        }
    }

    /// Every path a walk visits, entering every directory.
    fn visited(root: &str, limits: &WalkLimits) -> (Vec<String>, WalkEnd) {
        let mut paths = Vec::new();
        let mut visit = |entry: &Visit| {
            paths.push(entry.path.to_string());
            Next::Enter
        };
        let end = walk(open_dir(root), root, limits, &mut visit).unwrap();
        (paths, end)
    }

    #[test]
    fn the_walk_visits_everything_below_and_follows_no_link() {
        let t = tree();
        let (mut paths, end) = visited(&t.root, &generous(8, false));
        paths.sort();
        let want: Vec<String> = [
            "etc",
            "etc/alias.conf",
            "etc/app.conf",
            "etc/db.conf",
            "etc/notes.txt",
            "etc/sub",
            "etc/sub/deep.conf",
            "link",
            "logs",
            "logs/big.bin",
            "logs/old.log",
            "secret",
            "secret/plan.txt",
            "server.key",
        ]
        .iter()
        .map(|rest| t.path(rest))
        .collect();
        assert_eq!(paths, want);
        assert!(!end.out_of_time && !end.too_many && !end.overfull);
        assert_eq!(end.unreadable, 0);
    }

    #[test]
    fn the_walk_goes_only_as_deep_as_asked() {
        let t = tree();
        let (mut one, _) = visited(&t.root, &generous(1, false));
        one.sort();
        assert_eq!(
            one,
            ["etc", "link", "logs", "secret", "server.key"].map(|rest| t.path(rest))
        );
        let (two, _) = visited(&t.root, &generous(2, false));
        assert!(two.contains(&t.path("etc/sub")));
        assert!(!two.contains(&t.path("etc/sub/deep.conf")));
    }

    #[test]
    fn a_sorted_walk_visits_each_directory_in_name_order() {
        let t = tree();
        let (paths, _) = visited(&t.path("etc"), &generous(8, true));
        assert_eq!(
            paths,
            [
                "alias.conf",
                "app.conf",
                "db.conf",
                "notes.txt",
                "sub",
                "sub/deep.conf"
            ]
            .map(|rest| t.path(&format!("etc/{rest}")))
        );
    }

    #[test]
    fn the_walk_does_not_enter_what_the_visitor_declines() {
        let t = tree();
        let mut paths = Vec::new();
        let mut visit = |entry: &Visit| {
            paths.push(entry.path.to_string());
            if entry.path.ends_with("/etc") {
                Next::Continue
            } else {
                Next::Enter
            }
        };
        walk(open_dir(&t.root), &t.root, &generous(8, false), &mut visit).unwrap();
        assert!(paths.contains(&t.path("etc")));
        assert!(!paths.iter().any(|path| path.contains("/etc/")));
        assert!(paths.contains(&t.path("secret/plan.txt")));
    }

    #[test]
    fn the_walk_stops_when_the_visitor_says_so() {
        let t = tree();
        let mut count = 0;
        let mut visit = |_: &Visit| {
            count += 1;
            Next::Stop
        };
        walk(open_dir(&t.root), &t.root, &generous(8, false), &mut visit).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn the_walk_stops_at_its_entry_limit_and_says_so() {
        let t = tree();
        let limits = WalkLimits {
            max_entries: 3,
            ..generous(8, false)
        };
        let (paths, end) = visited(&t.root, &limits);
        assert_eq!(paths.len(), 3);
        assert!(end.too_many);
    }

    #[test]
    fn the_walk_enters_no_directory_after_its_deadline() {
        let t = tree();
        let limits = WalkLimits {
            deadline: Instant::now(),
            ..generous(8, false)
        };
        let (paths, end) = visited(&t.root, &limits);
        assert!(end.out_of_time);
        // nothing below the starting directory's own entries was reached
        assert!(paths.iter().all(|path| {
            path.strip_prefix(&format!("{}/", t.root))
                .is_some_and(|rest| !rest.contains('/'))
        }));
        let notes = walk_notes(&end, "search");
        assert!(
            notes.iter().any(|note| note.contains("time limit")),
            "{notes:?}"
        );
    }

    #[test]
    fn a_directory_that_cannot_be_read_is_counted_not_fatal() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::Uid::effective().is_root() {
            return; // root can read everything
        }
        let t = tree();
        let closed = t.path("logs");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let (paths, end) = visited(&t.root, &generous(8, false));
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(end.unreadable, 1);
        assert!(paths.contains(&t.path("etc/app.conf")));
        assert!(!paths.contains(&t.path("logs/old.log")));
    }

    // -- fs_search: what matches ---------------------------------------------------------

    fn facts(kind: FileType, size: u64, mtime: i64, uid: u32) -> Facts {
        Facts {
            kind,
            mode: 0o100644,
            uid,
            gid: 0,
            size,
            mtime,
            dev: 1,
        }
    }

    fn any() -> Criteria {
        Criteria {
            name: None,
            newer_than: None,
            older_than: None,
            min_bytes: None,
            kind: KindFilter::Any,
            owner: None,
        }
    }

    #[test]
    fn criteria_combine_and_each_can_exclude() {
        let file = facts(FileType::RegularFile, 2048, 1000, 7);
        let dir = facts(FileType::Directory, 4096, 1000, 7);
        let link = facts(FileType::Symlink, 10, 1000, 7);
        assert!(any().matches("a.conf", &file));

        let by_name = Criteria {
            name: Some("*.conf".to_string()),
            ..any()
        };
        assert!(by_name.matches("a.conf", &file));
        assert!(!by_name.matches("a.conf.bak", &file));
        assert!(!by_name.matches("conf", &file));

        let newer = Criteria {
            newer_than: Some(1000),
            ..any()
        };
        assert!(newer.matches("x", &file));
        assert!(!newer.matches("x", &facts(FileType::RegularFile, 1, 999, 7)));
        let older = Criteria {
            older_than: Some(1000),
            ..any()
        };
        assert!(older.matches("x", &file));
        assert!(!older.matches("x", &facts(FileType::RegularFile, 1, 1001, 7)));

        // a size is only compared for regular files
        let big = Criteria {
            min_bytes: Some(2048),
            ..any()
        };
        assert!(big.matches("x", &file));
        assert!(!big.matches("x", &facts(FileType::RegularFile, 2047, 1000, 7)));
        assert!(!big.matches("x", &dir));

        for (kind, wants) in [
            (KindFilter::File, [true, false, false]),
            (KindFilter::Dir, [false, true, false]),
            (KindFilter::Link, [false, false, true]),
        ] {
            let only = Criteria { kind, ..any() };
            let got = [
                only.matches("x", &file),
                only.matches("x", &dir),
                only.matches("x", &link),
            ];
            assert_eq!(got, wants, "{kind:?}");
        }

        let owned = Criteria {
            owner: Some(7),
            ..any()
        };
        assert!(owned.matches("x", &file));
        assert!(!owned.matches("x", &facts(FileType::RegularFile, 1, 1000, 8)));

        // all of them at once
        let all = Criteria {
            name: Some("*.conf".to_string()),
            newer_than: Some(500),
            older_than: Some(1500),
            min_bytes: Some(1),
            kind: KindFilter::File,
            owner: Some(7),
        };
        assert!(all.matches("a.conf", &file));
        assert!(!all.matches("a.txt", &file));
    }

    #[tokio::test]
    async fn fs_search_finds_files_by_name_at_any_depth() {
        let t = tree();
        let tool = find(tools(), "fs_search");
        assert_eq!(
            (tool.access, tool.permission.as_str()),
            (Access::Read, "fs.view")
        );
        let text = ok_text(
            t.search(
                "rita",
                json!({"path": t.root, "name": "*.conf", "sort": "path"}),
            )
            .await,
        );
        assert_eq!(
            listed(&text),
            [
                format!("{} -> ../secret/plan.txt", t.path("etc/alias.conf")),
                t.path("etc/app.conf"),
                t.path("etc/db.conf"),
                t.path("etc/sub/deep.conf"),
            ]
        );
        assert!(
            text.starts_with(&format!("{}/: 4 matching entries\n", t.root)),
            "{text}"
        );
        // the link to a directory outside was shown as a link at most, never followed
        assert!(!text.contains("x.conf"), "{text}");
        // one audited decision, for the directory that was asked about
        let records = t.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["resource"], format!("{}/", t.root));
        assert_eq!(records[0]["decision"], "allow");
    }

    #[tokio::test]
    async fn fs_search_filters_by_age_size_type_and_owner() {
        let t = tree();
        let text = ok_text(
            t.search("rita", json!({"path": t.root, "older_than_days": 300}))
                .await,
        );
        assert_eq!(listed(&text), [t.path("logs/old.log")]);

        let text = ok_text(
            t.search(
                "rita",
                json!({"path": t.root, "newer_than_minutes": 60, "type": "file", "sort": "path"}),
            )
            .await,
        );
        let recent = listed(&text);
        assert!(recent.contains(&t.path("etc/app.conf")), "{text}");
        assert!(!recent.contains(&t.path("logs/old.log")), "{text}");

        let text = ok_text(
            t.search("rita", json!({"path": t.root, "min_size_kb": 2}))
                .await,
        );
        assert_eq!(listed(&text), [t.path("logs/old.log")]);

        let text = ok_text(
            t.search(
                "rita",
                json!({"path": t.root, "type": "dir", "sort": "path"}),
            )
            .await,
        );
        assert_eq!(
            listed(&text),
            ["etc/", "etc/sub/", "logs/", "secret/"].map(|rest| t.path(rest))
        );

        let text = ok_text(
            t.search(
                "rita",
                json!({"path": t.root, "type": "link", "sort": "path"}),
            )
            .await,
        );
        assert_eq!(
            listed(&text),
            [
                format!("{} -> ../secret/plan.txt", t.path("etc/alias.conf")),
                format!("{} -> ../outside", t.path("link")),
            ]
        );

        let mine = ok_text(
            t.search(
                "rita",
                json!({"path": t.root, "owner": own_user(), "type": "file", "name": "db.conf"}),
            )
            .await,
        );
        assert_eq!(listed(&mine), [t.path("etc/db.conf")]);
        // a numeric uid is accepted too
        let uid = nix::unistd::Uid::current().as_raw().to_string();
        let mine = ok_text(
            t.search(
                "rita",
                json!({"path": t.root, "owner": uid, "name": "db.conf"}),
            )
            .await,
        );
        assert_eq!(listed(&mine), [t.path("etc/db.conf")]);
    }

    #[tokio::test]
    async fn fs_search_orders_and_limits_what_it_shows() {
        let t = tree();
        let text = ok_text(
            t.search(
                "rita",
                json!({"path": t.root, "type": "file", "sort": "largest", "limit": 2}),
            )
            .await,
        );
        assert_eq!(listed(&text)[0], t.path("logs/old.log"));
        assert_eq!(listed(&text).len(), 2);
        let first = text.lines().next().unwrap();
        assert!(first.contains("7 matching entries"), "{first}");
        assert!(first.contains("the 2 largest are shown"), "{first}");

        // newest first is the default: the year-old log comes last
        let text = ok_text(
            t.search("rita", json!({"path": t.root, "type": "file"}))
                .await,
        );
        assert_eq!(listed(&text).last().unwrap(), &t.path("logs/old.log"));

        let text = ok_text(
            t.search("rita", json!({"path": t.root, "depth": 1, "sort": "path"}))
                .await,
        );
        assert_eq!(
            listed(&text),
            [
                t.path("etc/"),
                format!("{} -> ../outside", t.path("link")),
                t.path("logs/"),
                t.path("secret/"),
            ]
        );
    }

    #[tokio::test]
    async fn fs_search_never_shows_a_never_readable_path() {
        let t = tree();
        let text = ok_text(
            t.search("rita", json!({"path": t.root, "name": "server*"}))
                .await,
        );
        assert!(!text.contains("server.key"), "{text}");
        assert!(text.contains("0 matching entries"), "{text}");
        // it says that something is held back, and not how much
        assert!(text.contains("[some entries are not shown"), "{text}");
        let note = text.lines().find(|line| line.starts_with("[some")).unwrap();
        assert!(!note.chars().any(|c| c.is_ascii_digit()), "{note}");
    }

    #[tokio::test]
    async fn fs_search_does_not_enter_a_directory_the_caller_may_not_list() {
        let t = tree();
        // dana is denied everything under secret/: the directory's name is an entry of
        // a directory she may list, what is in it is not
        let text = ok_text(
            t.search("dana", json!({"path": t.root, "sort": "path"}))
                .await,
        );
        let paths = listed(&text);
        assert!(paths.contains(&t.path("secret/")), "{text}");
        assert!(!text.contains("plan.txt -"), "{text}");
        assert!(!paths.contains(&t.path("secret/plan.txt")), "{text}");
        assert!(text.contains("[some entries are not shown"), "{text}");
        // rita sees it, and is told of nothing withheld but the key
        let text = ok_text(t.search("rita", json!({"path": t.path("secret")})).await);
        assert_eq!(listed(&text), [t.path("secret/plan.txt")]);
        assert!(!text.contains("[some entries"), "{text}");
    }

    #[tokio::test]
    async fn fs_search_needs_a_grant_that_covers_the_directory() {
        let t = tree();
        // nora may list etc/ and below, not the directory above it
        match t.search("nora", json!({"path": t.root})).await {
            Err(ToolError::Denied(message)) => assert!(message.contains("fs.view"), "{message}"),
            other => panic!("expected a denial, got {other:?}"),
        }
        let text = ok_text(
            t.search(
                "nora",
                json!({"path": t.path("etc"), "name": "*.conf", "type": "file"}),
            )
            .await,
        );
        assert_eq!(listed(&text).len(), 3);
        // otto holds no fs.view at all
        assert!(matches!(
            t.search("otto", json!({"path": t.root})).await,
            Err(ToolError::Denied(_))
        ));
        // secret/ itself: dana's deny covers it
        assert!(matches!(
            t.search("dana", json!({"path": t.path("secret")})).await,
            Err(ToolError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn fs_search_is_confined_to_the_listable_directories() {
        let t = tree();
        let outside = Path::new(&t.root).parent().unwrap().join("outside");
        match t.search("rita", json!({"path": outside})).await {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("fs.list_roots"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // through a link, the real location is what counts
        assert!(matches!(
            t.search("rita", json!({"path": t.path("link")})).await,
            Err(ToolError::Denied(_))
        ));
        // a path that does not exist outside the roots gets the same answer
        assert!(matches!(
            t.search("rita", json!({"path": "/nonexistent-opsmcp-test/x"}))
                .await,
            Err(ToolError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn fs_search_checks_the_grant_before_saying_a_path_is_not_a_directory() {
        let t = tree();
        match t
            .search("rita", json!({"path": t.path("etc/app.conf")}))
            .await
        {
            Err(ToolError::Invalid(message)) => {
                assert!(message.contains("not a directory"), "{message}");
            }
            other => panic!("expected an invalid-argument error, got {other:?}"),
        }
        // nora may not see anything under secret/: she learns nothing about its type
        assert!(matches!(
            t.search("nora", json!({"path": t.path("secret/plan.txt")}))
                .await,
            Err(ToolError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn fs_search_rejects_unusable_arguments() {
        let t = tree();
        for bad in [
            json!({"path": t.root, "name": "etc/*.conf"}),
            json!({"path": t.root, "name": ""}),
            json!({"path": t.root, "owner": "-x"}),
            json!({"path": t.root, "owner": "a b"}),
            json!({"path": t.root, "depth": 0}),
            json!({"path": t.root, "depth": 21}),
            json!({"path": t.root, "limit": 1001}),
            json!({"path": t.root, "type": "socket"}),
            json!({"path": t.root, "sort": "oldest"}),
            json!({"path": "relative/path"}),
            json!({"name": "*.conf"}),
        ] {
            assert!(
                matches!(
                    t.search("rita", bad.clone()).await,
                    Err(ToolError::Invalid(_))
                ),
                "{bad}"
            );
        }
        // an owner that does not exist is found out after authorization, as a failure
        match t
            .search(
                "rita",
                json!({"path": t.root, "owner": "no-such-user-opsmcp"}),
            )
            .await
        {
            Err(ToolError::Failed(message)) => assert!(message.contains("no user"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(matches!(
            t.search(
                "otto",
                json!({"path": t.root, "owner": "no-such-user-opsmcp"})
            )
            .await,
            Err(ToolError::Denied(_))
        ));
    }

    #[test]
    fn a_search_result_says_what_was_not_seen_and_fits_the_budget() {
        let hit = |path: &str| Hit {
            key: 0,
            path: path.to_string(),
            facts: facts(FileType::RegularFile, 10, 0, 0),
            target: None,
        };
        let found = Found {
            hits: (0..200)
                .map(|n| hit(&format!("/srv/data/file-{n:03}")))
                .collect(),
            matched: 5000,
            withheld: true,
            end: WalkEnd {
                out_of_time: true,
                too_many: true,
                overfull: false,
                unreadable: 2,
            },
        };
        let text = render_search("/srv/data", &found, Sort::Path, 2000);
        assert!(text.len() <= 2000, "{}", text.len());
        assert!(
            text.starts_with("/srv/data/: 5000 matching entries; the 200 first by path are shown")
        );
        assert!(text.contains("/srv/data/file-000"));
        assert!(
            text.contains("more entries left out to fit the output limit"),
            "{text}"
        );
        for note in [
            "stopped at its time limit",
            "stopped after 500000 entries",
            "[2 directories could not be read]",
            "[some entries are not shown",
        ] {
            assert!(text.contains(note), "{note}: {text}");
        }
    }

    #[test]
    fn a_file_name_cannot_add_a_line_to_a_search_result() {
        let found = Found {
            hits: vec![Hit {
                key: 0,
                path: "/srv/a\n[forged note]".to_string(),
                facts: facts(FileType::RegularFile, 10, 0, 0),
                target: Some("x\ny".to_string()),
            }],
            matched: 1,
            withheld: false,
            end: WalkEnd::default(),
        };
        let text = render_search("/srv", &found, Sort::Path, 4000);
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.contains("/srv/a\\n[forged note] -> x\\ny"), "{text}");
    }

    // -- fs_grep -------------------------------------------------------------------------

    fn limits(lines: usize) -> GrepLimits {
        GrepLimits {
            file_bytes: GREP_FILE_BYTES,
            files: GREP_FILES,
            total_bytes: GREP_TOTAL_BYTES,
            lines,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    fn grep_bytes(data: &[u8], pattern: &str, limits: &GrepLimits) -> Matches {
        let mut found = Matches::default();
        grep_file(
            data,
            "/f",
            &compile(pattern, false).unwrap(),
            limits,
            &mut found,
        );
        found
    }

    #[test]
    fn grep_file_reports_each_matching_line_with_its_number() {
        let found = grep_bytes(b"alpha\nbeta\r\ngamma beta\n", "beta", &limits(100));
        assert_eq!(found.lines, ["/f:2: beta", "/f:3: gamma beta"]);
        assert_eq!((found.searched, found.binary, found.cut), (1, 0, 0));
        assert_eq!(found.stopped, None);
        // a last line without a line break is a line
        let found = grep_bytes(b"one\ntwo", "two", &limits(100));
        assert_eq!(found.lines, ["/f:2: two"]);
        // `$` means the end of a line, with or without a carriage return before it
        let found = grep_bytes(b"x = 1\r\n", "1$", &limits(100));
        assert_eq!(found.lines, ["/f:1: x = 1"]);
    }

    #[test]
    fn grep_file_skips_binary_files_and_stops_at_the_line_limit() {
        let found = grep_bytes(b"match\x00match\n", "match", &limits(100));
        assert!(found.lines.is_empty());
        assert_eq!((found.searched, found.binary), (0, 1));

        let found = grep_bytes(b"m\nm\nm\nm\n", "m", &limits(2));
        assert_eq!(found.lines.len(), 2);
        assert_eq!(found.stopped, Some(Stopped::Lines));
    }

    #[test]
    fn grep_file_searches_only_the_start_of_a_large_file() {
        let small = GrepLimits {
            file_bytes: 10,
            ..limits(100)
        };
        let found = grep_bytes(b"needle\n0123456789 needle\n", "needle", &small);
        assert_eq!(found.lines, ["/f:1: needle"]);
        assert_eq!(found.cut, 1);
        assert_eq!(found.bytes, 10);
        // exactly at the limit is not "larger"
        let exact = GrepLimits {
            file_bytes: 7,
            ..limits(100)
        };
        assert_eq!(grep_bytes(b"needle\n", "needle", &exact).cut, 0);
    }

    #[test]
    fn grep_file_stops_at_the_overall_byte_limit() {
        let tight = GrepLimits {
            total_bytes: 12,
            ..limits(100)
        };
        let pattern = compile("needle", false).unwrap();
        let mut found = Matches::default();
        grep_file(&b"needle 1\n"[..], "/a", &pattern, &tight, &mut found);
        assert_eq!(found.stopped, None);
        // the second file only gets what is left, and that ends the search
        grep_file(&b"xx\nneedle 2\n"[..], "/b", &pattern, &tight, &mut found);
        assert_eq!(found.stopped, Some(Stopped::Bytes));
        assert_eq!(found.lines, ["/a:1: needle 1"]);
        assert_eq!(found.bytes, 12);
        // nothing at all is left for a third
        let mut found = Matches {
            bytes: 12,
            ..Matches::default()
        };
        grep_file(&b"needle\n"[..], "/c", &pattern, &tight, &mut found);
        assert_eq!(found.stopped, Some(Stopped::Bytes));
        assert_eq!(found.searched, 0);
    }

    #[test]
    fn a_shown_line_is_cleaned_masked_and_cut() {
        let line = shown_line("/etc/app.conf", 3, b"password=hunter2 \x1b[31mred");
        assert!(line.starts_with("/etc/app.conf:3: "), "{line}");
        assert!(!line.contains("hunter2"), "{line}");
        assert!(!line.contains('\x1b'), "{line}");
        assert!(line.contains("\\x1b"), "{line}");

        let long = "x".repeat(1000);
        let line = shown_line("/f", 1, long.as_bytes());
        assert_eq!(line, format!("/f:1: {} [...]", "x".repeat(LINE_CHARS)));

        // a file name with a line break cannot start a line of its own
        let line = shown_line("/srv/a\n/etc/shadow:1: root", 1, b"x");
        assert_eq!(line.lines().count(), 1, "{line}");
    }

    #[tokio::test]
    async fn fs_grep_searches_the_files_under_a_directory() {
        let t = tree();
        let tool = find(tools(), "fs_grep");
        assert_eq!(
            (tool.access, tool.permission.as_str()),
            (Access::Read, "fs.read")
        );
        let text = ok_text(
            t.grep("rita", json!({"path": t.root, "pattern": "listen"}))
                .await,
        );
        assert_eq!(
            matches(&text),
            [
                format!("{}:2", t.path("etc/app.conf")),
                format!("{}:1", t.path("etc/sub/deep.conf")),
                // 200 lines match in the old log; the limit of 100 is reached there
            ]
            .into_iter()
            .chain((1..=98).map(|n| format!("{}:{n}", t.path("logs/old.log"))))
            .collect::<Vec<_>>()
        );
        assert!(text.contains("[stopped at 100 matching lines"), "{text}");
        assert!(
            text.contains(&format!("{}:2: listen = 8080", t.path("etc/app.conf"))),
            "{text}"
        );
        // the binary file was skipped and said so; the key was never opened
        assert!(
            text.contains("[1 files look binary and were skipped]"),
            "{text}"
        );
        assert!(!text.contains("server.key"), "{text}");
        assert!(!text.contains("PRIVATE"), "{text}");
        // nothing outside the directory, through the link
        assert!(!text.contains("x.conf"), "{text}");
        // one audited decision, for the directory
        let records = t.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["resource"], format!("{}/", t.root));
    }

    #[tokio::test]
    async fn fs_grep_narrows_by_file_name_case_and_depth() {
        let t = tree();
        let text = ok_text(
            t.grep(
                "rita",
                json!({"path": t.root, "pattern": "listen", "name": "*.conf"}),
            )
            .await,
        );
        assert_eq!(
            matches(&text),
            [
                format!("{}:2", t.path("etc/app.conf")),
                format!("{}:1", t.path("etc/sub/deep.conf")),
            ]
        );
        // secret/plan.txt is not a *.conf, and alias.conf (a link to it) is not followed
        assert!(!text.contains("nobody"), "{text}");

        let text = ok_text(
            t.grep(
                "rita",
                json!({"path": t.path("etc"), "pattern": "listen", "ignore_case": true}),
            )
            .await,
        );
        assert!(
            matches(&text).contains(&format!("{}:1", t.path("etc/notes.txt"))),
            "{text}"
        );
        let text = ok_text(
            t.grep("rita", json!({"path": t.path("etc"), "pattern": "listen"}))
                .await,
        );
        assert!(!text.contains("notes.txt"), "{text}");

        let text = ok_text(
            t.grep(
                "rita",
                json!({"path": t.path("etc"), "pattern": "listen", "depth": 1}),
            )
            .await,
        );
        assert_eq!(matches(&text), [format!("{}:2", t.path("etc/app.conf"))]);
        assert!(text.contains("(3 files searched)"), "{text}");
    }

    #[tokio::test]
    async fn fs_grep_masks_what_looks_like_a_secret() {
        let t = tree();
        let text = ok_text(
            t.grep("rita", json!({"path": t.path("etc"), "pattern": "token"}))
                .await,
        );
        assert_eq!(matches(&text), [format!("{}:3", t.path("etc/app.conf"))]);
        assert!(!text.contains("hunter2secret"), "{text}");
        assert!(text.contains("best effort"), "{text}");
    }

    #[tokio::test]
    async fn fs_grep_searches_one_file_when_given_a_file() {
        let t = tree();
        let file = t.path("etc/app.conf");
        let text = ok_text(
            t.grep("nora", json!({"path": file, "pattern": "^listen"}))
                .await,
        );
        assert_eq!(matches(&text), [format!("{file}:2")]);
        assert!(
            text.starts_with(&format!("{file}: 1 matching line for")),
            "{text}"
        );
        let records = t.audit.records();
        assert_eq!(records[0]["resource"], file);
        // no match is a success that says so
        let text = ok_text(
            t.grep("nora", json!({"path": file, "pattern": "absent"}))
                .await,
        );
        assert!(
            text.starts_with(&format!("{file}: 0 matching lines for")),
            "{text}"
        );
        // a binary file is not searched
        match t
            .grep(
                "rita",
                json!({"path": t.path("logs/big.bin"), "pattern": "listen"}),
            )
            .await
        {
            Err(ToolError::Failed(message)) => assert!(message.contains("binary"), "{message}"),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_grep_reads_only_what_the_caller_may_read() {
        let t = tree();
        // dana is denied secret/**: its file is passed over, and she is told only that
        // something was
        let text = ok_text(
            t.grep("dana", json!({"path": t.root, "pattern": "nobody|8080"}))
                .await,
        );
        assert_eq!(matches(&text), [format!("{}:2", t.path("etc/app.conf"))]);
        assert!(!text.contains("plan.txt"), "{text}");
        assert!(text.contains("[some files were not searched"), "{text}");
        // rita finds it
        let text = ok_text(
            t.grep("rita", json!({"path": t.root, "pattern": "nobody"}))
                .await,
        );
        assert_eq!(matches(&text), [format!("{}:1", t.path("secret/plan.txt"))]);

        // nora: etc/** only. Not the directory above, not a file elsewhere, and the
        // link in etc/ that points at the secret file is not followed.
        assert!(matches!(
            t.grep("nora", json!({"path": t.root, "pattern": "x"}))
                .await,
            Err(ToolError::Denied(_))
        ));
        assert!(matches!(
            t.grep(
                "nora",
                json!({"path": t.path("secret/plan.txt"), "pattern": "x"})
            )
            .await,
            Err(ToolError::Denied(_))
        ));
        let text = ok_text(
            t.grep("nora", json!({"path": t.path("etc"), "pattern": "nobody"}))
                .await,
        );
        assert!(matches(&text).is_empty(), "{text}");
        // asked for by name, the link resolves to the secret file: refused for nora
        assert!(matches!(
            t.grep(
                "nora",
                json!({"path": t.path("etc/alias.conf"), "pattern": "x"})
            )
            .await,
            Err(ToolError::Denied(_))
        ));
        assert!(matches!(
            t.grep("otto", json!({"path": t.root, "pattern": "x"}))
                .await,
            Err(ToolError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn fs_grep_never_reads_a_never_readable_file() {
        let t = tree();
        match t
            .grep(
                "rita",
                json!({"path": t.path("server.key"), "pattern": "PRIVATE"}),
            )
            .await
        {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("never-readable"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let text = ok_text(
            t.grep("rita", json!({"path": t.root, "pattern": "PRIVATE"}))
                .await,
        );
        assert!(matches(&text).is_empty(), "{text}");
        assert!(text.contains("[some files were not searched"), "{text}");
    }

    #[tokio::test]
    async fn fs_grep_reads_nothing_on_a_host_that_opens_no_directory_for_reading() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(base.join("a.conf"), "listen\n").unwrap();
        let (host, audit) =
            host("[roles.reader]\nallow = [\"@read\"]\n[unix_users.rita]\nroles = [\"reader\"]\n");
        let result = call(
            &host,
            "rita",
            &find(tools(), "fs_grep"),
            json!({"path": base, "pattern": "listen"}),
        )
        .await;
        match result {
            Err(ToolError::Denied(message)) => {
                assert!(message.contains("fs.read_roots"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(audit.records()[0]["decision"], "deny");
    }

    #[tokio::test]
    async fn fs_grep_does_not_hang_on_a_fifo_and_refuses_one_asked_for_by_name() {
        let t = tree();
        let fifo = t.path("etc/pipe.conf");
        rustix::fs::mkfifoat(rustix::fs::CWD, fifo.as_str(), Mode::from_raw_mode(0o644)).unwrap();
        let text = ok_text(
            t.grep("rita", json!({"path": t.path("etc"), "pattern": "host"}))
                .await,
        );
        assert_eq!(matches(&text), [format!("{}:1", t.path("etc/db.conf"))]);
        match t.grep("rita", json!({"path": fifo, "pattern": "x"})).await {
            Err(ToolError::Invalid(message)) => {
                assert!(
                    message.contains("neither a regular file nor a directory"),
                    "{message}"
                );
            }
            other => panic!("expected an invalid-argument error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fs_grep_rejects_unusable_arguments() {
        let t = tree();
        for bad in [
            json!({"path": t.root, "pattern": "(unclosed"}),
            json!({"path": t.root, "pattern": "x", "name": "a/b"}),
            json!({"path": t.root, "pattern": "x", "depth": 11}),
            json!({"path": t.root, "pattern": "x", "limit": 0}),
            json!({"path": t.root}),
            json!({"pattern": "x"}),
            json!({"path": "etc", "pattern": "x"}),
        ] {
            assert!(
                matches!(
                    t.grep("rita", bad.clone()).await,
                    Err(ToolError::Invalid(_))
                ),
                "{bad}"
            );
        }
        // a pattern that would need a huge automaton is refused, not built
        assert!(matches!(
            t.grep(
                "rita",
                json!({"path": t.root, "pattern": "(a{1000}){1000}"})
            )
            .await,
            Err(ToolError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn fs_grep_fits_its_answer_to_the_output_limit() {
        let t = tree_with("[limits]\nmax_output_bytes = 2048\n");
        let text = ok_text(
            t.grep(
                "rita",
                json!({"path": t.path("logs"), "pattern": "listen", "limit": 150}),
            )
            .await,
        );
        assert!(text.len() <= 2048, "{}", text.len());
        assert!(
            text.contains("more matching lines left out to fit the output limit"),
            "{text}"
        );
        // the notes survive the cut
        assert!(text.contains("[stopped at 150 matching lines"), "{text}");
    }

    #[test]
    fn a_grep_result_names_every_limit_that_was_reached() {
        let found = Matches {
            lines: vec!["/a:1: x".to_string()],
            searched: 5000,
            bytes: 64 * 1024 * 1024,
            binary: 3,
            cut: 2,
            unreadable: 4,
            withheld: true,
            stopped: Some(Stopped::Files),
        };
        let end = WalkEnd {
            out_of_time: false,
            too_many: false,
            overfull: true,
            unreadable: 1,
        };
        let text = render_grep("/srv/ (5000 files searched)", "x", &found, Some(&end), 8000);
        for note in [
            "/srv/ (5000 files searched): 1 matching line for \"x\"",
            "[stopped after 5000 files",
            "[a directory has more than 50000 entries",
            "[1 directories could not be read]",
            "[2 files are larger than 4 MiB",
            "[3 files look binary and were skipped]",
            "[4 files could not be read]",
            "[some files were not searched",
        ] {
            assert!(text.contains(note), "{note}: {text}");
        }
        for (stopped, words) in [
            (Stopped::Bytes, "[stopped after searching 64 MiB"),
            (Stopped::Time, "[stopped at the time limit"),
            (Stopped::Lines, "[stopped at 1 matching lines"),
        ] {
            let found = Matches {
                lines: vec!["/a:1: x".to_string()],
                bytes: 64 * 1024 * 1024,
                stopped: Some(stopped),
                ..Matches::default()
            };
            let text = render_grep("/srv/", "x", &found, None, 8000);
            assert!(text.contains(words), "{words}: {text}");
        }
    }
}
