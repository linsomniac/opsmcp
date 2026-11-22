//! The running kernel: modules, taint, livepatch, mitigations.

use std::cmp::Ordering;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::args::{Args, Param};
use super::{Ctx, Tool, ToolError, ToolResult, blocking, format_rows, format_table, one_line_cell};
use crate::policy::Access;
use crate::sanitize::{keep_head, redact_text};
use crate::timefmt::human_bytes;

/// Where the kernel's files are. Tests point these at a temporary directory.
#[derive(Clone, Debug)]
pub struct Roots {
    /// `/proc`
    pub proc: PathBuf,
    /// `/sys`
    pub sys: PathBuf,
    /// `/boot`
    pub boot: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            proc: PathBuf::from("/proc"),
            sys: PathBuf::from("/sys"),
            boot: PathBuf::from("/boot"),
        }
    }
}

const MODULE_VIEWS: [&str; 2] = ["summary", "all"];

pub fn tools() -> Vec<Tool> {
    tools_with(Roots::default())
}

pub fn tools_with(roots: Roots) -> Vec<Tool> {
    let roots = Arc::new(roots);
    vec![Tool::new(
        "kernel_status",
        "Show the running kernel: its release and boot parameters, whether it is tainted \
         and why, the loaded modules that are out-of-tree, proprietary or unsigned, live \
         patches, the CPU vulnerability mitigations, and whether a newer kernel is \
         installed but not yet running. Use it to check what a host actually booted, \
         before or after a kernel update, or when a driver is suspected. Name a module to \
         see its version and parameters.",
        Access::Read,
        "system.view",
        vec![
            Param::choice(
                "modules",
                "summary (default): count the loaded modules and list the out-of-tree, \
                 proprietary or unsigned ones; all: list every loaded module",
                &MODULE_VIEWS,
            ),
            Param::str(
                "module",
                "Show only this module's details: version, users and parameters",
            )
            .max_len(64),
        ],
        move |ctx, args| {
            let roots = roots.clone();
            async move { kernel_status(ctx, args, roots).await }
        },
    )]
}

/// One reason a kernel is tainted: the letter the kernel prints for it and what it means.
#[derive(Debug, PartialEq, Eq)]
pub struct Taint {
    pub letter: String,
    pub meaning: String,
}

/// The kernel's taint bits, lowest first: the letter it prints and what the bit means
/// (Documentation/admin-guide/tainted-kernels.rst).
const TAINT_BITS: [(char, &str); 20] = [
    ('P', "a proprietary module was loaded"),
    ('F', "a module was force loaded"),
    (
        'S',
        "the kernel is running on hardware that is out of specification",
    ),
    ('R', "a module was force unloaded"),
    ('M', "the processor reported a machine check exception"),
    ('B', "a bad page was referenced"),
    ('U', "taint was requested from user space"),
    ('D', "the kernel died recently (an oops or BUG)"),
    ('A', "an ACPI table was overridden"),
    ('W', "the kernel issued a warning"),
    ('C', "a staging driver was loaded"),
    ('I', "a workaround for a platform firmware bug was applied"),
    ('O', "an out-of-tree module was loaded"),
    ('E', "an unsigned module was loaded"),
    ('L', "a soft lockup occurred"),
    ('K', "the kernel has been live patched"),
    ('X', "auxiliary taint, defined by the distribution"),
    ('T', "the kernel was built with structure randomisation"),
    ('N', "an in-kernel test was run"),
    ('J', "user space used a mutating debug operation"),
];

/// The reasons encoded in `/proc/sys/kernel/tainted`, lowest bit first. A bit this table
/// does not know is still reported, by number.
pub fn decode_taint(value: u64) -> Vec<Taint> {
    let mut reasons = Vec::new();
    for bit in 0..u64::BITS {
        if value & (1u64 << bit) == 0 {
            continue;
        }
        let known = usize::try_from(bit)
            .ok()
            .and_then(|bit| TAINT_BITS.get(bit));
        reasons.push(match known {
            Some((letter, meaning)) => Taint {
                letter: letter.to_string(),
                meaning: (*meaning).to_string(),
            },
            None => Taint {
                letter: "?".to_string(),
                meaning: format!("bit {bit} is set (not a taint flag this version knows)"),
            },
        });
    }
    reasons
}

/// A release string in pieces: runs of digits as numbers, everything else as text.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Piece {
    // Declared first so that text sorts before a number in the same position.
    Text(String),
    Number(u64),
}

fn pieces(release: &str) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut digits = String::new();
    let mut text = String::new();
    for c in release.chars() {
        if c.is_ascii_digit() {
            if !text.is_empty() {
                out.push(Piece::Text(std::mem::take(&mut text)));
            }
            digits.push(c);
        } else {
            if !digits.is_empty() {
                // A run of digits too long for a u64 is not a version number; compare it
                // as the largest one rather than fail.
                out.push(Piece::Number(digits.parse().unwrap_or(u64::MAX)));
                digits.clear();
            }
            if c.is_ascii_alphabetic() {
                text.push(c);
            } else if !text.is_empty() {
                // punctuation only separates pieces
                out.push(Piece::Text(std::mem::take(&mut text)));
            }
        }
    }
    if !digits.is_empty() {
        out.push(Piece::Number(digits.parse().unwrap_or(u64::MAX)));
    }
    if !text.is_empty() {
        out.push(Piece::Text(text));
    }
    out
}

/// Orders two kernel release strings the way `sort -V` would: runs of digits compare as
/// numbers, everything else as text.
pub fn version_cmp(a: &str, b: &str) -> Ordering {
    pieces(a).cmp(&pieces(b))
}

/// The flavour of a kernel release: what follows its version numbers (`generic`,
/// `cloud-amd64`, `el9_4.x86_64+debug`), with the numbers inside it left out, since those
/// change from one build to the next (`el9_4` and `el9_5`, `arch1-1` and `arch1-2`).
///
/// AIDEV-NOTE: kernels of different flavours are different kernel lines that are
/// installed side by side (generic beside aws, a cloud image beside the plain one, a
/// debug or realtime build). Their version numbers say nothing about which one the host
/// boots, so "newer" is only ever said of a kernel with the running kernel's flavour.
pub fn flavour(release: &str) -> String {
    let start = release
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(release.len());
    let mut out = String::new();
    let mut in_number = false;
    for c in release.get(start..).unwrap_or("").chars() {
        if c.is_ascii_digit() {
            if !in_number {
                out.push('#');
            }
            in_number = true;
        } else {
            out.push(c);
            in_number = false;
        }
    }
    out
}

/// One line of `/proc/modules`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub size: u64,
    pub users: u64,
    /// The taint letters the kernel shows for the module, e.g. `OE`. Empty for none.
    pub taint: String,
}

/// `/proc/modules`: `NAME SIZE USERS USED-BY STATE ADDRESS [(TAINT)]`. Lines that do not
/// have that shape are skipped.
pub fn parse_modules(text: &str) -> Vec<Module> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next().filter(|name| is_module_name(name))?;
            let size = fields.next()?.parse().ok()?;
            let users = fields.next()?.parse().ok()?;
            let taint = fields
                .last()
                .and_then(|last| last.strip_prefix('(')?.strip_suffix(')'))
                .filter(|letters| letters.chars().all(|c| c.is_ascii_uppercase()))
                .unwrap_or("")
                .to_string();
            Some(Module {
                name: name.to_string(),
                size,
                users,
                taint,
            })
        })
        .collect()
}

/// A module name as it appears under `/sys/module`: letters, digits, `_` and `-`.
///
/// AIDEV-NOTE: this is what keeps a caller-supplied name from being a path. It becomes
/// one component under `/sys/module`, so it must never hold `/` or `.`.
fn is_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The mode in force from `/sys/kernel/security/lockdown` (`[none] integrity ...`).
pub fn lockdown_mode(text: &str) -> Option<String> {
    text.split_whitespace()
        .find_map(|word| word.strip_prefix('[')?.strip_suffix(']'))
        .filter(|mode| !mode.is_empty() && mode.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_string)
}

/// The most that is read of any one of the kernel's small files.
const SMALL_FILE: u64 = 16 * 1024;
/// The most that is read of `/proc/modules`.
const MODULES_FILE: u64 = 1024 * 1024;
/// The most entries looked at in any one directory.
const MAX_ENTRIES: usize = 2000;
/// The most parameters shown for one module.
const MAX_PARAMETERS: usize = 100;

/// At most `max` bytes of a file as text, without the white space around it. `None` if
/// it cannot be read.
fn read_trimmed(path: &Path, max: u64) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(max).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).trim().to_string())
}

/// The names in a directory, sorted, at most `MAX_ENTRIES` of them. `None` if it cannot
/// be listed.
fn names_in(dir: &Path) -> Option<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .take(MAX_ENTRIES)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Some(names)
}

/// Host text on one line of ours, cut to `max` characters.
fn shown(text: &str, max: usize) -> String {
    let line = one_line_cell(text);
    if line.chars().count() <= max {
        return line;
    }
    let mut kept: String = line.chars().take(max).collect();
    kept.push_str("...");
    kept
}

/// What the caller asked to see.
struct View {
    all_modules: bool,
    module: Option<String>,
}

/// The kernels installed in `/boot`: the release part of each `vmlinuz-RELEASE` name.
fn installed_kernels(boot: &Path) -> Option<Vec<String>> {
    let mut releases: Vec<String> = names_in(boot)?
        .into_iter()
        .filter_map(|name| name.strip_prefix("vmlinuz-").map(str::to_string))
        .filter(|release| !release.is_empty())
        .collect();
    releases.sort_by(|a, b| version_cmp(a, b));
    Some(releases)
}

/// The loaded modules, each with the taint letters from its `/sys/module/NAME/taint`
/// (or, where that file is missing, the ones `/proc/modules` showed).
fn loaded_modules(roots: &Roots) -> Option<Vec<Module>> {
    let text = read_trimmed(&roots.proc.join("modules"), MODULES_FILE)?;
    let mut modules = parse_modules(&text);
    modules.truncate(MAX_ENTRIES);
    for module in &mut modules {
        let file = roots.sys.join("module").join(&module.name).join("taint");
        if let Some(letters) = read_trimmed(&file, 64)
            && letters.chars().all(|c| c.is_ascii_uppercase())
        {
            module.taint = letters;
        }
    }
    Some(modules)
}

/// The CPU vulnerability files, those that say "Vulnerable" first, then the ones that
/// are only partly mitigated or unknown, then the mitigated ones, then those that do not
/// apply.
fn mitigations(sys: &Path) -> Option<Vec<(String, String)>> {
    let dir = sys.join("devices/system/cpu/vulnerabilities");
    let mut found: Vec<(String, String)> = names_in(&dir)?
        .into_iter()
        .filter_map(|name| {
            let status = read_trimmed(&dir.join(&name), SMALL_FILE)?;
            Some((name, status))
        })
        .collect();
    let rank = |status: &str| {
        if is_vulnerable(status) {
            0
        } else if is_partly_mitigated(status) {
            1
        } else if status.starts_with("Not affected") {
            3
        } else {
            2
        }
    };
    found.sort_by(|a, b| rank(&a.1).cmp(&rank(&b.1)).then_with(|| a.0.cmp(&b.0)));
    Some(found)
}

fn is_vulnerable(status: &str) -> bool {
    status.starts_with("Vulnerable")
}

/// A status that is neither "Vulnerable" nor a clean bill: the kernel says a mitigation
/// is on but names something still open ("Mitigation: Clear CPU buffers; SMT
/// vulnerable"), or that it does not know ("Unknown: ...").
///
/// AIDEV-NOTE: counted with the mitigated ones, these made the first line say that no
/// mitigation reports Vulnerable over a CPU that is still exposed across threads.
fn is_partly_mitigated(status: &str) -> bool {
    !is_vulnerable(status)
        && (status.starts_with("Unknown") || status.to_ascii_lowercase().contains("vulnerable"))
}

/// The live patches loaded: name, and whether each is enabled and in transition.
fn live_patches(sys: &Path) -> Vec<String> {
    let dir = sys.join("kernel/livepatch");
    let Some(names) = names_in(&dir) else {
        return Vec::new();
    };
    names
        .into_iter()
        .filter_map(|name| {
            let enabled = read_trimmed(&dir.join(&name).join("enabled"), 16)?;
            let state = if enabled == "1" {
                "enabled"
            } else {
                "disabled"
            };
            let moving =
                read_trimmed(&dir.join(&name).join("transition"), 16).as_deref() == Some("1");
            Some(if moving {
                format!("{} ({state}, transition in progress)", shown(&name, 80))
            } else {
                format!("{} ({state})", shown(&name, 80))
            })
        })
        .collect()
}

/// The details of one module.
fn module_details(roots: &Roots, asked: &str, modules: Option<&[Module]>) -> String {
    // The kernel names modules with underscores wherever the file name has a dash.
    let name = asked.replace('-', "_");
    let dir = roots.sys.join("module").join(&name);
    let loaded = modules.and_then(|all| all.iter().find(|module| module.name == name));
    if loaded.is_none() && !dir.is_dir() {
        return format!(
            "{name} is not loaded (and is not built into this kernel with parameters).\n"
        );
    }
    let mut text = format!("Module {name}\n");
    if loaded.is_none() {
        text.push_str("Built into the kernel (not a loadable module).\n");
    }
    for (label, file) in [("Version", "version"), ("Source version", "srcversion")] {
        if let Some(value) = read_trimmed(&dir.join(file), SMALL_FILE).filter(|v| !v.is_empty()) {
            text.push_str(&format!("{label}: {}\n", shown(&value, 200)));
        }
    }
    if let Some(module) = loaded {
        text.push_str(&format!("Size: {}\n", human_bytes(module.size)));
        text.push_str(&format!("Users: {}\n", module.users));
        let taint = if module.taint.is_empty() {
            "none"
        } else {
            module.taint.as_str()
        };
        text.push_str(&format!("Taint: {taint}\n"));
    }
    let parameters = dir.join("parameters");
    match names_in(&parameters) {
        Some(names) if !names.is_empty() => {
            text.push_str("Parameters:\n");
            for parameter in names.iter().take(MAX_PARAMETERS) {
                // AIDEV-NOTE: a module parameter can hold a secret (a key, a password
                // for a network block device), so values are masked like command lines.
                let value = match read_trimmed(&parameters.join(parameter), SMALL_FILE) {
                    Some(value) => shown(&redact_text(&format!("{parameter}={value}")), 200)
                        .split_once('=')
                        .map(|(_, value)| value.to_string())
                        .unwrap_or_default(),
                    None => "(not readable)".to_string(),
                };
                text.push_str(&format!("  {} = {value}\n", shown(parameter, 80)));
            }
            if names.len() > MAX_PARAMETERS {
                text.push_str(&format!(
                    "  [{} more parameters not shown]\n",
                    names.len() - MAX_PARAMETERS
                ));
            }
        }
        _ => text.push_str("Parameters: none\n"),
    }
    text
}

/// The whole report. Blocking: it reads files.
fn report(roots: &Roots, view: &View) -> String {
    let release = read_trimmed(&roots.proc.join("sys/kernel/osrelease"), SMALL_FILE)
        .filter(|release| !release.is_empty());
    let release_shown = release
        .as_deref()
        .map(|release| shown(release, 120))
        .unwrap_or_else(|| "(release unknown)".to_string());
    let modules = loaded_modules(roots);

    if let Some(asked) = &view.module {
        return format!(
            "Kernel {release_shown}\n{}",
            module_details(roots, asked, modules.as_deref())
        );
    }

    // What the first line says, most important first.
    let mut headline = Vec::new();
    let mut body = String::new();

    if let Some(build) = read_trimmed(&roots.proc.join("version"), SMALL_FILE) {
        body.push_str(&format!("Build: {}\n", shown(&build, 300)));
    }
    if let Some(cmdline) = read_trimmed(&roots.proc.join("cmdline"), SMALL_FILE) {
        // AIDEV-NOTE: boot parameters can carry secrets (an iSCSI or network-boot
        // password), so they are masked like any command line.
        body.push_str(&format!(
            "Boot parameters: {}\n",
            shown(&redact_text(&cmdline), 2000)
        ));
    }

    // installed kernels
    let mut newer = None;
    match installed_kernels(&roots.boot) {
        Some(kernels) if !kernels.is_empty() => {
            body.push_str("Installed kernels:\n");
            for kernel in &kernels {
                let note = match &release {
                    Some(running) if kernel == running => " (running)",
                    Some(running)
                        if kernel.starts_with(|c: char| c.is_ascii_digit())
                            && flavour(kernel) == flavour(running)
                            && version_cmp(kernel, running) == Ordering::Greater =>
                    {
                        newer = Some(kernel.clone());
                        " (newer than the running kernel: installed but not running; \
                         a reboot would start it)"
                    }
                    _ => "",
                };
                body.push_str(&format!("  {}{note}\n", shown(kernel, 120)));
            }
        }
        _ => body.push_str(&format!(
            "Installed kernels: none found in {} (no vmlinuz-* files, or it cannot be listed)\n",
            roots.boot.display()
        )),
    }

    // taint
    match read_trimmed(&roots.proc.join("sys/kernel/tainted"), 64)
        .and_then(|text| text.parse::<u64>().ok())
    {
        Some(0) => {
            headline.push("not tainted".to_string());
            body.push_str("Taint: 0 (not tainted)\n");
        }
        Some(value) => {
            let reasons = decode_taint(value);
            let letters: Vec<&str> = reasons.iter().map(|r| r.letter.as_str()).collect();
            headline.push(format!("tainted ({})", letters.join(", ")));
            body.push_str(&format!("Taint: {value}\n"));
            for reason in &reasons {
                body.push_str(&format!("  {}  {}\n", reason.letter, reason.meaning));
            }
        }
        None => body.push_str("Taint: not available\n"),
    }

    // modules
    match &modules {
        Some(modules) => {
            let plural = if modules.len() == 1 { "" } else { "s" };
            headline.push(format!("{} module{plural} loaded", modules.len()));
            let tainting: Vec<String> = modules
                .iter()
                .filter(|module| !module.taint.is_empty())
                .map(|module| format!("{} ({})", module.name, module.taint))
                .collect();
            if tainting.is_empty() {
                body.push_str(&format!(
                    "Modules: {} loaded; none is out-of-tree, proprietary or unsigned\n",
                    modules.len()
                ));
            } else {
                body.push_str(&format!(
                    "Modules: {} loaded; {} out-of-tree, proprietary or unsigned: {}\n",
                    modules.len(),
                    tainting.len(),
                    tainting.join(", ")
                ));
            }
        }
        None => body.push_str("Modules: not available\n"),
    }

    // live patching, lockdown, module loading
    let patches = live_patches(&roots.sys);
    if patches.is_empty() {
        body.push_str("Live patching: none\n");
    } else {
        body.push_str(&format!("Live patching: {}\n", patches.join(", ")));
    }
    if let Some(mode) = read_trimmed(&roots.sys.join("kernel/security/lockdown"), SMALL_FILE)
        .and_then(|text| lockdown_mode(&text))
    {
        body.push_str(&format!("Lockdown: {mode}\n"));
    }
    if let Some(value) = read_trimmed(&roots.proc.join("sys/kernel/modules_disabled"), 16) {
        body.push_str(&format!("kernel.modules_disabled: {}\n", shown(&value, 16)));
    }

    // mitigations
    match mitigations(&roots.sys) {
        Some(found) if !found.is_empty() => {
            let vulnerable = found
                .iter()
                .filter(|(_, status)| is_vulnerable(status))
                .count();
            headline.push(match vulnerable {
                0 => "no mitigation reports Vulnerable".to_string(),
                1 => "1 mitigation reports Vulnerable".to_string(),
                n => format!("{n} mitigations report Vulnerable"),
            });
            let partly = found
                .iter()
                .filter(|(_, status)| is_partly_mitigated(status))
                .count();
            match partly {
                0 => {}
                1 => headline.push("1 is only partly mitigated or unknown".to_string()),
                n => headline.push(format!("{n} are only partly mitigated or unknown")),
            }
            body.push_str("== CPU vulnerability mitigations ==\n");
            let rows: Vec<Vec<String>> = found
                .iter()
                .map(|(name, status)| vec![shown(name, 60), shown(status, 200)])
                .collect();
            body.push_str(&format_rows(&rows, &[false, false]));
        }
        _ => body.push_str("Mitigations: not available\n"),
    }

    if let Some(newer) = &newer {
        headline.push(format!(
            "a newer kernel, {}, is installed but not running",
            shown(newer, 120)
        ));
    }

    // every module, when asked for: last, because it is the long part
    if view.all_modules
        && let Some(modules) = &modules
    {
        body.push_str("== loaded modules ==\n");
        let rows: Vec<Vec<String>> = modules
            .iter()
            .map(|module| {
                vec![
                    module.name.clone(),
                    human_bytes(module.size),
                    module.users.to_string(),
                    if module.taint.is_empty() {
                        "-".to_string()
                    } else {
                        module.taint.clone()
                    },
                ]
            })
            .collect();
        body.push_str(&format_table(
            &["NAME", "SIZE", "USERS", "TAINT"],
            &rows,
            &[false, true, true, false],
        ));
    }

    let first = if headline.is_empty() {
        format!("Kernel {release_shown}\n")
    } else {
        format!("Kernel {release_shown}: {}.\n", headline.join("; "))
    };
    format!("{first}{body}")
}

async fn kernel_status(ctx: Ctx, args: Args, roots: Arc<Roots>) -> ToolResult {
    let module = args.str("module").map(str::to_string);
    if let Some(name) = &module
        && !is_module_name(name)
    {
        return Err(ToolError::Invalid(format!(
            "{name:?} is not a module name (letters, digits, _ and - only)"
        )));
    }
    let view = View {
        all_modules: args.str("modules") == Some("all"),
        module,
    };
    let auth = ctx.authorize(None)?;
    let text = blocking(ctx.clone(), move || Ok(report(&roots, &view))).await?;

    // The start is what matters most (the summary, taint, kernels); the long module
    // list comes last and is what gets cut.
    const NOTE_ROOM: usize = 80;
    let (kept, dropped) = keep_head(&text, ctx.output_budget().saturating_sub(NOTE_ROOM));
    if dropped == 0 {
        return auth.ok(kept);
    }
    auth.ok(format!(
        "{kept}[{dropped} more lines left out to fit the output limit]\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::testing::MemorySink;
    use crate::tools::testing::{call, find, host, ok_text};
    use crate::tools::{Host, ToolError, ToolResult};
    use serde_json::{Value, json};
    use std::fs;
    use std::path::Path;

    fn taint(letter: &str) -> String {
        letter.to_string()
    }

    #[test]
    fn an_untainted_kernel_has_no_reasons() {
        assert_eq!(decode_taint(0), Vec::new());
    }

    #[test]
    fn taint_bits_become_letters_with_their_meaning() {
        // bit 0 (proprietary), bit 12 (out-of-tree), bit 13 (unsigned)
        let reasons = decode_taint(1 + 4096 + 8192);
        let letters: Vec<String> = reasons.iter().map(|r| r.letter.clone()).collect();
        assert_eq!(letters, [taint("P"), taint("O"), taint("E")]);
        assert!(
            reasons[0].meaning.contains("proprietary"),
            "{:?}",
            reasons[0]
        );
        assert!(
            reasons[1].meaning.contains("out-of-tree"),
            "{:?}",
            reasons[1]
        );
        assert!(reasons[2].meaning.contains("unsigned"), "{:?}", reasons[2]);
        // bit 7: the kernel died (an oops or BUG); bit 9: a warning; bit 15: live patch
        let letters: Vec<String> = decode_taint(128 + 512 + 32768)
            .into_iter()
            .map(|r| r.letter)
            .collect();
        assert_eq!(letters, [taint("D"), taint("W"), taint("K")]);
    }

    #[test]
    fn a_taint_bit_this_code_does_not_know_is_still_reported() {
        let reasons = decode_taint(1 << 40);
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].letter, "?");
        assert!(reasons[0].meaning.contains("bit 40"), "{:?}", reasons[0]);
    }

    #[test]
    fn kernel_releases_are_ordered_by_their_numbers() {
        use Ordering::{Equal, Greater, Less};
        for (a, b, want) in [
            ("6.8.0-45-generic", "6.8.0-47-generic", Less),
            ("6.8.0-9-generic", "6.8.0-10-generic", Less),
            ("5.15.0-130-generic", "6.1.0-1-generic", Less),
            ("6.8.0-45-generic", "6.8.0-45-generic", Equal),
            ("6.12.9", "6.12.10", Less),
            ("6.12.10", "6.12.9", Greater),
            ("5.14.0-503.el9.x86_64", "5.14.0-70.el9.x86_64", Greater),
            ("6.1", "6.1.5", Less),
        ] {
            assert_eq!(version_cmp(a, b), want, "{a} vs {b}");
            assert_eq!(version_cmp(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn module_lines_are_parsed_with_and_without_taint_letters() {
        let text = "\
nvidia 54984704 123 nvidia_uvm,nvidia_modeset, Live 0x0000000000000000 (POE)
ext4 1101824 3 - Live 0x0000000000000000
snd_hda_intel 61440 0 - Live 0xffffffffc0a00000
broken line
";
        assert_eq!(
            parse_modules(text),
            vec![
                Module {
                    name: "nvidia".to_string(),
                    size: 54_984_704,
                    users: 123,
                    taint: "POE".to_string(),
                },
                Module {
                    name: "ext4".to_string(),
                    size: 1_101_824,
                    users: 3,
                    taint: String::new(),
                },
                Module {
                    name: "snd_hda_intel".to_string(),
                    size: 61_440,
                    users: 0,
                    taint: String::new(),
                },
            ]
        );
    }

    #[test]
    fn the_lockdown_mode_is_the_bracketed_word() {
        assert_eq!(
            lockdown_mode("[none] integrity confidentiality\n").as_deref(),
            Some("none")
        );
        assert_eq!(
            lockdown_mode("none [integrity] confidentiality\n").as_deref(),
            Some("integrity")
        );
        assert_eq!(lockdown_mode("garbage\n"), None);
        assert_eq!(lockdown_mode(""), None);
    }

    const CONFIG: &str = r#"
[roles.reader]
allow = ["@read"]
[roles.other]
allow = ["net.view"]
[unix_users.rita]
roles = ["reader"]
[unix_users.otto]
roles = ["other"]
"#;

    fn put(root: &Path, path: &str, content: &str) {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }

    /// A machine running 6.8.0-45 with 6.8.0-47 installed, one proprietary module and one
    /// vulnerable CPU mitigation.
    fn machine() -> (tempfile::TempDir, Roots) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "proc/sys/kernel/osrelease", "6.8.0-45-generic\n");
        put(
            root,
            "proc/version",
            "Linux version 6.8.0-45-generic (buildd@example) (gcc 13.2.0) #45-Ubuntu SMP\n",
        );
        put(
            root,
            "proc/cmdline",
            "BOOT_IMAGE=/vmlinuz-6.8.0-45-generic root=/dev/mapper/vg0-root ro quiet password=hunter2\n",
        );
        put(root, "proc/sys/kernel/tainted", "12289\n");
        put(root, "proc/sys/kernel/modules_disabled", "0\n");
        put(
            root,
            "proc/modules",
            "nvidia 54984704 123 nvidia_uvm, Live 0x0000000000000000 (POE)\n\
             ext4 1101824 3 - Live 0x0000000000000000\n\
             zfs 6000000 2 - Live 0x0000000000000000\n",
        );
        put(root, "sys/module/nvidia/taint", "POE\n");
        put(root, "sys/module/nvidia/version", "550.120\n");
        put(root, "sys/module/nvidia/srcversion", "ABCDEF0123456789\n");
        put(root, "sys/module/nvidia/refcnt", "123\n");
        put(
            root,
            "sys/module/nvidia/parameters/NVreg_DeviceFileMode",
            "438\n",
        );
        put(
            root,
            "sys/module/nvidia/parameters/api_key",
            "password=s3cr3tvalue\n",
        );
        put(root, "sys/module/ext4/taint", "\n");
        put(root, "sys/module/ext4/refcnt", "3\n");
        // zfs has no taint file here: the letters from /proc/modules would be used
        put(root, "boot/vmlinuz-6.8.0-45-generic", "");
        put(root, "boot/vmlinuz-6.8.0-47-generic", "");
        put(root, "boot/vmlinuz-6.8.0-31-generic", "");
        put(root, "boot/initrd.img-6.8.0-45-generic", "");
        put(
            root,
            "sys/devices/system/cpu/vulnerabilities/meltdown",
            "Not affected\n",
        );
        put(
            root,
            "sys/devices/system/cpu/vulnerabilities/spectre_v2",
            "Mitigation: Enhanced / Automatic IBRS\n",
        );
        put(
            root,
            "sys/devices/system/cpu/vulnerabilities/retbleed",
            "Vulnerable\n",
        );
        put(
            root,
            "sys/kernel/security/lockdown",
            "none [integrity] confidentiality\n",
        );
        put(root, "sys/kernel/livepatch/lkp_Ubuntu_6_8_0/enabled", "1\n");
        put(
            root,
            "sys/kernel/livepatch/lkp_Ubuntu_6_8_0/transition",
            "0\n",
        );
        let roots = Roots {
            proc: root.join("proc"),
            sys: root.join("sys"),
            boot: root.join("boot"),
        };
        (dir, roots)
    }

    async fn run(roots: &Roots, user: &str, arguments: Value) -> (ToolResult, MemorySink) {
        let (host, sink): (std::sync::Arc<Host>, MemorySink) = host(CONFIG);
        let tool = find(tools_with(roots.clone()), "kernel_status");
        (call(&host, user, &tool, arguments).await, sink)
    }

    #[tokio::test]
    async fn the_first_line_sums_up_what_is_notable() {
        let (_dir, roots) = machine();
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(first.starts_with("Kernel 6.8.0-45-generic"), "{first}");
        assert!(first.contains("tainted (P, O, E)"), "{first}");
        assert!(first.contains("3 modules"), "{first}");
        assert!(first.contains("1 mitigation reports Vulnerable"), "{first}");
        assert!(
            first.contains("a newer kernel, 6.8.0-47-generic, is installed but not running"),
            "{first}"
        );
    }

    #[tokio::test]
    async fn the_report_shows_build_boot_parameters_taint_and_kernels() {
        let (_dir, roots) = machine();
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        assert!(
            text.contains("Build: Linux version 6.8.0-45-generic"),
            "{text}"
        );
        assert!(
            text.contains("Boot parameters: BOOT_IMAGE=/vmlinuz-6.8.0-45-generic"),
            "{text}"
        );
        // a secret on the kernel command line is masked
        assert!(!text.contains("hunter2"), "{text}");
        assert!(
            text.contains("Taint: 12289") && text.contains("P  a proprietary module was loaded"),
            "{text}"
        );
        assert!(text.contains("6.8.0-45-generic (running)"), "{text}");
        assert!(
            text.contains("6.8.0-47-generic (newer than the running kernel"),
            "{text}"
        );
        // an older kernel is listed without comment; an initrd is not a kernel
        assert!(text.contains("6.8.0-31-generic"), "{text}");
        assert!(!text.contains("initrd"), "{text}");
        assert!(text.contains("Lockdown: integrity"), "{text}");
        assert!(text.contains("kernel.modules_disabled: 0"), "{text}");
        assert!(
            text.contains("Live patching: lkp_Ubuntu_6_8_0 (enabled)"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn tainting_modules_are_listed_in_the_summary() {
        let (_dir, roots) = machine();
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        assert!(
            text.contains(
                "Modules: 3 loaded; 1 out-of-tree, proprietary or unsigned: nvidia (POE)"
            ),
            "{text}"
        );
        // the full list is not shown unless asked for
        assert!(!text.contains("ext4"), "{text}");
    }

    #[tokio::test]
    async fn vulnerable_mitigations_come_first() {
        let (_dir, roots) = machine();
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {text}"))
        };
        assert!(at("retbleed") < at("spectre_v2"), "{text}");
        assert!(at("spectre_v2") < at("meltdown"), "{text}");
        assert!(
            text.contains("Mitigation: Enhanced / Automatic IBRS"),
            "{text}"
        );
    }

    #[test]
    fn the_flavour_of_a_kernel_is_what_follows_its_version_numbers() {
        // the same flavour whatever the numbers, also the numbers inside it
        for (a, b) in [
            ("6.8.0-45-generic", "6.11.0-9-generic"),
            ("6.1.0-13-amd64", "6.1.0-18-amd64"),
            ("6.1.0-13-cloud-amd64", "6.1.0-18-cloud-amd64"),
            (
                "5.14.0-427.13.1.el9_4.x86_64",
                "5.14.0-503.11.1.el9_5.x86_64",
            ),
            ("6.9.7-arch1-1", "6.10.2-arch1-2"),
            ("6.12.9", "6.12.10"),
        ] {
            assert_eq!(flavour(a), flavour(b), "{a} and {b}");
        }
        // different flavours: another kernel line altogether
        for (a, b) in [
            ("6.1.0-13-cloud-amd64", "6.1.0-18-amd64"),
            ("6.8.0-1015-aws", "6.8.0-45-generic"),
            ("6.8.0-45-generic", "6.8.0-45-lowlatency"),
            (
                "5.14.0-427.13.1.el9_4.x86_64",
                "5.14.0-427.13.1.el9_4.x86_64+debug",
            ),
            (
                "5.14.0-427.13.1.el9_4.x86_64",
                "5.14.0-427.13.1.rt14.298.el9_4.x86_64",
            ),
            ("6.1.0-18-amd64", "6.1.0-18-rt-amd64"),
            ("6.9.7-arch1-1", "6.6.36-1-lts"),
        ] {
            assert_ne!(flavour(a), flavour(b), "{a} and {b}");
        }
        assert_eq!(flavour("6.8.0-45-generic"), "generic");
        assert_eq!(flavour("6.12.9"), "");
    }

    /// AIDEV-NOTE: "a newer kernel is installed; a reboot would start it" was said of ANY
    /// installed kernel with a higher version. A host running 6.1.0-13-cloud-amd64 with
    /// the plain 6.1.0-18-amd64 image also installed (or generic beside aws, or a debug
    /// kernel) was told to reboot into a kernel it would never boot.
    #[tokio::test]
    async fn a_kernel_of_another_flavour_is_listed_without_being_called_newer() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "proc/sys/kernel/osrelease", "6.1.0-13-cloud-amd64\n");
        put(root, "boot/vmlinuz-6.1.0-13-cloud-amd64", "");
        put(root, "boot/vmlinuz-6.1.0-18-amd64", "");
        let roots = Roots {
            proc: root.join("proc"),
            sys: root.join("sys"),
            boot: root.join("boot"),
        };
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        assert!(
            text.contains("  6.1.0-13-cloud-amd64 (running)\n"),
            "{text}"
        );
        assert!(text.contains("  6.1.0-18-amd64\n"), "{text}");
        assert!(!text.contains("newer"), "{text}");
        assert!(!text.contains("reboot"), "{text}");

        // the same flavour, newer: that one a reboot would start
        put(root, "boot/vmlinuz-6.1.0-21-cloud-amd64", "");
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(
            first.contains("a newer kernel, 6.1.0-21-cloud-amd64, is installed but not running"),
            "{first}"
        );
        assert!(text.contains("  6.1.0-18-amd64\n"), "{text}");
    }

    /// AIDEV-NOTE: "Mitigation: Clear CPU buffers; SMT vulnerable" does not start with
    /// "Vulnerable", and neither does "Unknown: ...". Counted as mitigated, the first line
    /// said "no mitigation reports Vulnerable" over a CPU that is exposed across threads.
    #[tokio::test]
    async fn partly_mitigated_and_unknown_vulnerabilities_are_counted_apart() {
        let (dir, roots) = machine();
        put(
            dir.path(),
            "sys/devices/system/cpu/vulnerabilities/mmio_stale_data",
            "Mitigation: Clear CPU buffers; SMT vulnerable\n",
        );
        put(
            dir.path(),
            "sys/devices/system/cpu/vulnerabilities/mds",
            "Unknown: No mitigations\n",
        );
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert!(
            first.contains(
                "1 mitigation reports Vulnerable; 2 are only partly mitigated or unknown"
            ),
            "{first}"
        );
        // in the table they come after the vulnerable one and before the mitigated ones
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {text}"))
        };
        assert!(at("retbleed") < at("mds"), "{text}");
        assert!(at("mmio_stale_data") < at("spectre_v2"), "{text}");

        assert!(is_vulnerable("Vulnerable"));
        assert!(is_vulnerable(
            "Vulnerable: Clear CPU buffers attempted, no microcode"
        ));
        assert!(!is_vulnerable(
            "Mitigation: Clear CPU buffers; SMT vulnerable"
        ));
        assert!(is_partly_mitigated(
            "Mitigation: Clear CPU buffers; SMT vulnerable"
        ));
        assert!(is_partly_mitigated(
            "Mitigation: Retpolines; STIBP: disabled; RSB filling; PBRSB-eIBRS: Vulnerable"
        ));
        assert!(is_partly_mitigated(
            "Unknown: Dependent on hypervisor status"
        ));
        assert!(!is_partly_mitigated("Vulnerable"));
        assert!(!is_partly_mitigated("Not affected"));
        assert!(!is_partly_mitigated(
            "Mitigation: Enhanced / Automatic IBRS"
        ));
    }

    #[tokio::test]
    async fn all_modules_can_be_listed() {
        let (_dir, roots) = machine();
        let (result, _) = run(&roots, "rita", json!({"modules": "all"})).await;
        let text = ok_text(result);
        assert!(text.contains("NAME"), "{text}");
        for name in ["nvidia", "ext4", "zfs"] {
            assert!(text.contains(name), "{name}: {text}");
        }
        assert!(text.contains("52.4 MiB"), "{text}");
    }

    #[tokio::test]
    async fn one_module_shows_its_version_and_parameters_with_secrets_masked() {
        let (_dir, roots) = machine();
        let (result, _) = run(&roots, "rita", json!({"module": "nvidia"})).await;
        let text = ok_text(result);
        assert!(text.starts_with("Kernel 6.8.0-45-generic"), "{text}");
        assert!(text.contains("Module nvidia"), "{text}");
        assert!(text.contains("Version: 550.120"), "{text}");
        assert!(text.contains("Source version: ABCDEF0123456789"), "{text}");
        assert!(text.contains("Users: 123"), "{text}");
        assert!(text.contains("Taint: POE"), "{text}");
        assert!(text.contains("NVreg_DeviceFileMode = 438"), "{text}");
        assert!(!text.contains("s3cr3tvalue"), "{text}");
        // the other sections are left out
        assert!(!text.contains("retbleed"), "{text}");
    }

    #[tokio::test]
    async fn a_module_name_with_dashes_means_the_same_module() {
        let (dir, roots) = machine();
        put(dir.path(), "sys/module/snd_hda_intel/refcnt", "0\n");
        let (result, _) = run(&roots, "rita", json!({"module": "snd-hda-intel"})).await;
        let text = ok_text(result);
        assert!(text.contains("Module snd_hda_intel"), "{text}");
    }

    #[tokio::test]
    async fn a_module_that_is_not_loaded_is_reported_plainly() {
        let (_dir, roots) = machine();
        let (result, _) = run(&roots, "rita", json!({"module": "floppy"})).await;
        let text = ok_text(result);
        assert!(text.contains("floppy is not loaded"), "{text}");
    }

    #[tokio::test]
    async fn a_module_name_cannot_be_a_path() {
        let (_dir, roots) = machine();
        for bad in ["../../etc", "a/b", "", "-x", "a b", "a.b"] {
            let (result, sink) = run(&roots, "rita", json!({"module": bad})).await;
            assert!(
                matches!(result, Err(ToolError::Invalid(_))),
                "{bad:?}: {result:?}"
            );
            // refused before anything was authorized or read
            assert_eq!(sink.records().len(), 0, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn the_call_is_authorized_and_audited() {
        let (_dir, roots) = machine();
        let (result, sink) = run(&roots, "otto", json!({})).await;
        assert!(matches!(result, Err(ToolError::Denied(_))), "{result:?}");
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "deny");

        let (result, sink) = run(&roots, "rita", json!({})).await;
        ok_text(result);
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["permission"], "system.view");
    }

    #[tokio::test]
    async fn a_clean_kernel_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "proc/sys/kernel/osrelease", "6.12.9\n");
        put(root, "proc/sys/kernel/tainted", "0\n");
        put(root, "proc/modules", "ext4 1101824 3 - Live 0x0\n");
        put(root, "sys/module/ext4/taint", "\n");
        put(root, "boot/vmlinuz-6.12.9", "");
        put(
            root,
            "sys/devices/system/cpu/vulnerabilities/meltdown",
            "Not affected\n",
        );
        let roots = Roots {
            proc: root.join("proc"),
            sys: root.join("sys"),
            boot: root.join("boot"),
        };
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        let first = text.lines().next().unwrap();
        assert_eq!(
            first,
            "Kernel 6.12.9: not tainted; 1 module loaded; no mitigation reports Vulnerable."
        );
        assert!(text.contains("Taint: 0 (not tainted)"), "{text}");
        assert!(
            text.contains("Modules: 1 loaded; none is out-of-tree, proprietary or unsigned"),
            "{text}"
        );
        assert!(text.contains("Live patching: none"), "{text}");
        assert!(text.contains("6.12.9 (running)"), "{text}");
    }

    #[tokio::test]
    async fn missing_files_leave_parts_out_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "proc/sys/kernel/osrelease", "6.12.9\n");
        let roots = Roots {
            proc: root.join("proc"),
            sys: root.join("sys"),
            boot: root.join("boot"),
        };
        let (result, _) = run(&roots, "rita", json!({})).await;
        let text = ok_text(result);
        assert!(text.starts_with("Kernel 6.12.9"), "{text}");
        assert!(text.contains("Taint: not available"), "{text}");
        assert!(text.contains("Modules: not available"), "{text}");
        assert!(text.contains("Installed kernels: none found in"), "{text}");
        assert!(text.contains("Mitigations: not available"), "{text}");
    }

    #[tokio::test]
    async fn a_long_module_list_is_cut_to_the_output_limit_with_a_note() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        put(root, "proc/sys/kernel/osrelease", "6.12.9\n");
        let mut modules = String::new();
        for n in 0..400 {
            modules.push_str(&format!("module_number_{n} 4096 0 - Live 0x0\n"));
        }
        put(root, "proc/modules", &modules);
        let roots = Roots {
            proc: root.join("proc"),
            sys: root.join("sys"),
            boot: root.join("boot"),
        };
        let config = format!("{CONFIG}\n[limits]\nmax_output_bytes = 4096\n");
        let (host, _sink) = host(&config);
        let tool = find(tools_with(roots), "kernel_status");
        let text = ok_text(call(&host, "rita", &tool, json!({"modules": "all"})).await);
        assert!(text.len() <= 4096, "{}", text.len());
        assert!(text.contains("left out to fit the output limit"), "{text}");
    }
}
