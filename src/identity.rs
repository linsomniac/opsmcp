//! Who is calling, for the stdio transport (local use and SSH).
//!
//! AIDEV-NOTE: this is the trust anchor for local and SSH use. The caller is the Unix
//! user that started the process. Privileged use goes through sudo: `sudo opsmcp serve`
//! runs as root, and the caller is then the user sudo says invoked it (SUDO_UID, which
//! sudo sets itself and a user cannot override through sudo). sudo is the only supported
//! privilege gate; a setuid opsmcp is refused outright.

use std::ffi::CString;

use nix::unistd::{Gid, Group, Uid, User};

/// The calling Unix user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixIdentity {
    pub user: String,
    pub uid: u32,
    /// Names of every group the user belongs to, from the user database.
    pub groups: Vec<String>,
    pub via_sudo: bool,
}

/// Decides whose identity to use, from the real and effective uid and `SUDO_UID`.
/// Returns the uid and whether it came from sudo.
pub fn caller_uid(
    real: u32,
    effective: u32,
    sudo_uid: Option<&str>,
) -> Result<(u32, bool), String> {
    if real != effective {
        return Err(
            "opsmcp must not be run setuid; use sudo to run it with more privilege".to_string(),
        );
    }
    if effective == 0
        && let Some(text) = sudo_uid
    {
        // Fail closed: root with a SUDO_UID we cannot read is not silently treated as root.
        let uid: u32 = text
            .parse()
            .map_err(|_| format!("SUDO_UID is not a user id: {text:?}"))?;
        return Ok((uid, uid != 0));
    }
    Ok((real, false))
}

/// The identity of whoever started this process.
pub fn current() -> Result<UnixIdentity, String> {
    let real = rustix::process::getuid().as_raw();
    let effective = rustix::process::geteuid().as_raw();
    let sudo_uid = std::env::var("SUDO_UID").ok();
    let (uid, via_sudo) = caller_uid(real, effective, sudo_uid.as_deref())?;
    lookup(uid, via_sudo)
}

fn lookup(uid: u32, via_sudo: bool) -> Result<UnixIdentity, String> {
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| format!("looking up uid {uid}: {e}"))?
        .ok_or_else(|| format!("uid {uid} has no entry in the user database"))?;
    let name = CString::new(user.name.clone())
        .map_err(|_| format!("user name for uid {uid} contains a NUL byte"))?;
    let gids = nix::unistd::getgrouplist(&name, user.gid)
        .map_err(|e| format!("looking up groups of {}: {e}", user.name))?;
    let mut groups: Vec<String> = gids.into_iter().filter_map(group_name).collect();
    groups.sort();
    groups.dedup();
    Ok(UnixIdentity {
        user: user.name,
        uid,
        groups,
        via_sudo,
    })
}

fn group_name(gid: Gid) -> Option<String> {
    Group::from_gid(gid).ok().flatten().map(|g| g.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_uid_follows_sudo_only_when_running_as_root() {
        type Case = ((u32, u32, Option<&'static str>), Result<(u32, bool), ()>);
        let cases: &[Case] = &[
            // an ordinary user is themselves
            ((1000, 1000, None), Ok((1000, false))),
            // sudo: root on behalf of uid 1000
            ((0, 0, Some("1000")), Ok((1000, true))),
            // root without sudo is root
            ((0, 0, None), Ok((0, false))),
            ((0, 0, Some("0")), Ok((0, false))),
            // an unprivileged user cannot claim to be someone else
            ((1000, 1000, Some("0")), Ok((1000, false))),
            ((1000, 1000, Some("1234")), Ok((1000, false))),
            // a SUDO_UID that is not a uid fails closed
            ((0, 0, Some("abc")), Err(())),
            ((0, 0, Some("")), Err(())),
            ((0, 0, Some("-1")), Err(())),
            // setuid execution is refused
            ((1000, 0, None), Err(())),
            ((0, 1000, None), Err(())),
        ];
        for ((real, effective, sudo), want) in cases {
            let got = caller_uid(*real, *effective, *sudo).map_err(|_| ());
            assert_eq!(
                got, *want,
                "real {real} effective {effective} sudo {sudo:?}"
            );
        }
    }

    #[test]
    fn current_resolves_the_user_running_the_tests() {
        let me = current().unwrap();
        assert_eq!(me.uid, rustix::process::getuid().as_raw());
        assert!(!me.user.is_empty());
        assert!(!me.groups.is_empty());
    }
}
