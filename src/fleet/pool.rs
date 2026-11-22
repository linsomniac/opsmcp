//! The SSH sessions a fleet server keeps open to hosts, and its memory of the hosts that
//! did not answer.
//!
//! AIDEV-NOTE: a session is only ever reused for the SAME rule, host, address of that
//! host and (when the rule reuses the caller's identity) caller. That key is what stands
//! between one identity's session and another caller's request, so nothing may look a
//! session up by host alone.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::fleet::ssh::HostLink;

/// What a session belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    /// The `[[fleet.access]]` rule, by position.
    pub rule: usize,
    /// The host, by its inventory name.
    pub host: String,
    /// Where the host was when the session was opened: its address and, if the
    /// inventory sets one, its port.
    ///
    /// AIDEV-NOTE: the inventory can be read again while the server runs, and a host
    /// can then have another address. A session to the old address may be to another
    /// machine by now, so the address is part of what a session belongs to: it is
    /// never looked up by the name alone.
    pub address: String,
    pub port: Option<u16>,
    /// The caller, when the session carries the caller's own identity. `None` for an
    /// identity of the fleet's own, which every caller of the rule shares on purpose.
    pub caller: Option<String>,
}

/// Why there is no session to use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// The host could not be reached: just now, or a moment ago (and it is being left
    /// alone for a while).
    Unreachable(String),
    /// Every session allowed is open and in use.
    Busy(String),
}

struct Live {
    link: Arc<HostLink>,
    _permit: OwnedSemaphorePermit,
}

impl Live {
    /// Nobody is using the session: the pool holds the only reference to it.
    fn unused(&self) -> bool {
        Arc::strong_count(&self.link) == 1 && self.link.in_flight() == 0
    }
}

/// What is known about one key: its session, if it has one, and how the last attempt
/// to open one failed.
#[derive(Default)]
struct SlotState {
    live: Option<Live>,
    /// When the last attempt to open a session failed, and why.
    failed: Option<(Instant, String)>,
}

#[derive(Default)]
struct Slot {
    state: tokio::sync::Mutex<SlotState>,
}

/// How often a caller waiting for room looks again for a session that can make way.
const ROOM_CHECK_EVERY: Duration = Duration::from_millis(100);

struct Down {
    since: Instant,
    why: String,
}

pub struct Pool {
    slots: Mutex<HashMap<Key, Arc<Slot>>>,
    down: Mutex<HashMap<Key, Down>>,
    permits: Arc<Semaphore>,
    max: usize,
    idle: Duration,
    retry: Duration,
    /// How long a caller waits for room when every session is open and in use.
    wait: Duration,
    /// Set when the server is stopping: no new session is opened after that.
    closed: std::sync::atomic::AtomicBool,
}

impl Pool {
    /// `max` sessions at most; one unused for `idle` is closed; a host that could not be
    /// reached is left alone for `retry`.
    pub fn new(max: usize, idle: Duration, retry: Duration) -> Pool {
        Pool {
            slots: Mutex::new(HashMap::new()),
            down: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(max)),
            max,
            idle,
            retry,
            wait: Duration::from_secs(10),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// How long a caller waits for room when every session allowed is open and in use.
    #[cfg(test)]
    pub fn waiting(mut self, wait: Duration) -> Pool {
        self.wait = wait;
        self
    }

    fn slots(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Arc<Slot>>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn down(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Down>> {
        self.down.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The session for `key`: the one already open, or a new one made by `open`.
    ///
    /// Callers that ask for the same key at once wait for one attempt and share its
    /// outcome, so a host is never connected to several times over for one burst.
    pub async fn get<F, Fut>(&self, key: &Key, open: F) -> Result<Arc<HostLink>, Unavailable>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<HostLink, String>>,
    {
        use std::sync::atomic::Ordering;
        let stopping = || Unavailable::Busy("the fleet server is stopping".to_string());
        if self.closed.load(Ordering::Relaxed) {
            return Err(stopping());
        }
        self.check(key).map_err(Unavailable::Unreachable)?;
        let asked = Instant::now();
        let slot = self.slots().entry(key.clone()).or_default().clone();
        let mut state = slot.state.lock().await;
        if let Some(existing) = state.live.as_ref()
            && !existing.link.is_closed()
        {
            return Ok(existing.link.clone());
        }
        // Gone, or never there. Dropping it gives its place back.
        state.live = None;
        // AIDEV-NOTE: an attempt that failed while we were waiting for the slot is as
        // fresh as anything we could find out ourselves, so its outcome is ours too.
        // Without this, callers queued behind a dead host would each wait out a whole
        // connection attempt in turn (and each would knock on a host that just said no).
        if let Some((when, why)) = &state.failed
            && *when > asked
        {
            return Err(Unavailable::Unreachable(why.clone()));
        }
        self.check(key).map_err(Unavailable::Unreachable)?;
        if self.closed.load(Ordering::Relaxed) {
            return Err(stopping());
        }

        // Room for one more session: at once if there is, else by closing one nobody is
        // using, else by waiting a moment for one to fall out of use. Calls for many
        // hosts at once can want more sessions than are allowed; they should take
        // turns, not be turned away.
        let waited_since = Instant::now();
        let permit = loop {
            if let Ok(permit) = self.permits.clone().try_acquire_owned() {
                break permit;
            }
            self.close_longest_unused(&slot);
            if let Ok(permit) = self.permits.clone().try_acquire_owned() {
                break permit;
            }
            if waited_since.elapsed() >= self.wait {
                return Err(Unavailable::Busy(format!(
                    "all {} sessions to hosts are in use; try again shortly",
                    self.max
                )));
            }
            tokio::time::sleep(ROOM_CHECK_EVERY).await;
        };
        match open().await {
            Ok(link) => {
                self.mark_up(key);
                state.failed = None;
                let link = Arc::new(link);
                state.live = Some(Live {
                    link: link.clone(),
                    _permit: permit,
                });
                Ok(link)
            }
            Err(why) => {
                self.mark_down(key, &why);
                state.failed = Some((Instant::now(), why.clone()));
                Err(Unavailable::Unreachable(why))
            }
        }
    }

    /// Closes the session that has gone unused for longest, if any is unused. `ours` is
    /// the slot the caller has locked, which is skipped.
    ///
    /// AIDEV-NOTE: the place is given back at once, while the `ssh` process behind the
    /// session gets a moment to end cleanly. For that moment there can be a few more
    /// processes than `max_connections`; it is not a leak.
    fn close_longest_unused(&self, ours: &Arc<Slot>) {
        let others: Vec<Arc<Slot>> = self
            .slots()
            .values()
            .filter(|slot| !Arc::ptr_eq(slot, ours))
            .cloned()
            .collect();
        let mut longest: Option<(Duration, Arc<Slot>)> = None;
        for slot in others {
            let Ok(state) = slot.state.try_lock() else {
                continue; // being opened or handed out right now
            };
            let Some(idle) = state
                .live
                .as_ref()
                .filter(|live| live.unused())
                .map(|l| l.link.idle_for())
            else {
                continue;
            };
            drop(state);
            if longest.as_ref().is_none_or(|(most, _)| idle > *most) {
                longest = Some((idle, slot));
            }
        }
        if let Some((_, slot)) = longest
            && let Ok(mut state) = slot.state.try_lock()
            && state.live.as_ref().is_some_and(Live::unused)
        {
            state.live = None;
        }
    }

    /// `Err` with the reason while `key` is being left alone after a failure.
    pub fn check(&self, key: &Key) -> Result<(), String> {
        let mut down = self.down();
        let Some(entry) = down.get(key) else {
            return Ok(());
        };
        let ago = entry.since.elapsed();
        if ago >= self.retry {
            down.remove(key);
            return Ok(());
        }
        Err(format!(
            "{} (that was {} s ago; it is not tried again for another {} s)",
            entry.why,
            ago.as_secs(),
            (self.retry - ago).as_secs().max(1)
        ))
    }

    /// Remembers that `key` could not be reached.
    ///
    /// AIDEV-NOTE: this is also what keeps a fleet server from hammering a host that
    /// refuses its credential, which is how the fleet server would get itself banned
    /// (fail2ban and the like) by the very hosts it is meant to reach.
    pub fn mark_down(&self, key: &Key, why: &str) {
        if self.retry.is_zero() {
            return;
        }
        self.down().insert(
            key.clone(),
            Down {
                since: Instant::now(),
                why: why.to_string(),
            },
        );
    }

    /// Forgets that `key` could not be reached.
    pub fn mark_up(&self, key: &Key) {
        self.down().remove(key);
    }

    /// Closes sessions that have ended or have not been used for the idle time, and
    /// forgets failures that are old enough to be tried again. Returns how many
    /// sessions were closed.
    pub async fn reap(&self) -> usize {
        let slots: Vec<Arc<Slot>> = self.slots().values().cloned().collect();
        let mut closed = 0;
        for slot in &slots {
            let Ok(mut state) = slot.state.try_lock() else {
                continue;
            };
            let done = state.live.as_ref().is_some_and(|live| {
                live.link.is_closed() || (live.unused() && live.link.idle_for() >= self.idle)
            });
            if done {
                state.live = None;
                closed += 1;
            }
        }
        drop(slots);
        // Forget the empty places, so that the table does not grow with every key ever
        // seen. One that somebody else holds is in the middle of being filled.
        self.slots().retain(|_, slot| {
            Arc::strong_count(slot) > 1
                || slot
                    .state
                    .try_lock()
                    .is_ok_and(|state| state.live.is_some())
        });
        let retry = self.retry;
        self.down().retain(|_, entry| entry.since.elapsed() < retry);
        closed
    }

    /// Sessions currently open.
    #[cfg(test)]
    pub fn open_sessions(&self) -> usize {
        self.max - self.permits.available_permits().min(self.max)
    }

    /// Closes every session, giving the hosts a moment to end theirs cleanly, and opens
    /// no more: the server is stopping.
    pub async fn close_all(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let slots: Vec<Arc<Slot>> = self.slots().drain().map(|(_, slot)| slot).collect();
        let mut ending = tokio::task::JoinSet::new();
        for slot in slots {
            let Some(live) = slot.state.lock().await.live.take() else {
                continue;
            };
            // A session somebody is still using ends when they let go of it.
            if let Ok(link) = Arc::try_unwrap(live.link) {
                ending.spawn(link.end());
            }
        }
        while ending.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::link::Link;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key(rule: usize, host: &str, caller: Option<&str>) -> Key {
        Key {
            rule,
            host: host.to_string(),
            address: host.to_string(),
            port: None,
            caller: caller.map(str::to_string),
        }
    }

    /// The far ends of the links the test has opened; dropping one closes its link.
    #[derive(Default)]
    struct Hosts {
        ends: Mutex<Vec<tokio::io::DuplexStream>>,
        opened: AtomicUsize,
    }

    impl Hosts {
        /// A link whose other end nobody answers on.
        fn link(&self) -> HostLink {
            let (ours, theirs) = tokio::io::duplex(4096);
            self.ends.lock().unwrap().push(theirs);
            self.opened.fetch_add(1, Ordering::SeqCst);
            let (read, write) = tokio::io::split(ours);
            HostLink::over(Link::start(read, write, 4096))
        }

        fn opened(&self) -> usize {
            self.opened.load(Ordering::SeqCst)
        }

        /// The host hangs up on every link opened so far.
        fn hang_up(&self) {
            self.ends.lock().unwrap().clear();
        }
    }

    async fn get(pool: &Pool, hosts: &Hosts, key: &Key) -> Result<Arc<HostLink>, Unavailable> {
        pool.get(key, || async { Ok(hosts.link()) }).await
    }

    fn pool(max: usize) -> Pool {
        Pool::new(max, Duration::from_secs(300), Duration::from_millis(300))
    }

    /// Keeps a request waiting on `link`, so that the link counts as in use.
    fn occupy(link: &Arc<HostLink>) -> tokio::task::JoinHandle<()> {
        let link = link.clone();
        tokio::spawn(async move {
            let _ = link.request("tools/call", json!({})).await;
        })
    }

    async fn until(what: impl Fn() -> bool) {
        for _ in 0..200 {
            if what() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the condition never became true");
    }

    #[tokio::test]
    async fn a_session_is_opened_once_and_then_reused() {
        let (pool, hosts) = (pool(4), Hosts::default());
        let web1 = key(0, "web1", None);
        let first = get(&pool, &hosts, &web1).await.unwrap();
        let second = get(&pool, &hosts, &web1).await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(hosts.opened(), 1);
        assert_eq!(pool.open_sessions(), 1);
    }

    #[tokio::test]
    async fn sessions_are_never_shared_across_hosts_rules_or_callers() {
        let (pool, hosts) = (pool(8), Hosts::default());
        let keys = [
            key(0, "web1", None),
            key(0, "web2", None),
            key(1, "web1", None),
            key(1, "web1", Some("sean")),
            key(1, "web1", Some("dana")),
        ];
        let mut links = Vec::new();
        for key in &keys {
            links.push(get(&pool, &hosts, key).await.unwrap());
        }
        assert_eq!(hosts.opened(), keys.len());
        for (i, a) in links.iter().enumerate() {
            for b in &links[i + 1..] {
                assert!(!Arc::ptr_eq(a, b));
            }
        }
        // and each key gets its own session back
        for (key, link) in keys.iter().zip(&links) {
            assert!(Arc::ptr_eq(&get(&pool, &hosts, key).await.unwrap(), link));
        }
        assert_eq!(hosts.opened(), keys.len());
    }

    #[tokio::test]
    async fn a_session_that_ended_is_replaced() {
        let (pool, hosts) = (pool(4), Hosts::default());
        let web1 = key(0, "web1", None);
        let first = get(&pool, &hosts, &web1).await.unwrap();
        hosts.hang_up();
        until(|| first.is_closed()).await;
        let second = get(&pool, &hosts, &web1).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(!second.is_closed());
        assert_eq!(hosts.opened(), 2);
        assert_eq!(pool.open_sessions(), 1);
        // a session that ended is also cleared away without anyone asking for it
        drop(second);
        hosts.hang_up();
        for _ in 0..200 {
            if pool.reap().await == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(pool.open_sessions(), 0);
    }

    #[tokio::test]
    async fn callers_asking_at_once_share_one_attempt() {
        let (pool, hosts) = (Arc::new(pool(4)), Arc::new(Hosts::default()));
        let web1 = key(0, "web1", None);
        let mut asking = Vec::new();
        for _ in 0..8 {
            let (pool, hosts, web1) = (pool.clone(), hosts.clone(), web1.clone());
            asking.push(tokio::spawn(async move {
                pool.get(&web1, || async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(hosts.link())
                })
                .await
                .unwrap()
            }));
        }
        let mut links = Vec::new();
        for task in asking {
            links.push(task.await.unwrap());
        }
        assert_eq!(hosts.opened(), 1);
        assert!(links.iter().all(|link| Arc::ptr_eq(link, &links[0])));
    }

    // Time is paused in this test: it advances only when the test sleeps, so "at once"
    // and "after the pause" mean exactly that however busy the machine is.
    #[tokio::test(start_paused = true)]
    async fn a_host_that_could_not_be_reached_is_left_alone_for_a_while() {
        let (pool, hosts) = (pool(4), Hosts::default());
        let web1 = key(0, "web1", None);
        let attempts = AtomicUsize::new(0);
        let failing = || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<HostLink, String>("ssh could not connect or log in: no route to host".to_string())
        };
        let first = pool.get(&web1, failing).await.err().unwrap();
        assert_eq!(
            first,
            Unavailable::Unreachable(
                "ssh could not connect or log in: no route to host".to_string()
            )
        );
        // asked again at once: not tried, and the answer says why and for how long
        let second = pool.get(&web1, failing).await.err().unwrap();
        let Unavailable::Unreachable(why) = &second else {
            panic!("{second:?}");
        };
        assert!(
            why.contains("no route to host") && why.contains("not tried again"),
            "{why}"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(pool.check(&web1).is_err());
        // another host is not affected
        assert!(get(&pool, &hosts, &key(0, "web2", None)).await.is_ok());
        // after the pause it is tried again, and success clears the memory
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(pool.check(&web1).is_ok());
        assert!(get(&pool, &hosts, &web1).await.is_ok());
        assert!(pool.check(&web1).is_ok());
    }

    #[tokio::test]
    async fn a_failure_can_be_recorded_and_cleared_from_outside() {
        let pool = pool(4);
        let web1 = key(2, "web1", None);
        pool.mark_down(&web1, "it refused the credential (HTTP 401)");
        let why = pool.check(&web1).unwrap_err();
        assert!(why.contains("HTTP 401"), "{why}");
        pool.mark_up(&web1);
        assert!(pool.check(&web1).is_ok());
    }

    #[tokio::test]
    async fn with_no_pause_configured_every_call_tries_again() {
        let pool = Pool::new(4, Duration::from_secs(300), Duration::ZERO);
        let web1 = key(0, "web1", None);
        let attempts = AtomicUsize::new(0);
        for _ in 0..3 {
            let outcome = pool
                .get(&web1, || async {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err::<HostLink, String>("down".to_string())
                })
                .await;
            assert_eq!(
                outcome.err(),
                Some(Unavailable::Unreachable("down".to_string()))
            );
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn at_the_limit_an_unused_session_makes_room_for_a_new_one() {
        let (pool, hosts) = (pool(2), Hosts::default());
        let (a, b, c) = (key(0, "a", None), key(0, "b", None), key(0, "c", None));
        // a call takes a session, uses it and lets go of it; remember which it was
        let first = Arc::as_ptr(&get(&pool, &hosts, &a).await.unwrap());
        tokio::time::sleep(Duration::from_millis(30)).await;
        let second = Arc::as_ptr(&get(&pool, &hosts, &b).await.unwrap());
        // both are unused; the one unused for longest goes
        drop(get(&pool, &hosts, &c).await.unwrap());
        assert_eq!(pool.open_sessions(), 2);
        assert_eq!(hosts.opened(), 3);
        // b's session is still the same one, without a new connection
        assert_eq!(Arc::as_ptr(&get(&pool, &hosts, &b).await.unwrap()), second);
        assert_eq!(hosts.opened(), 3);
        // a's was the one closed: asking for a again opens a new one
        let again = get(&pool, &hosts, &a).await.unwrap();
        assert_ne!(Arc::as_ptr(&again), first);
        assert_eq!(hosts.opened(), 4);
        assert_eq!(pool.open_sessions(), 2);
    }

    #[tokio::test]
    async fn a_caller_waits_a_moment_for_room_rather_than_being_turned_away() {
        let pool = Arc::new(pool(1).waiting(Duration::from_secs(10)));
        let hosts = Arc::new(Hosts::default());
        let first = get(&pool, &hosts, &key(0, "a", None)).await.unwrap();
        let busy = occupy(&first);
        until(|| first.in_flight() == 1).await;
        // someone asks for another host while the one session allowed is in use
        let asking = {
            let (pool, hosts) = (pool.clone(), hosts.clone());
            tokio::spawn(async move { get(&pool, &hosts, &key(0, "b", None)).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !asking.is_finished(),
            "it should be waiting for room, not refused"
        );
        assert_eq!(hosts.opened(), 1);
        // the first call ends; its session is unused now and makes room
        busy.abort();
        let _ = busy.await;
        drop(first);
        let got = tokio::time::timeout(Duration::from_secs(5), asking).await;
        assert!(matches!(got, Ok(Ok(Ok(_)))), "it never got its session");
        assert_eq!(hosts.opened(), 2);
        assert_eq!(pool.open_sessions(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn callers_waiting_on_an_attempt_that_fails_share_its_outcome() {
        // with no pause configured at all: they asked while it was being tried, so its
        // outcome is as fresh as anything they could find out themselves
        let pool = Arc::new(Pool::new(4, Duration::from_secs(300), Duration::ZERO));
        let attempts = Arc::new(AtomicUsize::new(0));
        let web1 = key(0, "web1", None);
        let ask = |pool: Arc<Pool>, attempts: Arc<AtomicUsize>, web1: Key| async move {
            pool.get(&web1, || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(200)).await;
                Err::<HostLink, String>("down".to_string())
            })
            .await
        };
        let mut asking = Vec::new();
        for _ in 0..6 {
            asking.push(tokio::spawn(ask(
                pool.clone(),
                attempts.clone(),
                web1.clone(),
            )));
        }
        for task in asking {
            let outcome = task.await.unwrap();
            assert_eq!(
                outcome.err(),
                Some(Unavailable::Unreachable("down".to_string()))
            );
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        // a call made after it failed tries for itself
        let _ = ask(pool.clone(), attempts.clone(), web1).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn at_the_limit_with_every_session_in_use_the_answer_is_busy() {
        let hosts = Hosts::default();
        let pool = pool(2).waiting(Duration::from_millis(300));
        let (a, b, c) = (key(0, "a", None), key(0, "b", None), key(0, "c", None));
        let first = get(&pool, &hosts, &a).await.unwrap();
        let second = get(&pool, &hosts, &b).await.unwrap();
        let (_busy_a, _busy_b) = (occupy(&first), occupy(&second));
        until(|| first.in_flight() == 1 && second.in_flight() == 1).await;
        let began = std::time::Instant::now();
        let refused = get(&pool, &hosts, &c).await.err().unwrap();
        assert!(matches!(refused, Unavailable::Busy(_)), "{refused:?}");
        // it waited for room first
        assert!(
            began.elapsed() >= Duration::from_millis(250),
            "{:?}",
            began.elapsed()
        );
        // being busy is not being down: c is tried again as soon as there is room
        assert!(pool.check(&c).is_ok());
        assert_eq!(hosts.opened(), 2);
        // the sessions in use were left alone
        assert!(!first.is_closed() && !second.is_closed());
    }

    // Time is paused: "idle for long enough" does not depend on how fast the test runs.
    #[tokio::test(start_paused = true)]
    async fn sessions_unused_for_the_idle_time_are_closed_and_busy_ones_kept() {
        let pool = Pool::new(4, Duration::from_millis(100), Duration::from_millis(300));
        let hosts = Hosts::default();
        drop(get(&pool, &hosts, &key(0, "idle", None)).await.unwrap());
        let busy = get(&pool, &hosts, &key(0, "busy", None)).await.unwrap();
        let _waiting = occupy(&busy);
        until(|| busy.in_flight() == 1).await;
        assert_eq!(
            pool.reap().await,
            0,
            "nothing has been idle long enough yet"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(pool.reap().await, 1);
        assert_eq!(pool.open_sessions(), 1);
        // the busy one is still there, and is the one handed out
        assert!(Arc::ptr_eq(
            &get(&pool, &hosts, &key(0, "busy", None)).await.unwrap(),
            &busy
        ));
        assert_eq!(hosts.opened(), 2);
        // the idle one is gone: asking for it opens a new session
        drop(get(&pool, &hosts, &key(0, "idle", None)).await.unwrap());
        assert_eq!(hosts.opened(), 3);
    }

    #[tokio::test]
    async fn closing_everything_leaves_no_session() {
        let (pool, hosts) = (pool(4), Hosts::default());
        let link = get(&pool, &hosts, &key(0, "a", None)).await.unwrap();
        get(&pool, &hosts, &key(0, "b", None)).await.unwrap();
        pool.close_all().await;
        assert_eq!(pool.open_sessions(), 0);
        drop(link);
        // the server is stopping: nothing new is opened behind its back
        let later = get(&pool, &hosts, &key(0, "a", None)).await.err().unwrap();
        assert!(
            matches!(&later, Unavailable::Busy(why) if why.contains("stopping")),
            "{later:?}"
        );
        assert_eq!(hosts.opened(), 2);
    }
}
