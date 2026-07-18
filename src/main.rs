//! # hop-relayd — the cloud relay daemon
//!
//! An always-on Hop node that bridges local meshes over the internet (DESIGN.md
//! §19, §21): the **device → device → relay → relay → device → device** flow. A
//! relay is *just a Hop node with a bearer* — it does epidemic store-and-forward
//! and dedup like any node, and the bundles it carries are sealed end-to-end (§4),
//! so it relays ciphertext it cannot read.
//!
//! Two bearers, same node:
//!
//! * `--listen host:port` — raw TCP (path A, the single GCE VM). Each opaque link
//!   packet is framed with a 4-byte big-endian length prefix.
//! * `--ws host:port` — WebSocket (path B, Cloud Run behind the global LB). Each
//!   link packet is exactly one WS binary frame, so WS supplies the framing. The
//!   load balancer terminates TLS, so the daemon speaks plain `ws://` on `$PORT`.
//!
//! In both cases the link's Noise XX handshake (inside the node) authenticates both
//! ends — the bearer carries opaque bytes and knows nothing about the protocol.
//!
//! Usage:
//!   hop-relayd [--listen 0.0.0.0:9443] [--ws 0.0.0.0:8080] [--peer host:port]...
//!              [--db hop-relay.db] [--identity-file PATH] [--firestore PROJECT]
//!
//! The identity is loaded from `--identity-file` (32 raw bytes, e.g. a mounted
//! Secret Manager secret) when given, else persisted next to the db (`<db>.key`),
//! so the relay's address is stable across restarts.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hop_core::admission::{
    byte_channel, ByteReceiver, ByteReservation, ByteSender, QueueAdmissionError, QueueLimits,
};
use hop_core::prelude::*;
use hop_core::store::{DurabilityHandle, DurabilityReadiness, Store};
#[cfg(feature = "firestore")]
use hop_store_firestore::FirestoreStore;
#[cfg(all(feature = "firestore", test))]
use hop_store_firestore::FIRESTORE_STARTUP_MAX_BYTES;
use hop_store_sqlite::SqliteStore;
use tungstenite::Message;

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

/// Max accepted inbound frame/message size (services-05). The raw-TCP bearer path already caps a
/// frame at this; the WS path must use the SAME bound instead of tungstenite's 64 MiB default, or a
/// single WS client could push a 64 MiB message that the TCP path would have rejected at 1 MiB.
const MAX_FRAME_BYTES: usize = 1 << 20; // 1 MiB
const MAX_EVENT_QUEUE_EVENTS: usize = 512;
const MAX_EVENT_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_SOURCE_EVENTS: usize = 32;
const MAX_EVENT_SOURCE_BYTES: usize = MAX_EVENT_BYTES;
const MAX_EVENT_BATCH: usize = 32;
const DRIVER_TICK_INTERVAL: Duration = Duration::from_secs(1);
const DURABILITY_PROBE_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(feature = "firestore")]
const FIRESTORE_READ_RESERVATION_BYTES: usize = 2 * 1024 * 1024;
#[cfg(feature = "firestore")]
const FIRESTORE_READ_RESERVATION_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(all(feature = "firestore", test))]
const MAX_RELAY_QUEUED_RESERVED_STARTUP_BYTES: usize =
    MAX_EVENT_QUEUE_BYTES + FIRESTORE_STARTUP_MAX_BYTES;
const MAX_OUTBOUND_FRAMES_PER_LINK: usize = 32;
const FRAME_RESERVATION_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_LOG_SUBSCRIBER_LINES: usize = 128;

/// services-r2-02: the single frame-size predicate both the raw-TCP read loop and (via
/// `WebSocketConfig`) the WS path enforce, extracted so the cap is unit-testable. A frame at or
/// under the cap is accepted; anything larger is rejected (the connection is dropped). Keeping this a
/// named helper means a regression that widens the cap fails a test rather than silently passing CI.
fn frame_len_ok(n: usize) -> bool {
    n <= MAX_FRAME_BYTES
}

/// services-04: cap concurrent inbound connections so the one-thread-per-connection accept loops
/// can't be driven to thread/memory exhaustion on a single-instance region (the port endpoint's
/// F-19 control, ported back to relayd). Over the cap we shed the socket rather than spawn.
///
/// services-r3-01: this budget is for MESH connections only (raw-TCP bearers and WS device/relay
/// links). Idle public log-stream viewers get their own, much smaller budget ([`MAX_LOG_CONNS`]) so
/// a flood of unauthenticated plain-HTTP viewers can NEVER camp the slots a mesh peer needs, and
/// `/healthz` is exempt entirely (it answers immediately and closes). Admission therefore happens
/// AFTER the peek-classification, not blindly at accept, so each connection charges the right pool.
const MAX_CONNS: usize = 1_024;
static ACTIVE_CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// services-r3-01: a separate, deliberately small budget for public live-log viewers. These are
/// idle, unauthenticated observers; they must not be able to exhaust the mesh budget. Even fully
/// saturated, log viewers leave all [`MAX_CONNS`] mesh slots free. Combined with the per-viewer
/// total deadline in `serve_log_stream`, a silent holder cannot camp even a log slot indefinitely.
const MAX_LOG_CONNS: usize = 64;
static ACTIVE_LOG_CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A public log viewer holds a slot for at most this long, then the stream is closed. Bounds how
/// long any single (even actively-draining) viewer can occupy one of the [`MAX_LOG_CONNS`] slots, so
/// the small log pool keeps rotating and cannot be permanently pinned. Viewers just reconnect.
const LOG_STREAM_MAX_MS: u64 = 10 * 60 * 1000; // 10 minutes

/// The effective per-viewer deadline in ms. Normally [`LOG_STREAM_MAX_MS`]; a test seam
/// (`HOP_LOG_STREAM_MAX_MS`) lets a test drive a short deadline and observe the stream close.
fn log_stream_max_ms() -> u64 {
    std::env::var("HOP_LOG_STREAM_MAX_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(LOG_STREAM_MAX_MS)
}

/// Decrements a connection counter when a handler thread finishes (incl. panic unwind). The pointer
/// identifies which pool (`ACTIVE_CONNS` or `ACTIVE_LOG_CONNS`) this guard charged.
struct ConnGuard(&'static std::sync::atomic::AtomicUsize);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Admit against a given counter/cap, returning a guard that releases the slot on drop. `None` ⇒
/// over the cap, shed the connection.
fn admit_against(
    counter: &'static std::sync::atomic::AtomicUsize,
    cap: usize,
) -> Option<ConnGuard> {
    if counter.fetch_add(1, Ordering::SeqCst) >= cap {
        counter.fetch_sub(1, Ordering::SeqCst);
        None
    } else {
        Some(ConnGuard(counter))
    }
}

/// Admit a MESH connection (raw-TCP bearer or WS device/relay link) against [`MAX_CONNS`].
/// `None` ⇒ over the mesh cap, shed. (services-04, services-r3-01)
fn admit_conn() -> Option<ConnGuard> {
    admit_against(&ACTIVE_CONNS, MAX_CONNS)
}

/// Admit a public log-stream viewer against the separate [`MAX_LOG_CONNS`] budget so viewers can
/// never consume a mesh slot. `None` ⇒ over the log cap, shed. (services-r3-01)
fn admit_log_conn() -> Option<ConnGuard> {
    admit_against(&ACTIVE_LOG_CONNS, MAX_LOG_CONNS)
}

/// services-r5-01: connections still in the peek-classification phase, before they charge their
/// real pool. The accept-loop spawn is gated on THIS budget, not the mesh budget, so an inbound WS
/// never charges (and so can never be shed at) the mesh cap before we know its kind. That keeps the
/// two live-path regressions of the r3-02 refactor from happening: `/healthz` is no longer gated by
/// a full mesh (it would organically fail the Cloud Run check once MAX_CONNS real links attach), and
/// a slowloris camps only a cheap pending slot instead of a mesh slot. Sized well above [`MAX_CONNS`]
/// so an organic full-mesh reconnect plus health/log probes never sheds here; peek threads are
/// I/O-blocked (cheap) and bounded by the peek read timeout, so pending slots rotate quickly. A flood
/// large enough to fill this budget is an active attacker, not organic load.
const MAX_WS_PENDING: usize = 2_048;
static ACTIVE_WS_PENDING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Admit a connection into the peek-classification phase against [`MAX_WS_PENDING`]. `None` ⇒ too
/// many connections mid-classification, shed without spawning (keeps thread spawn bounded).
fn admit_ws_pending() -> Option<ConnGuard> {
    admit_against(&ACTIVE_WS_PENDING, MAX_WS_PENDING)
}

/// F-7: [`MAX_CONNS`]/[`MAX_WS_PENDING`] above are GLOBAL caps only: they bound how many connections
/// exist, not how much of the single driver thread any one of them can consume. Every live link's
/// `Ev::Data` funnels through the one-thread `apply_event` → `node.handle`, which runs a full Noise
/// unwrap + bundle parse + crypto per frame. Unbounded, one hostile peer streaming max-size
/// ([`MAX_FRAME_BYTES`]) frames back to back can monopolize that one thread, CPU-starving every other
/// peer and stalling the F-17 `LAST_TICK_MS` heartbeat (risking a false `/healthz` 503 restart).
///
/// relayd sits behind a Cloud Run load balancer, so a per-CLIENT-IP limiter (like the endpoint's
/// XFF-keyed `allow_source`/`MAX_REQ_PER_WINDOW`, F-19) is useless here: every connection shares the
/// LB's one front-end IP, so an IP-keyed bucket would either throttle every peer as one global budget
/// or (if it skips the LB IP, as the endpoint does) throttle nobody at all. The identity that actually
/// distinguishes a hostile node from the rest is its Noise static key (its address), but that is only
/// known once the XX handshake completes (`Node::peer_links`). See [`PeerRateKey`].
const PEER_RATE_WINDOW_MS: u64 = 10_000; // same cadence as the endpoint's RATE_WINDOW
/// Generous on purpose: real device traffic is small, bursty chat bundles, nowhere near this. Every
/// frame is already bounded at [`MAX_FRAME_BYTES`] regardless of count, so this count budget also caps
/// a single authenticated peer's worst-case cumulative decode work per window, which is the actual
/// scarce resource (the one driver thread), while leaving ample headroom for organic high-throughput
/// relaying.
const MAX_PEER_MSGS_PER_WINDOW: u32 = 300;
const MAX_PEER_BYTES_PER_WINDOW: usize = 32 * 1024 * 1024;
/// The budget for the single shared pre-handshake bucket (see [`PeerRateKey::PreAuth`]). Larger than a
/// per-peer budget because EVERY connecting peer's handshake frames share it, so a burst of legitimate
/// peers dialing at once (e.g. after a relay restart) must not be starved. A sustained pre-auth flood
/// is still capped at this aggregate rate; the accepted cost is that under such a flood some legit
/// handshakes are delayed (not dropped: the peer's bearer retries), never a memory or driver-thread DoS.
const MAX_PREAUTH_MSGS_PER_WINDOW: u32 = 3_000;
const MAX_PREAUTH_BYTES_PER_WINDOW: usize = 64 * 1024 * 1024;
/// Above this many tracked keys we sweep expired windows so the map can't grow without bound as peers
/// churn (mirrors the endpoint's `RATE_MAP_SWEEP_AT` and this file's dedup-map age-eviction).
const PEER_RATE_SWEEP_AT: usize = 10_000;
/// HARD ceiling on distinct tracked keys (pass-18 F-18a). The staleness sweep above is NOT a bound: an
/// attacker minting fresh authenticated identities (one frame each, then disconnect) fills the map with
/// NON-stale entries the sweep won't touch. Past this ceiling we force-evict the oldest-window entries
/// regardless of staleness, so the map size is bounded no matter the churn rate. Only `Peer` entries can
/// accumulate (all pre-auth traffic shares the one `PreAuth` bucket), and each still costs a full Noise
/// XX handshake to create, but that is not itself a hard bound, so this ceiling is the backstop.
const MAX_PEER_RATE_KEYS: usize = 20_000;

/// Who a driver-thread [`Ev::Data`] budget is charged against (F-7). Before the Noise XX handshake
/// completes we don't yet know the peer's address, and behind the LB we have no usable per-source key
/// for an unauthenticated connection, so ALL pre-handshake frames share ONE global [`PreAuth`] bucket.
/// Keying pre-auth per LINK id (the pre-pass-18 design) was unsound: a link id is per-connection and
/// ever-incrementing, so an attacker who never authenticates got a fresh budget on every reconnect
/// (F-18b), and each dead link left a map entry (F-18a). One shared bucket caps aggregate pre-auth work
/// regardless of connection churn. Once the handshake reveals an address (`Node::peer_links`), the
/// budget follows that ADDRESS: the thing that actually identifies a hostile party, and it survives a
/// drop-and-redial (a reconnecting peer must still complete a fresh handshake before a `Data` frame of
/// theirs is charged to their address again).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum PeerRateKey {
    /// The single shared bucket for every not-yet-authenticated frame.
    PreAuth,
    Peer(PubKeyBytes),
}

/// One fixed window's tally for a single [`PeerRateKey`].
struct PeerRateWindow {
    start_ms: u64,
    msgs: u32,
    bytes: usize,
}

/// Resolve the [`PeerRateKey`] for `link`: the authenticated peer address once the handshake has
/// revealed one, else the shared [`PeerRateKey::PreAuth`] bucket. `O(live links)`, bounded by
/// [`MAX_CONNS`]: relayd only learns a link's address by querying `Node::peer_links`, so this scan is
/// inherent to relayd's position below the core's transport seam. It runs on the (already frame-bounded)
/// driver thread and only for frames that pass the length cap.
/// True ⇔ `key` is still under its window budget (this call is counted against it either way). False ⇒
/// the caller must shed the frame, never hand it to `node.handle`, so a flood costs this map lookup, not
/// a Noise-unwrap + parse + crypto pass. `PreAuth` gets [`MAX_PREAUTH_MSGS_PER_WINDOW`]; an authenticated
/// `Peer` gets the per-identity [`MAX_PEER_MSGS_PER_WINDOW`].
fn peer_data_allowed(
    rates: &mut HashMap<PeerRateKey, PeerRateWindow>,
    key: PeerRateKey,
    now: u64,
    bytes: usize,
) -> bool {
    if rates.len() > PEER_RATE_SWEEP_AT {
        rates.retain(|_, w| now.saturating_sub(w.start_ms) < PEER_RATE_WINDOW_MS);
    }
    // F-18a hard bound: if the staleness sweep did not get us under the ceiling, the map is full of
    // CURRENT-window entries, i.e. an active fresh-identity flood. Force-evict down to half the ceiling,
    // oldest windows first, so the map size is bounded regardless of churn. We remove an EXACT count of
    // keys (not a start_ms cutoff), because under a same-window flood every entry shares one start_ms and
    // a cutoff would evict nothing. Evicting an active entry only resets that key's window (a mild,
    // self-correcting effect under attack), never a safety issue. This O(n log n) pass runs only while
    // flooded past MAX_PEER_RATE_KEYS, never on the organic path.
    if rates.len() >= MAX_PEER_RATE_KEYS {
        let n_remove = rates.len() - MAX_PEER_RATE_KEYS / 2;
        let mut by_age: Vec<(u64, PeerRateKey)> =
            rates.iter().map(|(k, w)| (w.start_ms, *k)).collect();
        by_age.sort_unstable_by_key(|(start, _)| *start);
        for (_, k) in by_age.into_iter().take(n_remove) {
            rates.remove(&k);
        }
    }
    let (message_budget, byte_budget) = match key {
        PeerRateKey::PreAuth => (MAX_PREAUTH_MSGS_PER_WINDOW, MAX_PREAUTH_BYTES_PER_WINDOW),
        PeerRateKey::Peer(_) => (MAX_PEER_MSGS_PER_WINDOW, MAX_PEER_BYTES_PER_WINDOW),
    };
    let w = rates.entry(key).or_insert(PeerRateWindow {
        start_ms: now,
        msgs: 0,
        bytes: 0,
    });
    if now.saturating_sub(w.start_ms) >= PEER_RATE_WINDOW_MS {
        w.start_ms = now;
        w.msgs = 0;
        w.bytes = 0;
    }
    w.msgs += 1;
    w.bytes = w.bytes.saturating_add(bytes);
    w.msgs <= message_budget && w.bytes <= byte_budget
}

/// F-17: wall-clock ms of the driver loop's last iteration. `/healthz` reports unhealthy if this
/// stops advancing, so Cloud Run restarts a wedged instance instead of the default TCP check passing
/// forever (with one instance per region, a wedged instance IS the region). `0` = not started yet.
static LAST_TICK_MS: AtomicU64 = AtomicU64::new(0);
/// A driver that hasn't ticked in this long is considered wedged (the loop times out every ≤1s).
const HEALTHZ_STALE_MS: u64 = 30_000;

/// F-21: set by the SIGTERM handler. The single-owner driver loop checks it each iteration and, on
/// shutdown, drains the durable store before exiting so a spool/handoff write accepted moments before
/// Cloud Run reaps the instance isn't lost.
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// stores-09: a shared handle to the durable store's dropped-op counter (Firestore mirror backlog
/// shedding under a degraded backend). `/healthz` reads it so a relay that is silently losing durable
/// writes reports unhealthy instead of all-green. `None` for the sqlite/in-memory store (nothing is
/// shed there). Set once at startup by `build_store`.
static MIRROR_DROPPED: OnceLock<std::sync::Arc<AtomicU64>> = OnceLock::new();
static MIRROR_FAILED: OnceLock<std::sync::Arc<AtomicU64>> = OnceLock::new();
static DURABILITY: OnceLock<DurabilityHandle> = OnceLock::new();

extern "C" fn on_sigterm(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install the SIGTERM (and SIGINT) handler. Async-signal-safe: it only sets an atomic.
fn install_shutdown_handler() {
    // Coerce to a fn pointer before the numeric cast (fn *item* → integer is a clippy lint).
    let handler = on_sigterm as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// Events the driver loop processes (one owner of the node, no locks). Each live
/// connection hands the driver a `Sender` it pushes outgoing link packets into;
/// the connection's own thread owns the transport and does the writing.
enum Ev {
    Up(u64, Role, SyncSender<Vec<u8>>),
    Data(u64, Vec<u8>),
    Down(u64),
    /// A sealed bundle pulled from durable storage (a cross-partition handoff that
    /// landed in our Firestore partition while warm) to store + relay (DESIGN.md §28).
    /// Only produced by the cloud handoff worker (the `firestore` feature).
    #[cfg_attr(not(feature = "firestore"), allow(dead_code))]
    Ingest(Vec<u8>),
    /// A mailbox pull whose source copy may be deleted only after the node has accepted and durably
    /// flushed it. The driver acknowledges custody through the one-shot channel.
    #[cfg_attr(not(feature = "firestore"), allow(dead_code))]
    IngestCustody(Vec<u8>, mpsc::SyncSender<bool>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum EventSource {
    Link(u64),
    Data(PeerRateKey),
    Durable,
}

#[derive(Default)]
struct IngressAdmission {
    link_keys: HashMap<u64, PeerRateKey>,
    rates: HashMap<PeerRateKey, PeerRateWindow>,
}

#[derive(Clone)]
struct EventTx {
    queue: ByteSender<Ev, EventSource>,
    ingress: Arc<Mutex<IngressAdmission>>,
    durability: DurabilityHandle,
}

struct DataReservation {
    key: PeerRateKey,
    capacity: ByteReservation<Ev, EventSource>,
}

impl EventTx {
    fn send(&self, event: Ev) -> std::result::Result<(), QueueAdmissionError> {
        if !self.durability.is_ready() && !matches!(&event, Ev::Down(_)) {
            if let Ev::IngestCustody(_, ack) = &event {
                let _ = ack.send(false);
            }
            return Err(QueueAdmissionError::NotReady);
        }
        match event {
            Ev::Data(link, bytes) => self.try_send_data(link, bytes),
            event => {
                let (source, bytes, down) = match &event {
                    Ev::Up(link, _, _) => (EventSource::Link(*link), 1, None),
                    Ev::Down(link) => (EventSource::Link(*link), 1, Some(*link)),
                    Ev::Ingest(bytes) => (EventSource::Durable, bytes.len(), None),
                    Ev::IngestCustody(bytes, _) => (EventSource::Durable, bytes.len(), None),
                    Ev::Data(..) => unreachable!(),
                };
                let result = self.queue.send(source, bytes, event);
                if let Some(link) = down {
                    self.ingress
                        .lock()
                        .expect("relay ingress lock")
                        .link_keys
                        .remove(&link);
                }
                result
            }
        }
    }

    fn data_permit(&self, link: u64, bytes: usize) -> Option<PeerRateKey> {
        if !self.durability.is_ready() || bytes > MAX_FRAME_BYTES {
            return None;
        }
        let mut admission = self.ingress.lock().expect("relay ingress lock");
        let key = admission
            .link_keys
            .get(&link)
            .copied()
            .unwrap_or(PeerRateKey::PreAuth);
        peer_data_allowed(&mut admission.rates, key, now_ms(), bytes).then_some(key)
    }

    fn try_send_permitted(
        &self,
        link: u64,
        key: PeerRateKey,
        bytes: Vec<u8>,
    ) -> std::result::Result<(), QueueAdmissionError> {
        if !self.durability.is_ready() {
            return Err(QueueAdmissionError::NotReady);
        }
        let len = bytes.len();
        self.queue
            .try_send(EventSource::Data(key), len, Ev::Data(link, bytes))
    }

    fn try_send_data(
        &self,
        link: u64,
        bytes: Vec<u8>,
    ) -> std::result::Result<(), QueueAdmissionError> {
        if !self.durability.is_ready() {
            return Err(QueueAdmissionError::NotReady);
        }
        let key = self
            .data_permit(link, bytes.len())
            .ok_or(QueueAdmissionError::SourceFull)?;
        self.try_send_permitted(link, key, bytes)
    }

    fn reserve_data(
        &self,
        link: u64,
        bytes: usize,
    ) -> std::result::Result<DataReservation, QueueAdmissionError> {
        if !self.durability.is_ready() {
            return Err(QueueAdmissionError::NotReady);
        }
        if bytes > MAX_FRAME_BYTES {
            return Err(QueueAdmissionError::EventTooLarge);
        }
        let key = self
            .ingress
            .lock()
            .expect("relay ingress lock")
            .link_keys
            .get(&link)
            .copied()
            .unwrap_or(PeerRateKey::PreAuth);
        let capacity =
            self.queue
                .reserve_timeout(EventSource::Data(key), bytes, FRAME_RESERVATION_TIMEOUT)?;
        Ok(DataReservation { key, capacity })
    }

    fn send_reserved_data(
        &self,
        link: u64,
        mut reservation: DataReservation,
        bytes: Vec<u8>,
    ) -> std::result::Result<(), QueueAdmissionError> {
        if !self.durability.is_ready() {
            return Err(QueueAdmissionError::NotReady);
        }
        let len = bytes.len();
        if len > MAX_FRAME_BYTES {
            return Err(QueueAdmissionError::EventTooLarge);
        }
        let mut admission = self.ingress.lock().expect("relay ingress lock");
        if !peer_data_allowed(&mut admission.rates, reservation.key, now_ms(), len) {
            return Err(QueueAdmissionError::SourceFull);
        }
        drop(admission);
        reservation.capacity.shrink_to(len);
        reservation.capacity.try_send(Ev::Data(link, bytes))
    }

    fn bind_peers(&self, peers: &[(PubKeyBytes, u64)]) {
        let mut admission = self.ingress.lock().expect("relay ingress lock");
        let live: std::collections::HashSet<u64> = peers.iter().map(|(_, link)| *link).collect();
        admission.link_keys.retain(|link, _| live.contains(link));
        for (peer, link) in peers {
            admission.link_keys.insert(*link, PeerRateKey::Peer(*peer));
        }
    }

    fn protocol_ready(&self) -> bool {
        self.durability.is_ready()
    }

    #[cfg(feature = "firestore")]
    fn reserve_durable(
        &self,
    ) -> std::result::Result<ByteReservation<Ev, EventSource>, QueueAdmissionError> {
        if !self.durability.is_ready() {
            return Err(QueueAdmissionError::NotReady);
        }
        self.queue.reserve_timeout(
            EventSource::Durable,
            FIRESTORE_READ_RESERVATION_BYTES,
            FIRESTORE_READ_RESERVATION_TIMEOUT,
        )
    }

    #[cfg(feature = "firestore")]
    fn send_reserved_durable(
        &self,
        mut reservation: ByteReservation<Ev, EventSource>,
        event: Ev,
    ) -> std::result::Result<(), QueueAdmissionError> {
        if !self.durability.is_ready() {
            return Err(QueueAdmissionError::NotReady);
        }
        let bytes = match &event {
            Ev::Ingest(bytes) | Ev::IngestCustody(bytes, _) => bytes.len(),
            _ => return Err(QueueAdmissionError::SourceFull),
        };
        if bytes > reservation.bytes() {
            reservation.grow_to(bytes, FIRESTORE_READ_RESERVATION_TIMEOUT)?;
        } else {
            reservation.shrink_to(bytes);
        }
        reservation.send(event)
    }

    #[cfg(test)]
    fn usage(&self) -> (usize, usize) {
        self.queue.usage()
    }
}

struct EventRx(ByteReceiver<Ev, EventSource>);

impl EventRx {
    fn recv_timeout(&self, timeout: Duration) -> std::result::Result<Ev, RecvTimeoutError> {
        self.0.recv_timeout(timeout)
    }

    fn try_recv(&self) -> std::result::Result<Ev, mpsc::TryRecvError> {
        self.0.try_recv()
    }
}

#[cfg(test)]
fn event_channel() -> (EventTx, EventRx) {
    event_channel_with_durability(DurabilityHandle::ready())
}

fn event_channel_with_durability(durability: DurabilityHandle) -> (EventTx, EventRx) {
    let (queue, rx) = byte_channel(QueueLimits {
        max_events: MAX_EVENT_QUEUE_EVENTS,
        max_bytes: MAX_EVENT_QUEUE_BYTES,
        max_event_bytes: MAX_EVENT_BYTES,
        max_source_events: MAX_EVENT_SOURCE_EVENTS,
        max_source_bytes: MAX_EVENT_SOURCE_BYTES,
    });
    (
        EventTx {
            queue,
            ingress: Arc::new(Mutex::new(IngressAdmission::default())),
            durability,
        },
        EventRx(rx),
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// UTC `HH:MM:SS` from epoch ms (for the log stream).
fn hms(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

// ---------------------------------------------------------------------------
// Live network-log hub: a ring buffer + fan-out to HTTP viewers.
//
// services-03: the plain-HTTP log stream is UNAUTHENTICATED (anyone who opens
// https://relay.hopme.sh gets it). For an "untraceable-by-default" network that is a free
// traffic-analysis feed, so it is split two ways:
//
//   * `netlog` (PUBLIC): safe, non-correlatable lines only: this node's identity, connection
//     lifecycle by opaque link number, and AGGREGATE counters (peers=N held=M). These go to the
//     ring + HTTP viewers + stderr.
//   * `netlog_private` (OPERATOR): per-message metadata (bundle ids, destination addresses/regions,
//     mailbox-tag prefixes, per-peer joins/leaves). These go ONLY to stderr / Cloud Logging, never
//     to the ring or the public stream, so the world cannot correlate spool/pull timing to tags.
//
// The public stream is additionally OFF BY DEFAULT and only enabled by `HOP_PUBLIC_LOG_STREAM=1`.
// When off, a visitor still gets a healthy 200 with the identity header and live aggregate counters
// (so Cloud Run's non-WS probes stay happy), but no per-event line feed at all.
// ---------------------------------------------------------------------------

/// Is the public per-event log stream enabled? Off by default (services-03); operators opt in with
/// `HOP_PUBLIC_LOG_STREAM=1` on a relay whose traffic they accept exposing.
fn public_log_stream_enabled() -> bool {
    matches!(
        std::env::var("HOP_PUBLIC_LOG_STREAM").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

// Tests that mutate the process-global HOP_PUBLIC_LOG_STREAM env var live in separate test modules
// but share one process; Rust runs test fns in parallel threads, so they would otherwise race on the
// var (one test's set_var flips the flag mid-assert in another). Serialize them on this shared lock.
#[cfg(test)]
static PUBLIC_LOG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Serializes tests that read/write the process-global driver statics (LAST_TICK_MS, SHUTDOWN) so a
// concurrent test can't observe another's transient value (e.g. driver_step storing a fresh tick
// while a healthz test asserts a stale one). Shared across the healthz / driver-loop / shutdown test
// modules. Recover from poisoning so one failing assertion reports ITS failure, not a cascade.
#[cfg(test)]
static DRIVER_STATICS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn lock_driver_statics() -> std::sync::MutexGuard<'static, ()> {
    DRIVER_STATICS_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

struct LogHub {
    inner: Mutex<LogInner>,
}
struct LogInner {
    who: String, // this relay's identity header (region + address)
    ring: VecDeque<String>,
    subs: Vec<SyncSender<String>>,
}

impl LogHub {
    fn set_identity(&self, who: String) {
        self.inner.lock().unwrap().who = who;
    }

    /// Emit a PUBLIC-safe line: ring + HTTP viewers + stderr. Only non-correlatable lines
    /// (identity, link lifecycle, aggregate counters) may go here, see the module note.
    fn emit(&self, line: String) {
        let stamped = format!("{} {}", hms(now_ms()), line);
        eprintln!("{stamped}");
        let mut g = self.inner.lock().unwrap();
        g.ring.push_back(stamped.clone());
        while g.ring.len() > 400 {
            g.ring.pop_front();
        }
        g.subs.retain(|s| match s.try_send(stamped.clone()) {
            Ok(()) | Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        });
    }

    /// Register a viewer: returns this node's identity, the recent backlog (only when the public
    /// stream is enabled), and a stream of future public lines.
    fn subscribe(&self) -> (String, Vec<String>, Receiver<String>) {
        let (tx, rx) = mpsc::sync_channel(MAX_LOG_SUBSCRIBER_LINES);
        let mut g = self.inner.lock().unwrap();
        g.subs.push(tx);
        let backlog = if public_log_stream_enabled() {
            g.ring.iter().cloned().collect()
        } else {
            Vec::new()
        };
        (g.who.clone(), backlog, rx)
    }
}

static LOG: OnceLock<LogHub> = OnceLock::new();

fn log_hub() -> &'static LogHub {
    LOG.get_or_init(|| LogHub {
        inner: Mutex::new(LogInner {
            who: String::new(),
            ring: VecDeque::new(),
            subs: Vec::new(),
        }),
    })
}

/// Emit a PUBLIC-safe line to the live network log (ring + HTTP viewers + stderr). Use only for
/// non-correlatable lines; per-message metadata MUST use [`netlog_private`] (services-03).
fn netlog(line: impl Into<String>) {
    log_hub().emit(line.into());
}

/// Emit an OPERATOR-only line: stderr / Cloud Logging ONLY, never the public HTTP stream or ring
/// (services-03). Use for anything that could correlate a bundle/peer/mailbox-tag to timing.
fn netlog_private(line: impl Into<String>) {
    eprintln!("{} {}", hms(now_ms()), line.into());
}

// ---------------------------------------------------------------------------------------------
// §35 keyed relay: access policy from flags + the usage ledger the meter flushes into.
// The gate + meter live in hop-core (Node::on_bundle, the custody choke point); relayd's job is
// configuration, the periodic drain into durable kv, and operator observability. Ledger rows are
// per (hour, tenant): key `usage/{hour}/{tenant-hex}` under the node's kv (mirrored to Firestore
// on the fleet), value = two u64 LE (bundles, payload bytes). The §37 reconciler reads these
// rows from a watermark and turns them into Stripe meter events; only ever ADD fields by a new
// key prefix, never re-shape this value in place.

/// Parse exactly `N` bytes of lowercase/uppercase hex (2N chars). None on any malformation.
fn parse_hex_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Lowercase hex of arbitrary bytes (ledger keys, log lines).
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a `--tenant-key` value `<tenant_hex16>:<pubkey_hex32>` into (TenantId, PubKeyBytes).
/// None on any malformation (fails the keyed relay closed at startup).
fn parse_tenant_key(s: &str) -> Option<(TenantId, PubKeyBytes)> {
    let (t, k) = s.split_once(':')?;
    Some((parse_hex_bytes::<16>(t)?, parse_hex_bytes::<32>(k)?))
}

/// Build the node's §35 admission policy from the parsed flags. `Ok(None)` = stay `Open` (the
/// default everywhere). `--require-stamps` with zero usable roots is a configuration error and
/// refuses startup: a keyed fleet must never silently run open because an operator fat-fingered
/// a hex key.
fn access_policy_from(
    require_stamps: bool,
    tenant_keys: &[(TenantId, PubKeyBytes)],
    deny_tenants: &[TenantId],
    stamp_flag_error: bool,
) -> std::result::Result<Option<AccessPolicy>, String> {
    if !require_stamps {
        return Ok(None);
    }
    // Fail closed: a malformed --tenant-key/--deny-tenant would drop an entry (an authorized tenant
    // silently refused, or the emergency denylist silently open). Never boot keyed on a typo.
    if stamp_flag_error {
        return Err("--require-stamps with a malformed --tenant-key/--deny-tenant".to_string());
    }
    if tenant_keys.is_empty() {
        return Err("--require-stamps needs at least one valid --tenant-key".to_string());
    }
    let mut server = KeyServer::new();
    for (tenant, pk) in tenant_keys {
        server.insert(*tenant, *pk);
    }
    let denied = deny_tenants.iter().copied().collect();
    Ok(Some(AccessPolicy::Keyed(KeyedAccess::new(server, denied))))
}

/// How often the driver drains the node's in-memory §35 usage into the durable ledger. A crash
/// loses at most one interval; the ledger's granularity is the hour bucket regardless.
const USAGE_FLUSH_MS: u64 = 30_000;

/// Last ledger flush (driver-thread only; a static so `driver_step`'s signature stays put).
static LAST_USAGE_FLUSH_MS: AtomicU64 = AtomicU64::new(0);

/// One ledger row key: per (hour bucket, tenant).
fn usage_kv_key(hour: u64, tenant: &TenantId) -> String {
    format!("usage/{hour}/{}", hex_string(tenant))
}

/// Ledger row value: `bundles` then `payload_bytes`, both u64 LE (16 bytes total).
fn encode_usage(u: &Usage) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&u.bundles.to_le_bytes());
    out.extend_from_slice(&u.payload_bytes.to_le_bytes());
    out
}

/// Decode a ledger row; anything malformed reads as zero (the row is then overwritten whole,
/// so a corrupt value can never wedge the flush loop).
fn decode_usage(bytes: &[u8]) -> Usage {
    if bytes.len() != 16 {
        return Usage::default();
    }
    Usage {
        bundles: u64::from_le_bytes(bytes[..8].try_into().unwrap_or_default()),
        payload_bytes: u64::from_le_bytes(bytes[8..].try_into().unwrap_or_default()),
    }
}

/// Read-modify-write the drained per-tenant usage into the hour-bucketed ledger rows. Only this
/// node writes its own kv, so the RMW is race-free. Returns the number of rows touched.
fn merge_usage_into_store<S: Store>(
    store: &mut S,
    drained: &[(TenantId, Usage)],
    now_ms: u64,
) -> usize {
    let hour = now_ms / 3_600_000;
    for (tenant, usage) in drained {
        let key = usage_kv_key(hour, tenant);
        let mut total = store
            .get_kv(&key)
            .map(|b| decode_usage(&b))
            .unwrap_or_default();
        total.add(usage);
        store.put_kv(&key, encode_usage(&total));
    }
    drained.len()
}

/// Drain the node's §35 meter + refusal counter into the ledger and the private log, now.
fn flush_usage_now<S: Store>(node: &mut Node<S>, now: u64) {
    let refused = node.take_access_refused();
    if refused > 0 {
        // Aggregate count only, operator-only: a per-refusal line would be a traffic-analysis
        // feed (services-03).
        netlog_private(format!(
            "access: refused {refused} foreign bundle(s) without a valid carriage stamp"
        ));
    }
    let dropped = node.take_usage_dropped();
    if dropped > 0 {
        netlog_private(format!(
            "usage: {dropped} accepted bundle(s) UNMETERED (tenant-map overflow) — shorten the flush interval"
        ));
    }
    let drained = node.take_usage();
    if drained.is_empty() {
        return;
    }
    let rows = merge_usage_into_store(&mut node.store, &drained, now);
    netlog_private(format!(
        "usage: merged {rows} tenant row(s) into the ledger"
    ));
}

/// Rate-limited flush, called once per driver iteration.
fn maybe_flush_usage<S: Store>(node: &mut Node<S>, now: u64) {
    let last = LAST_USAGE_FLUSH_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < USAGE_FLUSH_MS {
        return;
    }
    LAST_USAGE_FLUSH_MS.store(now, Ordering::Relaxed);
    flush_usage_now(node, now);
}

/// Readiness combines the driver heartbeat with durable custody. `/healthz` must not report success
/// while Firestore has rejected or failed an accepted mutation. Cloud Run liveness uses `/livez`
/// separately so a durable-backend outage stops traffic without inducing a restart loop.
fn healthz_status(
    last_tick_ms: u64,
    now: u64,
    readiness: DurabilityReadiness,
    unreconciled: u64,
    dropped: u64,
    failed: u64,
) -> (&'static str, String) {
    let healthy = last_tick_ms != 0 && now.saturating_sub(last_tick_ms) < HEALTHZ_STALE_MS;
    if !healthy {
        ("503 Service Unavailable", "stale".to_string())
    } else if readiness != DurabilityReadiness::Ready {
        (
            "503 Service Unavailable",
            format!(
                "not ready: durability={readiness:?} unreconciled={unreconciled} mirror_rejected={dropped} mirror_failed={failed}"
            ),
        )
    } else {
        ("200 OK", "ok".to_string())
    }
}

fn livez_status(last_tick_ms: u64, now: u64) -> (&'static str, &'static str) {
    if last_tick_ms != 0 && now.saturating_sub(last_tick_ms) < HEALTHZ_STALE_MS {
        ("200 OK", "live")
    } else {
        ("503 Service Unavailable", "stale")
    }
}

fn serve_healthz(mut stream: TcpStream) {
    let last = LAST_TICK_MS.load(Ordering::Relaxed);
    let dropped = MIRROR_DROPPED
        .get()
        .map(|d| d.load(Ordering::Relaxed))
        .unwrap_or(0);
    let failed = MIRROR_FAILED
        .get()
        .map(|d| d.load(Ordering::Relaxed))
        .unwrap_or(0);
    let readiness = DURABILITY
        .get()
        .map(DurabilityHandle::status)
        .unwrap_or(DurabilityReadiness::Ready);
    let unreconciled = DURABILITY
        .get()
        .map(DurabilityHandle::unreconciled)
        .unwrap_or(0);
    let (status, body) = healthz_status(last, now_ms(), readiness, unreconciled, dropped, failed);
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn serve_livez(mut stream: TcpStream) {
    let (status, body) = livez_status(LAST_TICK_MS.load(Ordering::Relaxed), now_ms());
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

/// services-r7-01: a NON-BLOCKING check for a `GET /healthz` request already buffered on a freshly
/// accepted socket. Used by the WS accept loop to fast-path the Cloud Run liveness probe PAST the
/// pending-peek budget, so a slowloris that fills `MAX_WS_PENDING` cannot starve the probe and force a
/// false restart. Non-blocking is the whole point: if no bytes are buffered yet (a silent slowloris),
/// `peek` returns `WouldBlock` and we return false instantly, so this never stalls the accept loop. It
/// leaves the socket back in BLOCKING mode for whatever handler serves the connection next.
fn peek_is_probe(stream: &TcpStream, path: &str) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut buf = [0u8; 24];
    let n = stream.peek(&mut buf).unwrap_or(0);
    let _ = stream.set_nonblocking(false);
    // The request line begins "GET /healthz ...". Only the buffered prefix is needed; a probe sends the
    // whole line in one packet, so it is present by accept time on the same-host Cloud Run probe.
    String::from_utf8_lossy(&buf[..n])
        .to_ascii_lowercase()
        .contains(&format!("get {path}"))
}

fn peek_is_healthz(stream: &TcpStream) -> bool {
    peek_is_probe(stream, "/healthz") || peek_is_probe(stream, "/readyz")
}

fn peek_is_livez(stream: &TcpStream) -> bool {
    peek_is_probe(stream, "/livez")
}

/// Stream the live network log to a plain-HTTP visitor (text/plain, incremental). Leads
/// with this node's identity so a visitor to the anycast name sees which region answered.
fn serve_log_stream(stream: TcpStream) {
    serve_log_stream_for(stream, log_stream_max_ms());
}

fn serve_log_stream_for(mut stream: TcpStream, maximum_ms: u64) {
    // services-r3-01: a public log viewer holds one of the small [`MAX_LOG_CONNS`] slots. Bound how
    // long it can hold it with a total deadline, and use a write timeout so a stalled reader (a slow
    // or wedged TCP peer that never drains) cannot block this thread forever on `write_all`. Together
    // these guarantee the log pool keeps rotating and a silent/slow holder cannot pin a slot.
    let deadline = std::time::Instant::now() + Duration::from_millis(maximum_ms);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    let (who, backlog, rx) = log_hub().subscribe();
    let header = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                  Cache-Control: no-cache\r\nConnection: close\r\n\r\n";
    if stream.write_all(header.as_bytes()).is_err() {
        return;
    }
    let who = if who.is_empty() {
        "(starting)".to_string()
    } else {
        who
    };
    if stream
        .write_all(format!("== hop relay :: {who} ==\n").as_bytes())
        .is_err()
    {
        return;
    }
    // services-03: when the public per-event stream is OFF (the default), do not expose the ring of
    // per-message lines. Serve only a note that live metadata is private; the caller stays a healthy
    // 200 with periodic public aggregate lines (peers=N held=M) still arriving via the subscription.
    if !public_log_stream_enabled() {
        let note =
            "live per-event log is private on this relay; only aggregate counters are shown \
                    (set HOP_PUBLIC_LOG_STREAM=1 to expose per-event lines)\n";
        if stream.write_all(note.as_bytes()).is_err() {
            return;
        }
    } else {
        for line in backlog {
            if stream.write_all(format!("{line}\n").as_bytes()).is_err() {
                return;
            }
        }
    }
    if stream.flush().is_err() {
        return;
    }
    // A viewer connecting is itself only logged privately (it is an observer, not network traffic).
    netlog_private("http: log viewer connected");
    loop {
        // services-r3-01: enforce the total-connection deadline so no viewer can pin a log slot
        // beyond LOG_STREAM_MAX_MS. Wake at least every 15s to emit a keepalive `: ping`.
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let wait = (deadline - now).min(Duration::from_secs(15));
        match rx.recv_timeout(wait) {
            Ok(line) => {
                if stream.write_all(format!("{line}\n").as_bytes()).is_err()
                    || stream.flush().is_err()
                {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if stream.write_all(b": ping\n").is_err() || stream.flush().is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// The relay's parsed command-line configuration. Extracted from `main` so the arg grammar
/// (per-flag defaults, the bare-invocation TCP fallback, and `--mesh-fanout` integer parsing) is
/// unit-testable without spawning the daemon.
struct Config {
    listen: Option<String>,
    ws: Option<String>,
    db: String,
    identity_file: Option<String>,
    peers: Vec<String>,
    firestore: Option<String>,
    region: Option<String>,
    advertise: Option<String>,
    /// 0 = handoff-only (no relay-to-relay dialing); >0 enables online-only epidemic fan-out.
    mesh_fanout: usize,
    /// §35: require a valid carriage stamp before taking custody of any foreign bundle. Off by
    /// default (an open relay); the hosted fleet turns it on with at least one --billing-root.
    require_stamps: bool,
    /// §35 keyserver: authorized (tenant id, stamping public key) pairs. A stamp whose signer is
    /// not one of these never verifies ("an unauthed key cannot ride").
    tenant_keys: Vec<(TenantId, PubKeyBytes)>,
    /// §35 emergency denylist: tenant ids (hex, 16 bytes) refused before cert expiry.
    deny_tenants: Vec<TenantId>,
    /// Set when a `--billing-root`/`--deny-tenant` value failed to parse. A keyed relay MUST
    /// refuse to start on this: silently skipping a malformed root shifts every later root's
    /// kid index (a cert's `kid` is positional into the root list), so the fleet would boot
    /// with the wrong key mapping and refuse all legitimate traffic; a skipped deny-tenant
    /// would fail the emergency denylist open. Fatal only under `--require-stamps`.
    stamp_flag_error: bool,
}

/// Parse the relay's command-line flags. A bare invocation (no `--listen`/`--ws`) defaults to the
/// path-A TCP bearer on 9443; unknown flags are ignored with a warning; `--mesh-fanout` falls back
/// to 0 on a missing/unparseable value.
fn parse_args(args: impl Iterator<Item = String>) -> Config {
    let mut cfg = Config {
        listen: None,
        ws: None,
        db: "hop-relay.db".to_string(),
        identity_file: None,
        peers: Vec::new(),
        firestore: None,
        region: None,
        advertise: None,
        mesh_fanout: 0,
        require_stamps: false,
        tenant_keys: Vec::new(),
        deny_tenants: Vec::new(),
        stamp_flag_error: false,
    };
    let mut args = args;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => cfg.listen = args.next(),
            "--ws" => cfg.ws = args.next(),
            "--db" => {
                if let Some(d) = args.next() {
                    cfg.db = d;
                }
            }
            "--identity-file" => cfg.identity_file = args.next(),
            "--firestore" => cfg.firestore = args.next(), // GCP project id → durable per-node store
            "--region" => cfg.region = args.next(),       // this node's region (registry, §28)
            "--advertise" => cfg.advertise = args.next(), // our connectable wss:// endpoint
            // Online-only relay-to-relay epidemic fan-out (DESIGN.md §28): dial up to N
            // *currently-online* peer relays (never wakes a sleeping one). 0 = off.
            "--mesh-fanout" => {
                cfg.mesh_fanout = args.next().and_then(|s| s.parse().ok()).unwrap_or(0)
            }
            "--peer" => {
                if let Some(p) = args.next() {
                    cfg.peers.push(p);
                }
            }
            // §35 keyed-relay flags. Malformed hex is skipped with a warning; the fatal case
            // (--require-stamps with zero usable roots) is refused at startup by
            // access_policy_from, never silently run open.
            "--require-stamps" => cfg.require_stamps = true,
            // --tenant-key <tenant_hex16>:<pubkey_hex32> adds one authorized tenant to the keyserver.
            "--tenant-key" => match args.next().as_deref().and_then(parse_tenant_key) {
                Some(pair) => cfg.tenant_keys.push(pair),
                None => {
                    eprintln!("bad --tenant-key: expected <32 hex>:<64 hex>");
                    cfg.stamp_flag_error = true; // never silently drop an authorized tenant
                }
            },
            "--deny-tenant" => match args.next().as_deref().and_then(parse_hex_bytes::<16>) {
                Some(t) => cfg.deny_tenants.push(t),
                None => {
                    eprintln!("bad --deny-tenant: expected 32 hex chars");
                    cfg.stamp_flag_error = true; // never fail the emergency denylist open
                }
            },
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }
    // Preserve the path-A default: a bare invocation listens on TCP 9443.
    if cfg.listen.is_none() && cfg.ws.is_none() {
        cfg.listen = Some("0.0.0.0:9443".to_string());
    }
    cfg
}

/// Derive this node's effective identity: a per-region backbone identity when `--region` is set
/// (each region is its own node/partition, §27/§28), else the base identity unchanged. Extracted
/// so the region-derivation branch is unit-testable.
fn regional_identity(base: Identity, base_seed: &[u8; 32], region: Option<&str>) -> Identity {
    if let Some(r) = region {
        // Per-region backbone node: a stable, distinct identity from the shared seed + region name,
        // so each region is its own node (own Firestore partition + liveness-registry entry)
        // without needing a separate secret per region.
        let id = Identity::from_secret_bytes(&region_seed(base_seed, r));
        println!(
            "hop-relayd: region={r} derived address {}",
            bs58_addr(&id.address())
        );
        id
    } else {
        base
    }
}

/// Apply the cloud-relay node parameters (a much larger learned-route table + custody window than a
/// phone, the relay app id/kind, and, when advertising, the identify name from the endpoint host).
/// Extracted so the relay-specific node configuration is unit-testable.
fn configure_node<S: Store>(node: &mut Node<S>, advertise: Option<&str>) {
    // Cloud node: a much larger learned-route table than a phone (DESIGN.md §27) so the backbone
    // becomes the long-memory route learner.
    node.set_route_capacity(200_000);
    // A large custody window: with forward-before-evict this is a sliding window of concurrent
    // in-flight bundles (incl. chunked media), not a cap on transfer size (DESIGN.md §6).
    node.set_max_relayed(8192);
    // Stamp the Hop-relay app id so a relay hop shows as "Hop Relay" in traces.
    node.set_app(hop_core::relay_app_id());
    // §35 custody beacon: a relay advertises what it holds on connect so peers stop re-offering
    // those, cutting the duplicate-ingress COGS that dominates a high-degree relay's cost.
    node.set_emit_have(true);
    // Answer hop.identify as a relay, named by its public domain (the host of --advertise, e.g.
    // us-central1.relay.hopme.sh) so trace resolution shows relays by domain (§29).
    node.set_kind(NodeKind::Relay);
    if let Some(adv) = advertise {
        node.set_name(Some(host_of(adv)));
    }
    // The cloud relay is internet-connected, so it serves as an HNS resolver for peers that ask it
    // (DESIGN.md §30). Resolution still works without it, but an always-on relay is convenient.
    #[cfg(feature = "firestore")]
    node.set_internet(true);
}

/// Emit the startup banners (stdout) and seed the live-log identity + "relay up" line, so a visitor
/// to the anycast name sees which region answered. Extracted so the identity/region strings the log
/// stream leads with are unit-testable.
fn announce_startup(
    listen: Option<&str>,
    ws: Option<&str>,
    peer_count: usize,
    addr: &[u8],
    region: Option<&str>,
) {
    println!(
        "hop-relayd: address {} {}{}{} backbone peer(s)",
        bs58_addr(addr),
        listen.map(|l| format!("tcp {l} ")).unwrap_or_default(),
        ws.map(|w| format!("ws {w} ")).unwrap_or_default(),
        peer_count,
    );
    // Identify this node in the live HTTP log stream (so a visitor to the anycast name sees which
    // region answered).
    log_hub().set_identity(format!(
        "region={} node={}",
        region.unwrap_or("local"),
        bs58_addr(addr)
    ));
    netlog(format!(
        "relay up: region={} node={}",
        region.unwrap_or("local"),
        bs58_addr(addr)
    ));
}

/// Apply one driver event to the node + the per-link writer table. Extracted from the driver loop so
/// the event-handling logic (link up/down bookkeeping, data hand-off, ingest of a durable-store
/// bundle) is unit-testable with a real `Node`; the loop itself only wraps this with the recv
/// timeout tick and the shutdown drain.
/// services-r7-01: run one core call under catch_unwind so a panic on attacker-controlled input (bundle
/// decode / Noise / verify) becomes a logged skip instead of tearing down the
/// always-on driver loop. relayd is the MOST internet-exposed process (it accepts connections from any
/// mesh node worldwide with no prior trust), yet it was the ONE service missing this guard: the endpoint
/// wraps every core call in guard_core (20 sites) and the gateway added it (services-r6-01), but relayd
/// ran node.handle / ingest / tick UNGUARDED on the main thread. A single core panic
/// on unauthenticated bytes unwound the main thread and exited the process; Cloud Run restarted and the
/// attacker resent the same packet: an unauthenticated remote crash-loop DoS. We do NOT log the bytes.
///
/// F-18d (pass-18 audit): this catches a panic around the WHOLE call (`node.handle`/`ingest`/
/// `tick`/...), not around the individual `self.*` mutations inside one `on_bundle` match arm.
/// That is coarse but deliberately so: `Node`'s fields are plain safe-Rust `HashMap`/`Vec` (no
/// `unsafe` invariants), so a mid-arm panic is memory-safe regardless of where it lands. A
/// dedicated audit of `on_bundle` (`core/hop-core/src/node.rs`) found no reachable panic between
/// an arm's paired mutations (pending/tx/forwarded/store/subscriptions/...) from attacker-
/// controlled input; every attacker-shaped field
/// is decoded via `Option`/`Result`, never an indexing/unwrap panic. Arms are also structured
/// compute-then-commit or fail-safe-ordered (e.g. `Payload::HpsRekey` installs the new
/// subscription before removing the old one, so a hypothetical future panic between them leaves a
/// harmless stale duplicate, never a lost subscription) specifically so THIS coarse-grained catch
/// stays sufficient. See `node::tests::hps_rekey_install_before_remove_survives_a_mid_arm_panic`
/// and `node::tests::traced_ack_purge_arm_is_never_left_half_applied_under_a_mid_arm_panic` for
/// the enforcing regression tests.
fn guard_core<T>(what: &str, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!("hop-relayd: core panic in {what}; skipped (relay stays up)");
            None
        }
    }
}

fn apply_event<S: Store>(
    node: &mut Node<S>,
    writers: &mut HashMap<u64, SyncSender<Vec<u8>>>,
    ev: Ev,
) {
    match ev {
        Ev::Up(link, role, out) => {
            writers.insert(link, out);
            netlog(format!("conn up: link={link} ({role:?})"));
            guard_core("bearer-connected", || {
                node.handle(BearerEvent::Connected(link, role))
            });
        }
        Ev::Data(link, bytes) => {
            // Producer-side admission has already charged this frame to its authenticated identity
            // (or the shared pre-auth bucket) before it entered the bounded queue.
            guard_core("bearer-data", || {
                node.handle(BearerEvent::Data(link, bytes))
            });
        }
        Ev::Down(link) => {
            writers.remove(&link);
            // No per-link rate entry to drop: pre-auth traffic shares the one `PreAuth` bucket (F-18b),
            // and a `PeerRateKey::Peer` entry for whoever this link belonged to is deliberately left in
            // place so a same-window reconnect cannot reset that identity's budget. The map is bounded by
            // the staleness sweep + the MAX_PEER_RATE_KEYS hard ceiling in `peer_data_allowed`.
            netlog(format!("conn down: link={link}"));
            guard_core("bearer-disconnected", || {
                node.handle(BearerEvent::Disconnected(link))
            });
        }
        Ev::Ingest(bytes) => {
            ingest_durable(node, bytes, false);
        }
        Ev::IngestCustody(bytes, ack) => {
            let _ = ack.send(ingest_durable(node, bytes, true));
        }
    }
}

fn ingest_durable<S: Store>(node: &mut Node<S>, bytes: Vec<u8>, require_flush: bool) -> bool {
    if node.store.durability_status() != DurabilityReadiness::Ready {
        return false;
    }
    if let Ok(b) = Bundle::from_bytes(&bytes) {
        let dst = match b.inner.dst {
            Destination::Device(d) | Destination::AckTo(d, _) => short_b58(&d),
            Destination::Broadcast => "broadcast".to_string(),
            Destination::Vaccine(..) => "vaccine".to_string(),
        };
        // services-03: bundle id + destination address is per-message metadata.
        netlog_private(format!("ingest: msg {} → dst {}", short_b58(&b.id()), dst));
        if guard_core("ingest", || node.ingest(b)).is_none() {
            return false;
        }
        return node.store.durability_status() == DurabilityReadiness::Ready
            && (!require_flush || node.store.flush(Duration::from_secs(5)));
    }
    false
}

/// Drain the node's outgoing link packets to each link's writer thread, dropping a writer whose
/// thread has gone. Extracted from the driver loop for unit testing.
fn pump_outgoing<S: Store>(node: &mut Node<S>, writers: &mut HashMap<u64, SyncSender<Vec<u8>>>) {
    // Guarded like the other core calls: a panic while serializing outbound packets must not kill the
    // driver either. On a caught panic there is simply nothing to pump this tick.
    let outgoing = guard_core("drain-outgoing", || node.drain_outgoing()).unwrap_or_default();
    let mut blocked = Vec::new();
    for (link, bytes) in outgoing {
        if let Some(out) = writers.get(&link) {
            if matches!(
                out.try_send(bytes),
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_))
            ) {
                blocked.push(link);
            }
        }
    }
    for link in blocked {
        writers.remove(&link);
        guard_core("bearer-disconnected", || {
            node.handle(BearerEvent::Disconnected(link))
        });
    }
}

/// Log authenticated peer joins/leaves (by address) privately and return the new peer set.
/// services-03: a per-peer address join/leave is correlatable traffic metadata, so it goes only to
/// Cloud Logging; the public stream sees just the aggregate peers=N counter (via [`maybe_emit_stats`]).
fn log_peer_changes<S: Store>(
    node: &Node<S>,
    prev: &std::collections::HashSet<Vec<u8>>,
) -> std::collections::HashSet<Vec<u8>> {
    let cur: std::collections::HashSet<Vec<u8>> = node.peers().iter().map(|a| a.to_vec()).collect();
    for p in cur.difference(prev) {
        netlog_private(format!("peer connected: {}", short_b58(p)));
    }
    for p in prev.difference(&cur) {
        netlog_private(format!("peer left: {}", short_b58(p)));
    }
    cur
}

/// Emit the periodic public AGGREGATE stats line (peers=N held=M) at most every 10s. Returns the
/// updated `last_stats_ms` (unchanged when it isn't time yet). Extracted from the driver loop for
/// unit testing.
fn maybe_emit_stats<S: Store>(node: &Node<S>, last_stats_ms: u64, now: u64) -> u64 {
    if now.saturating_sub(last_stats_ms) >= 10_000 {
        netlog(format!(
            "stats: peers={} held={}",
            node.peers().len(),
            node.queue().len()
        ));
        now
    } else {
        last_stats_ms
    }
}

/// One iteration of the driver loop: advance the F-17 healthz heartbeat, on SIGTERM drain the durable
/// store and signal exit (F-21), then process one event (or, on the recv timeout, tick), pump
/// outgoing packets, and log peer/stat changes. Returns `false` when the loop should exit (SIGTERM
/// drain done, or the event channel closed). Extracted from `main` so the per-iteration control flow
/// is unit-testable; the firestore-only worker dispatch (handoff snapshots) stays in
/// `main` and runs after each step.
struct DriverSchedule {
    last_stats_ms: u64,
    next_tick: Instant,
    next_durability_probe: Instant,
}

fn driver_step<S: Store>(
    node: &mut Node<S>,
    writers: &mut HashMap<u64, SyncSender<Vec<u8>>>,
    tx: &EventTx,
    rx: &EventRx,
    prev_peers: &mut std::collections::HashSet<Vec<u8>>,
    schedule: &mut DriverSchedule,
) -> bool {
    // F-17: heartbeat for /healthz. The loop iterates at least once per second (recv timeout → tick);
    // if node.handle/tick ever deadlocks, this stops advancing and /healthz goes 503.
    LAST_TICK_MS.store(now_ms(), Ordering::Relaxed);
    // F-21: on SIGTERM, drain the durable store's pending mirror queue before exiting, so a
    // spool/handoff write accepted just before Cloud Run reaps us survives. Cloud Run grants a grace
    // window on shutdown; bound the flush well inside it.
    if SHUTDOWN.load(Ordering::SeqCst) {
        // Drain the §35 meter into the ledger BEFORE the store flush, so the counted usage
        // rides the same mirror drain out (billing survives the reap; F-21).
        flush_usage_now(node, now_ms());
        let flushed = node.store.flush(Duration::from_secs(8));
        netlog(format!(
            "SIGTERM: durable-store flush {} — exiting",
            if flushed { "drained" } else { "timed out" }
        ));
        return false;
    }
    if node.store.durability_status() != DurabilityReadiness::Ready {
        if Instant::now() >= schedule.next_durability_probe {
            let _ = node.store.probe_durability();
            schedule.next_durability_probe = Instant::now() + DURABILITY_PROBE_INTERVAL;
        }
        if node.store.durability_status() != DurabilityReadiness::Ready {
            suspend_protocol(node, writers);
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => reject_degraded_event(event),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return false,
            }
            while schedule.next_tick <= Instant::now() {
                schedule.next_tick += DRIVER_TICK_INTERVAL;
            }
            return true;
        }
    }
    tick_if_due(node, &mut schedule.next_tick);
    let wait = schedule.next_tick.saturating_duration_since(Instant::now());
    let first = match rx.recv_timeout(wait) {
        Ok(event) => Some(event),
        Err(RecvTimeoutError::Timeout) => {
            tick_if_due(node, &mut schedule.next_tick);
            None
        }
        Err(RecvTimeoutError::Disconnected) => return false,
    };
    if let Some(first) = first {
        apply_event(node, writers, first);
        tx.bind_peers(&node.peer_links());
        for _ in 1..MAX_EVENT_BATCH {
            if node.store.durability_status() != DurabilityReadiness::Ready {
                break;
            }
            if Instant::now() >= schedule.next_tick {
                break;
            }
            match rx.try_recv() {
                Ok(event) => {
                    apply_event(node, writers, event);
                    tx.bind_peers(&node.peer_links());
                    if node.store.durability_status() != DurabilityReadiness::Ready {
                        break;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return false,
            }
        }
    }
    if node.store.durability_status() != DurabilityReadiness::Ready {
        suspend_protocol(node, writers);
        return true;
    }
    tick_if_due(node, &mut schedule.next_tick);
    pump_outgoing(node, writers);
    // Log authenticated peer joins/leaves privately; emit periodic public AGGREGATE stats.
    *prev_peers = log_peer_changes(node, prev_peers);
    schedule.last_stats_ms = maybe_emit_stats(node, schedule.last_stats_ms, now_ms());
    // §35: periodically drain the meter into the durable usage ledger.
    maybe_flush_usage(node, now_ms());
    true
}

fn reject_degraded_event(event: Ev) {
    if let Ev::IngestCustody(_, ack) = event {
        let _ = ack.send(false);
    }
}

fn suspend_protocol<S: Store>(node: &mut Node<S>, writers: &mut HashMap<u64, SyncSender<Vec<u8>>>) {
    let links: Vec<u64> = writers.keys().copied().collect();
    writers.clear();
    for link in links {
        guard_core("durability-disconnect", || {
            node.handle(BearerEvent::Disconnected(link))
        });
    }
}

fn tick_if_due<S: Store>(node: &mut Node<S>, next_tick: &mut Instant) {
    let monotonic_now = Instant::now();
    if monotonic_now < *next_tick {
        return;
    }
    guard_core("tick", || node.tick(now_ms()));
    while *next_tick <= monotonic_now {
        *next_tick += DRIVER_TICK_INTERVAL;
    }
}

/// One iteration of the raw-TCP accept loop: admit against the mesh cap (services-04), shedding the
/// socket when over it, else spawn a per-connection `serve_tcp` handler that holds the slot guard for
/// its lifetime. Extracted so the admit-or-shed decision is unit-testable over a loopback socket.
fn spawn_tcp_conn(stream: TcpStream, ev_tx: &EventTx) {
    if !ev_tx.protocol_ready() {
        drop(stream);
        return;
    }
    let Some(guard) = admit_conn() else {
        drop(stream); // services-04: shed over the connection cap rather than spawn unboundedly
        return;
    };
    let ev_tx = ev_tx.clone();
    std::thread::spawn(move || {
        let _guard = guard; // releases the slot on drop (incl. panic unwind)
        serve_tcp(stream, Role::Responder, &ev_tx)
    });
}

/// One iteration of the WebSocket accept loop. services-r7-01: a non-blocking `GET /healthz`
/// fast-path serves the Cloud Run liveness probe EXEMPT from every budget (a slowloris filling
/// MAX_WS_PENDING can no longer starve it, and an empty buffer returns instantly so a silent slowloris
/// never stalls this loop). services-r3-02 / r5-01: every other connection is admitted only against
/// the cheap PENDING-peek budget and handed to `admit_and_serve_ws` on a worker thread, so the
/// timeout-bounded peek/classify never stalls this accept path and the mesh cap is charged only after
/// the kind is known. Extracted so the fast-path/admit decision is unit-testable.
fn dispatch_ws_accept(stream: TcpStream, ev_tx: &EventTx) {
    if peek_is_livez(&stream) {
        std::thread::spawn(move || serve_livez(stream));
        return;
    }
    if peek_is_healthz(&stream) {
        std::thread::spawn(move || serve_healthz(stream));
        return;
    }
    let Some(pending) = admit_ws_pending() else {
        drop(stream); // too many connections mid-classification: shed (bounded spawn)
        return;
    };
    let ev_tx = ev_tx.clone();
    std::thread::spawn(move || admit_and_serve_ws(stream, pending, &ev_tx));
}

fn main() {
    install_shutdown_handler(); // F-21: drain the durable store on SIGTERM before the instance is reaped
    let Config {
        listen,
        ws,
        db,
        identity_file,
        peers,
        firestore,
        region,
        advertise,
        mesh_fanout,
        require_stamps,
        tenant_keys,
        deny_tenants,
        stamp_flag_error,
    } = parse_args(std::env::args().skip(1));

    let base_identity = load_identity(&identity_file, &format!("{db}.key"));
    // The shared base seed — every region derives its node identity from this same seed, so any
    // node can compute any other region's address (cross-partition handoff, §28).
    let base_seed = base_identity.to_secret_bytes();
    let identity = regional_identity(base_identity, &base_seed, region.as_deref());
    let addr = identity.address();
    let store = build_store(&firestore, &db, &addr)
        .unwrap_or_else(|error| panic!("durable store failed readiness: {error}"));
    let durability = store.durability_handle().unwrap_or_default();
    let _ = DURABILITY.set(durability.clone());
    let mut node = Node::with_store(identity, store);
    configure_node(&mut node, advertise.as_deref());
    // Seed the node clock to wall time BEFORE serving. A relay's now_ms is 0 until the driver's
    // first idle tick; without this seed, a stamped bundle arriving in that window is expiry-
    // checked at now_ms=0, where every cert reads unexpired (0 >= exp is false), so an
    // already-expired tenant cert would be admitted + metered. Seeding closes that startup gap.
    node.set_time(now_ms());
    // §35 keyed-relay admission, config-gated (default: open, exactly the pre-stamp behavior).
    match access_policy_from(
        require_stamps,
        &tenant_keys,
        &deny_tenants,
        stamp_flag_error,
    ) {
        Err(e) => {
            eprintln!("hop-relayd: {e}");
            std::process::exit(2);
        }
        Ok(Some(policy)) => {
            println!(
                "hop-relayd: keyed relay: {} tenant key(s), {} denied tenant(s)",
                tenant_keys.len(),
                deny_tenants.len()
            );
            node.set_access_policy(policy);
            // Populate the epoch hint tables against the clock we just seeded, so the first bundle
            // (which may arrive before the first idle tick) is admitted, not refused.
            node.refresh_access();
        }
        Ok(None) => {}
    }
    announce_startup(
        listen.as_deref(),
        ws.as_deref(),
        peers.len(),
        &addr,
        region.as_deref(),
    );

    let (tx, rx) = event_channel_with_durability(durability.clone());

    // Accept inbound TCP device/relay connections (one thread per connection).
    if let Some(addr) = listen {
        let tx = tx.clone();
        let listener = TcpListener::bind(&addr).expect("bind --listen address");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                spawn_tcp_conn(stream, &tx);
            }
        });
    }

    // Accept inbound WebSocket connections (Cloud Run / LB front door).
    if let Some(addr) = ws {
        let tx = tx.clone();
        let listener = TcpListener::bind(&addr).expect("bind --ws address");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                dispatch_ws_accept(stream, &tx);
            }
        });
    }

    // The set of relay node ids (base58) we've seen in the liveness registry — used to
    // tell a device peer from a peer relay when recording device presence (§28).
    #[cfg(feature = "firestore")]
    let known_relays: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));

    // Backbone (DESIGN.md §28): heartbeat into the passive liveness registry and dial
    // currently-online peer relays (pull-on-wake). Cloud-only (needs Firestore + a TLS
    // WebSocket client); a node is summoned by clients, never by a peer.
    #[cfg(feature = "firestore")]
    if let (Some(project), Some(region), Some(advertise)) =
        (firestore.clone(), region.clone(), advertise.clone())
    {
        backbone::spawn(
            project,
            region,
            advertise,
            addr.to_vec(),
            known_relays.clone(),
            mesh_fanout,
            tx.clone(),
        );
    }
    #[cfg(not(feature = "firestore"))]
    let _ = (&region, &advertise, &mesh_fanout);

    // Cross-partition handoff (DESIGN.md §28): record device presence, hand undeliverable
    // device bundles into the destination region's mailbox, and reload our own partition
    // so a warm node ingests handoffs others wrote. Cloud-only.
    #[cfg(feature = "firestore")]
    let handoff_tx = match (firestore.clone(), region.clone()) {
        (Some(project), Some(region)) => Some(handoff::spawn(
            project,
            region,
            base_seed,
            addr.to_vec(),
            known_relays.clone(),
            tx.clone(),
            durability.clone(),
        )),
        _ => None,
    };

    // Dial backbone peer relays over TCP, reconnecting forever.
    for peer in peers {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            match TcpStream::connect(&peer) {
                Ok(stream) => {
                    eprintln!("backbone: connected to {peer}");
                    serve_tcp(stream, Role::Initiator, &tx);
                }
                Err(e) => eprintln!("backbone: {peer} unreachable ({e}); retrying"),
            }
            std::thread::sleep(Duration::from_secs(5));
        });
    }

    // Driver: the sole owner of the node + the per-link outgoing senders.
    let mut writers: HashMap<u64, SyncSender<Vec<u8>>> = HashMap::new();
    let mut prev_peers: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut driver_schedule = DriverSchedule {
        last_stats_ms: 0,
        next_tick: Instant::now() + DRIVER_TICK_INTERVAL,
        next_durability_probe: Instant::now() + DURABILITY_PROBE_INTERVAL,
    };
    #[cfg(feature = "firestore")]
    let mut last_handoff_ms: u64 = 0;
    #[cfg(feature = "firestore")]
    let mut pending_wanted = Vec::new();
    loop {
        if !driver_step(
            &mut node,
            &mut writers,
            &tx,
            &rx,
            &mut prev_peers,
            &mut driver_schedule,
        ) {
            break;
        }
        // Feed the handoff worker a fresh snapshot of who's connected and what we can't
        // deliver locally, on a slow timer (the worker does the blocking Firestore I/O
        // off this thread, §28).
        #[cfg(feature = "firestore")]
        if durability.is_ready() {
            if let Some(htx) = &handoff_tx {
                let now = now_ms();
                if now.saturating_sub(last_handoff_ms) >= HANDOFF_INTERVAL_MS {
                    last_handoff_ms = now;
                    if pending_wanted.is_empty() {
                        pending_wanted = node.take_wanted_mailboxes();
                    }
                    let snapshot = handoff::Snapshot {
                        now_ms: now,
                        devices: node.peers(),
                        undeliverable: node.undeliverable_device_bundles(),
                        spool: node.spoolable_private_bundles(),
                        wanted: pending_wanted.clone(),
                    };
                    match htx.try_send(snapshot) {
                        Ok(()) | Err(TrySendError::Disconnected(_)) => pending_wanted.clear(),
                        Err(TrySendError::Full(_)) => {}
                    }
                }
            }
        }
    }
}

/// Derive a region's backbone identity seed from the shared base seed + region name.
/// Every node computes this the same way, so a node can address any region's partition
/// (and the dest node it belongs to) without a per-region secret (DESIGN.md §27/§28).
fn region_seed(base: &[u8; 32], region: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"hop.relay.region.v1");
    h.update(base);
    h.update(region.as_bytes());
    *h.finalize().as_bytes()
}

/// The node address (base58) of `region`'s backbone relay, derived from the shared seed.
#[cfg(feature = "firestore")]
fn region_node_b58(base: &[u8; 32], region: &str) -> String {
    let addr = Identity::from_secret_bytes(&region_seed(base, region)).address();
    bs58::encode(addr).into_string()
}

/// How often the driver hands the worker a fresh handoff snapshot.
#[cfg(feature = "firestore")]
const HANDOFF_INTERVAL_MS: u64 = 20_000;

/// Drive one raw-TCP connection: a writer thread owns the write half and drains the
/// outgoing channel; this thread reads length-framed packets off the read half.
fn serve_tcp(stream: TcpStream, role: Role, ev_tx: &EventTx) {
    let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
    let _ = stream.set_nodelay(true);
    let mut write_half = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let (out_tx, out_rx) = mpsc::sync_channel::<Vec<u8>>(MAX_OUTBOUND_FRAMES_PER_LINK);
    if ev_tx.send(Ev::Up(link, role, out_tx)).is_err() {
        return;
    }
    std::thread::spawn(move || {
        while let Ok(bytes) = out_rx.recv() {
            let len = (bytes.len() as u32).to_be_bytes();
            if write_half
                .write_all(&len)
                .and_then(|_| write_half.write_all(&bytes))
                .and_then(|_| write_half.flush())
                .is_err()
            {
                break;
            }
        }
    });

    let mut read = stream;
    loop {
        let mut len = [0u8; 4];
        if read.read_exact(&mut len).is_err() {
            break;
        }
        let n = u32::from_be_bytes(len) as usize;
        if !frame_len_ok(n) {
            break; // frame too large; drop the connection
        }
        let reservation = match ev_tx.reserve_data(link, n) {
            Ok(reservation) => reservation,
            Err(_) => break,
        };
        let mut buf = vec![0u8; n];
        if read.read_exact(&mut buf).is_err() {
            break;
        }
        if ev_tx.send_reserved_data(link, reservation, buf).is_err() {
            break;
        }
    }
    let _ = ev_tx.send(Ev::Down(link));
}

/// Drive one WebSocket connection: one thread both reads binary frames and, on a
/// short read timeout, drains the outgoing channel. The LB terminates TLS, so this
/// is plain `ws://`; each link packet is one binary frame (no extra framing).
/// The three request shapes the WS front door serves, decided by a non-consuming peek so each can
/// charge the correct connection budget (services-r3-01). `Empty` = no data / a probe with no
/// payload (nothing to serve).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WsKind {
    Healthz,
    Livez,
    LogStream,
    Upgrade,
    Empty,
}

/// Classify an inbound $PORT request without consuming any bytes, so the accept loop can pick the
/// right budget BEFORE spawning a handler. Cloud Run sends plain HTTP (connectivity checks, health
/// probes, any non-WS GET); a real WebSocket upgrade is a mesh link. A non-consuming `peek` leaves
/// the bytes in the socket buffer for `serve_healthz` / `serve_log_stream` / tungstenite to re-read.
fn classify_ws_peek(stream: &TcpStream) -> WsKind {
    let _ = stream.set_nodelay(true);
    // A short read timeout bounds how long a stalled/slowloris client can hold the accept thread on
    // the peek; on timeout the peek returns an error and we treat it as Empty (shed, no slot).
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut head = [0u8; 1024];
    let kind = match stream.peek(&mut head) {
        Ok(n) if n > 0 => {
            let req = String::from_utf8_lossy(&head[..n]).to_ascii_lowercase();
            // F-17: a real health probe, tied to the driver loop's heartbeat — distinct from the log
            // stream, which stays up even if the driver deadlocks and so is NOT a health signal.
            if req.contains("get /livez") {
                WsKind::Livez
            } else if req.contains("get /healthz") || req.contains("get /readyz") {
                WsKind::Healthz
            } else if req.contains("upgrade: websocket") {
                WsKind::Upgrade
            } else {
                WsKind::LogStream
            }
        }
        _ => WsKind::Empty, // no data / probe with no payload — nothing to serve
    };
    // Restore the blocking socket the handlers expect (tungstenite reads without a read timeout).
    if kind == WsKind::Upgrade {
        let _ = stream.set_read_timeout(None);
    }
    kind
}

/// services-r3-02 / r5-01: runs on the spawned worker thread (NOT the accept loop). Peek-classifies
/// the connection (the slow, timeout-bounded step, off the accept path so a slowloris can't stall
/// new accepts), then charges the REAL pool once the kind is known and serves. The caller charged a
/// pending-peek slot (`pending`); we release it as soon as classification finishes and admit against
/// the actual budget, so the mesh cap is only ever charged by a real mesh link (not by healthz, a log
/// viewer, or an unclassified slowloris):
///   * `Healthz`  : exempt from every budget. Serve immediately (never shed at any cap).
///   * `LogStream`: charges the SMALL log budget only; if the log pool is full, shed.
///   * `Upgrade`  : a real mesh link. Charge the mesh budget now; if the mesh cap is full, shed.
///   * `Empty`    : nothing to serve. Drop.
fn admit_and_serve_ws(stream: TcpStream, pending: ConnGuard, ev_tx: &EventTx) {
    let kind = classify_ws_peek(&stream);
    // Classification done: release the transient pending-peek slot and charge the durable pool.
    drop(pending);
    match kind {
        WsKind::Livez => {
            serve_livez(stream);
        }
        WsKind::Healthz => {
            serve_healthz(stream); // liveness probe: exempt from every budget
        }
        WsKind::LogStream => {
            let Some(_log_guard) = admit_log_conn() else {
                drop(stream); // log pool full: shed on the log budget
                return;
            };
            serve_ws(stream, kind, ev_tx);
        }
        WsKind::Upgrade => {
            if !ev_tx.protocol_ready() {
                drop(stream);
                return;
            }
            let Some(_guard) = admit_conn() else {
                drop(stream); // mesh cap full: a real mesh link sheds on the mesh budget
                return;
            };
            serve_ws(stream, kind, ev_tx);
        }
        WsKind::Empty => {
            drop(stream); // no data / probe with no payload: nothing to serve
        }
    }
}

fn ws_bearer_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
}

fn serve_ws(stream: TcpStream, kind: WsKind, ev_tx: &EventTx) {
    // The accept loop already peek-classified this connection and charged the right budget
    // (services-r3-01). Dispatch non-mesh shapes to their handlers; only a real upgrade continues
    // into the WS driver below. If we just closed non-WS GETs, Cloud Run would see a malformed/empty
    // response and recycle the instance in a loop, so a plain GET gets the live log stream instead.
    match kind {
        WsKind::Livez => {
            serve_livez(stream);
            return;
        }
        WsKind::Healthz => {
            serve_healthz(stream);
            return;
        }
        WsKind::LogStream => {
            serve_log_stream(stream);
            return;
        }
        WsKind::Empty => return,
        WsKind::Upgrade => {}
    }
    // services-05: cap the WS message/frame size to match the raw-TCP bearer path, instead of
    // tungstenite's 64 MiB default, so neither transport accepts an oversized message.
    let mut ws = match tungstenite::accept_with_config(stream, Some(ws_bearer_config())) {
        Ok(w) => w,
        Err(_) => return, // malformed upgrade
    };
    // A read timeout lets the single owner thread interleave writes with reads.
    let _ = ws
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(100)));

    let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
    let (out_tx, out_rx) = mpsc::sync_channel::<Vec<u8>>(MAX_OUTBOUND_FRAMES_PER_LINK);
    if ev_tx.send(Ev::Up(link, Role::Responder, out_tx)).is_err() {
        return;
    }

    'conn: loop {
        // Flush anything the node wants to send before parking on read.
        loop {
            match out_rx.try_recv() {
                Ok(bytes) => {
                    if ws.write(Message::Binary(bytes.into())).is_err() {
                        break 'conn;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break 'conn,
            }
        }
        if ws.flush().is_err() {
            break;
        }
        let reservation = match ev_tx.reserve_data(link, MAX_FRAME_BYTES) {
            Ok(reservation) => reservation,
            Err(QueueAdmissionError::TimedOut) | Err(QueueAdmissionError::QueueFull) => continue,
            Err(_) => break,
        };
        match ws.read() {
            Ok(Message::Binary(b)) => {
                if ev_tx
                    .send_reserved_data(link, reservation, b.to_vec())
                    .is_err()
                {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => drop(reservation), // control frames retain no producer bytes
            Err(tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // read timed out: loop back to drain outgoing, then read again
            }
            Err(_) => break,
        }
    }
    let _ = ev_tx.send(Ev::Down(link));
}

/// Dial one **currently-online** peer relay over TLS WebSocket and bridge it to the driver as
/// an Initiator link — the relay-to-relay epidemic of DESIGN.md §28. Dials **once**: on
/// disconnect it returns, and the backbone's observe loop re-dials only if the peer is still in
/// the registry (so a peer that went offline is never re-woken). Mirrors `serve_ws`'s
/// single-thread read/drain interleave, as a non-blocking client (a TLS read timeout doesn't
/// reliably surface as WouldBlock; non-blocking does — same fix as the endpoint dialer).
#[cfg(feature = "firestore")]
fn dial_peer(url: &str, ev_tx: &EventTx) {
    use tungstenite::stream::MaybeTlsStream;
    let (mut ws, _resp) =
        match tungstenite::client::connect_with_config(url, Some(ws_bearer_config()), 3) {
            Ok(c) => c,
            Err(e) => {
                netlog(format!("peer: {url} unreachable ({e})"));
                return;
            }
        };
    match ws.get_ref() {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_nonblocking(true);
        }
        MaybeTlsStream::Rustls(t) => {
            let _ = t.get_ref().set_nonblocking(true);
        }
        _ => {}
    }
    let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
    let (out_tx, out_rx) = mpsc::sync_channel::<Vec<u8>>(MAX_OUTBOUND_FRAMES_PER_LINK);
    if ev_tx.send(Ev::Up(link, Role::Initiator, out_tx)).is_err() {
        return;
    }
    netlog(format!("peer: dialed {url} (link {link})"));
    'conn: loop {
        loop {
            match out_rx.try_recv() {
                Ok(bytes) => match ws.write(Message::Binary(bytes.into())) {
                    Ok(()) => {}
                    Err(tungstenite::Error::Io(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break 'conn,
                },
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break 'conn,
            }
        }
        match ws.flush() {
            Ok(()) => {}
            Err(tungstenite::Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        let reservation = match ev_tx.reserve_data(link, MAX_FRAME_BYTES) {
            Ok(reservation) => reservation,
            Err(QueueAdmissionError::TimedOut) | Err(QueueAdmissionError::QueueFull) => continue,
            Err(_) => break,
        };
        match ws.read() {
            Ok(Message::Binary(b)) => {
                if ev_tx
                    .send_reserved_data(link, reservation, b.to_vec())
                    .is_err()
                {
                    return;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => drop(reservation),
            Err(tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
    let _ = ev_tx.send(Ev::Down(link));
    netlog(format!("peer: link {link} to {url} closed"));
}

/// Pick the store backend: durable per-node Firestore (scale-to-zero) when built with
/// `--features firestore` and given a project, else local SQLite.
#[cfg(feature = "firestore")]
fn build_store(
    firestore: &Option<String>,
    db: &str,
    addr: &[u8],
) -> std::result::Result<Box<dyn Store>, String> {
    if let Some(project) = firestore {
        let s = FirestoreStore::open(project, addr)
            .map_err(|error| format!("firestore open failed for project {project}: {error}"))?;
        println!("store: firestore (project {project})");
        let _ = MIRROR_DROPPED.set(s.mirror_dropped_handle());
        let _ = MIRROR_FAILED.set(s.mirror_failed_handle());
        return Ok(Box::new(s));
    }
    SqliteStore::open(db)
        .map(|store| Box::new(store) as Box<dyn Store>)
        .map_err(|error| format!("sqlite open failed: {error}"))
}

#[cfg(not(feature = "firestore"))]
fn build_store(
    firestore: &Option<String>,
    db: &str,
    _addr: &[u8],
) -> std::result::Result<Box<dyn Store>, String> {
    if firestore.is_some() {
        return Err("firestore configured but support was not compiled in".into());
    }
    SqliteStore::open(db)
        .map(|store| Box::new(store) as Box<dyn Store>)
        .map_err(|error| format!("sqlite open failed: {error}"))
}

/// Load the relay identity: from a 32-byte file (mounted secret) when given, else
/// from `<db>.key`, generating and persisting one on first run.
fn load_identity(identity_file: &Option<String>, key_path: &str) -> Identity {
    if let Some(path) = identity_file {
        match std::fs::read(path) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(seed) => return Identity::from_secret_bytes(&seed),
                Err(_) => panic!("--identity-file {path} must be exactly 32 bytes"),
            },
            Err(e) => panic!("--identity-file {path} unreadable: {e}"),
        }
    }
    if let Ok(bytes) = std::fs::read(key_path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Identity::from_secret_bytes(&seed);
        }
    }
    let id = Identity::generate();
    // services-13: this is a 32-byte long-term secret. Write it 0600 (owner-only) so a shared VM's
    // other users can't read the relay's private identity seed, and log LOUDLY on failure - a
    // silently-dropped write means the address silently changes on every restart.
    let secret = id.to_secret_bytes();
    if let Err(e) = write_secret_600(key_path, &secret) {
        eprintln!(
            "relayd: FAILED to persist identity seed to {key_path}: {e} - \
             this relay's address WILL change on restart (fix perms/disk and retry)"
        );
    }
    id
}

/// Write `bytes` to `path` with owner-only (0600) permissions, creating or truncating. On Unix the
/// mode is applied at create time via `OpenOptions` so the secret is never briefly world-readable;
/// on non-Unix targets it falls back to a plain write (the relay only ships on Unix).
fn write_secret_600(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // Re-assert the mode in case the file pre-existed with looser perms (create+mode only
        // sets perms on creation, not when opening an existing file).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    }
}

fn bs58_addr(addr: &[u8]) -> String {
    bs58::encode(addr).into_string()
}

/// A short base58 prefix of an address for compact log lines.
fn short_b58(addr: &[u8]) -> String {
    bs58::encode(addr).into_string().chars().take(10).collect()
}

/// The host of a `wss://`/`ws://` URL — the relay's identify name (DESIGN.md §29).
/// `wss://us-central1.relay.hopme.sh/` → `us-central1.relay.hopme.sh`.
fn host_of(url: &str) -> String {
    let s = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);
    s.split('/').next().unwrap_or(s).to_string()
}

/// The backbone (DESIGN.md §28): liveness heartbeat + a passive registry read. It does
/// **not** dial peers. Dialing a peer's endpoint goes through the LB and cold-starts
/// (wakes) that region, which violates "nodes never wake nodes" and keeps the whole mesh
/// lit (one client anywhere → the entire fleet stays warm, saturating each single
/// instance → 429s). Cross-region delivery is the non-waking Firestore cross-partition
/// handoff (below): a node writes a bundle into the destination region's partition, which
/// that region drains when its *own* clients next wake it. So the only wake source is a
/// node's own clients. We keep the heartbeat (so tooling/handoff can see which regions are
/// warm) and a pure registry read (so the handoff can tell a peer relay from a device).
#[cfg(feature = "firestore")]
mod backbone {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hop_store_firestore::Registry;

    use super::now_ms;

    const HEARTBEAT_SECS: u64 = 30;
    const OBSERVE_SECS: u64 = 30;
    const TTL_MS: u64 = 90_000; // a peer silent longer than this is treated as offline

    /// Start the heartbeat + registry-observe threads, and (if `fanout > 0`) the online-only
    /// relay-to-relay dialer. `ev_tx` is the driver's event channel; a dialed peer link bridges
    /// into it exactly like an inbound connection (DESIGN.md §28).
    pub fn spawn(
        project: String,
        region: String,
        advertise: String,
        addr: Vec<u8>,
        known_relays: Arc<Mutex<HashSet<String>>>,
        fanout: usize,
        ev_tx: super::EventTx,
    ) {
        let reg = Arc::new(Registry::new(&project, &addr));
        let me = bs58::encode(&addr).into_string();
        known_relays.lock().unwrap().insert(me.clone());
        eprintln!(
            "backbone: region={region} advertise={advertise} mesh-fanout={fanout}{}",
            if fanout == 0 {
                " (handoff-only, no dialing)"
            } else {
                " (online-only epidemic)"
            }
        );

        // Announce our liveness so tooling/handoff can see which regions are warm.
        {
            let reg = reg.clone();
            std::thread::spawn(move || loop {
                if let Err(e) = reg.heartbeat(&region, &advertise, now_ms()) {
                    eprintln!("backbone: heartbeat failed: {e}");
                }
                std::thread::sleep(Duration::from_secs(HEARTBEAT_SECS));
            });
        }

        // Observe the registry (a pure read — wakes no one): learn peer-relay ids (so the
        // handoff records device presence only for actual devices, §28) and, when fanout is
        // enabled, dial up to `fanout` *currently-online* peers we're not already linked to.
        // We never dial a peer absent from the registry — a sleeping region is never woken.
        let dialed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        std::thread::spawn(move || loop {
            match reg.online(now_ms(), TTL_MS) {
                Ok(peers) => {
                    {
                        let mut kr = known_relays.lock().unwrap();
                        for p in &peers {
                            kr.insert(p.node.clone());
                        }
                    }
                    if fanout > 0 {
                        let mut held = dialed.lock().unwrap();
                        held.retain(|ep| peers.iter().any(|p| &p.endpoint == ep)); // drop gone peers
                        for p in &peers {
                            if held.len() >= fanout {
                                break; // bounded fan-out: a handful of peers, not a full mesh
                            }
                            if p.node == me || held.contains(&p.endpoint) {
                                continue;
                            }
                            held.insert(p.endpoint.clone());
                            let (ep, ev_tx, dialed) =
                                (p.endpoint.clone(), ev_tx.clone(), dialed.clone());
                            std::thread::spawn(move || {
                                super::dial_peer(&ep, &ev_tx);
                                dialed.lock().unwrap().remove(&ep); // link closed — re-dial if still online
                            });
                        }
                    }
                }
                Err(e) => eprintln!("backbone: registry read failed: {e}"),
            }
            std::thread::sleep(Duration::from_secs(OBSERVE_SECS));
        });
    }
}

/// The durable blind-spool mailbox logic (§39 P5) plus the dedup-map age-eviction (services-r2-04),
/// kept store-agnostic and free of any Firestore dependency so it compiles and is unit-tested in the
/// default build (not only when `--features firestore` is on). The concrete `MailboxStore` impl for
/// the Firestore `Presence` and the worker that drives this live in the firestore-gated `handoff`
/// module below.
#[cfg_attr(not(feature = "firestore"), allow(dead_code))]
mod mailbox {
    use std::collections::HashMap;

    use hop_core::bundle::BundleId;
    use hop_core::crypto::Tag;

    /// services-r2-04: hard fallback cap on a dedup map. Age eviction (drop expired entries) is the
    /// primary bound; this only triggers if a pathological set of all-far-future entries piles up,
    /// evicting the nearest-to-expiry so memory stays bounded WITHOUT a wholesale clear() that would
    /// let already-handed/-spooled bundles be redundantly rewritten to Firestore on the next cycle.
    const DEDUP_CAP: usize = 100_000;

    /// services-r2-04: evict dedup entries whose bundle has already expired (epoch-ms `<= now_ms`,
    /// treating `0` as never-expire), then, if still over [`DEDUP_CAP`], evict the nearest-to-expiry
    /// surplus. Age-based instead of the old wholesale `clear()`, so an expired/TTL-swept bundle is
    /// forgotten (it can never be re-handed) while a still-live one stays deduped and is NOT
    /// redundantly re-written every cycle.
    pub(crate) fn evict_expired<K: Clone + std::hash::Hash + Eq>(
        map: &mut HashMap<K, u64>,
        now_ms: u64,
    ) {
        map.retain(|_, &mut exp| exp == 0 || exp > now_ms);
        if map.len() > DEDUP_CAP {
            let excess = map.len() - DEDUP_CAP;
            // Collect the `excess` nearest-to-expiry keys (0 = never-expire sorts last).
            let mut by_exp: Vec<(u64, K)> = map
                .iter()
                .map(|(k, &e)| (if e == 0 { u64::MAX } else { e }, k.clone()))
                .collect();
            by_exp.select_nth_unstable_by_key(excess.saturating_sub(1), |(e, _)| *e);
            for (_, k) in by_exp.into_iter().take(excess) {
                map.remove(&k);
            }
        }
    }

    /// The durable blind-spool mailbox operations the §39 P5 worker needs (F-18). Abstracting these
    /// out of the concrete Firestore `Presence` makes the cross-region spool→pull round trip testable
    /// with an in-memory fake that two "regions" share.
    pub trait MailboxStore {
        fn spool_to_mailbox(
            &self,
            tag_b58: &str,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> Result<(), String>;
        fn visit_mailbox<R>(
            &self,
            tag_b58: &str,
            reserve: impl FnMut() -> Result<R, String>,
            visit: impl FnMut(R, Vec<u8>, u64) -> Result<(), String>,
        ) -> Result<(), String>;
        fn delete_mailbox_bundle(&self, tag_b58: &str, id: &BundleId) -> Result<(), String>;
    }

    /// One mailbox item offered to the driver. The durable source remains present until the driver
    /// acknowledges that it accepted and flushed the bundle into its own store.
    pub struct MailboxPull {
        pub tag_b58: String,
        pub id: BundleId,
        pub bytes: Vec<u8>,
    }

    /// §39 P5 spool + want-beacon, store-agnostic. Spools each un-routable private bundle by its
    /// mailbox-tag; for each wanted tag, pulls anything held under it, dedups by id, deletes the
    /// spool copy, and returns the bytes to re-ingest. `spooled`/`pulled` carry cross-cycle dedup.
    pub fn process_mailbox<M: MailboxStore, R>(
        store: &M,
        spool: &[(BundleId, Tag, Vec<u8>, u64)],
        wanted: &[Tag],
        spooled: &mut HashMap<(BundleId, Tag), u64>,
        pulled: &mut HashMap<BundleId, u64>,
        mut reserve: impl FnMut() -> Result<R, String>,
        mut offer: impl FnMut(MailboxPull, R) -> Result<bool, String>,
    ) -> Result<(), String> {
        let mut first_error = None;
        for (id, tag, bytes, expires) in spool {
            // services-r2-04: dedup value is the bundle's own expiry, so the caller can age-evict.
            if spooled.insert((*id, *tag), *expires).is_some() {
                continue; // already spooled this cycle-set
            }
            let tag_b58 = bs58::encode(tag).into_string();
            if let Err(e) = store.spool_to_mailbox(&tag_b58, id, bytes, *expires) {
                // services-03: bundle id + mailbox-tag prefix is exactly the spool/pull correlation
                // pair §39 must not leak to the public; operator log (Cloud Logging) only.
                super::netlog_private(format!(
                    "spool FAILED: msg {} → mailbox {}: {e}",
                    super::short_b58(id),
                    &tag_b58[..tag_b58.len().min(8)]
                ));
                spooled.remove(&(*id, *tag)); // let a later cycle retry
                if first_error.is_none() {
                    first_error = Some(e);
                }
            } else {
                super::netlog_private(format!(
                    "spool: msg {} → mailbox {}",
                    super::short_b58(id),
                    &tag_b58[..tag_b58.len().min(8)]
                ));
            }
        }

        for tag in wanted {
            let tag_b58 = bs58::encode(tag).into_string();
            let visit_result =
                store.visit_mailbox(&tag_b58, &mut reserve, |reservation, bytes, expires| {
                    let Ok(bundle) = hop_core::bundle::Bundle::from_bytes(&bytes) else {
                        return Ok(());
                    };
                    let id = bundle.id();
                    if pulled.contains_key(&id) {
                        return Ok(());
                    }
                    super::netlog_private(format!(
                        "want-beacon: pulled msg {} from mailbox {}",
                        super::short_b58(&id),
                        &tag_b58[..tag_b58.len().min(8)]
                    ));
                    let accepted = offer(
                        MailboxPull {
                            tag_b58: tag_b58.clone(),
                            id,
                            bytes,
                        },
                        reservation,
                    )?;
                    if accepted {
                        pulled.insert(id, expires);
                    }
                    Ok(())
                });
            if let Err(error) = visit_result {
                eprintln!("spool: list_mailbox failed: {error}");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hop_core::crypto::PubKeyBytes;
        use std::collections::HashMap;
        use std::sync::Mutex;

        /// One shared in-memory Firestore-like mailbox store; two `RegionWorker`s over the SAME
        /// instance simulate region A spooling and region B pulling (the cross-region path).
        #[derive(Default)]
        struct FakeMailbox {
            // tag_b58 → (bundle-id → bytes)
            boxes: Mutex<HashMap<String, HashMap<BundleId, Vec<u8>>>>,
        }
        impl MailboxStore for FakeMailbox {
            fn spool_to_mailbox(
                &self,
                tag_b58: &str,
                id: &BundleId,
                data: &[u8],
                _e: u64,
            ) -> Result<(), String> {
                self.boxes
                    .lock()
                    .unwrap()
                    .entry(tag_b58.to_string())
                    .or_default()
                    .insert(*id, data.to_vec());
                Ok(())
            }
            fn visit_mailbox<R>(
                &self,
                tag_b58: &str,
                mut reserve: impl FnMut() -> Result<R, String>,
                mut visit: impl FnMut(R, Vec<u8>, u64) -> Result<(), String>,
            ) -> Result<(), String> {
                let ids: Vec<_> = self
                    .boxes
                    .lock()
                    .unwrap()
                    .get(tag_b58)
                    .map(|mailbox| mailbox.keys().copied().collect())
                    .unwrap_or_default();
                for id in ids {
                    let reservation = reserve()?;
                    let data = self
                        .boxes
                        .lock()
                        .unwrap()
                        .get(tag_b58)
                        .and_then(|mailbox| mailbox.get(&id))
                        .cloned();
                    if let Some(data) = data {
                        visit(reservation, data, 0)?;
                    }
                }
                Ok(())
            }
            fn delete_mailbox_bundle(&self, tag_b58: &str, id: &BundleId) -> Result<(), String> {
                if let Some(m) = self.boxes.lock().unwrap().get_mut(tag_b58) {
                    m.remove(id);
                }
                Ok(())
            }
        }

        impl FakeMailbox {
            fn mailbox_len(&self, tag: &Tag) -> usize {
                self.boxes
                    .lock()
                    .unwrap()
                    .get(&bs58::encode(tag).into_string())
                    .map(HashMap::len)
                    .unwrap_or(0)
            }
        }

        fn private_bundle_for(
            spk_pub: &hop_core::crypto::XPubKeyBytes,
            seal_to: &PubKeyBytes,
        ) -> (BundleId, Tag, Vec<u8>) {
            use hop_core::bundle::{Bundle, BundleOpts, Payload};
            use hop_core::crypto::{
                mailbox_route, mailbox_tag, MAILBOX_ROUTE_PREFIX_BYTES, TAG_LEN,
            };
            // F-06 / core-protocol-r2-02: the recipient's mailbox tag (address + epoch 0) is projected
            // to its 2-byte ROUTING PREFIX; the private header now carries only that prefix (never the
            // full tag), so the relay's spool key is an anonymity set, not a per-recipient address.
            let route = mailbox_route(&mailbox_tag(seal_to, 0));
            let b = Bundle::create_private(
                seal_to,
                spk_pub,
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: b"cross-region".to_vec(),
                },
                Some(route),
                BundleOpts::default(),
            )
            .unwrap();
            // The relay spools/pulls under the route-key: the 2-byte prefix right-padded into a full
            // Tag (matching the driver's spoolable_private_bundles / take_wanted_mailboxes keys).
            let mut spool_key = [0u8; TAG_LEN];
            spool_key[..MAILBOX_ROUTE_PREFIX_BYTES].copy_from_slice(&route);
            (b.id(), spool_key, b.to_bytes().unwrap())
        }

        #[test]
        fn cross_region_spool_then_want_beacon_pulls_exactly_once() {
            use hop_core::prelude::Identity;
            let store = FakeMailbox::default();
            let bob = Identity::generate();
            let spk = bob.derive_prekey();
            let (id, tag, bytes) = private_bundle_for(&spk.public, &bob.address());

            // Region A: no live gradient → spool the bundle. Its own dedup sets.
            let (mut sp_a, mut pl_a) = (HashMap::new(), HashMap::new());
            let mut out_a = Vec::new();
            process_mailbox(
                &store,
                &[(id, tag, bytes.clone(), 0)],
                &[],
                &mut sp_a,
                &mut pl_a,
                || Ok(()),
                |pull, ()| {
                    out_a.push(pull);
                    Ok(false)
                },
            )
            .unwrap();
            assert!(out_a.is_empty(), "spooling ingests nothing");
            assert_eq!(
                store.mailbox_len(&tag),
                1,
                "bundle is durably spooled by mailbox-tag"
            );

            // Region B (DIFFERENT worker/dedup sets, SAME store): bob beacons → want-beacon pulls it.
            let (mut sp_b, mut pl_b) = (HashMap::new(), HashMap::new());
            let mut out_b = Vec::new();
            process_mailbox(
                &store,
                &[],
                &[tag],
                &mut sp_b,
                &mut pl_b,
                || Ok(()),
                |pull, ()| {
                    out_b.push(pull);
                    Ok(false)
                },
            )
            .unwrap();
            assert_eq!(
                out_b.len(),
                1,
                "want-beacon in region B pulls the bundle spooled in region A"
            );
            assert_eq!(
                hop_core::bundle::Bundle::from_bytes(&out_b[0].bytes)
                    .unwrap()
                    .id(),
                id,
                "pulled the right bundle"
            );

            // The source remains until the driver accepts and durably flushes custody.
            assert_eq!(
                store.mailbox_len(&tag),
                1,
                "source retained before custody acknowledgement"
            );
            store
                .delete_mailbox_bundle(&out_b[0].tag_b58, &out_b[0].id)
                .unwrap();
            pl_b.insert(out_b[0].id, 0);
            let (mut sp_c, mut pl_c) = (HashMap::new(), HashMap::new());
            let mut out_c = Vec::new();
            process_mailbox(
                &store,
                &[],
                &[tag],
                &mut sp_c,
                &mut pl_c,
                || Ok(()),
                |pull, ()| {
                    out_c.push(pull);
                    Ok(false)
                },
            )
            .unwrap();
            assert!(out_c.is_empty(), "no double-delivery on re-beacon");
        }

        #[test]
        fn same_worker_pull_dedups_within_its_pulled_set() {
            use hop_core::prelude::Identity;
            let store = FakeMailbox::default();
            let bob = Identity::generate();
            let spk = bob.derive_prekey();
            let (id, tag, bytes) = private_bundle_for(&spk.public, &bob.address());
            let (mut sp, mut pl) = (HashMap::new(), HashMap::new());
            process_mailbox(
                &store,
                &[(id, tag, bytes.clone(), 0)],
                &[],
                &mut sp,
                &mut pl,
                || Ok(()),
                |_pull, ()| Ok(false),
            )
            .unwrap();
            let mut first = Vec::new();
            process_mailbox(
                &store,
                &[],
                &[tag],
                &mut sp,
                &mut pl,
                || Ok(()),
                |pull, ()| {
                    first.push(pull);
                    Ok(false)
                },
            )
            .unwrap();
            pl.insert(first[0].id, 0);
            // Re-insert into the store behind the worker's back to prove `pulled` dedup, not just deletion.
            let _ = store.spool_to_mailbox(&bs58::encode(tag).into_string(), &id, &bytes, 0);
            let mut again = Vec::new();
            process_mailbox(
                &store,
                &[],
                &[tag],
                &mut sp,
                &mut pl,
                || Ok(()),
                |pull, ()| {
                    again.push(pull);
                    Ok(false)
                },
            )
            .unwrap();
            assert!(
                again.is_empty(),
                "a bundle id already pulled by this worker is not re-ingested"
            );
        }
    }
}

/// Cross-partition handoff (DESIGN.md §28): the offline-destination mailbox.
///
/// Each region's relay owns a Firestore partition. When a relay holds a device-addressed
/// bundle it can't deliver locally, it looks up where that device last checked in
/// (presence) and writes the bundle into *that region's* partition — the destination
/// region then delivers it on its next device check-in (cold start rehydrates; a warm
/// node ingests via the reload loop below). Presence is recorded for connected device
/// peers (a peer relay, identified via the registry, is skipped). All blocking Firestore
/// I/O runs here, off the single-owner driver thread.
#[cfg(feature = "firestore")]
mod handoff {
    use std::collections::{HashMap, HashSet};
    use std::sync::mpsc::{self, SyncSender};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hop_core::bundle::BundleId;
    use hop_core::crypto::{PubKeyBytes, Tag};
    use hop_store_firestore::Presence;

    use super::mailbox::{evict_expired, process_mailbox, MailboxStore};
    use super::{now_ms, region_node_b58, DurabilityHandle, Ev, EventTx};

    /// A device-presence record is trusted this long after check-in (matches the
    /// registry TTL — beyond it, we don't know where the device is, so we don't hand off).
    const PRESENCE_TTL_MS: u64 = 90_000;
    /// How often a warm node re-reads its own partition for handoffs others wrote.
    const RELOAD_SECS: u64 = 30;

    /// What the driver tells the worker each cycle: who's connected, and what we hold
    /// that we can't deliver locally.
    pub struct Snapshot {
        pub now_ms: u64,
        pub devices: Vec<PubKeyBytes>,
        pub undeliverable: Vec<(BundleId, PubKeyBytes, Vec<u8>, u64)>,
        /// §39 P5: private bundles with no live recv-gradient — durably spool each by its
        /// mailbox-tag (a rotatable pseudonym) so an offline recipient can pull it on return.
        pub spool: Vec<(BundleId, Tag, Vec<u8>, u64)>,
        /// §39 P5: mailbox-tags whose recv-gradient we just (re)laid — the want-beacon. That
        /// recipient is reachable again, so pull anything spooled under each tag and re-ingest.
        pub wanted: Vec<Tag>,
    }

    /// Start the presence/handoff worker and the warm-reload thread. Returns the channel
    /// the driver pushes [`Snapshot`]s into.
    pub fn spawn(
        project: String,
        region: String,
        base_seed: [u8; 32],
        addr: Vec<u8>,
        known_relays: Arc<Mutex<HashSet<String>>>,
        ev_tx: EventTx,
        durability: DurabilityHandle,
    ) -> SyncSender<Snapshot> {
        let me = bs58::encode(&addr).into_string();

        // Worker: consume driver snapshots, record device presence, and hand undeliverable
        // bundles into their destination region's partition.
        let (snap_tx, snap_rx) = mpsc::sync_channel::<Snapshot>(1);
        {
            let presence = Presence::new(&project);
            let region = region.clone();
            let known_relays = known_relays.clone();
            let ev_tx = ev_tx.clone();
            let durability = durability.clone();
            std::thread::spawn(move || {
                // Bundles already handed off (id → dest region), so we don't re-write them every
                // cycle. services-r2-04: each dedup entry carries the bundle's own `expires_at`, so
                // we evict by AGE (drop entries whose bundle has expired / been TTL-swept and thus
                // can never be re-handed/re-spooled) instead of a wholesale clear(). A wholesale
                // clear at the cap let an already-handed bundle be re-put/re-spooled on the next
                // cycle (a periodic redundant-Firestore-write storm). Age eviction keeps memory
                // bounded without the rewrite burst; a hard cap (evict nearest-to-expiry) remains a
                // fallback so a pathological all-far-future set is still bounded.
                let mut handed: HashMap<(BundleId, String), u64> = HashMap::new();
                // §39 P5: private bundles already spooled to a mailbox (id → tag), and bundles
                // already pulled back from a mailbox (id), so neither is redone every cycle.
                let mut spooled: HashMap<(BundleId, Tag), u64> = HashMap::new();
                let mut pulled: HashMap<BundleId, u64> = HashMap::new();
                for snap in snap_rx {
                    if !durability.is_ready() {
                        continue;
                    }
                    evict_expired(&mut handed, snap.now_ms);
                    evict_expired(&mut spooled, snap.now_ms);
                    evict_expired(&mut pulled, snap.now_ms);
                    // Record presence for connected device peers (skip peer relays).
                    for dev in &snap.devices {
                        let b58 = bs58::encode(dev).into_string();
                        if known_relays.lock().unwrap().contains(&b58) {
                            continue;
                        }
                        if let Err(e) = presence.set_presence(&b58, &region, snap.now_ms) {
                            durability.mark_not_ready();
                            eprintln!("handoff: set_presence failed: {e}");
                        }
                    }
                    // Hand off what we can't deliver locally to the dest device's region.
                    for (id, dst, bytes, expires) in &snap.undeliverable {
                        let dst_b58 = bs58::encode(dst).into_string();
                        let dst_region =
                            match presence.region_of(&dst_b58, snap.now_ms, PRESENCE_TTL_MS) {
                                Ok(Some(r)) => r,
                                Ok(None) => continue, // unknown/stale — nowhere to hand off yet
                                Err(e) => {
                                    durability.mark_not_ready();
                                    eprintln!("handoff: region_of failed: {e}");
                                    continue;
                                }
                            };
                        if dst_region == region {
                            continue; // already in our partition; we'll deliver on reconnect
                        }
                        if handed.insert((*id, dst_region.clone()), *expires).is_some() {
                            continue; // already written this cycle-set
                        }
                        let dest_node = region_node_b58(&base_seed, &dst_region);
                        if let Err(e) = presence.put_bundle_to(&dest_node, id, bytes, *expires) {
                            durability.mark_not_ready();
                            // services-03: bundle id + destination region is per-message metadata.
                            super::netlog_private(format!(
                                "handoff FAILED: msg {} → {} (region {dst_region}): {e}",
                                super::short_b58(id),
                                super::short_b58(dst)
                            ));
                            handed.remove(&(*id, dst_region)); // let a later cycle retry
                        } else {
                            super::netlog_private(format!(
                                "handoff: msg {} → dst {} (region {dst_region})",
                                super::short_b58(id),
                                super::short_b58(dst)
                            ));
                        }
                    }

                    // §39 P5 spool + want-beacon, extracted into a store-agnostic function so the
                    // cross-region round trip is unit-testable with a fake shared mailbox (F-18).
                    let mailbox_result = process_mailbox(
                        &presence,
                        &snap.spool,
                        &snap.wanted,
                        &mut spooled,
                        &mut pulled,
                        || {
                            ev_tx
                                .reserve_durable()
                                .map_err(|error| format!("durable reservation failed: {error:?}"))
                        },
                        |pull, reservation| {
                            let (ack_tx, ack_rx) = mpsc::sync_channel(0);
                            ev_tx
                                .send_reserved_durable(
                                    reservation,
                                    Ev::IngestCustody(pull.bytes, ack_tx),
                                )
                                .map_err(|error| {
                                    format!("durable ingest admission failed: {error:?}")
                                })?;
                            if ack_rx.recv_timeout(Duration::from_secs(6)) != Ok(true) {
                                return Ok(false);
                            }
                            <Presence as MailboxStore>::delete_mailbox_bundle(
                                &presence,
                                &pull.tag_b58,
                                &pull.id,
                            )?;
                            Ok(true)
                        },
                    );
                    if let Err(error) = mailbox_result {
                        durability.mark_not_ready();
                        eprintln!("handoff: mailbox custody failed: {error}");
                    }
                }
            });
        }

        // Warm reload: re-read our own partition so handoffs written by other regions
        // while we're already up get ingested (a cold start gets them via rehydrate).
        {
            let presence = Presence::new(&project);
            let durability = durability.clone();
            std::thread::spawn(move || {
                // services-r2-04: the reload dedup set was an unbounded HashSet<BundleId> that grew
                // for the whole process lifetime (every handoff ever re-read stayed remembered). Give
                // it the same age-based eviction as its handed/spooled/pulled siblings: key each id by
                // the bundle's own expiry so an expired / TTL-swept bundle (which can never reappear
                // in the partition) is forgotten, with a hard cap fallback. Bounded, not a leak.
                let mut ingested: HashMap<BundleId, u64> = HashMap::new();
                loop {
                    std::thread::sleep(Duration::from_secs(RELOAD_SECS));
                    if !durability.is_ready() {
                        continue;
                    }
                    evict_expired(&mut ingested, now_ms());
                    let result = presence.visit_bundles_of(
                        &me,
                        || {
                            ev_tx
                                .reserve_durable()
                                .map_err(|error| format!("durable reservation failed: {error:?}"))
                        },
                        |reservation, bytes, expires| {
                            let Ok(bundle) = hop_core::bundle::Bundle::from_bytes(&bytes) else {
                                return Ok(());
                            };
                            if ingested.contains_key(&bundle.id()) {
                                return Ok(());
                            }
                            ev_tx
                                .send_reserved_durable(reservation, Ev::Ingest(bytes))
                                .map_err(|error| {
                                    format!("durable ingest admission failed: {error:?}")
                                })?;
                            ingested.insert(bundle.id(), expires);
                            Ok(())
                        },
                    );
                    if let Err(e) = result {
                        durability.mark_not_ready();
                        eprintln!("handoff: partition reload failed: {e}");
                    }
                }
            });
        }

        snap_tx
    }

    /// The Firestore `Presence` is the production [`MailboxStore`] (the in-memory fake in the mailbox
    /// module's tests is the other impl); this just forwards each trait method to the inherent one.
    impl MailboxStore for Presence {
        fn spool_to_mailbox(
            &self,
            tag_b58: &str,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> Result<(), String> {
            Presence::spool_to_mailbox(self, tag_b58, id, data, expires_at)
        }
        fn visit_mailbox<R>(
            &self,
            tag_b58: &str,
            reserve: impl FnMut() -> Result<R, String>,
            visit: impl FnMut(R, Vec<u8>, u64) -> Result<(), String>,
        ) -> Result<(), String> {
            Presence::visit_mailbox(self, tag_b58, reserve, visit)
        }
        fn delete_mailbox_bundle(&self, tag_b58: &str, id: &BundleId) -> Result<(), String> {
            Presence::delete_mailbox_bundle(self, tag_b58, id)
        }
    }
}

#[cfg(all(test, unix))]
mod secret_perms_tests {
    use super::write_secret_600;
    use std::os::unix::fs::PermissionsExt;

    fn temp_path(name: &str) -> String {
        format!(
            "{}/hop-relayd-{name}-{}.key",
            std::env::temp_dir().display(),
            std::process::id()
        )
    }

    #[test]
    fn identity_secret_is_written_owner_only() {
        // services-13: a fresh identity seed file must land at 0600 (no group/other bits).
        let path = temp_path("fresh");
        let _ = std::fs::remove_file(&path);
        write_secret_600(&path, &[9u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "identity seed must be owner-only, got {mode:o}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), vec![9u8; 32]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rewrite_tightens_a_preexisting_world_readable_file() {
        // A file that already exists 0644 must be tightened to 0600 on rewrite, not left loose.
        let path = temp_path("loose");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_600(&path, &[1u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewrite must tighten perms, got {mode:o}");
        assert_eq!(std::fs::read(&path).unwrap(), vec![1u8; 32]);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod log_privacy_tests {
    use super::{netlog, netlog_private, LogHub, LogInner, MAX_LOG_SUBSCRIBER_LINES};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // These tests use the process-global log hub via netlog/netlog_private, so they subscribe to a
    // LOCAL hub built the same way and route through the same emit path to assert routing. Because
    // netlog talks to the static hub, we assert routing behavior on a fresh LogHub directly.
    fn fresh_hub() -> LogHub {
        LogHub {
            inner: Mutex::new(LogInner {
                who: String::new(),
                ring: VecDeque::new(),
                subs: Vec::new(),
            }),
        }
    }

    #[test]
    fn public_emit_reaches_subscribers_private_does_not() {
        // services-03: a public emit() must fan out to a viewer; per-message metadata must NEVER be
        // routed through the hub (netlog_private goes only to stderr).
        let hub = fresh_hub();
        let (_who, _backlog, rx) = hub.subscribe();
        hub.emit("stats: peers=3 held=7".to_string());
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("public line delivered to viewer");
        assert!(got.contains("peers=3 held=7"), "public aggregate delivered");

        // netlog_private must not touch the hub at all: nothing more arrives on the stream.
        netlog_private("spool: msg ABC → mailbox XY");
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "private per-message metadata must never reach a public viewer"
        );
    }

    #[test]
    fn slow_log_subscriber_has_a_bounded_nonblocking_queue() {
        let hub = fresh_hub();
        let (_who, _backlog, rx) = hub.subscribe();
        for i in 0..(MAX_LOG_SUBSCRIBER_LINES + 50) {
            hub.emit(format!("line {i}"));
        }

        let mut received = 0;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, MAX_LOG_SUBSCRIBER_LINES);

        hub.emit("after drain".to_string());
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .unwrap()
                .contains("after drain"),
            "the subscriber remains live after shedding overflow lines"
        );
    }

    #[test]
    fn public_stream_is_off_by_default() {
        // services-03: without HOP_PUBLIC_LOG_STREAM the per-event backlog is withheld (a visitor
        // gets identity + aggregate counters, not the ring of individual lines). The env var is not
        // set in the test process, so subscribe() returns an empty backlog even with a full ring.
        // Hold the shared env lock: a parallel test mutating HOP_PUBLIC_LOG_STREAM would otherwise
        // flip the flag between remove_var and subscribe().
        let _env = super::PUBLIC_LOG_ENV_LOCK.lock().unwrap();
        let hub = fresh_hub();
        hub.emit("conn up: link=1 (Responder)".to_string());
        hub.emit("stats: peers=1 held=0".to_string());
        std::env::remove_var("HOP_PUBLIC_LOG_STREAM");
        let (_who, backlog, _rx) = hub.subscribe();
        assert!(
            backlog.is_empty(),
            "with the public stream off, no per-event backlog is exposed"
        );
        // Sanity: netlog is the public path (compiles + routes through emit).
        netlog("relay up: region=test");
    }

    #[test]
    fn ring_is_capped_at_400_and_public_subscribe_returns_the_backlog() {
        // The public-safe ring is bounded (oldest lines drop past 400) so a long-lived relay's hub
        // can't grow without bound; and with the public stream ON, a new viewer's subscribe() returns
        // that capped ring as its backlog (services-03). Serialize on the env lock (subscribe reads
        // the global HOP_PUBLIC_LOG_STREAM flag).
        let _env = super::PUBLIC_LOG_ENV_LOCK.lock().unwrap();
        let hub = fresh_hub();
        for i in 0..450 {
            hub.emit(format!("line {i}"));
        }
        std::env::set_var("HOP_PUBLIC_LOG_STREAM", "1");
        let (_who, backlog, _rx) = hub.subscribe();
        std::env::remove_var("HOP_PUBLIC_LOG_STREAM");
        assert_eq!(backlog.len(), 400, "the ring is capped at 400 lines");
        assert!(
            backlog.last().unwrap().contains("line 449"),
            "the newest line is retained"
        );
        assert!(
            backlog.iter().all(|l| !l.contains("line 0 ")),
            "the oldest lines were evicted"
        );
    }
}

#[cfg(test)]
mod control_path_tests {
    // services-r2-02: the newly-added robustness controls (frame cap + connection shedding) are the
    // exact surface that keeps a degraded/attacked relay from exhausting threads or memory, yet had
    // no direct tests. These exercise them so a regression fails a test, not CI.
    use super::{
        admit_conn, admit_log_conn, event_channel, frame_len_ok, peek_is_healthz, MAX_CONNS,
        MAX_FRAME_BYTES, MAX_LOG_CONNS,
    };
    use std::sync::Mutex;

    // These tests all mutate the process-global connection counters, so they must not run
    // concurrently with each other. Serialize them on one lock (Rust runs test fns in parallel).
    static CONN_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_conn_tests() -> std::sync::MutexGuard<'static, ()> {
        CONN_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn peek_is_healthz_fast_paths_a_probe_and_never_blocks_on_a_slowloris() {
        // services-r7-01: the accept-loop healthz fast-path must (a) recognize a buffered `GET /healthz`
        // so a liveness probe is served EXEMPT from the pending-peek budget (a slowloris that fills
        // MAX_WS_PENDING can no longer starve it), and (b) return instantly for a silent slowloris
        // (connect, send nothing) so it never stalls the accept loop. This is what closes the r5
        // residual where healthz shared the WS port and was gated by the pending budget.
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        // (a) A healthz probe that sends its request line WITH the connection is recognized.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            std::thread::sleep(Duration::from_millis(60)); // hold open past the peek
        });
        let (sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(25)); // let the probe's bytes arrive
        assert!(
            peek_is_healthz(&sock),
            "a buffered healthz probe is fast-pathed"
        );
        probe.join().unwrap();

        // (b) A silent slowloris (no bytes) is NOT healthz, and the check returns instantly (non-blocking:
        // if it blocked on the classify timeout this would hang / take seconds).
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let slow = std::thread::spawn(move || {
            let _c = TcpStream::connect(addr2).unwrap();
            std::thread::sleep(Duration::from_millis(60)); // connect, send nothing
        });
        let (sock2, _) = listener2.accept().unwrap();
        let t0 = Instant::now();
        assert!(
            !peek_is_healthz(&sock2),
            "a silent slowloris is not healthz"
        );
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "and the non-blocking peek does not stall the accept loop"
        );
        slow.join().unwrap();

        // (c) A non-healthz request (a real mesh upgrade) is not fast-pathed - it takes the normal path.
        let listener3 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr3 = listener3.local_addr().unwrap();
        let other = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr3).unwrap();
            c.write_all(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
                .unwrap();
            std::thread::sleep(Duration::from_millis(60));
        });
        let (sock3, _) = listener3.accept().unwrap();
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            !peek_is_healthz(&sock3),
            "a non-healthz request is not fast-pathed"
        );
        other.join().unwrap();
    }

    #[test]
    fn frame_cap_rejects_oversized_and_accepts_at_the_bound() {
        // The WS path and the raw-TCP path must share the SAME 1 MiB bound (not tungstenite's 64 MiB
        // default), so a single WS client can't push a frame the TCP path would have rejected.
        assert!(frame_len_ok(0));
        assert!(
            frame_len_ok(MAX_FRAME_BYTES),
            "exactly at the cap is accepted"
        );
        assert!(
            !frame_len_ok(MAX_FRAME_BYTES + 1),
            "one byte over the cap is rejected"
        );
        assert!(
            !frame_len_ok(64 << 20),
            "the old 64 MiB default is rejected"
        );
    }

    #[test]
    fn admit_conn_sheds_over_the_connection_cap() {
        let _lock = lock_conn_tests();
        // Over MAX_CONNS, admit_conn returns None (the socket is shed) instead of spawning a handler
        // thread; dropping a guard frees its slot so the next connection is admitted again.
        let mut guards = Vec::new();
        for _ in 0..MAX_CONNS {
            let g = admit_conn().expect("under the cap is admitted");
            guards.push(g);
        }
        // At the cap: the next admit is shed.
        assert!(
            admit_conn().is_none(),
            "a connection over MAX_CONNS is shed, not spawned"
        );
        // Free one slot; the next admit succeeds again (the guard's Drop released it).
        guards.pop();
        let g = admit_conn().expect("a freed slot re-admits");
        drop(g);
        // Release everything so the global counter returns to zero for any later test.
        guards.clear();
        assert!(
            admit_conn().is_some(),
            "counter fully released after cleanup"
        );
    }

    #[test]
    fn log_viewers_cannot_starve_a_mesh_connection() {
        // services-r3-01 (HIGH regression): the core proof. Fill EVERY log-stream slot with idle
        // viewers, then over-fill (extra viewers are shed on their own budget). A mesh connection
        // (WS device/relay link) must STILL be admitted, because log viewers charge a separate pool
        // and can never touch the mesh budget. Before the fix, both shared MAX_CONNS, so N idle
        // viewers filled the pool and this admit_conn() would have returned None (starvation).
        let _lock = lock_conn_tests();
        let mut log_guards = Vec::new();
        for _ in 0..MAX_LOG_CONNS {
            log_guards.push(admit_log_conn().expect("log viewer admitted under the log cap"));
        }
        // The log pool is now full: extra viewers are shed (their own budget, not the mesh budget).
        assert!(
            admit_log_conn().is_none(),
            "log viewers are capped by their OWN small budget, not the mesh budget"
        );
        // The whole point: a mesh link is admitted regardless of how many log viewers are camped.
        let mesh = admit_conn().expect(
            "a mesh connection MUST be admitted even with every log-stream slot occupied \
             (log viewers must never starve mesh traffic)",
        );
        drop(mesh);
        log_guards.clear();
        // Symmetric: a full mesh budget must not shed a log viewer either (no reverse starvation).
        let mut mesh_guards = Vec::new();
        for _ in 0..MAX_CONNS {
            mesh_guards.push(admit_conn().expect("mesh link admitted under the mesh cap"));
        }
        assert!(admit_conn().is_none(), "mesh budget is full");
        assert!(
            admit_log_conn().is_some(),
            "a log viewer is still admitted when the mesh budget is full (separate pools)"
        );
        mesh_guards.clear();
    }

    #[test]
    fn log_stream_closes_at_the_total_deadline() {
        // services-r3-01: a viewer that never disconnects must NOT camp its slot forever. With a
        // short deadline (test seam), serve_log_stream emits its header/note then closes the socket
        // when LOG_STREAM_MAX_MS elapses, so the reader observes EOF (read returns 0). Before the
        // fix, serve_log_stream looped forever with no total deadline.
        use super::serve_log_stream_for;
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};

        let _lock = lock_conn_tests();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_log_stream_for(sock, 300);
            done_tx.send(()).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let start = std::time::Instant::now();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(4))
            .expect("log stream handler did not return at its deadline");
        assert!(start.elapsed() < std::time::Duration::from_secs(4));
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn peek_classifies_healthz_log_and_upgrade_so_each_charges_the_right_budget() {
        // services-r3-01 / services-r3-04: the peek routes /healthz, a plain GET, and a WS upgrade
        // distinctly. Healthz must be classified as Healthz (the accept loop then serves it with NO
        // slot charged, so a liveness probe is never shed at the cap); a plain GET => LogStream
        // (charges the small log budget); a real upgrade => Upgrade (charges the mesh budget).
        use super::{classify_ws_peek, WsKind};
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};

        fn classify(req: &[u8]) -> WsKind {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let req = req.to_vec();
            let h = std::thread::spawn(move || {
                let mut c = TcpStream::connect(addr).unwrap();
                c.write_all(&req).unwrap();
                // Hold the socket open until classification has peeked.
                std::thread::sleep(std::time::Duration::from_millis(150));
            });
            let (sock, _) = listener.accept().unwrap();
            // Give the client a moment to send before we peek.
            std::thread::sleep(std::time::Duration::from_millis(30));
            let kind = classify_ws_peek(&sock);
            h.join().unwrap();
            kind
        }

        assert_eq!(
            classify(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"),
            WsKind::Healthz,
            "healthz probe is classified as Healthz (served with NO slot charged)"
        );
        assert_eq!(
            classify(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            WsKind::LogStream,
            "a plain non-upgrade GET is a log viewer (charges the small log budget)"
        );
        assert_eq!(
            classify(
                b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            ),
            WsKind::Upgrade,
            "a real WS upgrade is a mesh link (charges the mesh budget)"
        );
    }

    // The log budget must be a small reserve, strictly smaller than the mesh budget, so even a
    // fully-saturated log pool is a bounded, negligible resource cost and can never dominate; and at
    // least one viewer can still watch. These are compile-time invariants of the two constants, so a
    // const assertion enforces them at BUILD time (stronger than a runtime test, and it cannot drift).
    const _: () = assert!(
        MAX_LOG_CONNS < MAX_CONNS,
        "log viewers get a strictly smaller budget than mesh links"
    );
    const _: () = assert!(
        MAX_LOG_CONNS >= 1,
        "at least one viewer can still watch the log"
    );

    #[test]
    fn admit_and_serve_ws_runs_classify_off_the_accept_thread_and_reconciles_budgets() {
        // services-r3-02 / r5-01: the accept loop admits against the PENDING-peek budget and hands the
        // socket to admit_and_serve_ws on a worker thread, which does the (timeout-bounded,
        // slowloris-prone) peek there instead of inline, then charges the REAL pool once the kind is
        // known. The correctness we protect:
        //   * Healthz is EXEMPT and served EVEN WHEN THE MESH POOL IS FULL (the r5-01 regression: the
        //     r3-02 version charged a mesh slot up front, so at MAX_CONNS a healthz was shed, failing
        //     the Cloud Run check and restart-looping the region organically, no attacker).
        //   * A LogStream charges exactly one LOG slot and ZERO mesh slots, so a slow viewer can never
        //     camp mesh; the whole mesh budget stays free while a log viewer serves.
        //   * Healthz / Empty leave no slot held in any pool (no leak).
        use super::{
            admit_and_serve_ws, admit_conn, admit_ws_pending, ACTIVE_CONNS, ACTIVE_LOG_CONNS,
            ACTIVE_WS_PENDING, MAX_CONNS, MAX_LOG_CONNS,
        };
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::Ordering;

        let _lock = lock_conn_tests();
        assert_eq!(ACTIVE_CONNS.load(Ordering::SeqCst), 0, "clean start (mesh)");
        assert_eq!(
            ACTIVE_LOG_CONNS.load(Ordering::SeqCst),
            0,
            "clean start (log)"
        );

        // Helper: run admit_and_serve_ws on a worker (as the accept loop would), feeding it `req`.
        // Returns the bytes the client read back (so a caller can assert healthz actually SERVED a
        // response rather than being shed) once the handler returns.
        fn run(req: &[u8]) -> Vec<u8> {
            let pending = admit_ws_pending().expect("pending-peek slot admitted");
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let req = req.to_vec();
            let client = std::thread::spawn(move || {
                let mut c = TcpStream::connect(addr).unwrap();
                c.write_all(&req).unwrap();
                // Drain to EOF so the handler completes (healthz writes then closes).
                let mut sink = Vec::new();
                let _ = c.read_to_end(&mut sink);
                sink
            });
            let (sock, _) = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(30)); // let the client send
            let (ev_tx, _ev_rx) = event_channel();
            std::thread::spawn(move || {
                admit_and_serve_ws(sock, pending, &ev_tx);
            })
            .join()
            .unwrap();
            client.join().unwrap()
        }

        // Healthz: served with NO slot held afterward (pending slot released, not leaked). The driver
        // loop is not running in this test, so healthz reports 503 (stale tick) - the point is that it
        // SERVES an HTTP response at all (200 or 503) rather than being shed (which returns nothing).
        let resp = run(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(
            resp.windows(4).any(|w| w == b"HTTP"),
            "healthz served an HTTP response (not shed)"
        );
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "healthz charged NO mesh slot (exempt)"
        );
        assert_eq!(
            ACTIVE_LOG_CONNS.load(Ordering::SeqCst),
            0,
            "healthz charged NO log slot either"
        );
        assert_eq!(
            ACTIVE_WS_PENDING.load(Ordering::SeqCst),
            0,
            "pending-peek slot released after classification"
        );

        // r5-01 REGRESSION GUARD: with the mesh pool SATURATED to MAX_CONNS, a healthz still serves.
        // The r3-02 code charged a mesh slot before classifying, so this shed the probe at the cap and
        // organically restart-looped the region. Fill the mesh pool, then prove healthz is unaffected.
        let mut mesh_full: Vec<_> = (0..MAX_CONNS)
            .map(|_| admit_conn().expect("saturate the mesh pool"))
            .collect();
        assert_eq!(ACTIVE_CONNS.load(Ordering::SeqCst), MAX_CONNS, "mesh full");
        let resp = run(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(
            resp.windows(4).any(|w| w == b"HTTP"),
            "healthz STILL serves an HTTP response with the mesh pool full (never shed at the mesh cap)"
        );
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            MAX_CONNS,
            "healthz did not touch the mesh pool (still exactly MAX_CONNS from our guards)"
        );
        mesh_full.clear();
        assert_eq!(ACTIVE_CONNS.load(Ordering::SeqCst), 0, "mesh pool released");

        // Empty: a probe with no payload leaves no slot held and serves nothing.
        run(b"");
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "empty probe held no mesh slot"
        );

        // LogStream: while it serves, it holds a LOG slot and NO mesh slot, and the full mesh budget
        // stays free (a real link is admissible even while a log viewer is being served). Use the
        // short-deadline test seam so the log handler closes promptly.
        std::env::set_var("HOP_LOG_STREAM_MAX_MS", "300");
        let pending = admit_ws_pending().expect("pending-peek slot admitted");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut sink = Vec::new();
            let _ = c.read_to_end(&mut sink); // block until the deadline closes the stream
        });
        let (sock, _) = listener.accept().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let (ev_tx, _ev_rx) = event_channel();
        let worker = std::thread::spawn(move || admit_and_serve_ws(sock, pending, &ev_tx));
        // Give the worker time to classify + reconcile onto the log pool, then observe mid-serve.
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "a log viewer holds NO mesh slot (reconciled off it), so mesh links are never starved"
        );
        assert_eq!(
            ACTIVE_LOG_CONNS.load(Ordering::SeqCst),
            1,
            "a log viewer charges exactly one LOG slot"
        );
        // The whole mesh budget is free even while a log viewer is being served.
        let mut mesh_guards = Vec::new();
        for _ in 0..MAX_CONNS {
            mesh_guards.push(admit_conn().expect("mesh link admissible while a log viewer serves"));
        }
        assert!(ACTIVE_LOG_CONNS.load(Ordering::SeqCst) <= MAX_LOG_CONNS);
        mesh_guards.clear();
        worker.join().unwrap();
        client.join().unwrap();
        std::env::remove_var("HOP_LOG_STREAM_MAX_MS");
        assert_eq!(
            ACTIVE_LOG_CONNS.load(Ordering::SeqCst),
            0,
            "log slot released when the viewer's deadline closed the stream"
        );
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "no leaked mesh slots"
        );
    }

    #[test]
    fn spawn_tcp_conn_admits_a_connection_and_releases_its_slot_on_close() {
        // The raw-TCP accept-loop body: admit a mesh slot and bridge the socket to serve_tcp (an Up
        // event reaches the driver). When the peer disconnects, serve_tcp returns and the slot guard
        // drops, releasing the mesh slot (no leak on a normal disconnect).
        use super::{spawn_tcp_conn, Ev, ACTIVE_CONNS};
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::Ordering;
        let _lock = lock_conn_tests();
        assert_eq!(ACTIVE_CONNS.load(Ordering::SeqCst), 0, "clean start");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (sock, _) = listener.accept().unwrap();
        let (ev_tx, ev_rx) = event_channel();
        spawn_tcp_conn(sock, &ev_tx);
        let up = ev_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("link up");
        assert!(
            matches!(up, Ev::Up(_, super::Role::Responder, _)),
            "spawn_tcp_conn admits and bridges an Up event"
        );
        drop(client); // disconnect: serve_tcp returns and the guard releases the slot
        let start = std::time::Instant::now();
        while ACTIVE_CONNS.load(Ordering::SeqCst) != 0
            && start.elapsed() < std::time::Duration::from_secs(3)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "the mesh slot is released when the connection closes"
        );
    }

    #[test]
    fn dispatch_ws_accept_fast_paths_healthz_and_admits_a_real_upgrade() {
        // The WS accept-loop body. (a) A buffered `GET /healthz` is served EXEMPT from every budget on
        // its own thread (no mesh/pending slot charged). (b) A real WS upgrade is admitted via the
        // pending budget and bridged to the driver as a mesh link (an Up event arrives), then its slot
        // is released when the link closes.
        use super::{dispatch_ws_accept, Ev, ACTIVE_CONNS, ACTIVE_WS_PENDING};
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::Ordering;
        let _lock = lock_conn_tests();

        // (a) healthz fast-path: an HTTP response comes back and no slot is charged.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            let mut sink = Vec::new();
            let _ = c.read_to_end(&mut sink);
            sink
        });
        let (sock, _) = listener.accept().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(25)); // let the probe's bytes arrive
        let (ev_tx, _ev_rx) = event_channel();
        dispatch_ws_accept(sock, &ev_tx);
        let resp = probe.join().unwrap();
        assert!(
            resp.windows(4).any(|w| w == b"HTTP"),
            "healthz was served an HTTP response"
        );
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "healthz charged no mesh slot"
        );
        assert_eq!(
            ACTIVE_WS_PENDING.load(Ordering::SeqCst),
            0,
            "healthz charged no pending slot"
        );

        // (b) a real WS upgrade: admitted (pending budget) and bridged as a mesh link.
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr2).unwrap();
            let (mut ws, _r) =
                tungstenite::client(format!("ws://127.0.0.1:{}/", addr2.port()), stream).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(80)); // hold the link, then close
            let _ = ws.close(None);
            let _ = ws.flush();
        });
        let (sock2, _) = listener2.accept().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let (ev_tx2, ev_rx2) = event_channel();
        dispatch_ws_accept(sock2, &ev_tx2);
        let up = ev_rx2
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("upgrade link up");
        assert!(
            matches!(up, Ev::Up(_, super::Role::Responder, _)),
            "a real WS upgrade is admitted and bridged as a mesh link"
        );
        client.join().unwrap();
        let start = std::time::Instant::now();
        while ACTIVE_CONNS.load(Ordering::SeqCst) != 0
            && start.elapsed() < std::time::Duration::from_secs(3)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "the mesh slot is released when the upgrade link closes"
        );
    }

    #[test]
    fn admit_and_serve_ws_sheds_an_upgrade_and_a_log_viewer_when_their_pools_are_full() {
        // The pool-full shed branches of admit_and_serve_ws: with the mesh pool saturated a real WS
        // upgrade is shed on the mesh budget (no Ev::Up reaches the driver); with the log pool
        // saturated a plain GET (log viewer) is shed on the log budget. Neither leaks a slot.
        use super::{
            admit_and_serve_ws, admit_conn, admit_log_conn, admit_ws_pending, Ev, ACTIVE_CONNS,
            ACTIVE_LOG_CONNS, MAX_CONNS, MAX_LOG_CONNS,
        };
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::Ordering;
        let _lock = lock_conn_tests();

        // Send `req`, run admit_and_serve_ws on the accepted socket, and report whether it produced an
        // Ev::Up (i.e. was admitted rather than shed). Raw bytes (no tungstenite handshake) so a shed
        // that drops the socket never blocks the client.
        fn produced_up(req: &[u8]) -> bool {
            let pending = admit_ws_pending().expect("pending slot");
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let req = req.to_vec();
            let client = std::thread::spawn(move || {
                let mut c = TcpStream::connect(addr).unwrap();
                let _ = c.write_all(&req);
                std::thread::sleep(std::time::Duration::from_millis(80));
            });
            let (sock, _) = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20)); // let the request bytes arrive
            let (ev_tx, ev_rx) = event_channel();
            std::thread::spawn(move || admit_and_serve_ws(sock, pending, &ev_tx))
                .join()
                .unwrap();
            client.join().unwrap();
            matches!(
                ev_rx.recv_timeout(std::time::Duration::from_millis(200)),
                Ok(Ev::Up(..))
            )
        }

        // Mesh pool saturated: a real upgrade is shed (no Up), leaving the mesh count unchanged.
        let mut mesh: Vec<_> = (0..MAX_CONNS).map(|_| admit_conn().unwrap()).collect();
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            MAX_CONNS,
            "mesh saturated"
        );
        assert!(
            !produced_up(
                b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            ),
            "a WS upgrade is shed when the mesh pool is full"
        );
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            MAX_CONNS,
            "the shed did not charge (or leak) a mesh slot"
        );
        mesh.clear();

        // Log pool saturated: a plain GET (a log viewer) is shed on the log budget.
        let mut logs: Vec<_> = (0..MAX_LOG_CONNS)
            .map(|_| admit_log_conn().unwrap())
            .collect();
        assert_eq!(
            ACTIVE_LOG_CONNS.load(Ordering::SeqCst),
            MAX_LOG_CONNS,
            "log pool saturated"
        );
        assert!(
            !produced_up(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            "a log viewer never produces an Up (and here it is shed on a full log pool)"
        );
        assert_eq!(
            ACTIVE_LOG_CONNS.load(Ordering::SeqCst),
            MAX_LOG_CONNS,
            "the shed did not charge (or leak) a log slot"
        );
        logs.clear();
        assert_eq!(
            ACTIVE_CONNS.load(Ordering::SeqCst),
            0,
            "no leaked mesh slots"
        );
        assert_eq!(
            ACTIVE_LOG_CONNS.load(Ordering::SeqCst),
            0,
            "no leaked log slots"
        );
    }
}

#[cfg(test)]
mod handoff_dedup_tests {
    // services-r2-04: age-based eviction of the handoff/spool dedup maps, replacing the wholesale
    // clear() that let already-handed bundles be redundantly re-written to Firestore after a reset.
    // The helper now lives in the always-compiled `mailbox` module, so this runs in the default
    // build (not only under --features firestore).
    use super::mailbox::evict_expired;
    use std::collections::HashMap;

    #[test]
    fn evict_expired_drops_only_past_entries_and_keeps_live_ones() {
        let now = 1_000_000u64;
        let mut m: HashMap<u32, u64> = HashMap::new();
        m.insert(1, now - 1); // expired
        m.insert(2, now); // exactly now -> expired (not > now)
        m.insert(3, now + 1); // still live
        m.insert(4, 0); // never-expire sentinel -> kept
        evict_expired(&mut m, now);
        assert!(!m.contains_key(&1), "past entry dropped");
        assert!(!m.contains_key(&2), "at-now entry dropped");
        assert!(
            m.contains_key(&3),
            "future entry kept (still deduped, not re-written)"
        );
        assert!(m.contains_key(&4), "never-expire entry kept");
    }

    #[test]
    fn reload_ingest_dedup_map_evicts_expired_ids_so_it_is_bounded_not_a_leak() {
        // The warm partition-reload thread used to accumulate an unbounded HashSet<BundleId> that
        // grew for the whole process lifetime. It now keys each id by the bundle's own expiry and
        // runs evict_expired every cycle, exactly like the handed/spooled/pulled dedup maps. This
        // models that reload dedup: a bundle seen while still live is deduped (not re-ingested), but
        // once its expiry passes the entry is dropped, so the map cannot grow without bound.
        use hop_core::bundle::BundleId;
        let id_a: BundleId = [1u8; 32];
        let id_b: BundleId = [2u8; 32];
        let mut ingested: HashMap<BundleId, u64> = HashMap::new();

        // Cycle 1 at t=1000: both bundles present, both fresh (ingest once, remembered).
        let mut t = 1_000u64;
        evict_expired(&mut ingested, t);
        assert!(ingested.insert(id_a, t + 100).is_none(), "a ingested once");
        assert!(
            ingested.insert(id_b, t + 5_000).is_none(),
            "b ingested once"
        );
        // Same cycle re-read: both already remembered, so neither re-ingests.
        assert!(ingested.insert(id_a, t + 100).is_some(), "a deduped");
        assert!(ingested.insert(id_b, t + 5_000).is_some(), "b deduped");

        // Cycle 2 at t=1200: a's bundle has expired and been TTL-swept from the partition. Age
        // eviction drops a's entry so the map does not retain forever-dead ids; b is still live.
        t = 1_200;
        evict_expired(&mut ingested, t);
        assert!(
            !ingested.contains_key(&id_a),
            "expired id forgotten (bounded, no leak)"
        );
        assert!(
            ingested.contains_key(&id_b),
            "still-live id kept (stays deduped)"
        );
    }

    #[test]
    fn evict_expired_bounds_a_pathological_all_future_set_without_a_wholesale_clear() {
        // The old code did `if len > 100_000 { clear() }`, a full wipe that let every entry be
        // redundantly re-put next cycle. Age eviction can't shrink an all-future set, so a hard cap
        // fallback evicts the nearest-to-expiry surplus while KEEPING most entries deduped (no wipe).
        let now = 1_000u64;
        let cap = 100_000usize;
        let mut m: HashMap<u64, u64> = HashMap::new();
        // cap + 25 entries, all far in the future (so age eviction removes none of them).
        for i in 0..(cap as u64 + 25) {
            m.insert(i, now + 10_000_000 + i); // strictly increasing future expiries
        }
        evict_expired(&mut m, now);
        assert_eq!(
            m.len(),
            cap,
            "trimmed to exactly the cap, NOT wiped to empty like the old clear()"
        );
        // The nearest-to-expiry (smallest expiry = smallest i) were the victims; the far-future
        // ones are retained, so most bundles stay deduped and are not redundantly re-written.
        assert!(!m.contains_key(&0), "nearest-to-expiry evicted");
        assert!(
            m.contains_key(&(cap as u64 + 24)),
            "far-future entry retained (still deduped)"
        );
    }
}

#[cfg(test)]
mod pure_helper_tests {
    use super::*;

    #[test]
    fn host_of_extracts_the_identify_name_from_a_ws_url() {
        // §29: a relay's identify name is the host of its --advertise URL, so a trace shows the
        // relay by domain. Strip the ws/wss scheme and any path; a bare host is passed through.
        assert_eq!(
            host_of("wss://us-central1.relay.hopme.sh/"),
            "us-central1.relay.hopme.sh"
        );
        assert_eq!(
            host_of("ws://eu.relay.hopme.sh:8080/x"),
            "eu.relay.hopme.sh:8080"
        );
        assert_eq!(host_of("wss://plainhost"), "plainhost");
        assert_eq!(
            host_of("relay.example.com/path"),
            "relay.example.com",
            "no scheme: still strips the path"
        );
        assert_eq!(host_of("bare"), "bare");
    }

    #[test]
    fn hms_formats_utc_hms_and_wraps_at_a_day() {
        // The live-log timestamp is UTC HH:MM:SS derived from epoch ms; it must wrap the hour at 24.
        assert_eq!(hms(0), "00:00:00");
        assert_eq!(hms(1_000), "00:00:01");
        assert_eq!(hms(61_000), "00:01:01");
        assert_eq!(hms(3_661_000), "01:01:01");
        // 25h past the epoch wraps back to 01:00:00 (hour mod 24), proving the wrap, not a raw count.
        assert_eq!(hms(25 * 3_600_000), "01:00:00");
        // Sub-second ms are floored, not rounded up.
        assert_eq!(hms(1_999), "00:00:01");
    }

    #[test]
    fn region_seed_is_deterministic_distinct_per_region_and_bound_to_the_base() {
        // §27/§28: every node derives a region's backbone seed the same way from the shared base +
        // region name, so any node can address any region WITHOUT a per-region secret. The
        // derivation must be deterministic (same inputs => same seed), distinct per region, and
        // change if the base seed changes (so two different fleets never collide).
        let base = [3u8; 32];
        let a = region_seed(&base, "us-central1");
        let a2 = region_seed(&base, "us-central1");
        let b = region_seed(&base, "europe-west1");
        assert_eq!(
            a, a2,
            "same base+region => identical seed (any node computes it)"
        );
        assert_ne!(a, b, "different regions get distinct seeds");
        // A different base seed yields a different region seed (fleet isolation).
        let other_base = [4u8; 32];
        assert_ne!(
            region_seed(&other_base, "us-central1"),
            a,
            "the region seed is bound to the base seed"
        );
        // It is not a trivial passthrough of the base.
        assert_ne!(a, base, "the seed is a hash, not the base itself");
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn region_node_b58_matches_the_identity_derived_from_the_region_seed() {
        // The handoff addresses a region's partition by the base58 of the node derived from that
        // region's seed. It must equal the address you'd get by deriving the Identity directly, or a
        // handoff would be written to the wrong partition and silently lost.
        let base = [5u8; 32];
        let region = "asia-east1";
        let got = region_node_b58(&base, region);
        let expected =
            bs58::encode(Identity::from_secret_bytes(&region_seed(&base, region)).address())
                .into_string();
        assert_eq!(
            got, expected,
            "region_node_b58 == b58(address(region_seed))"
        );
        // Different regions map to different partition nodes (no cross-region aliasing).
        assert_ne!(
            region_node_b58(&base, "asia-east1"),
            region_node_b58(&base, "asia-south1")
        );
    }

    #[test]
    fn short_b58_is_a_ten_char_prefix() {
        // Compact log lines use a 10-char base58 prefix of an address; it must be a true prefix of
        // the full encoding, capped at 10 chars.
        let addr = [42u8; 32];
        let full = bs58::encode(addr).into_string();
        let short = short_b58(&addr);
        assert!(short.len() <= 10);
        assert_eq!(
            short.len(),
            10,
            "a 32-byte address b58 is well over 10 chars"
        );
        assert!(
            full.starts_with(&short),
            "the short form is a prefix of the full"
        );
    }

    #[test]
    fn public_log_stream_flag_reads_the_env() {
        // services-03: the public per-event stream is opt-in via HOP_PUBLIC_LOG_STREAM; only the
        // truthy values enable it, everything else (incl. unset) leaves it off.
        // Hold the shared env lock so this test's set_var can't race a parallel test that reads the
        // flag via subscribe().
        let _env = PUBLIC_LOG_ENV_LOCK.lock().unwrap();
        for v in ["1", "true", "yes"] {
            std::env::set_var("HOP_PUBLIC_LOG_STREAM", v);
            assert!(public_log_stream_enabled(), "{v} enables the public stream");
        }
        for v in ["0", "false", "no", "", "garbage"] {
            std::env::set_var("HOP_PUBLIC_LOG_STREAM", v);
            assert!(!public_log_stream_enabled(), "{v:?} leaves it off");
        }
        std::env::remove_var("HOP_PUBLIC_LOG_STREAM");
        assert!(!public_log_stream_enabled(), "unset => off (safe default)");
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn tmp(name: &str) -> String {
        format!(
            "{}/hop-relayd-id-{name}-{}-{}.key",
            std::env::temp_dir().display(),
            std::process::id(),
            NEXT_LINK.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn load_identity_from_a_valid_32_byte_file_is_deterministic() {
        // A mounted 32-byte secret (--identity-file) must derive the SAME address every time, so the
        // relay's address is stable across restarts (peers keep reaching it). Two loads of the same
        // seed file yield the same address; a different seed yields a different one.
        let path = tmp("valid");
        std::fs::write(&path, [7u8; 32]).unwrap();
        let a = load_identity(&Some(path.clone()), "unused.key").address();
        let b = load_identity(&Some(path.clone()), "unused.key").address();
        assert_eq!(a, b, "same seed file => same address across loads");
        assert_eq!(
            a,
            Identity::from_secret_bytes(&[7u8; 32]).address(),
            "the address is derived from the exact seed bytes"
        );
        std::fs::write(&path, [8u8; 32]).unwrap();
        let c = load_identity(&Some(path.clone()), "unused.key").address();
        assert_ne!(a, c, "a different seed file => a different address");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_identity_panics_on_a_wrong_sized_identity_file() {
        // A misconfigured secret (not exactly 32 bytes) must FAIL LOUDLY (panic) rather than silently
        // generate a throwaway identity, which would give the relay a wrong/unstable address.
        let path = tmp("short");
        std::fs::write(&path, [1u8; 16]).unwrap(); // 16 bytes, not 32
        let r = std::panic::catch_unwind(|| load_identity(&Some(path.clone()), "unused.key"));
        assert!(
            r.is_err(),
            "a wrong-sized --identity-file must panic, not fall back"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_identity_generates_and_persists_when_no_key_exists_then_reloads_it() {
        // First run (no --identity-file, key_path missing): generate a fresh identity and PERSIST it,
        // so the SECOND run loads the same seed and keeps the same address (stable across restarts).
        let key = tmp("persist");
        let _ = std::fs::remove_file(&key);
        let first = load_identity(&None, &key).address();
        assert!(
            std::fs::metadata(&key).is_ok(),
            "the seed was persisted to key_path"
        );
        let second = load_identity(&None, &key).address();
        assert_eq!(
            first, second,
            "the persisted seed is reloaded => stable address across restarts"
        );
        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn load_identity_panics_on_an_unreadable_identity_file() {
        // A mounted secret that can't be read (missing/permission-denied) must FAIL LOUDLY rather than
        // fall back to a throwaway identity, which would give the relay a wrong/unstable address.
        let missing = format!(
            "{}/hop-relayd-does-not-exist-{}-{}.key",
            std::env::temp_dir().display(),
            std::process::id(),
            NEXT_LINK.fetch_add(1, Ordering::Relaxed)
        );
        let _ = std::fs::remove_file(&missing);
        let r = std::panic::catch_unwind(|| load_identity(&Some(missing.clone()), "unused.key"));
        assert!(
            r.is_err(),
            "an unreadable --identity-file must panic, not silently fall back"
        );
    }

    #[test]
    fn load_identity_generates_and_warns_when_the_seed_cannot_be_persisted() {
        // No --identity-file and a key_path whose parent directory does not exist: the read fails, so a
        // fresh identity is generated; persisting it fails (no such dir), which must warn loudly but
        // still return a usable identity (the relay comes up, just with a warned-about unstable seed).
        let unwritable = format!(
            "/hop-relayd-no-such-dir-{}-{}/seed.key",
            std::process::id(),
            NEXT_LINK.fetch_add(1, Ordering::Relaxed)
        );
        let id = load_identity(&None, &unwritable);
        // A real identity is returned (address derivable) despite the failed persist.
        assert_eq!(id.address().len(), Identity::generate().address().len());
        assert!(
            std::fs::metadata(&unwritable).is_err(),
            "the seed was NOT persisted (the parent dir does not exist)"
        );
    }
}

#[cfg(test)]
mod healthz_tests {
    use super::*;
    use std::net::TcpStream;

    // serve_healthz reads the process-global LAST_TICK_MS; serialize on the shared driver-statics
    // lock (also held by the driver-loop / shutdown tests) so no test observes another's transient
    // tick value. Recover from poisoning so a single failing assertion reports ITS failure rather
    // than cascading a PoisonError across the other tests.
    use super::lock_driver_statics as lock_healthz;

    #[test]
    fn healthz_status_reports_stale_degraded_and_healthy() {
        // Readiness requires both a fresh driver tick and durable custody. Liveness is tested
        // separately because a backend outage must stop traffic without causing restart churn.
        assert_eq!(
            healthz_status(0, 1_000_000, DurabilityReadiness::Ready, 0, 0, 0),
            ("503 Service Unavailable", "stale".to_string())
        );
        let (s, b) = healthz_status(1_000_000, 1_000_500, DurabilityReadiness::NotReady, 0, 7, 0);
        assert_eq!(s, "503 Service Unavailable");
        assert_eq!(
            b, "not ready: durability=NotReady unreconciled=0 mirror_rejected=7 mirror_failed=0",
            "a rejected durable write makes the relay unready"
        );
        let (s, b) = healthz_status(
            1_000_000,
            1_000_500,
            DurabilityReadiness::Quarantined,
            1,
            0,
            2,
        );
        assert_eq!(s, "503 Service Unavailable");
        assert_eq!(
            b,
            "not ready: durability=Quarantined unreconciled=1 mirror_rejected=0 mirror_failed=2"
        );
        assert_eq!(
            healthz_status(1_000_000, 1_000_500, DurabilityReadiness::Ready, 0, 0, 0,),
            ("200 OK", "ok".to_string())
        );
        assert_eq!(
            healthz_status(
                1_000_000,
                1_000_000 + HEALTHZ_STALE_MS + 1,
                DurabilityReadiness::Ready,
                0,
                0,
                0,
            ),
            ("503 Service Unavailable", "stale".to_string()),
            "a tick older than the stale window is a restart-worthy 503"
        );
    }

    #[test]
    fn livez_only_tracks_the_driver_heartbeat() {
        assert_eq!(
            livez_status(0, 1_000_000),
            ("503 Service Unavailable", "stale")
        );
        assert_eq!(livez_status(1_000_000, 1_000_500), ("200 OK", "live"));
        assert_eq!(
            livez_status(1_000_000, 1_000_000 + HEALTHZ_STALE_MS + 1),
            ("503 Service Unavailable", "stale")
        );
    }

    /// Drive serve_healthz over a real loopback socket and return the raw HTTP response.
    fn drive_healthz() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_healthz(sock);
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).ok();
        server.join().unwrap();
        resp
    }

    #[test]
    fn healthz_is_503_before_the_first_tick() {
        // F-17: before the driver has ticked once (LAST_TICK_MS == 0) the instance is not yet live,
        // so /healthz reports 503 stale — Cloud Run must NOT route traffic to a not-yet-started node.
        let _lock = lock_healthz();
        LAST_TICK_MS.store(0, Ordering::Relaxed);
        let resp = drive_healthz();
        assert!(
            resp.starts_with("HTTP/1.1 503"),
            "no tick yet => 503: {resp}"
        );
        assert!(resp.trim_end().ends_with("stale"));
    }

    #[test]
    fn healthz_is_200_when_the_driver_ticked_recently() {
        // F-17: a fresh tick within HEALTHZ_STALE_MS => 200 ok, so a healthy instance keeps serving.
        let _lock = lock_healthz();
        LAST_TICK_MS.store(now_ms(), Ordering::Relaxed);
        let resp = drive_healthz();
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "recent tick => 200: {resp}"
        );
        assert!(resp.trim_end().ends_with("ok"));
    }

    #[test]
    fn healthz_goes_503_when_the_tick_is_stale() {
        // F-17 (the core proof): a wedged driver stops advancing LAST_TICK_MS. Once the last tick is
        // older than HEALTHZ_STALE_MS, /healthz flips to 503 so Cloud Run restarts the wedged
        // instance instead of the default TCP probe passing forever (a wedged instance IS the region).
        let _lock = lock_healthz();
        let stale = now_ms().saturating_sub(HEALTHZ_STALE_MS + 5_000);
        LAST_TICK_MS.store(stale, Ordering::Relaxed);
        let resp = drive_healthz();
        assert!(
            resp.starts_with("HTTP/1.1 503"),
            "a tick older than the stale window => 503 (restart the wedged instance): {resp}"
        );
        // Restore a fresh tick so a later concurrent/ordered test isn't surprised.
        LAST_TICK_MS.store(now_ms(), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tcp_framing_tests {
    use super::*;
    use std::net::TcpStream;

    /// serve_tcp reads 4-byte big-endian length-prefixed frames off the socket and pushes each
    /// payload to the driver as an Ev::Data. This stands up a real loopback socket, feeds it framed
    /// packets, and asserts the driver channel receives EXACTLY those payloads in order — the wire
    /// contract path A relies on. An oversized length prefix (over MAX_FRAME_BYTES) must drop the
    /// connection (Down) without ever emitting a giant Data.
    fn run_serve_tcp(client_writes: impl FnOnce(&mut TcpStream) + Send + 'static) -> Vec<Ev> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, ev_rx) = event_channel();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_tcp(sock, Role::Responder, &ev_tx);
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client_writes(&mut client);
        // Half-close so serve_tcp's read loop hits EOF and returns, emitting Ev::Down.
        client.shutdown(std::net::Shutdown::Write).ok();
        // Drain the (finite) events until the server thread finishes and the channel closes.
        let mut evs = Vec::new();
        server.join().unwrap();
        while let Ok(ev) = ev_rx.try_recv() {
            evs.push(ev);
        }
        evs
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn serve_tcp_delivers_length_framed_payloads_in_order() {
        // The raw-TCP bearer frames each link packet with a 4-byte BE length. serve_tcp must decode
        // back the EXACT payloads, in order — a regression in the framing would corrupt every packet.
        let evs = run_serve_tcp(|c| {
            c.write_all(&framed(b"hello")).unwrap();
            c.write_all(&framed(b"world!!")).unwrap();
            c.flush().unwrap();
        });
        // Expect: Up, Data(hello), Data(world!!), Down.
        let datas: Vec<Vec<u8>> = evs
            .iter()
            .filter_map(|e| match e {
                Ev::Data(_, b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            datas,
            vec![b"hello".to_vec(), b"world!!".to_vec()],
            "payloads decoded exactly and in order"
        );
        assert!(
            matches!(evs.first(), Some(Ev::Up(_, Role::Responder, _))),
            "first event is link-up as Responder"
        );
        assert!(
            matches!(evs.last(), Some(Ev::Down(_))),
            "clean EOF ends with link-down"
        );
    }

    #[test]
    fn serve_ws_dispatches_healthz_to_the_health_handler() {
        // serve_ws is the WS front-door handler: the accept loop peek-classifies, then serve_ws
        // dispatches. A Healthz kind must be answered by serve_healthz (a plain HTTP response), NOT
        // fed into the WS driver — so a health probe on the $PORT front door works without a WS
        // upgrade. Drive serve_ws(kind=Healthz) directly and assert an HTTP status line comes back.
        // (Do NOT touch LAST_TICK_MS here — that global is owned by the serialized healthz_tests; we
        // only assert that SOME health HTTP response is produced, whatever the current tick state.)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, _ev_rx) = event_channel();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_ws(sock, WsKind::Healthz, &ev_tx);
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).ok();
        server.join().unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.1 503"),
            "serve_ws(Healthz) answers with the health handler's HTTP response, not a WS upgrade: {resp}"
        );
    }

    #[test]
    fn serve_ws_empty_kind_serves_nothing() {
        // A WsKind::Empty (a bare probe with no payload) is a no-op: serve_ws must return immediately
        // without spawning a WS session or writing anything, so a connectivity probe can't wedge a
        // handler. The driver channel receives NO Up event for an Empty connection.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, ev_rx) = event_channel();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_ws(sock, WsKind::Empty, &ev_tx);
        });
        let _client = TcpStream::connect(addr).unwrap();
        server.join().unwrap();
        assert!(
            ev_rx.try_recv().is_err(),
            "an Empty connection produces no driver event (no link is opened)"
        );
    }

    #[test]
    fn serve_tcp_drops_a_frame_over_the_size_cap_without_emitting_it() {
        // services-05: an oversized length prefix (> MAX_FRAME_BYTES) must drop the connection rather
        // than allocate/read a giant buffer — the DoS backstop. No Data is emitted for the bad frame;
        // the loop breaks and the link goes Down. We send a length just over the cap and then bytes.
        let evs = run_serve_tcp(|c| {
            let bad_len = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
            c.write_all(&bad_len).unwrap();
            // A little data after the bad prefix; serve_tcp must NOT read/emit it as a frame.
            c.write_all(b"junk").unwrap();
            c.flush().unwrap();
        });
        assert!(
            !evs.iter().any(|e| matches!(e, Ev::Data(..))),
            "an over-cap frame is never delivered as Data"
        );
        assert!(
            matches!(evs.last(), Some(Ev::Down(_))),
            "the connection is dropped (link-down) on an over-cap frame"
        );
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    fn args(v: &[&str]) -> std::vec::IntoIter<String> {
        v.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn bare_invocation_defaults_to_the_path_a_tcp_bearer() {
        // A bare `hop-relayd` (no --listen/--ws) must keep listening on TCP 9443 (path A), or a plain
        // VM invocation would come up with no bearer at all.
        let c = parse_args(args(&[]));
        assert_eq!(
            c.listen.as_deref(),
            Some("0.0.0.0:9443"),
            "no bearer flags => TCP 9443 default"
        );
        assert!(c.ws.is_none());
        assert_eq!(c.db, "hop-relay.db");
        assert_eq!(c.mesh_fanout, 0);
        assert!(c.peers.is_empty());
    }

    #[test]
    fn an_explicit_ws_suppresses_the_tcp_default() {
        // If the operator picks --ws (the Cloud Run path), the bare-invocation TCP fallback must NOT
        // also fire, or the daemon would bind an unwanted 9443 as well.
        let c = parse_args(args(&["--ws", "0.0.0.0:8080"]));
        assert_eq!(c.ws.as_deref(), Some("0.0.0.0:8080"));
        assert!(c.listen.is_none(), "an explicit --ws leaves --listen unset");
    }

    #[test]
    fn every_flag_parses_and_repeated_peer_accumulates() {
        let c = parse_args(args(&[
            "--listen",
            "1.2.3.4:1",
            "--ws",
            "5.6.7.8:2",
            "--db",
            "/tmp/x.db",
            "--identity-file",
            "/k",
            "--firestore",
            "proj",
            "--region",
            "us",
            "--advertise",
            "wss://us.relay/",
            "--mesh-fanout",
            "3",
            "--peer",
            "a:1",
            "--peer",
            "b:2",
        ]));
        assert_eq!(c.listen.as_deref(), Some("1.2.3.4:1"));
        assert_eq!(c.ws.as_deref(), Some("5.6.7.8:2"));
        assert_eq!(c.db, "/tmp/x.db");
        assert_eq!(c.identity_file.as_deref(), Some("/k"));
        assert_eq!(c.firestore.as_deref(), Some("proj"));
        assert_eq!(c.region.as_deref(), Some("us"));
        assert_eq!(c.advertise.as_deref(), Some("wss://us.relay/"));
        assert_eq!(c.mesh_fanout, 3);
        assert_eq!(c.peers, vec!["a:1".to_string(), "b:2".to_string()]);
    }

    #[test]
    fn a_bad_mesh_fanout_is_zero_and_unknown_flags_are_ignored() {
        // An unparseable --mesh-fanout must fall back to 0 (off), not panic; and an unknown flag is
        // skipped so parsing continues to the flags after it.
        let c = parse_args(args(&[
            "--mesh-fanout",
            "notanumber",
            "--bogus",
            "--listen",
            "x:9",
        ]));
        assert_eq!(c.mesh_fanout, 0, "unparseable fan-out => 0 (off)");
        assert_eq!(
            c.listen.as_deref(),
            Some("x:9"),
            "parsing continues past an unknown flag"
        );
    }
}

#[cfg(test)]
mod node_setup_tests {
    use super::*;

    #[test]
    fn regional_identity_derives_per_region_and_passes_through_without_a_region() {
        // §27/§28: with --region the node runs a distinct per-region backbone identity derived from
        // the shared seed (matching region_seed); with no region the base identity is used unchanged.
        let base = Identity::generate();
        let base_addr = base.address();
        let seed = base.to_secret_bytes();

        let passthrough = regional_identity(base, &seed, None);
        assert_eq!(
            passthrough.address(),
            base_addr,
            "no --region keeps the base identity"
        );

        let base2 = Identity::from_secret_bytes(&seed);
        let regional = regional_identity(base2, &seed, Some("us-central1"));
        assert_eq!(
            regional.address(),
            Identity::from_secret_bytes(&region_seed(&seed, "us-central1")).address(),
            "the regional identity is exactly the one derived from region_seed"
        );
        assert_ne!(
            regional.address(),
            base_addr,
            "a per-region node is a distinct node from the base"
        );
    }

    #[test]
    fn configure_node_sets_the_identify_name_from_the_advertise_host() {
        // §29: a relay identifies itself by the host of its --advertise URL, so a trace shows it by
        // domain. Without --advertise the name stays unset (callers fall back to the short address).
        let mut node = Node::with_store(Identity::generate(), MemoryStore::new());
        configure_node(&mut node, Some("wss://eu-west1.relay.hopme.sh/"));
        assert_eq!(
            node.name(),
            Some("eu-west1.relay.hopme.sh"),
            "identify name is the advertise host"
        );

        let mut node2 = Node::with_store(Identity::generate(), MemoryStore::new());
        configure_node(&mut node2, None);
        assert_eq!(node2.name(), None, "no --advertise => no identify name");
    }

    #[test]
    fn announce_startup_seeds_the_live_log_identity_with_region_and_address() {
        // announce_startup stamps the global log hub's identity (which the log stream leads with) so a
        // visitor to the anycast name sees which region + node answered. Assert a fresh subscriber
        // reads back that identity string (region-tagged; a unique region avoids racing other tests).
        let addr = Identity::generate().address();
        announce_startup(
            Some("0.0.0.0:9443"),
            None,
            2,
            &addr,
            Some("announce-test-region"),
        );
        let (who, _backlog, _rx) = log_hub().subscribe();
        assert!(
            who.contains("region=announce-test-region"),
            "log identity carries the region: {who}"
        );
        assert!(
            who.contains(&bs58_addr(&addr)),
            "log identity carries the node address: {who}"
        );
    }
}

#[cfg(test)]
mod driver_tests {
    use super::*;
    use std::sync::mpsc;

    fn test_node() -> Node<MemoryStore> {
        Node::with_store(Identity::generate(), MemoryStore::new())
    }

    #[test]
    fn apply_event_tracks_the_writer_table_across_up_data_down() {
        let mut node = test_node();
        let mut writers: HashMap<u64, SyncSender<Vec<u8>>> = HashMap::new();
        let (out_tx, _out_rx) = mpsc::sync_channel(MAX_OUTBOUND_FRAMES_PER_LINK);
        apply_event(&mut node, &mut writers, Ev::Up(7, Role::Responder, out_tx));
        assert!(writers.contains_key(&7), "Up registers the link's writer");
        // Garbage link bytes are tolerated (the node just fails to parse a frame); the table is intact.
        apply_event(&mut node, &mut writers, Ev::Data(7, vec![0u8, 1, 2, 3]));
        assert!(
            writers.contains_key(&7),
            "Data leaves the writer table alone"
        );
        apply_event(&mut node, &mut writers, Ev::Down(7));
        assert!(!writers.contains_key(&7), "Down removes the link's writer");
    }

    // A Store that panics on put, to prove apply_event's guard_core wrapper (F-2) turns a core panic
    // into a logged skip instead of a process kill. Everything else delegates to a real MemoryStore.
    struct PanicOnPut(MemoryStore);
    impl hop_core::store::Store for PanicOnPut {
        fn put(&mut self, _b: hop_core::bundle::Bundle, _now_ms: u64) -> bool {
            panic!("hostile bundle reached the store");
        }
        fn get(&self, id: &hop_core::bundle::BundleId) -> Option<hop_core::bundle::Bundle> {
            self.0.get(id)
        }
        fn remove(&mut self, id: &hop_core::bundle::BundleId) -> Option<hop_core::bundle::Bundle> {
            self.0.remove(id)
        }
        fn seen(&self, id: &hop_core::bundle::BundleId) -> bool {
            self.0.seen(id)
        }
        fn contains(&self, id: &hop_core::bundle::BundleId) -> bool {
            self.0.contains(id)
        }
        fn have(&self) -> hop_core::store::HaveSet {
            self.0.have()
        }
        fn prune(&mut self, now_ms: u64) {
            self.0.prune(now_ms)
        }
        fn split_copies(&mut self, id: &hop_core::bundle::BundleId) -> u16 {
            self.0.split_copies(id)
        }
        fn set_copies(&mut self, id: &hop_core::bundle::BundleId, copies: u16) {
            self.0.set_copies(id, copies)
        }
        fn apply_kv_batch(
            &mut self,
            mutations: &[hop_core::store::KvMutation],
        ) -> std::result::Result<(), String> {
            self.0.apply_kv_batch(mutations)
        }
        fn put_kv_critical(
            &mut self,
            key: &str,
            value: Vec<u8>,
        ) -> std::result::Result<(), String> {
            self.0.put_kv_critical(key, value)
        }
        fn remove_kv_critical(&mut self, key: &str) -> std::result::Result<(), String> {
            self.0.remove_kv_critical(key)
        }
    }

    struct ReadinessStore {
        inner: MemoryStore,
        durability: DurabilityHandle,
        probe_allowed: bool,
        prunes: Option<Arc<AtomicU64>>,
    }

    impl Store for ReadinessStore {
        fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
            self.inner.put(bundle, now_ms)
        }
        fn rehydrate(&mut self, bundle: Bundle, now_ms: u64) -> bool {
            self.inner.rehydrate(bundle, now_ms)
        }
        fn get(&self, id: &BundleId) -> Option<Bundle> {
            self.inner.get(id)
        }
        fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
            self.inner.remove(id)
        }
        fn seen(&self, id: &BundleId) -> bool {
            self.inner.seen(id)
        }
        fn contains(&self, id: &BundleId) -> bool {
            self.inner.contains(id)
        }
        fn have(&self) -> hop_core::store::HaveSet {
            self.inner.have()
        }
        fn prune(&mut self, now_ms: u64) {
            self.inner.prune(now_ms);
            if let Some(prunes) = &self.prunes {
                prunes.fetch_add(1, Ordering::AcqRel);
            }
        }
        fn split_copies(&mut self, id: &BundleId) -> u16 {
            self.inner.split_copies(id)
        }
        fn set_copies(&mut self, id: &BundleId, copies: u16) {
            self.inner.set_copies(id, copies)
        }
        fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
            self.inner.seen_expiry(id)
        }
        fn put_kv(&mut self, key: &str, value: Vec<u8>) {
            self.inner.put_kv(key, value)
        }
        fn apply_kv_batch(
            &mut self,
            mutations: &[hop_core::store::KvMutation],
        ) -> std::result::Result<(), String> {
            self.inner.apply_kv_batch(mutations)
        }
        fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
            self.inner.get_kv(key)
        }
        fn remove_kv(&mut self, key: &str) {
            self.inner.remove_kv(key)
        }
        fn list_kv_page(
            &self,
            prefix: &str,
            after: Option<&str>,
            limit: usize,
        ) -> Vec<(String, Vec<u8>)> {
            self.inner.list_kv_page(prefix, after, limit)
        }
        fn durability_status(&self) -> DurabilityReadiness {
            self.durability.status()
        }
        fn durability_handle(&self) -> Option<DurabilityHandle> {
            Some(self.durability.clone())
        }
        fn probe_durability(&mut self) -> std::result::Result<(), String> {
            let generation = self.durability.begin_recovery();
            if !self.probe_allowed {
                self.durability.mark_not_ready();
                return Err("probe still denied".into());
            }
            if !self.durability.mark_ready_if_reconciled(generation) {
                return Err("unreconciled mutation remains".into());
            }
            Ok(())
        }
    }

    #[test]
    fn guard_core_isolates_a_panic() {
        // The isolation primitive: a panicking closure is caught and yields None; a normal one passes
        // its value through. Revert-proof: remove the catch_unwind in guard_core and this test panics.
        assert_eq!(guard_core("ok", || 42), Some(42));
        assert!(guard_core("boom", || panic!("kaboom")).is_none());
    }

    #[test]
    fn runtime_degradation_refuses_custody_ack_and_closes_existing_protocol_links() {
        let _lock = lock_driver_statics();
        let durability = DurabilityHandle::ready();
        let store = ReadinessStore {
            inner: MemoryStore::new(),
            durability: durability.clone(),
            probe_allowed: false,
            prunes: None,
        };
        let mut node = Node::with_store(Identity::generate(), store);
        let (tx, rx) = event_channel_with_durability(durability.clone());
        let (writer, writer_rx) = mpsc::sync_channel(MAX_OUTBOUND_FRAMES_PER_LINK);
        let mut writers = HashMap::new();
        apply_event(&mut node, &mut writers, Ev::Up(44, Role::Responder, writer));
        assert!(writers.contains_key(&44));

        durability.mark_not_ready();
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        apply_event(
            &mut node,
            &mut writers,
            Ev::IngestCustody(vec![1, 2, 3], ack_tx),
        );
        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)), Ok(false));
        assert_eq!(
            tx.try_send_data(44, vec![1]),
            Err(QueueAdmissionError::NotReady),
            "existing producers cannot enqueue while custody is degraded"
        );

        let mut previous = std::collections::HashSet::new();
        let mut schedule = DriverSchedule {
            last_stats_ms: 0,
            next_tick: Instant::now() + DRIVER_TICK_INTERVAL,
            next_durability_probe: Instant::now() + DURABILITY_PROBE_INTERVAL,
        };
        assert!(driver_step(
            &mut node,
            &mut writers,
            &tx,
            &rx,
            &mut previous,
            &mut schedule,
        ));
        assert!(writers.is_empty());
        assert!(matches!(
            writer_rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn definitive_runtime_failure_recovers_admission_after_periodic_probe() {
        let _lock = lock_driver_statics();
        let durability = DurabilityHandle::not_ready();
        let store = ReadinessStore {
            inner: MemoryStore::new(),
            durability: durability.clone(),
            probe_allowed: true,
            prunes: None,
        };
        let mut node = Node::with_store(Identity::generate(), store);
        let (tx, rx) = event_channel_with_durability(durability.clone());
        let mut writers = HashMap::new();
        let mut previous = std::collections::HashSet::new();
        let mut schedule = DriverSchedule {
            last_stats_ms: 0,
            next_tick: Instant::now(),
            next_durability_probe: Instant::now(),
        };
        tx.send(Ev::Down(999)).unwrap();
        assert!(driver_step(
            &mut node,
            &mut writers,
            &tx,
            &rx,
            &mut previous,
            &mut schedule,
        ));
        assert_eq!(durability.status(), DurabilityReadiness::Ready);
        let (writer, _reader) = mpsc::sync_channel(MAX_OUTBOUND_FRAMES_PER_LINK);
        assert!(tx.send(Ev::Up(45, Role::Responder, writer)).is_ok());
    }

    #[test]
    fn unreconciled_runtime_failure_refuses_recovery_and_new_admission() {
        let _lock = lock_driver_statics();
        let durability = DurabilityHandle::ready();
        durability.quarantine();
        let store = ReadinessStore {
            inner: MemoryStore::new(),
            durability: durability.clone(),
            probe_allowed: true,
            prunes: None,
        };
        let mut node = Node::with_store(Identity::generate(), store);
        let (tx, rx) = event_channel_with_durability(durability.clone());
        let mut writers = HashMap::new();
        let mut previous = std::collections::HashSet::new();
        let mut schedule = DriverSchedule {
            last_stats_ms: 0,
            next_tick: Instant::now(),
            next_durability_probe: Instant::now(),
        };
        assert!(driver_step(
            &mut node,
            &mut writers,
            &tx,
            &rx,
            &mut previous,
            &mut schedule,
        ));
        assert_eq!(durability.status(), DurabilityReadiness::Quarantined);
        assert_eq!(durability.unreconciled(), 1);
        let (writer, _reader) = mpsc::sync_channel(MAX_OUTBOUND_FRAMES_PER_LINK);
        assert_eq!(
            tx.send(Ev::Up(46, Role::Responder, writer)),
            Err(QueueAdmissionError::NotReady)
        );
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn one_hundred_twenty_eight_firestore_producers_share_the_event_byte_ceiling() {
        let durability = DurabilityHandle::ready();
        let (tx, rx) = event_channel_with_durability(durability);
        let barrier = Arc::new(std::sync::Barrier::new(129));
        let mut workers = Vec::new();
        for _ in 0..128 {
            let tx = tx.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                tx.queue
                    .try_reserve(EventSource::Durable, FIRESTORE_READ_RESERVATION_BYTES)
                    .ok()
            }));
        }
        barrier.wait();
        let reservations: Vec<_> = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            reservations.len(),
            MAX_EVENT_SOURCE_BYTES / FIRESTORE_READ_RESERVATION_BYTES,
            "durable producers are limited by their shared source-byte budget"
        );
        assert!(tx.usage().1 <= MAX_EVENT_QUEUE_BYTES);
        drop(reservations);
        assert_eq!(tx.usage(), (0, 0));
        assert!(
            tx.reserve_durable().is_ok(),
            "released capacity is reusable"
        );
        drop(rx);
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn replenished_durable_producers_cannot_starve_repeated_tick_or_total_byte_deadlines() {
        let durability = DurabilityHandle::ready();
        let prunes = Arc::new(AtomicU64::new(0));
        let store = ReadinessStore {
            inner: MemoryStore::new(),
            durability: durability.clone(),
            probe_allowed: true,
            prunes: Some(prunes.clone()),
        };
        let mut node = Node::with_store(Identity::generate(), store);
        let (tx, rx) = event_channel_with_durability(durability);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let produced = Arc::new(AtomicU64::new(0));
        let mut producers = Vec::new();
        for link in 0..32u64 {
            let producer = tx.clone();
            let stop = stop.clone();
            let produced = produced.clone();
            producers.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    if let Ok(reservation) = producer.queue.reserve_timeout(
                        EventSource::Durable,
                        FIRESTORE_READ_RESERVATION_BYTES,
                        Duration::from_millis(20),
                    ) {
                        if reservation.try_send(Ev::Down(link)).is_ok() {
                            produced.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                }
            }));
        }

        let mut writers = HashMap::new();
        let mut previous = std::collections::HashSet::new();
        let mut schedule = DriverSchedule {
            last_stats_ms: now_ms(),
            next_tick: Instant::now(),
            next_durability_probe: Instant::now() + DURABILITY_PROBE_INTERVAL,
        };
        for deadline in 1..=4 {
            schedule.next_tick = Instant::now();
            assert!(driver_step(
                &mut node,
                &mut writers,
                &tx,
                &rx,
                &mut previous,
                &mut schedule,
            ));
            assert!(
                prunes.load(Ordering::Acquire) >= deadline,
                "continuously replenished producers did not starve tick deadline {deadline}"
            );
            let (_, queued_and_reserved) = tx.usage();
            assert!(queued_and_reserved <= MAX_EVENT_QUEUE_BYTES);
            assert!(
                FIRESTORE_STARTUP_MAX_BYTES.saturating_add(queued_and_reserved)
                    <= MAX_RELAY_QUEUED_RESERVED_STARTUP_BYTES,
                "startup plus queued and reserved bytes exceeded the relay aggregate ceiling"
            );
        }

        stop.store(true, Ordering::Release);
        for producer in producers {
            producer.join().unwrap();
        }
        assert!(
            produced.load(Ordering::Acquire) > MAX_EVENT_BATCH as u64,
            "producers replenished beyond one driver batch"
        );
    }

    #[test]
    fn apply_event_survives_a_core_panic_on_hostile_bytes() {
        // The whole point of F-2: a core panic while processing an ingested bundle must NOT kill the
        // driver. Back the node with a store that panics on put; feed a valid bundle through Ev::Ingest;
        // apply_event must return normally (guard_core swallowed the panic). Revert-proof: drop the
        // guard_core wrapper around node.ingest and this test unwinds through apply_event and fails.
        let mut node = Node::with_store(Identity::generate(), PanicOnPut(MemoryStore::new()));
        let mut writers: HashMap<u64, SyncSender<Vec<u8>>> = HashMap::new();
        let recipient = Identity::generate();
        let spk = recipient.derive_prekey();
        let bytes = {
            use hop_core::bundle::{Bundle, BundleOpts, Payload};
            Bundle::create_private(
                &recipient.address(),
                &spk.public,
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: b"hi".to_vec(),
                },
                None,
                BundleOpts::default(),
            )
            .unwrap()
            .to_bytes()
            .unwrap()
        };
        // If node.ingest -> store.put panics and is NOT caught, this call unwinds and the test fails.
        apply_event(&mut node, &mut writers, Ev::Ingest(bytes));
        // Reaching here means the panic was isolated; confirm the driver still processes the next event.
        apply_event(&mut node, &mut writers, Ev::Data(1, vec![0u8, 1, 2, 3]));
    }

    #[test]
    fn apply_event_ingest_holds_a_valid_bundle_and_ignores_garbage() {
        // Ev::Ingest is the durable-store rehydrate path: a well-formed sealed bundle addressed to a
        // device we can't reach is parsed and held for store-and-forward, so the node's queue grows; a
        // malformed ingest is a silent no-op (never a panic).
        let mut node = test_node();
        let mut writers = HashMap::new();
        let recipient = Identity::generate();
        let spk = recipient.derive_prekey();
        let bytes = {
            use hop_core::bundle::{Bundle, BundleOpts, Payload};
            Bundle::create_private(
                &recipient.address(),
                &spk.public,
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: b"hi".to_vec(),
                },
                None,
                BundleOpts::default(),
            )
            .unwrap()
            .to_bytes()
            .unwrap()
        };
        assert!(node.queue().is_empty(), "a fresh node holds nothing");
        apply_event(&mut node, &mut writers, Ev::Ingest(bytes));
        assert!(
            !node.queue().is_empty(),
            "an ingested undeliverable bundle is held for forwarding"
        );
        let held = node.queue().len();
        apply_event(&mut node, &mut writers, Ev::Ingest(vec![0xFF; 8]));
        assert_eq!(
            node.queue().len(),
            held,
            "an unparseable ingest is a no-op, not a panic"
        );

        // Also exercise the Device-addressed dst arm of the ingest log line (create_private above uses
        // the Broadcast dst; a normal public message is Destination::Device).
        let device_bundle = {
            use hop_core::bundle::{Bundle, BundleOpts, Payload};
            let sender = Identity::generate();
            Bundle::create(
                &sender,
                Destination::Device(recipient.address()),
                &recipient.address(),
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: b"device-addressed".to_vec(),
                },
                BundleOpts::default(),
            )
            .unwrap()
            .to_bytes()
            .unwrap()
        };
        apply_event(&mut node, &mut writers, Ev::Ingest(device_bundle));

        // And the Vaccine dst arm (a relay-vaccine bundle, §39): its ingest log line takes the
        // "vaccine" branch of the destination match.
        let vaccine_bundle = {
            use hop_core::bundle::{Bundle, BundleOpts};
            Bundle::create_vaccine([3u8; 32], BundleOpts::default())
                .to_bytes()
                .unwrap()
        };
        apply_event(&mut node, &mut writers, Ev::Ingest(vaccine_bundle));
    }

    #[test]
    fn custody_ingest_acks_only_after_parse_accept_and_flush() {
        let mut node = test_node();
        let mut writers = HashMap::new();

        let (bad_tx, bad_rx) = mpsc::sync_channel(1);
        apply_event(
            &mut node,
            &mut writers,
            Ev::IngestCustody(vec![0xFF; 8], bad_tx),
        );
        assert_eq!(bad_rx.recv_timeout(Duration::from_secs(1)), Ok(false));

        let recipient = Identity::generate();
        let sender = Identity::generate();
        let bytes = Bundle::create(
            &sender,
            Destination::Device(recipient.address()),
            &recipient.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"custody".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        let (ok_tx, ok_rx) = mpsc::sync_channel(1);
        apply_event(&mut node, &mut writers, Ev::IngestCustody(bytes, ok_tx));
        assert_eq!(ok_rx.recv_timeout(Duration::from_secs(1)), Ok(true));
        assert!(!node.queue().is_empty());
    }

    #[test]
    fn pump_outgoing_delivers_to_a_live_writer_and_drops_a_dead_one() {
        // An Initiator link enqueues a Noise handshake packet on connect; pump_outgoing must route it
        // to that link's writer channel. A writer whose receiver has been dropped (its thread is gone)
        // must be evicted from the table when the send fails.
        let mut node = test_node();
        let mut writers: HashMap<u64, SyncSender<Vec<u8>>> = HashMap::new();

        let (live_tx, live_rx) = mpsc::sync_channel::<Vec<u8>>(MAX_OUTBOUND_FRAMES_PER_LINK);
        node.handle(BearerEvent::Connected(1, Role::Initiator));
        node.tick(now_ms());
        writers.insert(1u64, live_tx);
        pump_outgoing(&mut node, &mut writers);
        assert!(
            live_rx.try_recv().is_ok(),
            "the handshake packet is delivered to link 1's live writer"
        );
        assert!(writers.contains_key(&1), "a live writer is retained");

        let (dead_tx, dead_rx) = mpsc::sync_channel::<Vec<u8>>(MAX_OUTBOUND_FRAMES_PER_LINK);
        drop(dead_rx); // the writer thread is gone: sends will fail
        node.handle(BearerEvent::Connected(2, Role::Initiator));
        node.tick(now_ms());
        writers.insert(2u64, dead_tx);
        pump_outgoing(&mut node, &mut writers);
        assert!(
            !writers.contains_key(&2),
            "a writer whose thread is gone is dropped from the table"
        );
    }

    #[test]
    fn maybe_emit_stats_only_advances_on_the_10s_cadence() {
        let node = test_node();
        // Under the interval: no emit, the last-stats timestamp is unchanged.
        assert_eq!(
            maybe_emit_stats(&node, 1_000, 1_000 + 9_999),
            1_000,
            "under 10s: hold the timestamp (no emit)"
        );
        // At/after the interval: emit, the timestamp advances to `now`.
        assert_eq!(
            maybe_emit_stats(&node, 1_000, 1_000 + 10_000),
            11_000,
            "at 10s: emit and advance the timestamp"
        );
    }

    #[test]
    fn log_peer_changes_returns_the_current_peer_set_and_logs_departures() {
        // A fresh node has no authenticated peers, so the returned "current" set is empty and equal in
        // size to node.peers(). Passing a non-empty `prev` (a peer we thought was connected) exercises
        // the "peer left" diff branch: prev has an address that cur does not, so it is logged as gone.
        let node = test_node();
        let empty = std::collections::HashSet::new();
        let cur = log_peer_changes(&node, &empty);
        assert_eq!(
            cur.len(),
            node.peers().len(),
            "the returned set mirrors node.peers()"
        );
        let mut prev = std::collections::HashSet::new();
        prev.insert(vec![7u8; 32]); // a stale "previously connected" peer, now absent
        let cur2 = log_peer_changes(&node, &prev);
        assert!(
            cur2.is_empty(),
            "the fresh node still has no peers; the stale peer is logged as departed"
        );
    }

    // ---------------------------------------------------------------------------------------
    // F-7: per-authenticated-peer fairness cap on Ev::Data (gap-report pass-17 closure).
    // ---------------------------------------------------------------------------------------

    /// Hand-drive a full Noise XX handshake between `a` (as `a_role` over its own `a_link`) and `b`
    /// (as `b_role` over its own `b_link`) until both settle, the same two-node pump pattern hop-core's
    /// own node.rs tests use, ported here since that harness is private to hop-core's test module. 12
    /// rounds is comfortably more than the 3-message XX exchange needs.
    fn handshake(
        a: &mut Node<MemoryStore>,
        a_link: u64,
        a_role: Role,
        b: &mut Node<MemoryStore>,
        b_link: u64,
        b_role: Role,
    ) {
        a.handle(BearerEvent::Connected(a_link, a_role));
        b.handle(BearerEvent::Connected(b_link, b_role));
        for _ in 0..12 {
            for (l, bytes) in a.drain_outgoing() {
                if l == a_link {
                    b.handle(BearerEvent::Data(b_link, bytes));
                }
            }
            for (l, bytes) in b.drain_outgoing() {
                if l == b_link {
                    a.handle(BearerEvent::Data(a_link, bytes));
                }
            }
        }
    }

    #[test]
    fn peer_data_allowed_admits_up_to_budget_then_sheds_and_resets_next_window() {
        // The core F-7 primitive, tested directly against its own state: MAX_PEER_MSGS_PER_WINDOW
        // calls for one key are admitted, the next is shed; a DIFFERENT key has its own untouched
        // budget in the very same window (the fairness property); once the window rolls over, the
        // original key is admitted again. Revert-proof: widen the `<=` to always pass (or drop it) in
        // peer_data_allowed and the "shed" assertion below fails.
        let mut rates: HashMap<PeerRateKey, PeerRateWindow> = HashMap::new();
        let hostile = PeerRateKey::Peer([9u8; 32]);
        let victim = PeerRateKey::Peer([4u8; 32]);
        let start = 1_000_000u64;

        for i in 0..MAX_PEER_MSGS_PER_WINDOW {
            assert!(
                peer_data_allowed(&mut rates, hostile, start + i as u64, 1),
                "message {i} is within budget"
            );
        }
        assert!(
            !peer_data_allowed(
                &mut rates,
                hostile,
                start + MAX_PEER_MSGS_PER_WINDOW as u64,
                1,
            ),
            "the message past the window budget is shed"
        );

        // Fairness: a different peer's key has its own untouched budget in the same window.
        assert!(
            peer_data_allowed(
                &mut rates,
                victim,
                start + MAX_PEER_MSGS_PER_WINDOW as u64,
                1,
            ),
            "a second peer is not shed by the first peer's exhausted budget"
        );

        // The window resets after PEER_RATE_WINDOW_MS: the hostile key is admitted again.
        assert!(
            peer_data_allowed(&mut rates, hostile, start + PEER_RATE_WINDOW_MS, 1),
            "a new fixed window resets the budget"
        );
    }

    #[test]
    fn preauth_bucket_is_shared_and_generous_not_per_link() {
        // F-18b: all pre-auth traffic shares ONE bucket with its own larger budget. Two different links
        // (a reconnect, a fresh link id) draw down the SAME PreAuth budget, so churn cannot reset it.
        // Revert-proof: key pre-auth per-link again and the "shared" assertion (exhausting via one key
        // sheds the other) fails.
        let mut rates: HashMap<PeerRateKey, PeerRateWindow> = HashMap::new();
        let now = 5_000_000u64;
        for i in 0..MAX_PREAUTH_MSGS_PER_WINDOW {
            assert!(
                peer_data_allowed(&mut rates, PeerRateKey::PreAuth, now + i as u64, 1),
                "pre-auth message {i} is within the shared budget"
            );
        }
        // Budget spent: the next pre-auth frame is shed, whatever link it arrived on. A reconnecting
        // attacker does not get a fresh budget (that was the F-18b hole).
        assert!(
            !peer_data_allowed(
                &mut rates,
                PeerRateKey::PreAuth,
                now + MAX_PREAUTH_MSGS_PER_WINDOW as u64,
                1,
            ),
            "F-18b: a reconnect cannot dodge the shared pre-auth cap"
        );
    }

    // The shared pre-auth budget is strictly larger than a single peer's, so a burst of legit handshakes
    // is not starved by the per-identity limit. A compile-time assertion (not a runtime one, which clippy
    // rightly flags as const).
    const _: () = assert!(MAX_PREAUTH_MSGS_PER_WINDOW > MAX_PEER_MSGS_PER_WINDOW);

    #[test]
    fn rate_map_is_hard_bounded_under_a_fresh_identity_flood() {
        // F-18a: an attacker minting fresh authenticated identities (one frame each, same window, so the
        // staleness sweep evicts nothing) must not grow peer_rates without bound. Insert well past the
        // hard ceiling in a single window and assert the map stays bounded. Revert-proof: remove the
        // MAX_PEER_RATE_KEYS force-eviction and this assertion fails (the map grows to the full count).
        let mut rates: HashMap<PeerRateKey, PeerRateWindow> = HashMap::new();
        let now = 7_000_000u64; // one fixed window for every insert
        for i in 0..(MAX_PEER_RATE_KEYS as u64 + 5_000) {
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&i.to_le_bytes());
            peer_data_allowed(&mut rates, PeerRateKey::Peer(addr), now, 1);
        }
        assert!(
            rates.len() <= MAX_PEER_RATE_KEYS,
            "F-18a: the rate map is hard-bounded ({} <= {}) even under a same-window fresh-identity flood",
            rates.len(),
            MAX_PEER_RATE_KEYS
        );
    }

    #[test]
    fn producer_admission_follows_the_authenticated_address_not_the_link_id() {
        // Before any handshake, an unknown link id has no peer yet: F-7 falls back to the shared PreAuth
        // bucket (F-18b: NOT a per-link key, so reconnect churn can't multiply the pre-auth budget).
        // Once the XX handshake completes, Node::peer_links reports the address, and the key switches to
        // that address: the identity that survives a reconnect on a fresh link id, which is the whole
        // point of not keying on IP behind the LB.
        let mut a = test_node();
        let mut b = test_node();
        let (tx, _rx) = event_channel();
        assert_eq!(
            tx.data_permit(42, 1),
            Some(PeerRateKey::PreAuth),
            "an unknown/unauthenticated link shares the PreAuth bucket"
        );
        handshake(&mut a, 1, Role::Initiator, &mut b, 2, Role::Responder);
        tx.bind_peers(&a.peer_links());
        assert_eq!(
            tx.data_permit(1, 1),
            Some(PeerRateKey::Peer(b.address())),
            "once authenticated, the key follows the peer's address, not the link id"
        );
        tx.bind_peers(&b.peer_links());
        assert_eq!(
            tx.data_permit(2, 1),
            Some(PeerRateKey::Peer(a.address())),
            "symmetric on the other side of the same link"
        );
    }

    #[test]
    fn saturated_event_queue_still_ticks_prunes_and_retransmits() {
        let clock = now_ms();
        let created_at = clock.saturating_sub(10_000);
        let identity = Identity::generate();
        let destination = Identity::generate();
        let pending = Bundle::create(
            &identity,
            Destination::Device(destination.address()),
            &destination.address(),
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"retry".to_vec(),
            },
            BundleOpts {
                created_at,
                lifetime_ms: 60_000,
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let pending_id = pending.id();
        let mut store = MemoryStore::new();
        assert!(store.put(pending, created_at));
        let mut node = Node::with_store(identity, store);
        node.set_time(created_at);
        node.set_observe(true);

        let mut peer = test_node();
        peer.set_time(created_at);
        handshake(&mut node, 1, Role::Initiator, &mut peer, 1, Role::Responder);
        node.drain_outgoing();
        node.drain_transfers();

        let expiring = Bundle::create(
            &Identity::generate(),
            Destination::Device(destination.address()),
            &destination.address(),
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"expire".to_vec(),
            },
            BundleOpts {
                created_at,
                lifetime_ms: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let expiring_id = expiring.id();
        assert!(node.store.put(expiring, created_at));

        let (event_tx, event_rx) = event_channel();
        let peers: Vec<_> = (0..=MAX_EVENT_QUEUE_EVENTS / MAX_EVENT_SOURCE_EVENTS)
            .map(|n| ([n as u8; 32], 1_000 + n as u64))
            .collect();
        event_tx.bind_peers(&peers);
        for (peer_index, (_, link)) in peers.iter().take(16).enumerate() {
            for _ in 0..MAX_EVENT_SOURCE_EVENTS {
                event_tx
                    .try_send_data(*link, vec![peer_index as u8])
                    .unwrap();
            }
            if peer_index == 0 {
                assert_eq!(
                    event_tx.try_send_data(*link, vec![0]),
                    Err(QueueAdmissionError::SourceFull)
                );
            }
        }
        assert_eq!(
            event_tx.try_send_data(peers[16].1, vec![16]),
            Err(QueueAdmissionError::QueueFull)
        );
        assert_eq!(
            event_tx.usage(),
            (MAX_EVENT_QUEUE_EVENTS, MAX_EVENT_QUEUE_EVENTS)
        );

        let mut writers = HashMap::new();
        let (writer, _writer_rx) = mpsc::sync_channel(MAX_OUTBOUND_FRAMES_PER_LINK);
        writers.insert(1, writer);
        let mut prev_peers = std::collections::HashSet::new();
        let mut schedule = DriverSchedule {
            last_stats_ms: clock,
            next_tick: Instant::now(),
            next_durability_probe: Instant::now() + DURABILITY_PROBE_INTERVAL,
        };
        assert!(driver_step(
            &mut node,
            &mut writers,
            &event_tx,
            &event_rx,
            &mut prev_peers,
            &mut schedule,
        ));

        assert!(
            !node.store.contains(&expiring_id),
            "tick pruned expired custody"
        );
        assert!(
            node.drain_transfers()
                .iter()
                .any(|(_, id, _)| *id == pending_id),
            "the pending bundle retransmitted while the event queue stayed nonempty"
        );
        assert_eq!(
            event_tx.usage().0,
            MAX_EVENT_QUEUE_EVENTS - MAX_EVENT_BATCH,
            "one step processes only a bounded batch"
        );
    }

    #[test]
    fn apply_event_caps_a_flooding_peer_by_identity_while_a_second_peer_is_unaffected() {
        // F-7, the end-to-end proof. `d` is the relay under test, authenticated with two REAL peers
        // (`hostile` and `victim`) over separate links. With `hostile` already at its budget for the
        // window, apply_event must shed its next Data frame (the message never reaches node.handle, so
        // it never lands in d's inbox), while `victim`'s frame, on a different link/identity, is
        // delivered normally in the SAME window. That proves both the cap AND the fairness (per-node,
        // not global/per-IP: relayd sits behind a Cloud Run LB, so both peers would look identical to an
        // IP-keyed limiter). Revert-proof: drop the `if peer_data_allowed(...)` gate around the
        // "bearer-data" guard_core call in apply_event (always call node.handle) and hostile's second
        // message is delivered, failing the "is shed" assertion below.
        let mut d = test_node();
        let mut hostile = test_node();
        let mut victim = test_node();
        let mut writers: HashMap<u64, SyncSender<Vec<u8>>> = HashMap::new();
        let (event_tx, event_rx) = event_channel();

        const LINK_HOSTILE: u64 = 101;
        const LINK_VICTIM: u64 = 102;
        handshake(
            &mut d,
            LINK_HOSTILE,
            Role::Responder,
            &mut hostile,
            1,
            Role::Initiator,
        );
        handshake(
            &mut d,
            LINK_VICTIM,
            Role::Responder,
            &mut victim,
            1,
            Role::Initiator,
        );
        assert!(
            d.peer_links().contains(&(hostile.address(), LINK_HOSTILE)),
            "d and hostile completed the handshake"
        );
        assert!(
            d.peer_links().contains(&(victim.address(), LINK_VICTIM)),
            "d and victim completed the handshake"
        );
        event_tx.bind_peers(&d.peer_links());

        // Publish + gossip d's prekey to both peers so send_to can open a forward-secret session to d
        // (DESIGN.md §25: content is never static-sealed, so a real send needs this first).
        d.publish_prekey().unwrap();
        for _ in 0..4 {
            for (l, bytes) in d.drain_outgoing() {
                if l == LINK_HOSTILE {
                    hostile.handle(BearerEvent::Data(1, bytes));
                } else if l == LINK_VICTIM {
                    victim.handle(BearerEvent::Data(1, bytes));
                }
            }
        }

        // Under budget: hostile's first message is handled normally and lands in d's inbox.
        let sent = hostile
            .send_to(
                &d.address(),
                "text/plain".into(),
                b"hostile-1".to_vec(),
                false,
            )
            .unwrap();
        assert!(sent.is_some(), "hostile is connected + has d's prekey");
        let outgoing = hostile.drain_outgoing();
        assert!(
            !outgoing.is_empty(),
            "hostile's prekey-backed send produced real wire bytes (not deferred)"
        );
        for (l, bytes) in outgoing {
            if l == 1 {
                event_tx.try_send_data(LINK_HOSTILE, bytes).unwrap();
                apply_event(
                    &mut d,
                    &mut writers,
                    event_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                );
            }
        }
        assert_eq!(
            d.take_inbox().len(),
            1,
            "hostile's first, in-budget message is delivered"
        );

        // Simulate hostile having already spent its whole window's budget: equivalent to having
        // already sent MAX_PEER_MSGS_PER_WINDOW frames this window, without looping that many times.
        event_tx.ingress.lock().unwrap().rates.insert(
            PeerRateKey::Peer(hostile.address()),
            PeerRateWindow {
                start_ms: now_ms(),
                msgs: MAX_PEER_MSGS_PER_WINDOW,
                bytes: 0,
            },
        );

        // Over budget: hostile's next message must be shed BEFORE it reaches node.handle, so it never
        // appears in d's inbox.
        let sent2 = hostile
            .send_to(
                &d.address(),
                "text/plain".into(),
                b"hostile-2".to_vec(),
                false,
            )
            .unwrap();
        assert!(sent2.is_some());
        for (l, bytes) in hostile.drain_outgoing() {
            if l == 1 {
                assert!(
                    event_tx.try_send_data(LINK_HOSTILE, bytes).is_err(),
                    "the hostile frame is rejected before enqueue"
                );
            }
        }
        assert!(
            d.take_inbox().is_empty(),
            "hostile's over-budget message is shed, not delivered"
        );

        // Fairness: victim, a completely different authenticated peer, is unaffected by hostile's
        // exhausted budget in the very same window and is delivered normally.
        let sent3 = victim
            .send_to(
                &d.address(),
                "text/plain".into(),
                b"victim-1".to_vec(),
                false,
            )
            .unwrap();
        assert!(sent3.is_some());
        for (l, bytes) in victim.drain_outgoing() {
            if l == 1 {
                event_tx.try_send_data(LINK_VICTIM, bytes).unwrap();
                apply_event(
                    &mut d,
                    &mut writers,
                    event_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                );
            }
        }
        assert_eq!(
            d.take_inbox().len(),
            1,
            "a second peer is not shed by the first peer's exhausted budget (per-node fairness)"
        );
    }
}

#[cfg(test)]
mod ws_and_tcp_driver_tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::{TcpListener, TcpStream};
    use tungstenite::Message;

    #[test]
    fn serve_ws_upgrade_bridges_binary_frames_both_ways_and_reports_down() {
        // serve_ws(Upgrade) is the WS mesh driver: accept the upgrade, feed each inbound binary frame
        // to the driver as Ev::Data, write each packet from the link's out channel back as a binary
        // frame, and report Ev::Down on close. Drive it end to end with a real tungstenite client.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, ev_rx) = event_channel();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_nodelay(true).ok();
            serve_ws(sock, WsKind::Upgrade, &ev_tx);
        });

        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).ok();
        let (mut ws, _resp) =
            tungstenite::client(format!("ws://127.0.0.1:{}/", addr.port()), stream).unwrap();
        ws.get_mut()
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();

        // The link comes up; the driver gets a Sender to push outbound packets.
        let out = match ev_rx.recv_timeout(Duration::from_secs(3)).expect("link up") {
            Ev::Up(_link, Role::Responder, out) => out,
            _ => panic!("expected Ev::Up(Responder)"),
        };

        // Client → server: a binary frame arrives verbatim as Ev::Data.
        ws.write(Message::Binary(b"ping-bytes".to_vec().into()))
            .unwrap();
        ws.flush().unwrap();
        let data = loop {
            match ev_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("data event")
            {
                Ev::Data(_l, b) => break b,
                _ => continue,
            }
        };
        assert_eq!(
            data, b"ping-bytes",
            "inbound WS binary frame delivered verbatim"
        );

        // Server → client: bytes pushed into the link's out channel come back as a binary frame.
        out.send(b"pong-bytes".to_vec()).unwrap();
        let got = loop {
            match ws.read() {
                Ok(Message::Binary(b)) => break b,
                Ok(_) => continue,
                Err(tungstenite::Error::Io(e))
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(e) => panic!("client read failed: {e}"),
            }
        };
        assert_eq!(
            got,
            b"pong-bytes".to_vec(),
            "outbound packet framed back to the client"
        );

        // Drop the client hard (no closing handshake): the server's next read errors out rather than
        // seeing a clean Close frame, and the driver still observes Ev::Down for the link.
        drop(ws);
        let mut saw_down = false;
        while let Ok(ev) = ev_rx.recv_timeout(Duration::from_secs(3)) {
            if matches!(ev, Ev::Down(_)) {
                saw_down = true;
                break;
            }
        }
        assert!(
            saw_down,
            "a hard client disconnect still reports the link down"
        );
        server.join().unwrap();
    }

    #[test]
    fn serve_ws_tolerates_read_timeouts_and_breaks_when_the_out_channel_disconnects() {
        // Two serve_ws edge paths: (1) an idle period trips the socket's read timeout
        // (WouldBlock/TimedOut), which must be tolerated (the loop keeps going, link stays up); and
        // (2) when the driver drops the link's out-channel sender, the write-drain loop observes
        // Disconnected and breaks the connection, reporting the link down.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, ev_rx) = event_channel();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_nodelay(true).ok();
            serve_ws(sock, WsKind::Upgrade, &ev_tx);
        });
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).ok();
        let (mut ws, _r) =
            tungstenite::client(format!("ws://127.0.0.1:{}/", addr.port()), stream).unwrap();
        ws.get_mut()
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok();
        let out = match ev_rx.recv_timeout(Duration::from_secs(3)).expect("link up") {
            Ev::Up(_l, Role::Responder, out) => out,
            _ => panic!("expected Ev::Up(Responder)"),
        };
        // Idle past the server's 100ms read timeout so its read loop takes the WouldBlock/TimedOut
        // branch at least once (a timed-out read must NOT tear the link down).
        std::thread::sleep(Duration::from_millis(250));
        // Drop the driver's out sender: serve_ws's write-drain loop sees Disconnected and breaks.
        drop(out);
        let mut saw_down = false;
        while let Ok(ev) = ev_rx.recv_timeout(Duration::from_secs(3)) {
            if matches!(ev, Ev::Down(_)) {
                saw_down = true;
                break;
            }
        }
        assert!(
            saw_down,
            "dropping the link's out sender ends the WS session and reports it down"
        );
        let _ = ws.close(None);
        server.join().unwrap();
    }

    #[test]
    fn serve_tcp_writer_thread_length_frames_outgoing_packets() {
        // The writer half of serve_tcp: a packet pushed into the link's out channel is written back to
        // the socket with a 4-byte big-endian length prefix (the exact framing the raw-TCP bearer
        // relies on). Grab the out Sender from Ev::Up, push bytes, and read the framed bytes back.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ev_tx, ev_rx) = event_channel();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_tcp(sock, Role::Responder, &ev_tx);
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let out = match ev_rx.recv_timeout(Duration::from_secs(3)).expect("link up") {
            Ev::Up(_l, Role::Responder, out) => out,
            _ => panic!("expected Ev::Up(Responder)"),
        };
        out.send(b"payload!!".to_vec()).unwrap();

        let mut len = [0u8; 4];
        client.read_exact(&mut len).unwrap();
        assert_eq!(
            u32::from_be_bytes(len) as usize,
            9,
            "the length prefix is the payload length"
        );
        let mut buf = vec![0u8; 9];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(
            &buf, b"payload!!",
            "the payload is written verbatim after the prefix"
        );

        // Exercise the writer thread's write-error path: shut the socket, then push another packet so
        // its framed write fails and it breaks (rather than only ending when the channel closes).
        client.shutdown(std::net::Shutdown::Both).ok();
        let _ = out.send(b"after-close".to_vec());
        std::thread::sleep(Duration::from_millis(20));
        drop(out); // end the writer thread's recv so serve_tcp returns
        server.join().unwrap();
    }
}

#[cfg(test)]
mod build_store_tests {
    use super::*;

    fn tmp_db(tag: &str) -> String {
        format!(
            "{}/hop-relayd-store-{tag}-{}-{}.db",
            std::env::temp_dir().display(),
            std::process::id(),
            NEXT_LINK.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn build_store_opens_a_usable_local_sqlite_store() {
        // The plain (non-firestore) path: no project id => a local SQLite mailbox cache. The returned
        // Box<dyn Store> must be a real, node-usable store and the db file must be created on disk.
        let db = tmp_db("plain");
        let _ = std::fs::remove_file(&db);
        let addr = Identity::generate().address();
        let store = build_store(&None, &db, &addr).unwrap();
        let _node = Node::with_store(Identity::generate(), store);
        assert!(
            std::fs::metadata(&db).is_ok(),
            "the sqlite db file was created"
        );
        let _ = std::fs::remove_file(&db);
    }

    #[cfg(not(feature = "firestore"))]
    #[test]
    fn configured_firestore_fails_closed_when_support_is_not_compiled_in() {
        let db = tmp_db("fallback");
        let _ = std::fs::remove_file(&db);
        let addr = Identity::generate().address();
        let error = build_store(&Some("some-gcp-project".to_string()), &db, &addr)
            .err()
            .expect("configured Firestore must fail closed");
        assert!(error.contains("not compiled"));
        assert!(
            std::fs::metadata(&db).is_err(),
            "no ephemeral/local fallback database is opened"
        );
        let _ = std::fs::remove_file(&db);
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn sigterm_handler_flips_the_shutdown_flag() {
        // F-21: install the (idempotent) handler, then invoke the async-signal-safe handler directly.
        // It must set the SHUTDOWN atomic the driver loop polls each iteration to trigger the
        // durable-store drain before exit.
        let _lock = lock_driver_statics();
        install_shutdown_handler();
        SHUTDOWN.store(false, Ordering::SeqCst);
        on_sigterm(libc::SIGTERM);
        assert!(
            SHUTDOWN.load(Ordering::SeqCst),
            "on_sigterm sets SHUTDOWN so the driver drains and exits"
        );
        SHUTDOWN.store(false, Ordering::SeqCst); // restore for any other test/run
    }

    #[test]
    fn driver_step_applies_an_event_advances_the_heartbeat_and_exits_on_shutdown_or_close() {
        // driver_step is one turn of the driver loop. With SHUTDOWN clear and an event queued, it must
        // apply the event (via apply_event), advance the F-17 healthz heartbeat, and return true
        // (continue). With SHUTDOWN set it drains the store and returns false (exit); a closed event
        // channel also returns false. Serialize on the shared lock: it writes LAST_TICK_MS/SHUTDOWN.
        let _lock = lock_driver_statics();
        let mut node = Node::with_store(Identity::generate(), MemoryStore::new());
        let mut writers: HashMap<u64, SyncSender<Vec<u8>>> = HashMap::new();
        let mut prev = std::collections::HashSet::new();
        let (tx, rx) = event_channel();
        let mut schedule = DriverSchedule {
            last_stats_ms: 0,
            next_tick: Instant::now(),
            next_durability_probe: Instant::now() + DURABILITY_PROBE_INTERVAL,
        };

        SHUTDOWN.store(false, Ordering::SeqCst);
        LAST_TICK_MS.store(0, Ordering::Relaxed);
        let (out_tx, _out_rx) = mpsc::sync_channel(MAX_OUTBOUND_FRAMES_PER_LINK);
        tx.send(Ev::Up(9, Role::Responder, out_tx)).unwrap();
        assert!(
            driver_step(&mut node, &mut writers, &tx, &rx, &mut prev, &mut schedule,),
            "a queued event => continue"
        );
        assert!(
            writers.contains_key(&9),
            "the event was applied via apply_event"
        );
        assert_ne!(
            LAST_TICK_MS.load(Ordering::Relaxed),
            0,
            "the F-17 heartbeat advanced this iteration"
        );

        // An idle iteration (channel open, nothing queued): recv_timeout elapses (~1s) and the node
        // ticks, still returning true. This is the steady-state path of the loop.
        schedule.next_tick = Instant::now();
        assert!(
            driver_step(&mut node, &mut writers, &tx, &rx, &mut prev, &mut schedule,),
            "an idle iteration ticks the node and continues"
        );

        // SIGTERM: driver_step drains the durable store and signals exit.
        SHUTDOWN.store(true, Ordering::SeqCst);
        assert!(
            !driver_step(&mut node, &mut writers, &tx, &rx, &mut prev, &mut schedule,),
            "SHUTDOWN set => drain and exit"
        );
        SHUTDOWN.store(false, Ordering::SeqCst);

        // A closed event channel (all senders dropped) also ends the loop.
        drop(tx);
        let (closed_tx, closed_rx) = event_channel();
        drop(closed_tx);
        let (control_tx, _control_rx) = event_channel();
        assert!(
            !driver_step(
                &mut node,
                &mut writers,
                &control_tx,
                &closed_rx,
                &mut prev,
                &mut schedule,
            ),
            "a disconnected channel => exit"
        );
    }
}

#[cfg(test)]
mod log_stream_public_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn public_on_serves_the_ring_backlog_and_streams_live_lines() {
        // services-03: with HOP_PUBLIC_LOG_STREAM=1 the log viewer gets the ring backlog (the
        // else-branch) AND any live public line emitted while connected (the recv-line path). Drive
        // serve_log_stream over a real socket against the global hub. Terminate robustly by closing the
        // client then emitting one more line (its failed write breaks the loop), so the test does not
        // depend on the deadline (which a parallel test could perturb via the env seam).
        let _env = PUBLIC_LOG_ENV_LOCK.lock().unwrap();
        std::env::set_var("HOP_PUBLIC_LOG_STREAM", "1");
        // NB: deliberately do NOT set HOP_LOG_STREAM_MAX_MS. That env seam is owned by the
        // CONN_TEST_LOCK log-stream tests (a different lock); writing it here would race them. This
        // test instead terminates deterministically via the forced write-failure below, independent
        // of whatever deadline is in effect.

        // Seed a distinctive backlog line into the GLOBAL ring BEFORE the viewer connects.
        netlog("PLS-BACKLOG stats: peers=1 held=0");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_log_stream(sock);
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        // Emit a live line after the viewer has had a moment to subscribe (recv-line path).
        std::thread::sleep(Duration::from_millis(120));
        netlog("PLS-LIVE stats: peers=2 held=1");

        // Read for up to ~3s or until both markers are seen.
        let mut text = String::new();
        let start = std::time::Instant::now();
        let mut buf = [0u8; 2048];
        while start.elapsed() < Duration::from_secs(3) {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    text.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if text.contains("PLS-BACKLOG") && text.contains("PLS-LIVE") {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // keep waiting (and let a live line be emitted/arrive)
                }
                Err(_) => break,
            }
        }
        assert!(
            text.contains("PLS-BACKLOG"),
            "public-on exposes the ring backlog to the viewer: {text}"
        );
        assert!(
            text.contains("PLS-LIVE"),
            "a live public line is streamed to the viewer: {text}"
        );

        // Terminate the handler deterministically: close the client, then emit a line whose failed
        // write breaks serve_log_stream's loop (independent of the deadline).
        client.shutdown(std::net::Shutdown::Both).ok();
        drop(client);
        for _ in 0..5 {
            netlog("PLS-DRAIN tick");
            if server.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        server.join().unwrap();
        std::env::remove_var("HOP_PUBLIC_LOG_STREAM");
    }
}

/// §35 keyed-relay configuration + usage-ledger tests. The gate/meter semantics themselves are
/// proven in hop-core (access_gate_tests); this covers relayd's slice: flags -> policy, and the
/// drain -> hour-bucketed kv ledger rows the §37 reconciler reads.
#[cfg(test)]
mod access_and_ledger_tests {
    use super::*;
    use hop_core::store::MemoryStore;

    #[test]
    fn hex_parsing_is_exact_and_rejects_malformation() {
        assert_eq!(parse_hex_bytes::<2>("beef"), Some([0xbe, 0xef]));
        assert_eq!(parse_hex_bytes::<2>("BEEF"), Some([0xbe, 0xef]));
        assert_eq!(parse_hex_bytes::<2>(" beef "), Some([0xbe, 0xef]));
        assert_eq!(parse_hex_bytes::<2>("bee"), None, "odd length");
        assert_eq!(parse_hex_bytes::<2>("beefee"), None, "wrong length");
        assert_eq!(parse_hex_bytes::<2>("bxef"), None, "non-hex");
        assert_eq!(hex_string(&[0xbe, 0xef]), "beef");
    }

    #[test]
    fn the_stamp_flags_parse_and_malformed_hex_flags_the_error() {
        let key = Identity::generate();
        let tenant_hex = "00112233445566778899aabbccddeeff";
        let good = format!("{tenant_hex}:{}", hex_string(&key.address()));
        let cfg = parse_args(
            [
                "--require-stamps",
                "--tenant-key",
                &good,
                "--tenant-key",
                "not-a-pair",
                "--deny-tenant",
                "ffeeddccbbaa99887766554433221100",
            ]
            .into_iter()
            .map(String::from),
        );
        assert!(cfg.require_stamps);
        assert_eq!(
            cfg.tenant_keys,
            vec![(
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff
                ],
                key.address()
            )]
        );
        assert!(
            cfg.stamp_flag_error,
            "a malformed --tenant-key sets the error flag"
        );
        assert_eq!(cfg.deny_tenants.len(), 1);
    }

    #[test]
    fn tenant_key_parsing_is_exact() {
        let pk = hex_string(&Identity::generate().address());
        let t = "00112233445566778899aabbccddeeff";
        assert!(parse_tenant_key(&format!("{t}:{pk}")).is_some());
        assert!(
            parse_tenant_key(&format!("{t}{pk}")).is_none(),
            "no separator"
        );
        assert!(
            parse_tenant_key(&format!("dead:{pk}")).is_none(),
            "short tenant"
        );
        assert!(
            parse_tenant_key(&format!("{t}:dead")).is_none(),
            "short key"
        );
    }

    #[test]
    fn access_policy_from_covers_open_keyed_and_the_fatal_misconfig() {
        let pair = ([9u8; 16], Identity::generate().address());
        // Default: open.
        assert!(matches!(
            access_policy_from(false, &[], &[], false),
            Ok(None)
        ));
        // Keyed with a tenant key: a Keyed policy.
        assert!(matches!(
            access_policy_from(true, &[pair], &[[9u8; 16]], false),
            Ok(Some(AccessPolicy::Keyed(_)))
        ));
        // require-stamps with zero tenant keys: refused, never silently open.
        assert!(access_policy_from(true, &[], &[], false).is_err());
        // require-stamps with a malformed key flag: refused.
        assert!(access_policy_from(true, &[pair], &[], true).is_err());
    }

    #[test]
    fn the_policy_wires_through_to_the_node() {
        let mut node = Node::new(Identity::generate());
        let pair = ([1u8; 16], Identity::generate().address());
        let policy = access_policy_from(true, &[pair], &[], false)
            .unwrap()
            .unwrap();
        node.set_access_policy(policy);
        assert!(matches!(node.access_policy(), AccessPolicy::Keyed(_)));
    }

    #[test]
    fn ledger_rows_roundtrip_and_malformed_values_read_as_zero() {
        let u = Usage {
            bundles: 42,
            payload_bytes: 1 << 40,
        };
        assert_eq!(decode_usage(&encode_usage(&u)), u);
        assert_eq!(decode_usage(b"garbage"), Usage::default());
        assert_eq!(decode_usage(&[]), Usage::default());
    }

    #[test]
    fn merges_accumulate_within_an_hour_and_split_across_hours_and_tenants() {
        let mut store = MemoryStore::new();
        let t1: TenantId = [1u8; 16];
        let t2: TenantId = [2u8; 16];
        let hour0 = 10 * 3_600_000; // hour bucket 10
                                    // Two flushes in the same hour accumulate into one row per tenant.
        merge_usage_into_store(
            &mut store,
            &[
                (
                    t1,
                    Usage {
                        bundles: 3,
                        payload_bytes: 300,
                    },
                ),
                (
                    t2,
                    Usage {
                        bundles: 1,
                        payload_bytes: 10,
                    },
                ),
            ],
            hour0,
        );
        merge_usage_into_store(
            &mut store,
            &[(
                t1,
                Usage {
                    bundles: 2,
                    payload_bytes: 200,
                },
            )],
            hour0 + 60_000,
        );
        assert_eq!(
            decode_usage(&store.get_kv(&usage_kv_key(10, &t1)).unwrap()),
            Usage {
                bundles: 5,
                payload_bytes: 500
            }
        );
        assert_eq!(
            decode_usage(&store.get_kv(&usage_kv_key(10, &t2)).unwrap()),
            Usage {
                bundles: 1,
                payload_bytes: 10
            }
        );
        // A flush in the next hour opens a new row; the old row is untouched.
        merge_usage_into_store(
            &mut store,
            &[(
                t1,
                Usage {
                    bundles: 7,
                    payload_bytes: 700,
                },
            )],
            11 * 3_600_000,
        );
        assert_eq!(
            decode_usage(&store.get_kv(&usage_kv_key(11, &t1)).unwrap()).bundles,
            7
        );
        assert_eq!(
            decode_usage(&store.get_kv(&usage_kv_key(10, &t1)).unwrap()).bundles,
            5
        );
        // And the ledger prefix lists exactly the three rows.
        assert_eq!(store.list_kv("usage/").len(), 3);
    }
}
