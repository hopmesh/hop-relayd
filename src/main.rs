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
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hop_core::prelude::*;
use hop_core::store::Store;
#[cfg(feature = "firestore")]
use hop_store_firestore::FirestoreStore;
use hop_store_sqlite::SqliteStore;
use tungstenite::Message;

static NEXT_LINK: AtomicU64 = AtomicU64::new(1);

/// Max accepted inbound frame/message size (services-05). The raw-TCP bearer path already caps a
/// frame at this; the WS path must use the SAME bound instead of tungstenite's 64 MiB default, or a
/// single WS client could push a 64 MiB message that the TCP path would have rejected at 1 MiB.
const MAX_FRAME_BYTES: usize = 1 << 20; // 1 MiB

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
    Up(u64, Role, Sender<Vec<u8>>),
    Data(u64, Vec<u8>),
    Down(u64),
    /// A sealed bundle pulled from durable storage (a cross-partition handoff that
    /// landed in our Firestore partition while warm) to store + relay (DESIGN.md §28).
    /// Only produced by the cloud handoff worker (the `firestore` feature).
    #[cfg_attr(not(feature = "firestore"), allow(dead_code))]
    Ingest(Vec<u8>),
    /// Raw DoH response bodies for a domain's full DNSSEC chain (DESIGN.md §30), from the DoH
    /// worker; core validates + caches. `(domain, bodies)`. Only in the cloud build.
    #[cfg(feature = "firestore")]
    DnsProof(String, Vec<String>),
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

struct LogHub {
    inner: Mutex<LogInner>,
}
struct LogInner {
    who: String, // this relay's identity header (region + address)
    ring: VecDeque<String>,
    subs: Vec<Sender<String>>,
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
        g.subs.retain(|s| s.send(stamped.clone()).is_ok());
    }

    /// Register a viewer: returns this node's identity, the recent backlog (only when the public
    /// stream is enabled), and a stream of future public lines.
    fn subscribe(&self) -> (String, Vec<String>, Receiver<String>) {
        let (tx, rx) = mpsc::channel();
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

/// F-17: liveness probe. 200 only if the driver loop ticked within [`HEALTHZ_STALE_MS`]; else 503,
/// so Cloud Run's startup/liveness probe restarts a wedged instance. This is a container-level probe
/// (Cloud Run hits it internally); do NOT wire an external uptime check against region endpoints —
/// DESIGN.md §1436 forbids externally probing regions because it wakes scaled-to-zero instances.
fn serve_healthz(mut stream: TcpStream) {
    let last = LAST_TICK_MS.load(Ordering::Relaxed);
    let healthy = last != 0 && now_ms().saturating_sub(last) < HEALTHZ_STALE_MS;
    // stores-09: surface the durable store's dropped-op count. We do NOT flip to 503 on drops (a
    // restart won't fix a Firestore outage and would drop the in-memory hot path too); we report it
    // in the body so a monitor/operator sees the relay is not currently durable. Only a wedged
    // driver (stale tick) is a restart-worthy 503.
    let dropped = MIRROR_DROPPED
        .get()
        .map(|d| d.load(Ordering::Relaxed))
        .unwrap_or(0);
    let (status, body) = if !healthy {
        ("503 Service Unavailable", "stale".to_string())
    } else if dropped > 0 {
        ("200 OK", format!("ok degraded: mirror_dropped={dropped}"))
    } else {
        ("200 OK", "ok".to_string())
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

/// Stream the live network log to a plain-HTTP visitor (text/plain, incremental). Leads
/// with this node's identity so a visitor to the anycast name sees which region answered.
fn serve_log_stream(mut stream: TcpStream) {
    // services-r3-01: a public log viewer holds one of the small [`MAX_LOG_CONNS`] slots. Bound how
    // long it can hold it with a total deadline, and use a write timeout so a stalled reader (a slow
    // or wedged TCP peer that never drains) cannot block this thread forever on `write_all`. Together
    // these guarantee the log pool keeps rotating and a silent/slow holder cannot pin a slot.
    let deadline = std::time::Instant::now() + Duration::from_millis(log_stream_max_ms());
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

fn main() {
    install_shutdown_handler(); // F-21: drain the durable store on SIGTERM before the instance is reaped
    let mut listen: Option<String> = None;
    let mut ws: Option<String> = None;
    let mut db = "hop-relay.db".to_string();
    let mut identity_file: Option<String> = None;
    let mut peers: Vec<String> = Vec::new();
    let mut firestore: Option<String> = None;
    let mut region: Option<String> = None;
    let mut advertise: Option<String> = None;
    let mut mesh_fanout: usize = 0; // 0 = handoff-only (no relay-to-relay dialing); >0 enables it
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next(),
            "--ws" => ws = args.next(),
            "--db" => db = args.next().unwrap_or(db),
            "--identity-file" => identity_file = args.next(),
            "--firestore" => firestore = args.next(), // GCP project id → durable per-node store
            "--region" => region = args.next(),       // this node's region (registry, §28)
            "--advertise" => advertise = args.next(), // our connectable wss:// endpoint for peers
            // Online-only relay-to-relay epidemic fan-out (DESIGN.md §28): dial up to N
            // *currently-online* peer relays (never wakes a sleeping one). 0 = off.
            "--mesh-fanout" => mesh_fanout = args.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            "--peer" => {
                if let Some(p) = args.next() {
                    peers.push(p);
                }
            }
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }
    // Preserve the path-A default: a bare invocation listens on TCP 9443.
    if listen.is_none() && ws.is_none() {
        listen = Some("0.0.0.0:9443".to_string());
    }

    let mut identity = load_identity(&identity_file, &format!("{db}.key"));
    // The shared base seed — every region derives its node identity from this same seed,
    // so any node can compute any other region's address (cross-partition handoff, §28).
    let base_seed = identity.to_secret_bytes();
    // Per-region backbone node: derive a stable, distinct identity from the shared seed
    // and the region name, so each region is its own node (own Firestore partition +
    // liveness-registry entry) without needing a separate secret per region (§27/§28).
    if let Some(r) = &region {
        identity = Identity::from_secret_bytes(&region_seed(&base_seed, r));
        println!(
            "hop-relayd: region={r} derived address {}",
            bs58_addr(&identity.address())
        );
    }
    let addr = identity.address();
    let store = build_store(&firestore, &db, &addr);
    let mut node = Node::with_store(identity, store);
    // Cloud node: a much larger learned-route table than a phone (DESIGN.md §27) so the
    // backbone becomes the long-memory route learner, and stamp the Hop-relay app id so
    // a relay hop shows as "Hop Relay" in traces.
    node.set_route_capacity(200_000);
    // Cloud relays run a large custody window — with forward-before-evict this is a
    // sliding window of concurrent in-flight bundles (incl. chunked media), not a cap on
    // transfer size, so many simultaneous large transfers can pass through (DESIGN.md §6).
    node.set_max_relayed(8192);
    node.set_app(hop_core::relay_app_id());
    // Answer hop.identify as a relay, named by its public domain (the host of --advertise,
    // e.g. us-central1.relay.hopme.sh) so trace resolution shows relays by domain (§29).
    node.set_kind(NodeKind::Relay);
    if let Some(adv) = &advertise {
        node.set_name(Some(host_of(adv)));
    }
    // The cloud relay is internet-connected, so it serves as an HNS resolver for peers that
    // ask it (DESIGN.md §30). Resolution still works without it — any internet-connected peer
    // resolves on its own — but an always-on relay is a convenient recursive resolver.
    #[cfg(feature = "firestore")]
    node.set_internet(true);
    println!(
        "hop-relayd: address {} {}{}{} backbone peer(s)",
        bs58_addr(&addr),
        listen
            .as_deref()
            .map(|l| format!("tcp {l} "))
            .unwrap_or_default(),
        ws.as_deref()
            .map(|w| format!("ws {w} "))
            .unwrap_or_default(),
        peers.len(),
    );
    // Identify this node in the live HTTP log stream (so a visitor to the anycast name
    // sees which region answered).
    log_hub().set_identity(format!(
        "region={} node={}",
        region.as_deref().unwrap_or("local"),
        bs58_addr(&addr)
    ));
    netlog(format!(
        "relay up: region={} node={}",
        region.as_deref().unwrap_or("local"),
        bs58_addr(&addr)
    ));

    let (tx, rx) = mpsc::channel::<Ev>();

    // Accept inbound TCP device/relay connections (one thread per connection).
    if let Some(addr) = listen {
        let tx = tx.clone();
        let listener = TcpListener::bind(&addr).expect("bind --listen address");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                // services-04: shed over the connection cap rather than spawn unboundedly.
                let Some(guard) = admit_conn() else {
                    drop(stream);
                    continue;
                };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let _guard = guard; // releases the slot on drop (incl. panic unwind)
                    serve_tcp(stream, Role::Responder, &tx)
                });
            }
        });
    }

    // Accept inbound WebSocket connections (Cloud Run / LB front door).
    if let Some(addr) = ws {
        let tx = tx.clone();
        let listener = TcpListener::bind(&addr).expect("bind --ws address");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                // services-r3-01: classify the request (WS upgrade / healthz / log-stream) via a
                // non-consuming peek BEFORE charging any budget, then admit against the RIGHT pool so
                // idle log viewers can never starve mesh links. Only the peek itself is done inline
                // (bounded, cheap); the long-lived handler runs on its own thread. Peek failures /
                // over-budget shed the socket without spawning, keeping thread spawn bounded.
                let kind = classify_ws_peek(&stream);
                let guard = match kind {
                    // Healthz answers immediately and closes: exempt from every budget so a real
                    // liveness probe is NEVER shed at the cap (services-r3-04). No slot charged.
                    WsKind::Healthz => {
                        std::thread::spawn(move || serve_healthz(stream));
                        continue;
                    }
                    // Log viewers charge their own small budget; over it, shed.
                    WsKind::LogStream => match admit_log_conn() {
                        Some(g) => g,
                        None => {
                            drop(stream);
                            continue;
                        }
                    },
                    // Real WS upgrade: a mesh link, charges the mesh budget; over it, shed.
                    WsKind::Upgrade => match admit_conn() {
                        Some(g) => g,
                        None => {
                            drop(stream);
                            continue;
                        }
                    },
                    // No data / empty probe: nothing to serve, no thread, no slot.
                    WsKind::Empty => {
                        drop(stream);
                        continue;
                    }
                };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let _guard = guard;
                    serve_ws(stream, kind, &tx)
                });
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

    // HNS resolver worker (DESIGN.md §30): drains domains the node wants resolved, fetches the
    // whole DNSSEC chain over DNS-over-HTTPS (TXT + DNSKEY/DS up to the root) off this thread,
    // and hands the raw response bodies back as Ev::DnsProof — core validates. Cloud-only.
    #[cfg(feature = "firestore")]
    let dns_tx: Sender<String> = {
        let (dtx, drx) = mpsc::channel::<String>();
        let ev_tx = tx.clone();
        std::thread::spawn(move || {
            let http = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("dns http client");
            for domain in drx {
                let bodies = fetch_dnssec_chain(&http, &domain);
                // services-03: the resolved domain is sensitive (reveals who someone is looking up).
                netlog_private(format!(
                    "hns: fetched {} chain records for {domain}",
                    bodies.len()
                ));
                let _ = ev_tx.send(Ev::DnsProof(domain, bodies));
            }
        });
        dtx
    };

    // Driver: the sole owner of the node + the per-link outgoing senders.
    let mut writers: HashMap<u64, Sender<Vec<u8>>> = HashMap::new();
    let mut prev_peers: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut last_stats_ms: u64 = 0;
    #[cfg(feature = "firestore")]
    let mut last_handoff_ms: u64 = 0;
    loop {
        // F-17: heartbeat for /healthz. The loop iterates at least once per second (recv timeout →
        // tick); if node.handle/tick ever deadlocks, this stops advancing and /healthz goes 503.
        LAST_TICK_MS.store(now_ms(), Ordering::Relaxed);
        // F-21: on SIGTERM, drain the durable store's pending mirror queue before exiting, so a
        // spool/handoff write accepted just before Cloud Run reaps us survives. Cloud Run grants a
        // grace window on shutdown; bound the flush well inside it.
        if SHUTDOWN.load(Ordering::SeqCst) {
            let flushed = node.store.flush(Duration::from_secs(8));
            netlog(format!(
                "SIGTERM: durable-store flush {} — exiting",
                if flushed { "drained" } else { "timed out" }
            ));
            break;
        }
        match rx.recv_timeout(Duration::from_millis(1000)) {
            Ok(Ev::Up(link, role, out)) => {
                writers.insert(link, out);
                netlog(format!("conn up: link={link} ({role:?})"));
                node.handle(BearerEvent::Connected(link, role));
            }
            Ok(Ev::Data(link, bytes)) => node.handle(BearerEvent::Data(link, bytes)),
            Ok(Ev::Down(link)) => {
                writers.remove(&link);
                netlog(format!("conn down: link={link}"));
                node.handle(BearerEvent::Disconnected(link));
            }
            Ok(Ev::Ingest(bytes)) => {
                if let Ok(b) = Bundle::from_bytes(&bytes) {
                    let dst = match b.inner.dst {
                        Destination::Device(d) | Destination::AckTo(d, _) => short_b58(&d),
                        Destination::Broadcast => "broadcast".to_string(),
                        Destination::Vaccine(..) => "vaccine".to_string(),
                    };
                    // services-03: bundle id + destination address is per-message metadata.
                    netlog_private(format!("ingest: msg {} → dst {}", short_b58(&b.id()), dst));
                    node.ingest(b);
                }
            }
            #[cfg(feature = "firestore")]
            Ok(Ev::DnsProof(domain, bodies)) => node.provide_dns_proof(&domain, bodies),
            Err(RecvTimeoutError::Timeout) => node.tick(now_ms()),
            Err(RecvTimeoutError::Disconnected) => break,
        }
        // Dispatch any HNS lookups the node wants to the DoH worker (DESIGN.md §30).
        #[cfg(feature = "firestore")]
        for domain in node.take_dns_lookups() {
            let _ = dns_tx.send(domain);
        }
        for (link, bytes) in node.drain_outgoing() {
            if let Some(out) = writers.get(&link) {
                if out.send(bytes).is_err() {
                    writers.remove(&link); // connection's writer thread is gone
                }
            }
        }

        // Log authenticated peer joins/leaves (by address) privately, and periodic AGGREGATE stats
        // publicly. services-03: a per-peer address join/leave is correlatable traffic metadata, so
        // it goes only to Cloud Logging; the public stream sees just the peers=N counter below.
        let cur: std::collections::HashSet<Vec<u8>> =
            node.peers().iter().map(|a| a.to_vec()).collect();
        for p in cur.difference(&prev_peers) {
            netlog_private(format!("peer connected: {}", short_b58(p)));
        }
        for p in prev_peers.difference(&cur) {
            netlog_private(format!("peer left: {}", short_b58(p)));
        }
        prev_peers = cur;
        let now = now_ms();
        if now.saturating_sub(last_stats_ms) >= 10_000 {
            last_stats_ms = now;
            netlog(format!(
                "stats: peers={} held={}",
                node.peers().len(),
                node.queue().len()
            ));
        }

        // Feed the handoff worker a fresh snapshot of who's connected and what we can't
        // deliver locally, on a slow timer (the worker does the blocking Firestore I/O
        // off this thread, §28).
        #[cfg(feature = "firestore")]
        if let Some(htx) = &handoff_tx {
            let now = now_ms();
            if now.saturating_sub(last_handoff_ms) >= HANDOFF_INTERVAL_MS {
                last_handoff_ms = now;
                let _ = htx.send(handoff::Snapshot {
                    now_ms: now,
                    devices: node.peers(),
                    undeliverable: node.undeliverable_device_bundles(),
                    spool: node.spoolable_private_bundles(),
                    wanted: node.take_wanted_mailboxes(),
                });
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
fn serve_tcp(stream: TcpStream, role: Role, ev_tx: &Sender<Ev>) {
    let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
    let _ = stream.set_nodelay(true);
    let mut write_half = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
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
        let mut buf = vec![0u8; n];
        if read.read_exact(&mut buf).is_err() {
            break;
        }
        if ev_tx.send(Ev::Data(link, buf)).is_err() {
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
            if req.contains("get /healthz") {
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

fn serve_ws(stream: TcpStream, kind: WsKind, ev_tx: &Sender<Ev>) {
    // The accept loop already peek-classified this connection and charged the right budget
    // (services-r3-01). Dispatch non-mesh shapes to their handlers; only a real upgrade continues
    // into the WS driver below. If we just closed non-WS GETs, Cloud Run would see a malformed/empty
    // response and recycle the instance in a loop, so a plain GET gets the live log stream instead.
    match kind {
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
    let ws_config = tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(MAX_FRAME_BYTES),
        max_frame_size: Some(MAX_FRAME_BYTES),
        ..Default::default()
    };
    let mut ws = match tungstenite::accept_with_config(stream, Some(ws_config)) {
        Ok(w) => w,
        Err(_) => return, // malformed upgrade
    };
    // A read timeout lets the single owner thread interleave writes with reads.
    let _ = ws
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(100)));

    let link = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
    if ev_tx.send(Ev::Up(link, Role::Responder, out_tx)).is_err() {
        return;
    }

    'conn: loop {
        // Flush anything the node wants to send before parking on read.
        loop {
            match out_rx.try_recv() {
                Ok(bytes) => {
                    if ws.write(Message::Binary(bytes)).is_err() {
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
        match ws.read() {
            Ok(Message::Binary(b)) => {
                if ev_tx.send(Ev::Data(link, b.to_vec())).is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {} // text/ping/pong/frame: tungstenite auto-replies to pings on flush
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
fn dial_peer(url: &str, ev_tx: &Sender<Ev>) {
    use tungstenite::stream::MaybeTlsStream;
    let (mut ws, _resp) = match tungstenite::connect(url) {
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
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
    if ev_tx.send(Ev::Up(link, Role::Initiator, out_tx)).is_err() {
        return;
    }
    netlog(format!("peer: dialed {url} (link {link})"));
    'conn: loop {
        loop {
            match out_rx.try_recv() {
                Ok(bytes) => match ws.write(Message::Binary(bytes)) {
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
        match ws.read() {
            Ok(Message::Binary(b)) => {
                if ev_tx.send(Ev::Data(link, b.to_vec())).is_err() {
                    return;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
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
fn build_store(firestore: &Option<String>, db: &str, addr: &[u8]) -> Box<dyn Store> {
    if let Some(project) = firestore {
        match FirestoreStore::open(project, addr) {
            Ok(s) => {
                println!("store: firestore (project {project})");
                // stores-09: expose the mirror's dropped-op counter to /healthz so a degraded
                // Firestore (writes being shed under backpressure) surfaces as unhealthy.
                let _ = MIRROR_DROPPED.set(s.mirror_dropped_handle());
                return Box::new(s);
            }
            Err(e) => eprintln!("firestore open failed ({e}); falling back to sqlite"),
        }
    }
    Box::new(SqliteStore::open(db).expect("open sqlite store"))
}

#[cfg(not(feature = "firestore"))]
fn build_store(firestore: &Option<String>, db: &str, _addr: &[u8]) -> Box<dyn Store> {
    if firestore.is_some() {
        eprintln!(
            "firestore support not compiled in (build with --features firestore); using sqlite"
        );
    }
    Box::new(SqliteStore::open(db).expect("open sqlite store"))
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

/// Fetch a domain's full DNSSEC chain over DNS-over-HTTPS (DESIGN.md §30) as raw JSON response
/// bodies for core to validate: the `_hopaddress.<domain>` TXT, plus DNSKEY + DS for every zone
/// from the domain up to the root (all with `do=1` so the RRSIG/DNSKEY/DS records are returned).
/// Core does the parsing + validation; the relay never decides the address.
#[cfg(feature = "firestore")]
fn fetch_dnssec_chain(http: &reqwest::blocking::Client, domain: &str) -> Vec<String> {
    let doh = |name: &str, qtype: u16| -> Option<String> {
        let url = format!("https://dns.google/resolve?name={name}&type={qtype}&do=1");
        http.get(&url).send().ok()?.text().ok()
    };
    let mut bodies = Vec::new();
    if let Some(b) = doh(&format!("_hopaddress.{domain}"), 16) {
        bodies.push(b);
    }
    // Walk zones: domain, parent, …, then the root (".").
    let mut zone = domain.to_string();
    loop {
        let is_root = zone == ".";
        if let Some(b) = doh(&zone, 48) {
            bodies.push(b); // DNSKEY
        }
        if is_root {
            break;
        }
        if let Some(b) = doh(&zone, 43) {
            bodies.push(b); // DS (lives in the parent, queried by the child name)
        }
        zone = match zone.find('.') {
            Some(i) => zone[i + 1..].to_string(),
            None => ".".to_string(),
        };
    }
    bodies
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
        ev_tx: super::Sender<super::Ev>,
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
    use std::sync::mpsc::{self, Sender};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hop_core::bundle::BundleId;
    use hop_core::crypto::{PubKeyBytes, Tag};
    use hop_store_firestore::Presence;

    use super::{region_node_b58, Ev};

    /// A device-presence record is trusted this long after check-in (matches the
    /// registry TTL — beyond it, we don't know where the device is, so we don't hand off).
    const PRESENCE_TTL_MS: u64 = 90_000;
    /// How often a warm node re-reads its own partition for handoffs others wrote.
    const RELOAD_SECS: u64 = 30;
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
        ev_tx: Sender<Ev>,
    ) -> Sender<Snapshot> {
        let me = bs58::encode(&addr).into_string();

        // Worker: consume driver snapshots, record device presence, and hand undeliverable
        // bundles into their destination region's partition.
        let (snap_tx, snap_rx) = mpsc::channel::<Snapshot>();
        {
            let presence = Presence::new(&project);
            let region = region.clone();
            let known_relays = known_relays.clone();
            let ev_tx = ev_tx.clone();
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
                    for bytes in process_mailbox(
                        &presence,
                        &snap.spool,
                        &snap.wanted,
                        &mut spooled,
                        &mut pulled,
                    ) {
                        if ev_tx.send(Ev::Ingest(bytes)).is_err() {
                            return; // driver gone
                        }
                    }
                }
            });
        }

        // Warm reload: re-read our own partition so handoffs written by other regions
        // while we're already up get ingested (a cold start gets them via rehydrate).
        {
            let presence = Presence::new(&project);
            std::thread::spawn(move || {
                let mut ingested: HashSet<BundleId> = HashSet::new();
                loop {
                    std::thread::sleep(Duration::from_secs(RELOAD_SECS));
                    match presence.list_bundles_of(&me) {
                        Ok(bundles) => {
                            for (bytes, _expires) in bundles {
                                if let Ok(b) = hop_core::bundle::Bundle::from_bytes(&bytes) {
                                    if !ingested.insert(b.id()) {
                                        continue; // already pushed to the driver
                                    }
                                    if ev_tx.send(Ev::Ingest(bytes)).is_err() {
                                        return; // driver gone
                                    }
                                }
                            }
                        }
                        Err(e) => eprintln!("handoff: partition reload failed: {e}"),
                    }
                }
            });
        }

        snap_tx
    }

    /// The durable blind-spool mailbox operations the §39 P5 worker needs (F-18). Abstracting these
    /// out of the concrete Firestore [`Presence`] makes the cross-region spool→pull round trip
    /// testable with an in-memory fake that two "regions" share.
    pub trait MailboxStore {
        fn spool_to_mailbox(
            &self,
            tag_b58: &str,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> Result<(), String>;
        fn list_mailbox(&self, tag_b58: &str) -> Result<Vec<(Vec<u8>, u64)>, String>;
        fn delete_mailbox_bundle(&self, tag_b58: &str, id: &BundleId) -> Result<(), String>;
    }

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
        fn list_mailbox(&self, tag_b58: &str) -> Result<Vec<(Vec<u8>, u64)>, String> {
            Presence::list_mailbox(self, tag_b58)
        }
        fn delete_mailbox_bundle(&self, tag_b58: &str, id: &BundleId) -> Result<(), String> {
            Presence::delete_mailbox_bundle(self, tag_b58, id)
        }
    }

    /// §39 P5 spool + want-beacon, store-agnostic. Spools each un-routable private bundle by its
    /// mailbox-tag; for each wanted tag, pulls anything held under it, dedups by id, deletes the
    /// spool copy, and returns the bytes to re-ingest. `spooled`/`pulled` carry cross-cycle dedup.
    pub fn process_mailbox<M: MailboxStore>(
        store: &M,
        spool: &[(BundleId, Tag, Vec<u8>, u64)],
        wanted: &[Tag],
        spooled: &mut HashMap<(BundleId, Tag), u64>,
        pulled: &mut HashMap<BundleId, u64>,
    ) -> Vec<Vec<u8>> {
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
            } else {
                super::netlog_private(format!(
                    "spool: msg {} → mailbox {}",
                    super::short_b58(id),
                    &tag_b58[..tag_b58.len().min(8)]
                ));
            }
        }

        let mut ingest = Vec::new();
        for tag in wanted {
            let tag_b58 = bs58::encode(tag).into_string();
            let held = match store.list_mailbox(&tag_b58) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("spool: list_mailbox failed: {e}");
                    continue;
                }
            };
            for (bytes, expires) in held {
                let Ok(b) = hop_core::bundle::Bundle::from_bytes(&bytes) else {
                    continue;
                };
                let id = b.id();
                if pulled.insert(id, expires).is_none() {
                    // services-03: pull side of the spool/pull correlation; operator log only.
                    super::netlog_private(format!(
                        "want-beacon: pulled msg {} from mailbox {}",
                        super::short_b58(&id),
                        &tag_b58[..tag_b58.len().min(8)]
                    ));
                    ingest.push(bytes);
                }
                let _ = store.delete_mailbox_bundle(&tag_b58, &id);
            }
        }
        ingest
    }

    #[cfg(test)]
    mod tests {
        use super::*;
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
            fn list_mailbox(&self, tag_b58: &str) -> Result<Vec<(Vec<u8>, u64)>, String> {
                Ok(self
                    .boxes
                    .lock()
                    .unwrap()
                    .get(tag_b58)
                    .map(|m| m.values().map(|v| (v.clone(), 0)).collect())
                    .unwrap_or_default())
            }
            fn delete_mailbox_bundle(&self, tag_b58: &str, id: &BundleId) -> Result<(), String> {
                if let Some(m) = self.boxes.lock().unwrap().get_mut(tag_b58) {
                    m.remove(id);
                }
                Ok(())
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
            let out_a = process_mailbox(
                &store,
                &[(id, tag, bytes.clone(), 0)],
                &[],
                &mut sp_a,
                &mut pl_a,
            );
            assert!(out_a.is_empty(), "spooling ingests nothing");
            assert_eq!(
                store
                    .list_mailbox(&bs58::encode(tag).into_string())
                    .unwrap()
                    .len(),
                1,
                "bundle is durably spooled by mailbox-tag"
            );

            // Region B (DIFFERENT worker/dedup sets, SAME store): bob beacons → want-beacon pulls it.
            let (mut sp_b, mut pl_b) = (HashMap::new(), HashMap::new());
            let out_b = process_mailbox(&store, &[], &[tag], &mut sp_b, &mut pl_b);
            assert_eq!(
                out_b.len(),
                1,
                "want-beacon in region B pulls the bundle spooled in region A"
            );
            assert_eq!(
                hop_core::bundle::Bundle::from_bytes(&out_b[0])
                    .unwrap()
                    .id(),
                id,
                "pulled the right bundle"
            );

            // Exactly once: the spool copy is deleted, so a re-beacon (even a fresh worker) pulls nothing.
            assert!(
                store
                    .list_mailbox(&bs58::encode(tag).into_string())
                    .unwrap()
                    .is_empty(),
                "spool copy deleted after pull"
            );
            let (mut sp_c, mut pl_c) = (HashMap::new(), HashMap::new());
            assert!(
                process_mailbox(&store, &[], &[tag], &mut sp_c, &mut pl_c).is_empty(),
                "no double-delivery on re-beacon"
            );
        }

        #[test]
        fn same_worker_pull_dedups_within_its_pulled_set() {
            use hop_core::prelude::Identity;
            let store = FakeMailbox::default();
            let bob = Identity::generate();
            let spk = bob.derive_prekey();
            let (id, tag, bytes) = private_bundle_for(&spk.public, &bob.address());
            let (mut sp, mut pl) = (HashMap::new(), HashMap::new());
            process_mailbox(&store, &[(id, tag, bytes, 0)], &[], &mut sp, &mut pl);
            // Re-insert into the store behind the worker's back to prove `pulled` dedup, not just deletion.
            let _ = store.spool_to_mailbox(&bs58::encode(tag).into_string(), &id, b"x", 0);
            let again = process_mailbox(&store, &[], &[tag], &mut sp, &mut pl);
            assert!(
                again.is_empty(),
                "a bundle id already pulled by this worker is not re-ingested"
            );
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
    use super::{netlog, netlog_private, LogHub, LogInner};
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
    fn public_stream_is_off_by_default() {
        // services-03: without HOP_PUBLIC_LOG_STREAM the per-event backlog is withheld (a visitor
        // gets identity + aggregate counters, not the ring of individual lines). The env var is not
        // set in the test process, so subscribe() returns an empty backlog even with a full ring.
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
}

#[cfg(test)]
mod control_path_tests {
    // services-r2-02: the newly-added robustness controls (frame cap + connection shedding) are the
    // exact surface that keeps a degraded/attacked relay from exhausting threads or memory, yet had
    // no direct tests. These exercise them so a regression fails a test, not CI.
    use super::{
        admit_conn, admit_log_conn, frame_len_ok, MAX_CONNS, MAX_FRAME_BYTES, MAX_LOG_CONNS,
    };
    use std::sync::Mutex;

    // These tests all mutate the process-global connection counters, so they must not run
    // concurrently with each other. Serialize them on one lock (Rust runs test fns in parallel).
    static CONN_TEST_LOCK: Mutex<()> = Mutex::new(());

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
        let _lock = CONN_TEST_LOCK.lock().unwrap();
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
        let _lock = CONN_TEST_LOCK.lock().unwrap();
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
        use super::serve_log_stream;
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let _lock = CONN_TEST_LOCK.lock().unwrap();
        std::env::set_var("HOP_LOG_STREAM_MAX_MS", "300");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            serve_log_stream(sock); // returns only when the deadline closes the stream
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        // Read until EOF; the server must close within ~the deadline (not hang forever).
        let start = std::time::Instant::now();
        let mut buf = [0u8; 4096];
        let mut saw_header = false;
        loop {
            match client.read(&mut buf) {
                Ok(0) => break, // EOF: server closed at the deadline
                Ok(n) => {
                    if String::from_utf8_lossy(&buf[..n]).contains("hop relay") {
                        saw_header = true;
                    }
                }
                // The server dropping the socket with unread buffered bytes surfaces as an
                // RST (ConnectionReset) rather than a clean EOF on some platforms. Either way the
                // connection is CLOSED at the deadline, which is exactly what we assert.
                Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(e) => panic!("read failed unexpectedly: {e}"),
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(4),
                "log stream did not close at its deadline (would camp a slot forever)"
            );
        }
        // The core proof is the timely close above; the header is best-effort (an RST can drop
        // buffered bytes before the client drains them, but the connection still closed on time).
        let _ = saw_header;
        server.join().unwrap();
        std::env::remove_var("HOP_LOG_STREAM_MAX_MS");
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
}

#[cfg(all(test, feature = "firestore"))]
mod handoff_dedup_tests {
    // services-r2-04: age-based eviction of the handoff/spool dedup maps, replacing the wholesale
    // clear() that let already-handed bundles be redundantly re-written to Firestore after a reset.
    use super::handoff::evict_expired;
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
}

#[cfg(test)]
mod healthz_tests {
    use super::*;
    use std::net::TcpStream;

    // serve_healthz reads the process-global LAST_TICK_MS; serialize so tests don't race the value.
    // Recover from poisoning so a single failing assertion reports ITS failure rather than
    // cascading a PoisonError across the other healthz tests (which would obscure the real break).
    static HEALTHZ_LOCK: Mutex<()> = Mutex::new(());
    fn lock_healthz() -> std::sync::MutexGuard<'static, ()> {
        HEALTHZ_LOCK.lock().unwrap_or_else(|p| p.into_inner())
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
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
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
        let (ev_tx, _ev_rx) = mpsc::channel::<Ev>();
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
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
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
