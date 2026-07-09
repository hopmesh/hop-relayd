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
// Live network-log hub: a ring buffer + fan-out to HTTP viewers. Visiting a relay
// over plain HTTP (e.g. relay.hopme.sh in a browser) streams these events live; the
// stream leads with this node's region+address so you know which region the anycast
// name routed you to.
// ---------------------------------------------------------------------------

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

    /// Append a timestamped line: store in the ring, fan out to viewers, mirror to stderr
    /// (so it also lands in Cloud Logging).
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

    /// Register a viewer: returns this node's identity, the recent backlog, and a stream
    /// of future lines.
    fn subscribe(&self) -> (String, Vec<String>, Receiver<String>) {
        let (tx, rx) = mpsc::channel();
        let mut g = self.inner.lock().unwrap();
        g.subs.push(tx);
        (g.who.clone(), g.ring.iter().cloned().collect(), rx)
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

/// Emit a line to the live network log (ring + HTTP viewers + stderr).
fn netlog(line: impl Into<String>) {
    log_hub().emit(line.into());
}

/// F-17: liveness probe. 200 only if the driver loop ticked within [`HEALTHZ_STALE_MS`]; else 503,
/// so Cloud Run's startup/liveness probe restarts a wedged instance. This is a container-level probe
/// (Cloud Run hits it internally); do NOT wire an external uptime check against region endpoints —
/// DESIGN.md §1436 forbids externally probing regions because it wakes scaled-to-zero instances.
fn serve_healthz(mut stream: TcpStream) {
    let last = LAST_TICK_MS.load(Ordering::Relaxed);
    let healthy = last != 0 && now_ms().saturating_sub(last) < HEALTHZ_STALE_MS;
    let (status, body) = if healthy {
        ("200 OK", "ok")
    } else {
        ("503 Service Unavailable", "stale")
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
    let _ = stream.set_read_timeout(None);
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
    for line in backlog {
        if stream.write_all(format!("{line}\n").as_bytes()).is_err() {
            return;
        }
    }
    if stream.flush().is_err() {
        return;
    }
    netlog("http: log viewer connected");
    loop {
        match rx.recv_timeout(Duration::from_secs(15)) {
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
                let tx = tx.clone();
                std::thread::spawn(move || serve_tcp(stream, Role::Responder, &tx));
            }
        });
    }

    // Accept inbound WebSocket connections (Cloud Run / LB front door).
    if let Some(addr) = ws {
        let tx = tx.clone();
        let listener = TcpListener::bind(&addr).expect("bind --ws address");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let tx = tx.clone();
                std::thread::spawn(move || serve_ws(stream, &tx));
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
                netlog(format!(
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
                    netlog(format!("ingest: msg {} → dst {}", short_b58(&b.id()), dst));
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

        // Log authenticated peer joins/leaves (by address) and periodic stats to the live
        // network log — so a viewer can see who's connected and what's held for relay.
        let cur: std::collections::HashSet<Vec<u8>> =
            node.peers().iter().map(|a| a.to_vec()).collect();
        for p in cur.difference(&prev_peers) {
            netlog(format!("peer connected: {}", short_b58(p)));
        }
        for p in prev_peers.difference(&cur) {
            netlog(format!("peer left: {}", short_b58(p)));
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
        if n > 1 << 20 {
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
fn serve_ws(stream: TcpStream, ev_tx: &Sender<Ev>) {
    let _ = stream.set_nodelay(true);
    // Cloud Run sends plain HTTP requests to $PORT (connectivity checks, health probes,
    // any non-WS GET). If we just close those, Cloud Run sees a malformed/empty response
    // and recycles the instance in a loop — starving real WS clients (503s). So peek the
    // request first; anything that isn't a WebSocket upgrade gets the live network-log
    // stream (a valid 200, so the instance stays healthy). A non-consuming peek leaves the
    // bytes for tungstenite.
    {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut head = [0u8; 1024];
        match stream.peek(&mut head) {
            Ok(n) if n > 0 => {
                let req = String::from_utf8_lossy(&head[..n]).to_ascii_lowercase();
                // F-17: a real health probe, tied to the driver loop's heartbeat — distinct from the
                // log stream, which stays up even if the driver deadlocks and so is NOT a health signal.
                if req.contains("get /healthz") {
                    serve_healthz(stream);
                    return;
                }
                if !req.contains("upgrade: websocket") {
                    serve_log_stream(stream);
                    return;
                }
            }
            _ => return, // no data / probe with no payload — nothing to serve
        }
        let _ = stream.set_read_timeout(None); // hand a clean blocking socket to tungstenite
    }
    let mut ws = match tungstenite::accept(stream) {
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
    let _ = std::fs::write(key_path, id.to_secret_bytes());
    id
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
    use std::collections::HashSet;
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
                // Bundles already handed off (id → dest region), so we don't re-write them
                // every cycle. Bounded reset keeps it from growing unboundedly.
                let mut handed: HashSet<(BundleId, String)> = HashSet::new();
                // §39 P5: private bundles already spooled to a mailbox (id → tag), and bundles
                // already pulled back from a mailbox (id), so neither is redone every cycle.
                let mut spooled: HashSet<(BundleId, Tag)> = HashSet::new();
                let mut pulled: HashSet<BundleId> = HashSet::new();
                for snap in snap_rx {
                    if handed.len() > 100_000 {
                        handed.clear();
                    }
                    if spooled.len() > 100_000 {
                        spooled.clear();
                    }
                    if pulled.len() > 100_000 {
                        pulled.clear();
                    }
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
                        if !handed.insert((*id, dst_region.clone())) {
                            continue; // already written this cycle-set
                        }
                        let dest_node = region_node_b58(&base_seed, &dst_region);
                        if let Err(e) = presence.put_bundle_to(&dest_node, id, bytes, *expires) {
                            super::netlog(format!(
                                "handoff FAILED: msg {} → {} (region {dst_region}): {e}",
                                super::short_b58(id),
                                super::short_b58(dst)
                            ));
                            handed.remove(&(*id, dst_region)); // let a later cycle retry
                        } else {
                            super::netlog(format!(
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
        spooled: &mut HashSet<(BundleId, Tag)>,
        pulled: &mut HashSet<BundleId>,
    ) -> Vec<Vec<u8>> {
        for (id, tag, bytes, expires) in spool {
            if !spooled.insert((*id, *tag)) {
                continue; // already spooled this cycle-set
            }
            let tag_b58 = bs58::encode(tag).into_string();
            if let Err(e) = store.spool_to_mailbox(&tag_b58, id, bytes, *expires) {
                super::netlog(format!(
                    "spool FAILED: msg {} → mailbox {}: {e}",
                    super::short_b58(id),
                    &tag_b58[..tag_b58.len().min(8)]
                ));
                spooled.remove(&(*id, *tag)); // let a later cycle retry
            } else {
                super::netlog(format!(
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
            for (bytes, _expires) in held {
                let Ok(b) = hop_core::bundle::Bundle::from_bytes(&bytes) else {
                    continue;
                };
                let id = b.id();
                if pulled.insert(id) {
                    super::netlog(format!(
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
            // F-06: the mailbox tag is derived from the recipient address + epoch (epoch 0 here).
            let mailbox = hop_core::crypto::mailbox_tag(seal_to, 0);
            let b = Bundle::create_private(
                seal_to,
                spk_pub,
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: b"cross-region".to_vec(),
                },
                Some(mailbox),
                BundleOpts::default(),
            )
            .unwrap();
            (b.id(), mailbox, b.to_bytes().unwrap())
        }

        #[test]
        fn cross_region_spool_then_want_beacon_pulls_exactly_once() {
            use hop_core::prelude::Identity;
            let store = FakeMailbox::default();
            let bob = Identity::generate();
            let spk = bob.derive_prekey();
            let (id, tag, bytes) = private_bundle_for(&spk.public, &bob.address());

            // Region A: no live gradient → spool the bundle. Its own dedup sets.
            let (mut sp_a, mut pl_a) = (HashSet::new(), HashSet::new());
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
            let (mut sp_b, mut pl_b) = (HashSet::new(), HashSet::new());
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
            let (mut sp_c, mut pl_c) = (HashSet::new(), HashSet::new());
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
            let (mut sp, mut pl) = (HashSet::new(), HashSet::new());
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
