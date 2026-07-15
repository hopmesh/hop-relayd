<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop-relayd</h1>

<p align="center">
  <b>The Hop relay: store-and-forward for peers that are offline, and the most internet-exposed process in the mesh.</b><br>
  An always-on Hop node that bridges local meshes over the internet.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-stable-CE422B" alt="Rust">
  <img src="https://img.shields.io/badge/deploy-Cloud%20Run%20%C2%B7%20Docker-1f6feb" alt="Cloud Run · Docker">
  <img src="https://img.shields.io/badge/license-Apache--2.0-3ddc84" alt="license Apache-2.0">
</p>

---

Hop is a **delay-tolerant, end-to-end-encrypted mesh**: messages hop device to device over BLE, Wi-Fi,
and the internet until they reach the person or service you meant. Held, never dropped.

**hop-relayd is the relay.** It's an always-on Hop node with an internet bearer that does epidemic
store-and-forward for peers that aren't currently reachable, so a message to someone offline is held
and delivered when they reconnect. It's just a Hop node with a bearer: it carries bundles sealed
end-to-end (it relays ciphertext it can't read), and because it accepts connections from any node
worldwide with no prior trust, it's the hardened front door of the network.

## Run it

```sh
# raw TCP bearer (a single VM); front it with your own TLS-terminating LB
cargo run -- --listen 0.0.0.0:9443

# WebSocket bearer + durable Firestore mailbox (Cloud Run behind a global LB)
cargo run --features firestore -- --ws 0.0.0.0:8080 --firestore my-gcp-project
```

Or as a container:

```sh
docker build -f Dockerfile -t hop-relayd .
docker run -p 8080:8080 \
  -e HOP_FIRESTORE_PROJECT=my-gcp-project \
  -e HOP_IDENTITY_FILE=/etc/hop/identity \
  hop-relayd
```

Full flags:

```
hop-relayd [--listen 0.0.0.0:9443] [--ws 0.0.0.0:8080] [--peer host:port]...
           [--db hop-relay.db] [--identity-file PATH] [--firestore PROJECT]
```

The identity loads from `--identity-file` (32 raw bytes, e.g. a mounted secret) when given, else it
persists next to the db, so the relay's address is stable across restarts.

## Two bearers, one node

| Flag       | Bearer      | Framing                                   | Where it fits                          |
| ---------- | ----------- | ----------------------------------------- | -------------------------------------- |
| `--listen` | raw TCP     | 4-byte big-endian length prefix per packet | a single always-on VM                  |
| `--ws`     | WebSocket   | one WS binary frame per packet            | Cloud Run behind a TLS-terminating LB  |

Either way the link's Noise XX handshake authenticates both ends inside the node; the bearer moves
opaque bytes and knows nothing about the protocol. The LB terminates TLS, so the daemon speaks plain
`ws://` on `$PORT`.

## Exposed to the whole internet, and built for it

Every byte on the wire is attacker-controlled, so the relay assumes hostility:

- **Per-peer fairness keyed on identity.** Frames are rate-capped per authenticated Noise static key,
  never per client IP (which is useless behind a load balancer). Pre-handshake frames share one bounded
  bucket, and the key map is hard-bounded against fresh-identity churn.
- **Bounded before allocation.** Frame length is capped at 1 MiB on both bearer paths before any
  allocation; total inbound connections are capped, with a separate small budget for public log-stream
  viewers so idle observers can never camp the slots a mesh peer needs.
- **Panic isolation.** Every core call on hostile bytes runs under `catch_unwind`, so a panic on a
  malformed bundle becomes a logged skip, not a process kill.
- **Clean shutdown.** A `SIGTERM` handler drains the durable-store queue before the instance is reaped.

## Store-and-forward

With `--features firestore` the node's durable store is a per-node Firestore mailbox (the spool that
holds bundles for offline peers and survives a scale-to-zero instance). Without it, the store is a
plain, bundled SQLite cache: the relay never needs at-rest encryption, because everything it holds is
already sealed end-to-end.

## Configure

| Env / flag              | Purpose                                                             |
| ----------------------- | ------------------------------------------------------------------- |
| `PORT`                  | Cloud Run's serving port; the WebSocket bearer binds here           |
| `HOP_FIRESTORE_PROJECT` | GCP project for the durable mailbox (with `--features firestore`)   |
| `HOP_IDENTITY_FILE`     | path to the 32-byte identity seed, for a stable address             |
| `--peer host:port`      | dial another relay to bridge meshes                                 |

## Status

Prototype. The core relay path (both bearers, dedup, store-and-forward, the abuse controls above) is
built and unit-tested, including the Firestore mailbox path under `--features firestore`. It runs on
Cloud Run or any container host behind a TLS-terminating load balancer.

## The Hop family

Hop is one protocol with many faces. The endpoint SDKs, same surface in your language:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir) ·
[apple](https://github.com/hopmesh/hop-sdk-apple) ·
[android](https://github.com/hopmesh/hop-sdk-android).
The protocol core is [hop-core](https://github.com/hopmesh/hop-core) / [libhop](https://github.com/hopmesh/libhop).

## License

[Apache-2.0](./LICENSE.md), use it freely. Only the protocol core (`hop-core`) is FSL-1.1-ALv2,
source-available and converting to Apache-2.0 after two years.
