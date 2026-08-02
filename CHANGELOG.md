# Changelog

Notable changes, generated from [conventional commits](https://www.conventionalcommits.org) by
git-cliff. Do not edit by hand.
## Unreleased

### Bug Fixes
- revive dead ingest, fail closed, bound stamps, measure bytes and carriage (1912c75)
- integrate the storage dimension onto current main (aedcfb2)
- reap slowloris on raw-TCP and the WS handshake (ADV18-04/05) (4aab3fa)
- retain mailbox custody until durable ingest (a16c38e)
- close F-18d, HpsRekey fails safe under a mid-arm panic (#104) (879019b)
- close two bypasses in the F-7 rate cap (F-18a unbounded map, F-18b pre-auth reset) (#96) (c07850c)
- close F-7 - per-node-identity rate cap on the driver's Ev::Data (#93) (9f1f743)
- panic-isolate the driver loop (F-2, HIGH) - close an unauthenticated remote-DoS gap (#87) (ac74b79)
- cover Destination::Vaccine in every workspace crate (relay/relayd/hop-sim) + workspace fmt/clippy (e611c4d)
- relayd F-18 test used the pre-F-06 mailbox_tag signature (firestore feature) (967a9a9)

### CI
- stop a disarmed audit being permanently red, and a test using a timeout as control flow (8be22a0)
- bump create-github-app-token to v3.2.0 across all mirrored components (efc9f6c)

### Chore
- invert the license tiers, FSL moves from core to services (14d7fec)
- purge em-dashes and en-dashes from source (d222435)
- drop the root license, license per-component (FSL-1.1-ALv2) (#146) (be2a5a7)

### Dependencies
- land the grouped rust-dependencies bump (sha2, ed25519/x25519-dalek, chacha20poly1305, snow, rusqlite, p256, uniffi, tungstenite) (#89) (2038ce9)

### Documentation
- regenerate from conventional commits (e6b97f2)
- regenerate from conventional commits (2741000)
- correct claims stated more strongly than the code supports (CLAIM-001..009) (f3fbfbf)
- regenerate from conventional commits (b96e019)
- regenerate from conventional commits (330c8c6)
- regenerate from conventional commits (096180b)
- regenerate from conventional commits (102ae67)
- regenerate from conventional commits (1572ae2)
- regenerate from conventional commits (a355901)
- branded, marketable READMEs for every sub-repo (9c2a477)

### Features
- finish inbound (import), drop export_pr (41c095e)
- §35 storage dimension, per-tenant held-byte occupancy (d58a544)
- relays + collectors read tenant keys from the registry (5b-2, reader) (f80f5b3)
- auto-generate monorepo + per-library changelogs (git-cliff) (8c64c37)
- custody beacon (mode-1 HaveSet exchange) to cut duplicate-ingress COGS (708b565)
- rotating key-hint carriage stamps (no tenant id on the wire) (a5e592d)
- §35 carriage stamps - keyed relays, per-bundle metering (wire v8) (4aae50f)

### Other
- say plainly that SVC-001's literal wording is not met, not that it is (133b36f)
- make the writer-scoped ledger readable end to end, and stop overclaiming (5ee2555)
- writer-scope the usage ledger rows so concurrent flushes compose (SVC-005) (b66cac9)
- gate the live log fan-out, not just its backlog (SVC-001) (935cba3)
- delete the dead copy-budget API and stop the simulator lying (9ab3138)
- rework the console deploy onto the new GitHub-is-change-management pipeline (b53b9d0)
- box the envelope stamp (clippy large-variant), fmt, §35 addendum (6b601b6)
- CLA gate on contributions (preserve commercial relicensing of core) (5a9aa7d)
- SECURITY.md per component + enable-security in the bootstrap script (a1492e9)
- copyright holder is Hop Mesh, LLC (7d8c514)
- fill the Apache-2.0 copyright placeholder (2026 Jason Waldrip) (2fb7d1c)
- Apache-2.0 for everything except core/ (only the protocol stays FSL) (0fe9439)
- CHANGE_REQUEST sync-back + document merge/conversation + confidentiality (9e1dec2)
- make the TLS-served reach record the only name path (drop DNSSEC-over-DoH) (#139) (8998288)
- session GC, sqlite schema guard, remove dead k-bit fields (103084e)
- remove Destination::InternetEgress (mesh-visible internet-bound leak) (5dd64d3)

### Testing
- verify durable custody acknowledgements (b86e9da)
- raise hop-relayd line coverage 41.2% -> 81.1% (#62) (40dd07b)

