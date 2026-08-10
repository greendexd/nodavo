<!-- doc-id: changelog; lang: en; revision: 11 -->

# Changelog

All notable changes to Nodavo will be documented here. The format follows Keep a Changelog principles, and the project intends to use Semantic Versioning after the first public build.

## [Unreleased]

### Added

- Initial bilingual repository and product documentation.
- Product plan, architecture, roadmap, security model, privacy policy, and clean-room policy.
- Pre-alpha peer-protocol documentation with channel separation, bounded canonical CBOR, current tags, freshness rules, and compatibility constraints.
- Community contribution and issue-reporting templates.
- Rust workspace foundations for bounded protocol messages, semantic input, session safety, device identity and pairing, discovery, QUIC/TLS transport, clipboard synchronization, file-transfer validation, local IPC, signed-update verification, and deterministic virtual adapters.
- Per-user Rust agent with bounded private-socket IPC, explicit pairing-time capability grants, ephemeral first-contact pairing, bilateral short-code confirmation, signed trust persistence, restart-safe pinned mutual-TLS reconnect, revocation, status, self-check, shutdown, and emergency stop.
- Authenticated symmetric peer-session runtime with protocol/capability negotiation, independent input sequence lanes, same-link bidirectional focus leases, datagram/pointer fallback, bounded command ingress, and restore-before-ack safety recovery.
- Bilingual SwiftUI macOS menu-bar shell for agent status, emergency stop, manual/listening pairing, explicit per-capability selection, and short-code confirmation.
- macOS manual focus controls plus a wired native capture/injection bridge with default-off suppression, bounded coalescing, non-evictable key/button events, priority lifecycle recovery, and synchronous forced-release acknowledgement.
- Owned macOS and Windows input runtimes with synthetic-event suppression, HID/media/button/motion/scroll translation, lifecycle recovery, deterministic forced release, plus input/clipboard feasibility programs. The Windows runtime is not yet wired to the agent or runtime-tested on Windows.
- Windows input, display, session-safety, clipboard, and current-user DPAPI boundaries, plus a protected same-user named-pipe server API; the Rust agent does not yet host that pipe.
- Bilingual WinUI 3 shell source with bounded status, emergency stop, manual/listening pairing, explicit per-capability selection, and short-code confirmation clients. It has received XML/source validation only, not Windows compile or runtime validation.
- Windows agent startup source with a same-user/session validated named-pipe server and DPAPI-protected identity/trust persistence; it cross-checks for Windows x64 but still needs Windows runtime validation.
- Bounded FIFO transfer scheduling with deterministic pause/resume/cancel effects, plus filesystem-backed private staging with durable progress journals, exact-offset restart resume, torn-tail truncation, per-file BLAKE3 verification, persisted-state discard, and no-overwrite finalization.
- Compile-only repository checks for bilingual documentation, Rust formatting and macOS/Windows builds, the WinUI 3 x64 project, and macOS Swift packages.
- Authenticated session-scoped display topology, mixed-DPI edge policy, relative pointer deltas, and a reliable pointer-entry acknowledgement gate before suppression.
- End-to-end bounded clipboard channels: text/HTML/PNG/clear on macOS and Windows, plus a strict canonical BMP/DIB subset on Windows.
- Production-default macOS Keychain storage with an explicit insecure-development file fallback, and a universal development app/DMG plus fail-closed Developer ID/notarization packaging path.
- Capability-rooted outbound file scanning and streaming with no-follow traversal, deterministic manifests, BLAKE3, mutation detection, resume evidence, and safe receiver staging.
- Directional persisted grant epochs, bounded trusted-device listing, transactional post-pair capability updates, peer-scoped revocation cleanup, and native trusted-device/file-selection UX on macOS and Windows.
- Authenticated bounded file channels with background workers, cooperative scan cancellation, same-process link-loss resume, completion ordering, process-wide staging leases, Windows birth-time owner-only DACLs, and conservative no-overwrite publication.
- A fail-closed x64+ARM64 Windows development MSIXBundle pipeline, plus a signed-update state-machine core with bounded staging, consent, rollback-floor, and restart/health contracts.
- An unconfigured-by-default, non-activating update slice with a compile-time pinned HTTPS manifest endpoint and Ed25519 public key, native platform TLS without redirects or decompression, signed-manifest and same-origin-artifact checks, exact offer-UUID consent, and resumable digest-verified private capability-root staging with a cross-process lease, quotas, retention, and fsync. The macOS Settings UI can check, refresh/poll progress, report up-to-date, consent or decline an exact offer, resume a paused download, and report verified staging in English and Russian without exposing a URL, path, or hash.

### Not yet available

- A usable or released macOS ↔ Windows application. Input/focus/clipboard/files are joined in the pre-alpha agent and native UX source exists, but real two-machine runtime qualification remains.
- Proven Windows agent/WinUI runtime behavior; release signing, an update endpoint/private signing key, protected update-state persistence and rollback floor, updater installation/activation/restart/rollback supervision, Windows updater staging/UI, hot-plug layout UX, detailed transfer progress/destinations, durable restart ownership journals, and Windows ARM64 execution are also missing.
- Full security, fuzz, stress, compatibility, upgrade, accessibility, and real-device test matrices; these remain release gates for feature-complete 1.0.
