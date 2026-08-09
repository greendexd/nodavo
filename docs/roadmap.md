<!-- doc-id: roadmap; lang: en; revision: 2 -->

# Roadmap

[English](roadmap.md) · [Русский](roadmap.ru.md)

The roadmap describes sequence, not promised dates. Work advances only when the previous acceptance gate is supported by reproducible evidence.

## Completed foundation

- Publish bilingual product, architecture, privacy, security, and clean-room documents.
- Create ADR process and repository quality checks.

## Now — M0 feasibility

- Spike macOS capture/injection and synthetic-event suppression.
- Spike Windows capture/injection and synthetic-event suppression.
- Prove QUIC datagrams plus reliable streams on a real LAN.
- Test text/image clipboard APIs independently on both systems.
- Determine whether true Finder ↔ Explorer drag/drop is safe and technically supportable.
- Validate the thin SwiftUI and WinUI 3 shells and choose their exact packaging paths after the platform spikes.

## Next — M1 through M3

- Build the Rust workspace and virtual platform adapters.
- Add native menu-bar/tray shells and authenticated local IPC.
- Implement identity storage, mDNS, pairing, pinning, revocation, and reconnect.
- Deliver one-way input in both directions.
- Add equal-peer focus ownership, emergency stop, screen graph, multi-monitor and mixed DPI.
- Publish latency, CPU, memory, reconnect, and stuck-key benchmarks.

## Then — M4 through M6

- Ship bounded text/HTML/image clipboard synchronization.
- Build a safe transfer queue, staging, hashing, resume, cancellation, and destination rules.
- Add cross-OS file clipboard and drag/drop only if M0 evidence supports it.
- Complete onboarding, permissions diagnostics, trusted-device management, autostart, logs, updates, and clean uninstall.
- Add continuous fuzzing and the real-hardware platform matrix.

## Before stable — M7 and M8

- Sign and notarize beta installers.
- Run at least 30 days of dogfood and a 100-pair public beta.
- Complete independent security review and resolve critical/high findings.
- Freeze protocol 1.0, migration rules, compatibility policy, SBOM/provenance, rollback and security response.
- Publish Homebrew/WinGet packages only after stable artifacts are verified.

## Later, not promised

- Linux support.
- More than two active peers.
- Mobile remote input.
- Optional LAN-only audio forwarding.
- Deskflow protocol interoperability mode.
- Organization policy deployment.

Public-internet relay, mandatory accounts, covert telemetry, and automatic received-file execution are not planned.
