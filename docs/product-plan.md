<!-- doc-id: product-plan; lang: en; revision: 2 -->

# Product plan

[English](product-plan.md) · [Русский](product-plan.ru.md)

## Product definition

Nodavo is a clean-room, local-first software KVM for people who use a Mac and a Windows PC at the same desk. It aims to provide bidirectional keyboard and pointer control, clipboard sharing, and intentional file transfer over a mutually authenticated local connection.

The product is not a remote desktop: every computer keeps its own display and runs its own applications.

## Primary users

1. Developers testing software across macOS and Windows.
2. Creators and streamers using different machines for production and capture.
3. Technical home-office users with a work Mac and a Windows workstation.
4. Labs and small teams that require local operation without cloud accounts.

## User promise

A new user should install Nodavo on two supported machines, grant understandable permissions, confirm a matching pairing code, arrange the displays, and move between computers in under three minutes—without creating an account or sending input data to the internet.

## 1.0 goals

- macOS 13+ and Windows 10 22H2/11 on x64 and ARM64.
- Equal peers: either physical keyboard and mouse can control the other machine.
- Pointer, buttons, wheel, common keyboard layouts, modifiers, media keys, and mixed-DPI displays.
- Clipboard text, HTML, and common image formats with loop prevention and limits.
- Explicit file/folder copy, queueing, cancellation, resume, integrity verification, and safe destination policy.
- mDNS discovery plus manual IP fallback.
- QUIC/TLS 1.3, user-confirmed pairing, mutual persistent identities, and revocation.
- Native permission, tray/menu-bar, layout, diagnostics, trusted-device, and update experiences.
- Signed installers, SBOM, checksums, provenance, and a documented security response process.

## 1.0 non-goals

- Video, screen, audio, or application streaming.
- Operation across the public internet or a hosted relay.
- Linux, mobile, tablet, or browser clients.
- Windows login, UAC secure desktop, or unattended privileged control.
- Automatic opening of received files.
- More than two active peers in one control session.
- Mandatory telemetry or cloud registration.

## Product constraints

- Plaintext transport is never offered.
- Discovery is not trust; pairing always requires user confirmation.
- Input, clipboard, and file permissions are separate capabilities.
- Synthetic events must not be recaptured and amplified.
- Disconnect, lock, sleep, crash, and emergency stop must release all keys and return local control.
- Logs must not contain input text, clipboard content, file contents, private filenames, keys, or stable network identifiers.

## Milestones and acceptance gates

Estimates assume focused solo development and are planning ranges, not promises. Hardware access, signing, and external security review can extend them. A stable product is realistically a **9–12+ month** effort full-time and longer part-time.

| Milestone | Planning range | Deliverable | Exit gate |
| --- | ---: | --- | --- |
| M0 — Feasibility | 2–4 weeks | Isolated macOS/Windows input, clipboard, QUIC, and Finder ↔ Explorer file-drop spikes | Synthetic events can be identified; permissions are understood; cross-OS file-drop path is proven or explicitly descoped |
| M1 — Foundation | 3–5 weeks | Rust workspace, native shells, local IPC, identity, discovery, pairing, reconnect | Two clean machines discover and pair without CLI; reconnect preserves verified identity |
| M2 — One-way input | 4–6 weeks | Mac → Windows and Windows → Mac pointer and keyboard | EN/RU layouts, modifiers, media keys; p95 LAN latency ≤15 ms; no stuck keys in stress cycles |
| M3 — Bidirectional KVM | 4–6 weeks | Equal peers, ownership lease, screen graph, DPI transforms | Deterministic switching, multi-monitor, sleep/reconnect, conflicting takeover and emergency stop pass |
| M4 — Clipboard | 3–5 weeks | Text, HTML, images, versioning and limits | No synchronization loop; 100 MB images bounded; malformed input fails safely |
| M5 — Files | 5–8 weeks | Files/folders, queue, resume, staging, hashes | 0 B–10 GB, Unicode, cancel/resume, no traversal/symlink escape, no silent overwrite |
| M6 — Product UX | 5–8 weeks | Onboarding, permissions, layout, transfers, diagnostics, autostart, uninstall | Clean user connects in under three minutes; clean-install/upgrade/uninstall matrix passes |
| M7 — Public beta | 8+ weeks | Signed beta, updater, protocol release candidate | 30-day dogfood, 100 real pairs, ≥99.5% crash-free sessions, no open critical/high after external review |
| M8 — Stable 1.0 | Gate driven | Stable protocol, supported matrix, release and recovery process | Reproducible artifacts, rollback, SBOM/provenance, response process and full documentation complete |

## Quality strategy

- Unit and property tests for codecs, state machines, transforms, mappings, trust, and limits.
- Fuzz every network decoder, clipboard parser, transfer manifest, discovery record, and IPC boundary.
- Simulate loss, duplication, reordering, MTU changes, address changes, suspend, and reconnect.
- Use virtual platform adapters for deterministic integration tests.
- Test real Mac ARM64/Intel and Windows x64/ARM64 hardware for hooks, permissions, DPI, drag/drop, sleep, and installers.
- Run 24-hour 1000 Hz pointer, clipboard churn, reconnect, and large-transfer soak tests.
- Verify EN/RU, dead keys, AltGr, Caps Lock, IME fallback, media keys, trackpads, and 125–1000 Hz mice.
- Review supply-chain changes with dependency policy, audits, lockfiles, SBOM, and signed provenance.

## Release and distribution

### macOS

- Signed and notarized universal or ARM64/x64 DMG.
- Hardened runtime and explicit Accessibility/Input Monitoring/Local Network onboarding.
- Homebrew Cask after beta reliability is demonstrated.

### Windows

- Authenticode-signed x64 and ARM64 MSIX/MSI, plus a portable ZIP when safe.
- Private-network-only firewall rule.
- WinGet publication after the stable channel is established.

### Shared release evidence

- Immutable tags and release notes in English and Russian.
- SHA-256 checksums and signed checksum manifest.
- SPDX or CycloneDX SBOM and build provenance.
- Stable and beta channels with verified rollback.
- Telemetry remains optional and is never required for updates.

## Success metrics

Before stable 1.0:

- At least 100 real paired Mac/Windows setups in public beta.
- p95 local input latency at or below 15 ms on the published reference LAN.
- At least 99.5% crash-free beta sessions.
- No unresolved critical/high findings from an independent security review.
- Published reproducible benchmarks and compatibility matrix.
- At least five meaningful external issues, fixes, documentation contributions, or test reports from non-maintainers.

These metrics demonstrate product health; stars and downloads alone do not.

## Risk register

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Finder ↔ Explorer drag/drop cannot be made safe and seamless | High | Prove during M0; fall back to explicit transfer queue rather than fake DnD |
| Keyboard semantics differ across platforms | High | Canonical HID events, layout matrix, Unicode fallback, real hardware tests |
| Synthetic input creates loops or stuck keys | Critical | Origin/session tagging, ownership lease, forced key release, emergency hotkey |
| Pairing can be spoofed on hostile LAN | Critical | SAS confirmation, mutual pinned identities, no silent TOFU |
| Clipboard/files become an attack channel | Critical | Capabilities, size limits, staging, path validation, no auto-open, fuzzing |
| macOS permissions reset after updates | Medium | Stable signing identity, permission diagnostics, upgrade tests |
| Windows secure desktop expands privilege surface | High | Explicitly exclude from 1.0 |
| Signing and hardware matrix cost delays releases | Medium | Budget before beta; never ship unsigned artifacts as stable |

## Open-source credibility

Nodavo should earn trust through a public protocol, threat model, clean-room policy, ADRs, reproducible benchmarks, continuous fuzzing, signed binaries, SBOM/provenance, good-first issues, transparent failures, and real maintainer work. The repository must never be presented as mature solely to qualify for a promotion or program.
