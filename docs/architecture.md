<!-- doc-id: architecture; lang: en; revision: 7 -->

# Architecture

[English](architecture.md) · [Русский](architecture.ru.md)

This document defines the intended architecture. It becomes binding only through implemented ADRs and tested code.

## System boundaries

Each device runs a native UI and an unprivileged Rust session agent. The UI owns user interaction and OS permission guidance. The agent owns network identity, pairing, session state, transport, input routing, clipboard, and transfers.

```mermaid
flowchart TB
    subgraph Mac["macOS device"]
        MUI["SwiftUI menu-bar app"]
        MA["Rust session agent"]
        MAP["CGEventTap / CGEvent / NSPasteboard"]
        MUI <-->|"launchd Mach-service XPC<br/>reciprocal per-message signing gates"| MA
        MA <--> MAP
    end

    subgraph Win["Windows device"]
        WUI["WinUI 3 tray app"]
        WA["Rust session agent"]
        WAP["Raw Input / hooks / SendInput / Win32 Clipboard + OLE"]
        WUI <-->|"current-user named pipe<br/>package/process/Authenticode gate"| WA
        WA <--> WAP
    end

    MA <-->|"mutually authenticated QUIC / TLS 1.3"| WA
```

No hosted control plane, account service, relay, or telemetry collector is required for normal operation.

## Planned Rust workspace

| Crate | Responsibility |
| --- | --- |
| `nodavo-protocol` | Versioned messages, limits, capabilities, error model, golden vectors |
| `nodavo-transport` | QUIC, streams, datagrams, reconnect, deadlines, backpressure |
| `nodavo-identity` | Ed25519 device identity, pairing, pinning, grants, revocation |
| `nodavo-discovery` | mDNS advertisement/browse and manual address fallback |
| `nodavo-session` | Peer lifecycle, focus ownership lease, switching and recovery |
| `nodavo-input` | Canonical HID events, mappings, coordinate and modifier state |
| `nodavo-clipboard` | Text/HTML/image normalization, versioning, ownership and limits |
| `nodavo-transfer` | Manifests, chunks, staging, BLAKE3, resume, quota and finalize |
| `nodavo-platform-macos` | Capture, injection, permissions, displays, pasteboard, Keychain and signed local-IPC peer policy |
| `nodavo-platform-windows` | Capture, injection, sessions, displays, clipboard and OLE APIs |
| `nodavo-local-ipc` | Authenticated UI ↔ agent protocol and OS access controls |
| `nodavo-agent` | Process orchestration and lifecycle |
| `nodavo-update` | Signed manifests, channels, verification and rollback metadata |

Crates use dependency injection at platform and transport boundaries. Tests can replace both with deterministic virtual adapters.

## Transport model

One authenticated QUIC connection carries independent channels:

- **Control stream:** protocol negotiation, capabilities, focus lease, display graph, liveness and errors.
- **Reliable input stream:** key/button down/up, critical modifier state and forced release.
- **Datagrams:** pointer motion and high-frequency scrolling with sequence numbers and latest-wins behavior.
- **Clipboard streams:** one bounded stream per clipboard revision and MIME representation.
- **File streams:** manifest control plus one unidirectional stream per file.

When QUIC datagrams are unavailable, pointer motion falls back to a short-lived reliable stream without changing security.

## Input model

- Physical keys use HID Usage IDs plus modifier state.
- Text/Unicode fallback handles layout-sensitive entry and future IME support.
- Pointer coordinates are normalized per display and transformed using the destination display scale.
- Every event includes session, origin, sequence, and capability context.
- Every input event also includes the active nonzero focus-lease identifier. Control, reliable input, and replaceable input have independent sequence lanes so datagram overtaking cannot invalidate a key release.
- Injected events are tagged or suppressed so they cannot re-enter capture.
- A single focus ownership lease prevents simultaneous routing loops.
- Capture suppression is off by default and can turn on only while forwarding under that lease. Ordinary focus return keeps the authenticated connection ready for reverse-direction control.

On disconnect, timeout, lock, sleep, crash, or emergency stop, both sides release all tracked keys/buttons and restore local cursor ownership.

## Discovery and pairing

1. mDNS publishes a minimal, non-sensitive service record.
2. A bounded unauthenticated TCP preflight exchanges only short-lived ephemeral certificate metadata at that location.
3. Each side pins the exact metadata before establishing a temporary TLS 1.3 QUIC pairing session.
4. Both UIs display the same short authentication string, bound to the TLS exporter and complete role-ordered persistent trust transcript.
5. The user confirms the match on both devices.
6. Devices exchange persistent public identities and explicit capability grants.
7. Future sessions require mutual proof of the pinned identities.

Private keys are stored in macOS Keychain and Windows DPAPI/CNG-backed storage. Discovery metadata is never accepted as identity proof.

## Clipboard and files

Clipboard synchronization is revisioned and content-addressed to prevent loops. Content is transferred only when its capability is enabled. Planned types are UTF-8 text, HTML, PNG/BMP, and file lists.

Files are written to a private staging directory, bounded by quotas, validated against traversal and unsafe links, and hashed with BLAKE3. A bounded durable progress journal records only exact contiguous offsets; restart resume requires the same authenticated manifest and truncates any non-durable tail. Final publication refuses existing destinations. Received content is never auto-opened.

Finder ↔ Explorer drag/drop is an M0 research gate. If native drag APIs cannot be made reliable and safe, 1.0 will expose an explicit transfer queue rather than simulate misleading drag/drop.

## Process privilege

The default 1.0 agent runs in the user session. A privileged Windows service is excluded because login/UAC secure-desktop control would significantly increase the attack surface. Any future privileged component requires a separate threat model and capability boundary.

## Local process trust

The macOS release path uses the per-user launchd Mach service `dev.nodavo.agent.ipc`. Before activation, the agent configures its listener and every accepted connection with the exact UI code-signing requirement; the Swift UI configures the reciprocal exact agent requirement before activating its client. XPC checks every received message. Both requirements bind the Developer ID chain, compile-time Team ID, exact identifiers and application/team entitlements, and absent `get-task-allow`. One-value XPC dictionaries carry the existing deny-unknown bounded JSON contract into the shared exhaustive agent dispatcher.

The former UDS audit-token design was withdrawn because current `LOCAL_PEERTOKEN` task identity cannot identify bytes queued before an exec. Development packaging deliberately retains that private same-UID UDS only behind a non-default feature and labels the artifact unsafe/non-distributable; it does not advertise the release Mach service. Release has no UDS fallback or environment path override. Reciprocal enforcement is implemented in source, while live production signing/notarization and installed mutual runtime evidence remain open release gates. Payload and process metadata are not logged.

On Windows, each current-user named-pipe connection carries exactly one request and response. The server retains connection-bound pipe, process, token, and executable handles for the exact packaged UI. Before sending, the UI authenticates its own compile-time package/PFN/AUMID and installed content root, then retains the server process, token, exact non-reparse agent executable beneath that root, and pinned Authenticode evidence. Both directions verify session/logon lineage and process/token stability before consuming the authenticated result. The separately launched Rust agent is not claimed to carry package identity; its exact installed path and signature are the reciprocal trust anchor. Development and release UI package identities are separate compile-time policies; unpackaged or unconfigured peers fail closed, and packaging signs and verifies both executables. Source and cross-target checks cover the policy, but installed-MSIX behavior, production publisher/signing/timestamp credentials, and real x64/ARM64 execution remain release gates. This boundary rejects an independent endpoint-squatting same-user process. It does not create a separate Windows principal: invasive access to an authorized process's handles or memory is explicitly outside the stated 1.0 threat model.

## Observability

Local structured logs contain event categories, timings, bounded error codes, and ephemeral correlation IDs—not keystrokes, clipboard data, file contents, private filenames, keys, or stable network identifiers. Crash reporting and telemetry remain disabled until explicit opt-in.
