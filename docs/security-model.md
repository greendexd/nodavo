<!-- doc-id: security-model; lang: en; revision: 2 -->

# Security model

[English](security-model.md) · [Русский](security-model.ru.md)

This is a design target, not a claim about a released implementation. The public [security policy](../SECURITY.md) explains vulnerability reporting.

## Assets to protect

- Keyboard and pointer events.
- Clipboard text, images, and file lists.
- File contents, metadata, destination paths, and transfer history.
- Device private keys, trust decisions, and capability grants.
- Update authenticity and rollback state.
- Local user control, especially the ability to disconnect immediately.

## Threat actors

- An attacker on the same local network.
- A spoofed discovery service or pairing man-in-the-middle.
- A previously trusted but now compromised peer.
- A malicious local process attempting to impersonate the UI or agent.
- A malicious clipboard/file sender exploiting parsers, paths, quotas, or auto-open behavior.
- A compromised dependency, build runner, download host, or update manifest.

Physical compromise of either paired machine, kernel compromise, malicious firmware, and a compromised OS trust store are outside the 1.0 defensive boundary, but must be stated in release documentation.

## Trust establishment

- mDNS discovery provides location only, never identity.
- Initial pairing uses an ephemeral encrypted channel and a short authentication string shown on both devices.
- The user must confirm the match on both sides.
- Devices then exchange persistent Ed25519 identities.
- Future connections require mutual proof of pinned identities.
- Silent trust-on-first-use is not allowed.
- Reset identity, key replacement, or revoked trust requires pairing again.

Private keys are non-exportable where practical and stored with macOS Keychain and Windows DPAPI/CNG. Trust records distinguish input, clipboard, and file capabilities.

## Session security

- QUIC with TLS 1.3; no plaintext compatibility mode.
- Version and capability negotiation is authenticated.
- Replay-resistant session identifiers and monotonically checked sequences.
- Bounded messages, timeouts, rate limits, and connection quotas.
- A single ownership lease controls remote input routing.
- Emergency disconnect is processed locally and cannot depend on the peer.
- Lock, sleep, timeout, and disconnect release all keys/buttons and revoke the active lease.

## Clipboard security

- Clipboard sync is disabled until explicitly enabled for a peer.
- Revisions and content hashes prevent loops and stale overwrites.
- MIME allowlist initially limits content to text, HTML, PNG/BMP, and file lists.
- Size, decompression, allocation, parsing-time, and concurrency limits apply before decode.
- HTML is transferred as data and never rendered inside a privileged Nodavo surface.
- Clipboard contents are never logged or sent as telemetry.

## File-transfer security

- Receiving files requires a separate grant.
- Manifests are bounded before allocation.
- Names are normalized and rejected for traversal, reserved-device paths, dangerous ambiguity, and invalid encoding.
- Symlinks, junctions, reparse points, sparse files, and special files are rejected in 1.0 unless separately specified and tested.
- Data is written to private staging, checked with BLAKE3, then atomically finalized.
- Existing files are never overwritten silently.
- Received files are not executed or automatically opened.
- Per-peer quotas, cancellation, backpressure, and rate limits limit denial of service.

## Local IPC

- macOS uses a user-owned Unix domain socket with restrictive permissions and peer credential checks.
- Windows uses a named pipe with an ACL limited to the current user and validates the peer process context.
- UI requests are capability checked; the UI does not directly read private network keys.

## Updates and supply chain

The following are mandatory release requirements, not descriptions of the current pre-alpha repository:

- Release artifacts will be code signed; macOS will be notarized and Windows will use Authenticode.
- Update manifests will be signed with an offline-controlled release key.
- Update state will reject rollback below the recorded safe version unless the user performs a documented recovery action.
- Releases will publish checksums, SBOM, provenance, dependency lockfiles, and source commit.
- Dependency policy, audits, CodeQL, fuzzing, and secret scanning will run continuously before a supported release exists.

## Logging and telemetry

Logs exclude keystrokes, clipboard contents, file contents, private filenames, device private keys, pairing codes, and stable IP identifiers. Optional diagnostics must be previewable and explicitly exported by the user.

Telemetry and crash upload are off by default. Any future opt-in schema must be documented, minimized, revocable, and independent from software updates.

## Required security gates

- Pairing MITM, key replacement, replay, revocation, malicious peer, parser fuzzing, path traversal, quota, update substitution, and local IPC impersonation tests.
- Independent review before public beta is promoted to stable.
- No open critical/high finding at the stable release gate.
- Private vulnerability reporting and a documented response owner.
