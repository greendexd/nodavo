<!-- doc-id: security-model; lang: en; revision: 10 -->

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
- An explicit pairing attempt first exchanges only bounded, short-lived TLS certificate metadata over an unauthenticated TCP preflight at the discovered or manually entered location. The metadata is public and never creates trust.
- Each side pins the exact received ephemeral certificate before opening the initial TLS 1.3 QUIC channel. Protected application data is never accepted on the preflight connection.
- The short authentication string binds the QUIC TLS exporter, roles, nonces, both persistent identities, both persistent certificates, grants, and protocol version, and is shown on both devices.
- The user must confirm the match on both sides.
- Devices then exchange persistent Ed25519 identities.
- Future connections require mutual proof of pinned identities.
- Silent trust-on-first-use is not allowed.
- Reset identity, key replacement, or revoked trust requires pairing again.

Private keys are non-exportable where practical and stored with macOS Keychain and Windows DPAPI/CNG. Trust records distinguish input, clipboard, and file capabilities. The local trust record also stores the bounded pairing display name and a nonzero monotonically increasing local grant epoch. Legacy pre-alpha trust records migrate to a neutral bounded display name and epoch `1`; migration does not infer new grants.

The current pre-alpha agent also contains an explicitly development-only, versioned file fallback for local two-process work. Unix directories are restricted to mode `0700`, files to `0600`, decoding is bounded, and atomic replacement is used, but this fallback does not satisfy the production Keychain/DPAPI requirement and must not ship as stable storage.

## Session security

- QUIC with TLS 1.3; no plaintext application/session compatibility mode. The first-contact TCP preflight carries only untrusted ephemeral certificate metadata and cannot authorize input, clipboard, files, or persistent trust.
- Version and capability negotiation is authenticated.
- Replay-resistant session identifiers and monotonically checked sequences.
- Bounded messages, timeouts, rate limits, and connection quotas.
- A single ownership lease controls remote input routing.
- Emergency disconnect is processed locally and cannot depend on the peer.
- Lock, sleep, timeout, and disconnect release all keys/buttons and revoke the active lease.
- Display snapshots are critical, versioned, bounded to 32 records, session-bound, and replay-checked. Native display identifiers remain local; a peer can name only an opaque token installed for this authenticated session.
- Local and peer capability epochs are directionally separate. Inbound input, topology, clipboard, and file metadata must cite the receiver's current persisted local epoch; outbound metadata cites the epoch authenticated from the peer. Reconnect exchanges both sides' complete grants and epochs.
- Post-pair capability changes use the existing mutually authenticated TLS control stream. They are not described as separately signed: pinned mTLS peer authentication, strict target/epoch validation, and the local OS-protected trust database are the trust boundary. Every accepted change releases affected input/content state and closes the old connection; reconnect must use the persisted policy and newly negotiated epochs.

## Input capture and injection

- Native capture starts in non-suppressing mode. Suppression is permitted only while an authenticated, authorized focus lease is actively routing local input to the peer.
- macOS requires the user-granted Accessibility trust boundary. Windows remains inside the current interactive user's default input desktop; login, Session 0, UAC secure desktop, and privileged unattended control are rejected.
- Nodavo injection carries a private process tag where the platform supports one. Capture rejects that tag and every event the OS reports as injected, preventing synthetic feedback loops.
- Keyboard usages, modifiers, media keys, pointer buttons, normalized motion, and line/precise scrolling are validated before injection. Native codes never cross the peer protocol directly.
- An edge transition uses a critical reliable pointer-entry message. Native suppression and relative deltas remain gated until the receiver validates the lease/session/grant, resolves the session display token, injects the entry position, and returns an authenticated acknowledgement. This prevents a lost or reordered entry datagram from applying deltas at a stale cursor.
- Routed motion uses bounded nonzero relative deltas with no display identity. Callback-queue coalescing preserves the exact sum only while it remains in range; otherwise events stay separate or fail back to explicit recovery instead of silently truncating physical motion.
- The injector tracks every accepted key/button press. Emergency stop, focus loss, lock, sleep, tap/hook disable, timeout, and transport failure synchronously request deterministic release and local-ownership restoration before successful acknowledgement.
- A disabled or timed-out capture hook fails closed: suppression stops, local ownership is restored, and the remote session cannot continue silently.
- Input payloads and pairing codes are excluded from logs, crash metadata, and telemetry.
- A topology revision must be installed and acknowledged before focus can move in the corresponding direction. Peer layout coordinates are descriptive only and never create adjacency. Edge routes are explicit local policy, disabled when empty, and still pass through the ordinary focus lease, debounce, hysteresis, and cooldown checks.
- macOS CGEvent and Windows Raw Input relative capture plus native relative injection are implemented and compile-tested. Real-device behavior, acceleration differences, extreme hardware deltas, mixed-DPI hardware, and long-session drift remain release-validation gates.

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
- The receive executor admits one queue-selected transfer to a staging owner at a time. It accepts only nonempty bounded chunks at the exact next offset, advances public filename-free progress only after the staging write is acknowledged, and refuses completion until every declared file byte is present.
- Explicit cancellation discards only the matching active transfer. A wrong identifier, parallel manifest, offset gap/overlap, incomplete completion, or staging failure is rejected without advancing receive state.
- Existing files are never overwritten silently.
- Received files are not executed or automatically opened.
- Per-peer quotas, cancellation, backpressure, and rate limits limit denial of service.

The pre-alpha receiver writes through capability-rooted, no-follow directory and file handles. Its staging root is private before any content name is created: Unix permissions are verified, while Windows creates an owner-only protected DACL atomically through a root-relative handle and rejects permissive, inherited, foreign-owned, reparse, or structurally ambiguous state. One process-wide operation lease serializes begin/resume/finalize/discard. Progress is acknowledged only after file and journal flushes; supported platforms also sync every mutated destination directory deepest-first and the destination root last. Windows exposes that directory-entry crash flushing is unsupported, so an untracked resume after an agent restart is rejected rather than advertised as power-loss durable.

Outbound selection is anchored by no-follow handles before canonicalization. Enumeration, manifest accounting, hashing, chunks, roots, stable file identities, and cooperative cancellation are bounded. Links, reparse points, sparse/special files, overlapping roots, hard-link aliases, mutations, cycles, and cross-platform path collisions fail closed. Publication never overwrites an existing destination. If a late multi-file publication or cleanup failure makes safe rollback ambiguous, the staging owner is poisoned and already published Nodavo identities are retained for explicit remediation instead of deleting a possibly substituted pathname.

The running agent associates inbound transfer identifiers only after an authenticated, authorized manifest and keeps that association peer-scoped across link loss. Revocation waits for workers and the staging lease, then discards only identifiers known for that peer. A durable peer-ownership journal across agent restart is not implemented yet; unknown persisted identifiers are never deleted merely because a peer presents their UUID. Outbound process-restart persistence and durable poison persistence are also stable-release gates.

## Local IPC

- macOS uses a user-owned Unix domain socket with restrictive permissions and peer credential checks.
- Windows uses a named pipe with an ACL limited to the current user and validates the peer process context.
- UI requests are capability checked; the UI does not directly read private network keys.
- Trusted-device listing is bounded to 32 public summaries containing only the local peer identifier, bounded display name, active/revoked state, and locally issued grants. It excludes certificates, endpoints, private material, and the peer's independently issued grants.

The current pre-alpha Unix socket authenticates only the owning user credential, and the Windows pipe authenticates the same SID/session. That blocks cross-user and remote clients but does not yet distinguish the signed Nodavo UI from another process already running as the same user. This also applies to update-check and exact-offer consent commands that mutate updater state. Signed-client or launch-bound authentication is therefore a stable-release gate; sensitive local requests remain narrowly bounded and release storage must not expose network private keys to the UI.

## Updates and supply chain

The agent now integrates a deliberately non-activating Unix/macOS slice around the pre-alpha update crate. Builds are unconfigured unless a manifest HTTPS endpoint and Ed25519 public key are explicitly embedded at compile time. When configured, the client uses the native platform TLS verifier/root store, disables redirects, ambient proxy discovery, cookies, credentials, and decompression, and applies bounded status, length, range, timeout, and body rules. The signed manifest must match the build's channel, target, and install identity, and its artifact must share the manifest origin. Consent is bound to the exact canonical offer UUID.

Accepted artifacts are resumed into a private capability-rooted content-addressed staging area, under a cross-process exclusive lease and bounded quota/retention policy. Writes are streamed through exact offset, size, and digest checks; files and supported directory mutations are synchronized before verified staging is reported. Staged content is not opened, executed, installed, or activated. The bilingual macOS Settings UI can manually check or refresh, poll bounded progress on a separate client, report an up-to-date result, accept or decline an exact offer, and resume a paused download without displaying the endpoint, filesystem path, or digest. Windows has no corresponding updater staging or UI integration.

This repository supplies no production endpoint, release private signing key, or evidence of a live production update check. It also has no protected production Keychain update journal or durable rollback floor. The state-machine contracts for restart, health checking, and rollback remain unconnected because there is no installer, activation step, restart handoff, health supervisor, or rollback supervisor. These are release gates rather than properties of the current staged artifact flow.

The following are mandatory release requirements:

- Release artifacts will be code signed; macOS will be notarized and Windows will use Authenticode.
- Update manifests will be signed with an offline-controlled release key.
- Update state will reject rollback below the recorded safe version unless the user performs a documented recovery action.
- Update-mutating local IPC will authenticate an authorized signed/provisioned Nodavo UI, not merely another process running as the same user.
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
