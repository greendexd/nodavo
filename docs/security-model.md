<!-- doc-id: security-model; lang: en; revision: 19 -->

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
- An independent malicious local process attempting to impersonate the UI or agent over its documented IPC endpoint, without first obtaining invasive access to an authorized Nodavo process.
- A malicious clipboard/file sender exploiting parsers, paths, quotas, or auto-open behavior.
- A compromised dependency, build runner, download host, or update manifest.

Physical compromise of either paired machine, kernel compromise, malicious firmware, and a compromised OS trust store are outside the 1.0 defensive boundary, but must be stated in release documentation. So are code injection, process hollowing, debugging, `PROCESS_DUP_HANDLE`, process-memory read/write, or arbitrary-code compromise involving an already authorized Nodavo UI or agent process: the local IPC gates reject an independent impersonating endpoint, but they do not create a separate OS principal or integrity boundary around the trusted process itself. Windows full-trust UI/agent processes make this distinction especially important. Supporting a threat model that includes invasive same-user process access requires a separately qualified broker or OS principal and is not claimed by 1.0.

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
- A native display callback is only a coalesced dirty signal. The platform publishes a replacement only after a bounded complete graph stabilizes; retired native identities are never reused. macOS uses CoreGraphics reconfiguration observation, while Windows combines a broadcast-capable hidden window with authoritative full polling and process-wide per-monitor-v2 DPI awareness.
- Local and peer capability epochs are directionally separate. Inbound input, topology, clipboard, and file metadata must cite the receiver's current persisted local epoch; outbound metadata cites the epoch authenticated from the peer. Reconnect exchanges both sides' complete grants and epochs.
- Post-pair capability changes use the existing mutually authenticated TLS control stream. They are not described as separately signed: pinned mTLS peer authentication, strict target/epoch validation, and the local OS-protected trust database are the trust boundary. Every accepted change releases affected input/content state and closes the old connection; reconnect must use the persisted policy and newly negotiated epochs.

## Input capture and injection

- Native capture starts in non-suppressing mode. Suppression is permitted only while an authenticated, authorized focus lease is actively routing local input to the peer.
- macOS requires the user-granted Accessibility trust boundary. Windows remains inside the current interactive user's default input desktop; login, Session 0, UAC secure desktop, and privileged unattended control are rejected.
- Readiness probes are content-free, bounded, cached briefly, and run off the async command dispatcher. They never construct or register a capture runtime; only permission/default-desktop state, display discovery, API capability, and a non-posting injector prerequisite are checked. `ready` is therefore a prerequisite signal, not live capture proof. A timeout or platform error reports unavailable rather than inferring success.
- The macOS permission command executes only in the authenticated agent identity. Displaying the system prompt is not authorization: its return value is ignored and the UI receives only the result of a new trust and prerequisite probe. Windows has no corresponding permission command, elevation path, or secure-desktop workaround.
- Session-topology readiness is independent of local display discovery. It becomes ready only after the exact authenticated remote topology is installed and either the local revision published for inbound control is exactly acknowledged or the local graph remains intentionally unpublished because no inbound input grant exists. It resets on disconnect, recovery, revoke, or failure.
- A local display change immediately blocks new focus. The agent closes native routing admission, waits for in-flight suppression decisions, drains the bounded admitted-input queue under the old lease, forces releases and restores local ownership, and installs only the latest validated map. If local topology is directionally published for inbound control, focus cannot resume until the peer acknowledges that exact replacement revision; outbound-only operation uses the same stable committed snapshot without publishing it. Snapshot acquisition, sends, and acknowledgement use fixed deadlines that a hot-plug storm cannot extend.
- Authenticated input for any non-current lease is inert before sequence advancement or native display resolution. Absolute pointer injection is the only topology-sensitive retry and is retained at capacity one for at most one retry; keys, buttons, scroll, relative deltas, and forced releases do not depend on display geometry.
- Capture and injector teardown are deadline-bounded. A timed-out or fatally failed native owner permanently poisons that process-local runtime so a detached old worker cannot overlap a new session; failed release or ownership restore latches the shared safety state before any later close or readiness publication.
- Nodavo injection carries a private process tag where the platform supports one. Capture rejects that tag and every event the OS reports as injected, preventing synthetic feedback loops.
- Keyboard usages, modifiers, media keys, pointer buttons, normalized motion, and line/precise scrolling are validated before injection. Native codes never cross the peer protocol directly.
- An edge transition uses a critical reliable pointer-entry message. Native suppression and relative deltas remain gated until the receiver validates the lease/session/grant, resolves the session display token, injects the entry position, and returns an authenticated acknowledgement. This prevents a lost or reordered entry datagram from applying deltas at a stale cursor.
- Routed motion uses bounded nonzero relative deltas with no display identity. Callback-queue coalescing preserves the exact sum only while it remains in range; otherwise events stay separate or fail back to explicit recovery instead of silently truncating physical motion.
- The injector tracks every accepted key/button press. Emergency stop, focus loss, lock, sleep, tap/hook disable, timeout, and transport failure synchronously request deterministic release and local-ownership restoration before successful acknowledgement.
- One safety operation has a 20-second end-to-end ceiling covering command admission, release acknowledgement, pre-existing session/worker quiescence, and authoritative enrollment and cleanup of inbound transfers. While it is active, stale handshake generations cannot publish `connected`/`ready` and new transfer-worker admission is closed. Success reopens admission and publishes `ready` only after cleanup under the same status lock. Timeout or any partial failure latches the agent in `stopping`, closes sessions, rejects later reconnect/pairing in that process, keeps worker admission closed, and never reports `ready`; restart is required after remediation. Native UIs use a longer bounded response deadline so they do not report timeout while this server budget is still valid.
- A disabled or timed-out capture hook fails closed: suppression stops, local ownership is restored, and the remote session cannot continue silently.
- Input payloads and pairing codes are excluded from logs, crash metadata, and telemetry.
- The readiness response contains enum states only; it excludes native display and desktop identifiers, process data, paths, peer identities, prompt details, and input content.
- A topology revision must be installed and, when directionally published, acknowledged before focus can move in that corresponding direction. A persisted placement contains only the peer identifier and one of disabled/left/right/above/below; native and session display identifiers cannot be represented. Ephemeral edge routes are derived only from current committed topologies, the peer input grant, and the exact acknowledgement of any local revision published for inbound control; an outbound-only local graph remains unpublished. Routes are disabled when empty or stale and still pass through the ordinary focus lease, reliable pointer-entry acknowledgement, debounce, hysteresis, and cooldown checks. Changing placement during non-local focus performs safety recovery and disconnects before the saved policy can be used again.
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
- The process-local public registry admits every authenticated queued/active manifest before retaining it, enforces one combined 128-nonterminal limit, and retains at most 32 terminal records. Its random public UUID is never a peer wire UUID and is never reused during the process. Internal no-reuse/tombstone state is hard-capped at 4,096 accepted generations and 8,192 peer/direction/wire entries; exact retained traffic stays idempotent at capacity, while a novel identity is rejected before mutation or acknowledgement. Snapshots expose no names, paths, hashes, peer identities, endpoints, epochs, timestamps, or raw errors and remain below the 64 KiB local-IPC limit.
- Explicit cancellation discards only the matching transfer and is linearized against finalization. `cancelled` is published only after cleanup succeeds; cleanup failure becomes sticky `failed/cleanup_failed`, poisons later file work, and cannot be retried into a false success. A wrong identifier, parallel manifest, offset gap/overlap, incomplete completion, or staging failure is rejected without advancing receive state.
- Existing files are never overwritten silently.
- Received files are not executed or automatically opened.
- Per-peer quotas, cancellation, backpressure, and rate limits limit denial of service.

The pre-alpha receiver writes through capability-rooted, no-follow directory and file handles. Its staging root is private before any content name is created: Unix permissions are verified, while Windows creates an owner-only protected DACL atomically through a root-relative handle and rejects permissive, inherited, foreign-owned, reparse, or structurally ambiguous state. One process-wide operation lease serializes begin/resume/finalize/discard. Progress is acknowledged only after file and journal flushes; supported platforms also sync every mutated destination directory deepest-first and the destination root last. Windows exposes that directory-entry crash flushing is unsupported, so an untracked resume after an agent restart is rejected rather than advertised as power-loss durable.

Outbound selection is anchored by no-follow handles before canonicalization. Enumeration, manifest accounting, hashing, chunks, roots, stable file identities, and cooperative cancellation are bounded. Links, reparse points, sparse/special files, overlapping roots, hard-link aliases, mutations, cycles, and cross-platform path collisions fail closed. Publication never overwrites an existing destination. If a late multi-file publication or cleanup failure makes safe rollback ambiguous, the staging owner is poisoned and already published Nodavo identities are retained for explicit remediation instead of deleting a possibly substituted pathname.

The running agent associates inbound transfer identifiers only after an authenticated, authorized manifest and keeps that association peer-scoped across link loss. Each persistent device identity gets a separate private staging namespace, so another peer presenting the same wire UUID cannot resume, finalize, or discard that state; legacy unscoped staging is not migrated. Revocation waits for workers and the staging lease, then discards only identifiers known for that peer. Process-lifetime completed/cancelled tombstones reject reconnect reannouncement, but public history, selected outbound sources, cancellation tombstones after process restart, and durable poison persistence are still stable-release gates.

## Local IPC

- macOS release builds use the per-user launchd Mach service `dev.nodavo.agent.ipc` with reciprocal per-message XPC code-signing requirements; only the explicit non-distributable development feature uses a private same-UID UDS.
- Windows uses one-request named-pipe connections with a current-user ACL and reciprocal connection-bound guards for the exact packaged UI and agent processes before any request is sent or decoded.
- UI requests are capability checked; the UI does not directly read private network keys.
- Trusted-device listing is bounded to 32 public summaries containing only the local peer identifier, bounded display name, active/revoked state, locally issued grants, and the five-state semantic placement. It excludes certificates, endpoints, native/session display identifiers, private material, and the peer's independently issued grants. Placement and manual-focus mutations are one-shot: an ambiguous response authorizes status-only reconciliation, not a blind resend. Malformed status or error envelopes cannot be treated as a deterministic acknowledgement or rejection.

The macOS agent installs an exact `xpc_connection_set_peer_code_signing_requirement` before activating its Mach-service listener and every accepted peer; the Swift UI installs the reciprocal helper requirement before activating its client connection. Both requirements bind the Apple/Developer ID chain, compile-time ten-character Team ID, exact `dev.nodavo.macos` or `dev.nodavo.agent` identifier, exact application/team entitlements, and absence of `get-task-allow`. The XPC contract checks every received message, so an independent same-user process cannot launder bytes queued before an exec into the signed UI. Requests/replies are exact one-value XPC dictionaries carrying the existing deny-unknown JSON contract, limited to 64 KiB, 16 peers, four outstanding requests per peer, 32 globally, and a 360-second hard request ceiling.

The earlier UDS audit-token design is explicitly withdrawn: `LOCAL_PEERTOKEN` describes current peer task state, not the origin of already queued bytes, so token rechecks and finite challenges cannot establish message provenance. Missing compile-time Team ID or Mach service fails closed, release has no UDS fallback, and `NODAVO_IPC_PATH` is ignored. Development packaging alone compiles the non-default `development-unverified-local-ipc` same-UID UDS bypass, marks it unsafe/non-distributable, and does not advertise the release Mach service. Reciprocal XPC authentication is implemented for correctly signed release builds, but live Nodavo Developer ID/provisioning/notarization credential proof and an installed mutual runtime exercise remain release gates.

The Windows UI-to-agent source path retains the accepted pipe, process, primary token, and exact process-image handles for the whole one-request connection. Initial authorization requires the same SID, interactive session and logon authentication identifier as the agent; unchanged process creation time and token identifiers; a full package identity matching the compile-time package name, publisher-derived family name, AUMID, architecture, empty resource identifier, and exact `Nodavo.Windows.exe`; and a valid Authenticode signature whose leaf certificate DER hash matches the policy embedded in that agent build. The retained identity is rechecked before blocking frame input and after bounded decode immediately before dispatch.

Before the Windows UI writes that request, it authenticates its own exact `Package.Current` name, publisher, PFN, AUMID, and installed content root, then obtains the pipe server PID and retains the server process, token, and no-share-delete executable handles. The server must execute the exact non-reparse `agent\nodavo-agent.exe` beneath that authenticated package root, share the UI's session/logon lineage, retain stable process creation and token identifiers, and carry the compile-time pinned Authenticode signer. It revalidates the retained identity after the framed reply and before JSON decoding. The separately launched Rust agent is not claimed to possess package identity or an AUMID; its authority comes from the authenticated package root plus the exact signed executable inside it. Development and release policies are mutually exclusive compile-time metadata with separate UI package identities; unconfigured, unpackaged, mismatched, unsigned, or substituted binaries fail closed. Release policy additionally requires normal Windows trust and validated timestamp evidence; development policy requires its separately installed development certificate and exact pin. Packaging signs and verifies both native executables before packing and again after unpacking.

These Windows checks have source, policy-test, cross-target, and package-script evidence only at this stage. They have not yet been exercised by an installed packaged UI on qualified Windows x64 or ARM64 hardware, and production publisher, Authenticode, and timestamp credentials are absent. Mutual source enforcement therefore exists, while installed mutual local-IPC qualification remains a release gate. A process with invasive access to an already authorized UI or agent can still steal or manipulate its handles or memory; this is the explicitly excluded authorized-process-compromise boundary, not a claimed same-user security principal.

## Updates and supply chain

The agent now integrates a deliberately non-activating Unix/macOS slice around the pre-alpha update crate. Builds are unconfigured unless a manifest HTTPS endpoint and Ed25519 public key are explicitly embedded at compile time. When configured, the client uses the native platform TLS verifier/root store, disables redirects, ambient proxy discovery, cookies, credentials, and decompression, and applies bounded status, length, range, timeout, and body rules. The signed manifest must match the build's channel, target, and install identity, and its artifact must share the manifest origin. Consent is bound to the exact canonical offer UUID.

Accepted artifacts are resumed into a private capability-rooted content-addressed staging area, under a cross-process exclusive lease and bounded quota/retention policy. Writes are streamed through exact offset, size, and digest checks; files and supported directory mutations are synchronized before verified staging is reported. The bilingual macOS Settings UI can manually check or refresh, poll bounded progress on a separate client, report an up-to-date result, accept or decline an exact offer, and resume a paused download without displaying the endpoint, filesystem path, or digest.

The source-only external-supervision reducer is a policy boundary, not an installer. A separate one-shot **Install and restart** decision can consume only the exact `ReadyToInstall` session into a bounded handoff containing a nonzero request ID and the exact original signed manifest envelope. In the default agent build this type exposes encoding and its request ID but not decoding, raw-envelope access, supervisor admission/host methods, reducer state, or actions. Repository and packaging gates reject the non-default `supervisor-host` feature from agent artifacts. This exclusion reduces accidental authority in the replaceable process but is not runtime authentication: a future supervisor must still mutually authenticate the old process and exact installed target/version, hold an exclusive lock, and use protected authenticated state.

The supervisor-side contract provisionally reserves the request without durably consuming it, loads a fresh rollback floor, re-verifies the exact original envelope under supervisor-local policy, derives the plan internally, and reopens and rehashes the exact sealed content-addressed artifact. Only then may it atomically persist the replay tombstone, exact old-process binding, and schema 3 journal, which binds the request ID, supervisor-generated transaction and attempt identities, candidate/predecessor evidence, and rollback state. Failures before that persistence authorize nothing. Once persistence is called, an error, malformed authenticated reload, or non-exact reload is outcome-unknown: the lock and admission remain closed, and only recovery from the authenticated store may authorize any retry, reducer action, or new request. The reducer then requires journal-before-effect transitions, bounded process attempts, authenticated exact-process exit after timeout, candidate health before commit, and floor advancement before backup retirement. The agent's shutdown path performs a bounded fail-closed drain and leaves session/transfer admission closed, but no update IPC invokes a supervisor.

macOS source can validate and retain a bounded sealed universal app tree with exact signing, entitlement, notarization/System Policy, ownership, mode, ACL, hardlink, content, and mutation proofs. It intentionally exposes no swap, activation, or rollback primitive: the tested unprivileged cross-parent exchange is incompatible with keeping both trees immutable. Windows source adds owner-only fixed-volume content-addressed staging, a cross-process lease, quotas/retention, and bounded read-only Appx inspection from retained handles. It performs no package deployment, registration, activation, launch, or rollback, and its native behavior still requires Windows runtime qualification.

This repository supplies no production endpoint, release private signing key, or evidence of a live production update check. It also has no protected production update journal or durable rollback floor, separately packaged supervisor executable, authenticated supervisor IPC, activation adapter, restart/health/rollback process wiring, or physical power-loss proof. Staged content is never executed or installed. These are release gates rather than properties of the current source foundations.

The following are mandatory release requirements:

- Release artifacts will be code signed; macOS will be notarized and Windows will use Authenticode.
- Update manifests will be signed with an offline-controlled release key.
- Update state will reject rollback below the recorded safe version unless the user performs a documented recovery action.
- Correctly signed releases must preserve macOS per-message reciprocal XPC code requirements and Windows reciprocal process/package/Authenticode guards with one-request pipe connections; signed mutual macOS runtime qualification, installed Windows mutual-IPC evidence, and live production credential proof remain release requirements.
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
