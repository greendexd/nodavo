<!-- doc-id: macos-app; lang: en; revision: 18 -->

# Nodavo for macOS

[English](README.md) · [Русский](README.ru.md)

The current SwiftUI menu-bar shell connects to the per-user Rust agent through signed XPC in a release build. The packaged LaunchAgent advertises `dev.nodavo.agent.ipc`; the agent verifies the exact UI signing requirement on every received message and the UI applies the reciprocal exact helper requirement. The shell displays bounded status/focus and trusted-device summaries, exposes local emergency stop and manual focus controls, implements listening/manual pairing with explicit per-capability selection and six-digit code confirmation, and supports transactional post-pair grant and per-device placement changes plus confirmed trust revocation. The Overview and Settings screens separately show agent reachability, Accessibility trust, local input readiness, local displays, and peer-topology synchronization. Layout exposes the exact persisted disabled/left/right/above/below preference for one selected trusted peer. The Transfers page queues up to 32 explicitly selected files/folders, shows bounded byte progress plus cancellation using redacted transfer identifiers, and states that received files use the fixed `Downloads/Nodavo` folder. Broad cross-platform and signed-runtime validation remain under implementation.

```bash
cargo run -p nodavo-agent --features development-unverified-local-ipc
swift run --package-path apps/macos \
  -Xswiftc -DNODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC Nodavo
```

The feature and Swift compile flag above select an explicit unsafe same-user UDS bypass for source-tree development only. It is incompatible with distribution. A default agent build without an embedded Team ID or registered Mach service fails closed and has no UDS fallback.

All pairing permissions default to off. The selected permissions are bound to the confirmed pairing transcript and signed device trust. Post-pair switches update only after the agent acknowledges the exact change; revoked devices cannot be edited and must be paired again. The UI never sends inferred filesystem paths: only absolute paths returned by an explicit local picker selection are accepted.

## Manual focus

Manual acquisition is available only from an exact authoritative local-focus status with a connected peer and ready input, local topology, and peer topology. It sends one `request_remote_focus` with the fixed five-second lease and a separate 15-second mutation deadline. A local reply or any ambiguous result waits the complete lease window and performs exactly one fresh eight-second status-only reconciliation; the mutation is never resent. Release likewise sends one 15-second `release_focus`: an exact local reply completes immediately, while any other successful or ambiguous result performs one status-only reconciliation. The maximum sequential path is 28 seconds within the 30-second operation contract.

Only an exact strict `focus_rejected` error is deterministic. Transport, timeout, unknown/malformed error, duplicate-key, status-shape, and decoding failures are ambiguous. Failed reconciliation locks both focus actions with unknown ownership until an explicit authoritative status refresh succeeds. Emergency stop remains available throughout, supersedes the focus generation, and prevents any late focus reply from changing presentation.

## Layout

The Layout page loads one strict bounded authoritative trusted-peer list. Every row must contain exactly one known `placement` value: `disabled`, `left`, `right`, `above`, or `below`; duplicate, missing, unknown, extra, or private fields are rejected before presentation. The UI selects one persisted peer identity and sends only that exact peer ID plus one semantic direction. It never sends display IDs, session IDs, coordinates, or inferred topology.

A placement choice is not applied optimistically. The displayed value changes only after an exact `peer_placement_changed` acknowledgement for the same peer and direction. A lost, malformed, or mismatched reply is outcome-ambiguous, so the mutation is never resent: the UI performs one fresh `list_trusted_peers` reconciliation and applies that whole authoritative result. If reconciliation also fails, that peer stays locked until an explicit refresh succeeds. Revoked peers and peers with an active or unresolved mutation cannot be changed. This path has strict decoder and generation/race tests, but physical edge switching with signed macOS and Windows packages remains a release gate.

## Transfers

The visible Transfers page polls a strict, bounded authoritative agent snapshot about once per second while work is nonterminal or a cancellation outcome is pending. Polling and cancellation use separate agent clients with short per-command deadlines, while local admission has its own bounded margin for two sequential preparation windows, so file progress cannot occupy pairing, readiness, update, or emergency-stop paths. Hiding the page or reaching an all-terminal snapshot stops polling. Duplicate JSON object keys are rejected from bounded raw bytes before decoding; missing, extra, private, malformed, oversized, duplicate, or noncanonical fields are also rejected. A rejected or older poll preserves the last rows as stale, retries with bounded backoff while work remains, and never invents a failed transfer. A truncated snapshot retains only bounded rows needed for a pending admission or cancellation; absence resolves an operation only in a non-truncated authoritative snapshot.

The UI shows current transfers and terminal transfers first observed during this app session. This is not durable transfer history. It shows direction, localized phase, bounded counters, and the shared `••••••••-12345678` identifier form, but never names, absolute paths, peer details, or private metadata. A signed release uses the fixed relative destination label `Downloads/Nodavo`; the development-unverified build remains in an isolated app-state folder, and neither mode opens received files automatically. A completed empty transfer is rendered as determinate 100%, including its accessibility value. Cancellation applies only the exact authoritative response for the same transfer ID. If a cancellation reply is ambiguous, cancellation authority remains locked to that one ID until authoritative convergence; another transfer cannot replace it. An ambiguous admission reply locks that picker selection and requires a fresh explicit selection before another send, preventing a blind duplicate.

## Readiness and Accessibility

Readiness is a strict public enum snapshot, not a diagnostic dump. The shell rejects missing, unknown, or malformed readiness values. Behind a finite deadline and short cache, the agent checks Accessibility trust, local display discovery, and a non-posting injector prerequisite; it never constructs a second capture runtime, suppresses, or injects input. **Ready** therefore describes current local prerequisites, not live capture proof. A connected session reports peer topology as ready only after the exact authenticated remote topology is installed and either the local revision published for inbound control is acknowledged or the local graph remains intentionally unpublished because no inbound input grant exists.

The macOS platform source now observes CoreGraphics display reconfiguration through a callback that only marks a coalesced dirty generation. Capture and injection share a stable bounded full snapshot with non-reused opaque identities. The agent closes routing admission, drains already admitted input, and releases the old focus lease. When the local topology is published for inbound control, the exact replacement revision must be acknowledged before the session becomes ready again; an outbound-only local graph remains intentionally unpublished and uses the stable committed snapshot directly. Focused/inert tests cover callback interleavings, teardown, stale identities, deadlines, and safety latching; a real signed Mac attached to a Windows peer has not yet passed physical hot-plug qualification.

**Allow Accessibility** asks macOS from the agent process that needs the permission and then performs a fresh probe. The prompt API's return value is not treated as authorization, so cancelling the prompt or leaving System Settings unchanged remains **Action required**. This source behavior and focused prerequisite tests are implemented; a signed, provisioned, notarized Nodavo build has not yet proved the complete TCC flow on a clean Mac.

## Updates

Settings exposes the current non-activating updater slice. A user can manually check or refresh, see an up-to-date result, explicitly choose **Download and stage** or **Decline** for the exact offer, follow bounded download progress, and resume a paused download. One generation-owned polling loop uses a separate agent client after consent or while downloading, so it does not block pairing, transfers, or emergency stop and stops at a terminal or paused state. The interface never displays the manifest URL, staging path, or digest. A verified result is reported honestly as staged; automatic installation is unavailable in the development build.

The agent side is unconfigured by default. Only a build that explicitly embeds a pinned HTTPS manifest endpoint and Ed25519 public key can contact an update service; the repository contains neither a production endpoint nor the private signing key, and no live production check or signing ceremony is claimed. The current macOS/Unix path uses native platform TLS without redirects or decompression, verifies a bounded signed manifest and same-origin artifact, binds consent to its canonical offer UUID, and resumably writes digest-verified content to a private capability-rooted staging root with a cross-process lease, quotas, retention, and fsync.

The platform source can validate and retain an exact bounded sealed universal app tree, including the app and nested agent signatures, entitlements, notarization/System Policy, owner/mode/ACL rules, hardlink rejection, immutable contents, and mutation detection. It intentionally exposes no swap, activation, or rollback API: local testing showed that unprivileged cross-parent exchange fails once both trees are sealed against same-user mutation. The repository still has no installer handoff, application or agent restart, health/rollback supervisor, protected production Keychain update journal, or durable rollback floor. Nothing staged is executed. Live proof with Nodavo production signing, provisioning, and notarization credentials remains an open release gate.

## Packaging

The repository can build a universal `arm64` + `x86_64` application containing the SwiftUI executable and a per-user agent helper. The same development run also emits an explicitly non-notarized universal update ZIP and exact size/SHA-256 metadata for validation tests; neither artifact is installable by the current product:

```bash
scripts/package-macos.sh --development --version 0.1.0 --build-number 1
```

This development artifact is ad-hoc signed, not notarized, has no provisioned Keychain access, does not register its bundled LaunchAgent, compiles the unsafe same-user UDS bypass, renders the Mach service disabled, and is labeled as not for distribution. Packaging asserts those properties. It is a bundle-layout test, not a release.

Release packaging fails closed unless the caller explicitly supplies a Developer ID identity, Team ID, separate provisioning profiles for `dev.nodavo.macos` and `dev.nodavo.agent`, and a `notarytool` Keychain profile:

```bash
APPLE_TEAM_ID=TEAMID1234 \
MACOS_SIGNING_IDENTITY="Developer ID Application: Example" \
MACOS_APP_PROVISIONING_PROFILE=/path/to/app.provisionprofile \
MACOS_AGENT_PROVISIONING_PROFILE=/path/to/agent.provisionprofile \
MACOS_NOTARY_PROFILE=nodavo-notary \
scripts/package-macos.sh --version 1.0.0 --build-number 1
```

Only the agent helper profile must authorize the exact Keychain access group `${APPLE_TEAM_ID}.dev.nodavo.agent`; the UI entitlement and profile do not receive that group. The release path embeds the validated Team ID into Rust and signed app metadata, asserts signed-mutual XPC policy through bounded pre-sign self-check output, verifies that the LaunchAgent advertises the exact Mach service, and checks the actual universal UI/helper against exact reciprocal Developer ID requirements, identifiers, entitlements, all architectures, hardened runtime, and absent `get-task-allow`. It then registers the helper and requires notarization acceptance, stapling, and Gatekeeper assessment. Those release steps have not been exercised without Nodavo signing/notarization credentials; the self-check alone is not signed runtime proof.

The packaged UI reports whether the helper is enabled, awaiting Login Items approval, missing, or failed to register. Registration failure never falls back to starting an unregistered helper or exposing a privileged service.
