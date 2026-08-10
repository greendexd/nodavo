<!-- doc-id: macos-app; lang: en; revision: 9 -->

# Nodavo for macOS

[English](README.md) · [Русский](README.ru.md)

The current SwiftUI menu-bar shell connects to the per-user Rust agent through signed XPC in a release build. The packaged LaunchAgent advertises `dev.nodavo.agent.ipc`; the agent verifies the exact UI signing requirement on every received message and the UI applies the reciprocal exact helper requirement. The shell displays bounded status/focus and trusted-device summaries, exposes local emergency stop and manual focus controls, implements listening/manual pairing with explicit per-capability selection and six-digit code confirmation, and supports transactional post-pair grant changes plus confirmed trust revocation. The Transfers page queues up to 32 explicitly selected files/folders and displays only a redacted queue reference. Broad cross-platform and signed-runtime validation remain under implementation.

```bash
cargo run -p nodavo-agent --features development-unverified-local-ipc
swift run --package-path apps/macos \
  -Xswiftc -DNODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC Nodavo
```

The feature and Swift compile flag above select an explicit unsafe same-user UDS bypass for source-tree development only. It is incompatible with distribution. A default agent build without an embedded Team ID or registered Mach service fails closed and has no UDS fallback.

All pairing permissions default to off. The selected permissions are bound to the confirmed pairing transcript and signed device trust. Post-pair switches update only after the agent acknowledges the exact change; revoked devices cannot be edited and must be paired again. The UI never sends inferred filesystem paths: only absolute paths returned by an explicit local picker selection are accepted.

## Updates

Settings exposes the current non-activating updater slice. A user can manually check or refresh, see an up-to-date result, explicitly choose **Download and stage** or **Decline** for the exact offer, follow bounded download progress, and resume a paused download. One generation-owned polling loop uses a separate agent client after consent or while downloading, so it does not block pairing, transfers, or emergency stop and stops at a terminal or paused state. The interface never displays the manifest URL, staging path, or digest. A verified result is reported honestly as staged; automatic installation is unavailable in the development build.

The agent side is unconfigured by default. Only a build that explicitly embeds a pinned HTTPS manifest endpoint and Ed25519 public key can contact an update service; the repository contains neither a production endpoint nor the private signing key, and no live production check or signing ceremony is claimed. The current macOS/Unix path uses native platform TLS without redirects or decompression, verifies a bounded signed manifest and same-origin artifact, binds consent to its canonical offer UUID, and resumably writes digest-verified content to a private capability-rooted staging root with a cross-process lease, quotas, retention, and fsync.

There is no installer handoff, activation, application or agent restart, health/rollback supervisor, protected production Keychain update journal, or durable rollback floor. Nothing staged is executed. For a correctly signed release, XPC enforces the exact Developer ID/Team ID identifiers and entitlements for every UI-to-agent message, while the UI reciprocally verifies the exact helper. The previous socket audit-token claim was withdrawn because it could authenticate a post-exec task while consuming bytes queued pre-exec. The development feature intentionally keeps only an unsafe same-UID UDS. Live proof with Nodavo production signing, provisioning, and notarization credentials remains an open release gate. Windows updater staging and UI integration are also absent.

## Packaging

The repository can build a universal `arm64` + `x86_64` application containing the SwiftUI executable and a per-user agent helper:

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
