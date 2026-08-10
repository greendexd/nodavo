<!-- doc-id: macos-app; lang: en; revision: 6 -->

# Nodavo for macOS

[English](README.md) · [Русский](README.ru.md)

The current SwiftUI menu-bar shell connects to the per-user Rust agent through its private Unix socket. It displays bounded status/focus and trusted-device summaries, exposes local emergency stop and manual focus controls, implements listening/manual pairing with explicit per-capability selection and six-digit code confirmation, and supports transactional post-pair grant changes plus confirmed trust revocation. The Transfers page queues up to 32 files or folders chosen explicitly with the macOS open panel and displays only a redacted queue reference. Pairing, pinned reconnect, the authenticated input session, native macOS capture/injection, and the bounded file-transfer queue run in pre-alpha. Edge switching, cross-device display mapping, detailed transfer progress in local IPC, and broad cross-platform validation remain under implementation.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

All pairing permissions default to off. The selected permissions are bound to the confirmed pairing transcript and signed device trust. Post-pair switches update only after the agent acknowledges the exact change; revoked devices cannot be edited and must be paired again. The UI never sends inferred filesystem paths: only absolute paths returned by an explicit local picker selection are accepted.

## Packaging

The repository can build a universal `arm64` + `x86_64` application containing the SwiftUI executable and a per-user agent helper:

```bash
scripts/package-macos.sh --development --version 0.1.0 --build-number 1
```

This development artifact is ad-hoc signed, not notarized, has no provisioned Keychain access, does not register its bundled LaunchAgent, and is labeled as not for distribution. It is a bundle-layout test, not a release.

Release packaging fails closed unless the caller explicitly supplies a Developer ID identity, Team ID, separate provisioning profiles for `dev.nodavo.macos` and `dev.nodavo.agent`, and a `notarytool` Keychain profile:

```bash
APPLE_TEAM_ID=TEAMID1234 \
MACOS_SIGNING_IDENTITY="Developer ID Application: Example" \
MACOS_APP_PROVISIONING_PROFILE=/path/to/app.provisionprofile \
MACOS_AGENT_PROVISIONING_PROFILE=/path/to/agent.provisionprofile \
MACOS_NOTARY_PROFILE=nodavo-notary \
scripts/package-macos.sh --version 1.0.0 --build-number 1
```

Both provisioning profiles must authorize the exact Keychain access group `${APPLE_TEAM_ID}.dev.nodavo.agent`. The release path uses the hardened runtime, registers the embedded helper as a per-user LaunchAgent, and requires notarization acceptance, stapling, and Gatekeeper assessment before reporting success. Those release steps have not been validated without Nodavo signing and notarization credentials.

The packaged UI reports whether the helper is enabled, awaiting Login Items approval, missing, or failed to register. Registration failure never falls back to starting an unregistered helper or exposing a privileged service.
