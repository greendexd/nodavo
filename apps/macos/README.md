<!-- doc-id: macos-app; lang: en; revision: 4 -->

# Nodavo for macOS

[English](README.md) · [Русский](README.ru.md)

The current SwiftUI menu-bar shell connects to the per-user Rust agent through its private Unix socket. It displays bounded status/focus metadata, exposes local emergency stop and manual focus controls, and implements listening/manual pairing with explicit per-capability selection and six-digit code confirmation. Pairing, pinned reconnect, the authenticated input session, and the macOS native capture/injection bridge run in pre-alpha. Edge switching, cross-device display mapping, trusted-device management, post-pair permission changes, and transfers remain under implementation.

```bash
cargo run -p nodavo-agent
swift run --package-path apps/macos Nodavo
```

All pairing permissions default to off. The selected permissions are bound to the confirmed pairing transcript and signed device trust.

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
